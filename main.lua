local colors = require 'ansicolors'
local crypto = require 'crypto'

local app = require 'pl.app'
local dir = require 'pl.dir'
local file = require 'pl.file'
local pretty = require 'pl.pretty'
local tablex = require 'pl.tablex'
local Set = require 'pl.Set'

local my_version = '0.1'

-----------------------------------------------------------------------
-- State directories and file paths
-----------------------------------------------------------------------

-- compute the directory that holds state metadata
local function state_dir(hash)
    return 'states/' .. hash
end

-- compute the path to a transition manifest file
local function manifest_path(hash)
    return state_dir(hash) .. '/manifest.lua'
end

-- compute the path to a transition signature
local function signature_path(hash, i)
    return state_dir(hash) .. '/sig_' .. i
end

local function keys_dir()
    return 'keys'
end

-----------------------------------------------------------------------
-- Crypto support functions
-----------------------------------------------------------------------

local function sha256(x)
    local h = crypto.sha256(x)
    return (string.gsub(h, '.', function(b) return string.format('%02x', string.byte(b)) end))
end

-- Get the private key object stored in a ed25519 private key PEM
local function open_private_key(filename)
    local pem = assert(file.read(filename))
    return crypto.privatekey(pem)
end

-- Open all the keys in the keys directory and return them in a table
-- indexed by public keys.
local function get_my_keys()
    local my_keys = {}
    for filename in dir.dirtree(keys_dir()) do
        local key = open_private_key(filename)
        local pub = key:pubstr()
        my_keys[pub] = key
    end
    return my_keys
end

-----------------------------------------------------------------------
-- Lua table utilities
-----------------------------------------------------------------------

local function readonly(t)
    assert(type(t) == 'table')
    local result = {}
    setmetatable(result, {
        __index = t,
        __newindex = function() error 'readonly' end,
        __metatable = 'readonly',
        __len = function() return #t end,
    })
    return result
end

-- printing function used when transition fragments print
local function debug_print(...)
    print(colors'%{magenta}debug>', ...)
end

local function build_env(signers)
    local overlay = {
        string = readonly(string),
        table = readonly(table),
        math = readonly(math),
        utf8 = readonly(utf8),
        signers = readonly(signers),

        type = type,
        assert = assert,
        next = next,
        pcall = pcall,
        tostring = tostring,
        tonumber = tonumber,
        pairs = pairs,
        ipairs = ipairs,
        xpcall = xpcall,
        error = error,
        select = select,

        print = debug_print, -- XXX: temporary
    }

    local env = {}
    setmetatable(env, {
        __index = overlay,
        __metatable = true,
    })

    return env
end

-----------------------------------------------------------------------
-- Smart transition implementation
-----------------------------------------------------------------------

-- Verify that the argument is a sha256 hash
local function valid_hash(h)
    assert(type(h) == 'string')
    assert(#h == 64)
    assert(string.match(h, '^[%l%d]*$'))
end

-- Check that the argument is a base64 encoded 32-byte value
-- matching the shape of Ed25519 public keys
local function valid_pubkey(k)
    assert(type(k) == 'string')
    crypto.publickey(k)
end

local function valid_transition(t)
    assert(type(t) == 'table')
    t = tablex.copy(t)

    assert(type(t.smartlua) == 'string')
    assert(t.smartlua == my_version)
    t.smartlua = nil

    if t.previous then
        valid_hash(t.previous)
        t.previous = nil
    end

    assert(type(t.signers) == 'table')
    do
        local s = tablex.copy(t.signers)
        for i, v in ipairs(s) do
            valid_pubkey(v)
            s[i] = nil
        end
        assert(next(s) == nil)
    end
    t.signers = nil

    assert(type(t.code) == 'string')
    t.code = nil

    -- no more entries allowed
    assert(next(t) == nil)
end

local function open_transition(filename)
    local content = assert(file.read(filename))
    local transition = assert(pretty.read(content))
    valid_transition(transition)
    return transition
end

local function step_transition(transition, env, signers, initial)
    tablex.icopy(signers, transition.signers)
    local e
    if initial then
        e = env
    else
        e = readonly(env)
    end
    local chunk = assert(load(transition.code, 'transition', 't', e))
    assert(pcall(chunk))
    return sha256(serialize(transition) .. serialize(env))
end

local function get_state(tophash)

    local transitions = {}
    local hashes = {}

    do
        local hash = tophash
        while hash ~= nil do
            local transition = open_transition(manifest_path(hash))

            table.insert(transitions, transition)
            table.insert(hashes, hash)
            hash = transition.previous
        end
    end

    local signers = {}
    local env = build_env(signers)

    for i = #transitions, 1, -1 do
        local initial = i == #transitions
        local transition = transitions[i]
        local hash = hashes[i]

        print(string.format(colors'Loading state: %{green}%s', hash))

        local got_hash = step_transition(transition, env, signers, initial)
        assert(got_hash == hash)

        for j, pubstr in ipairs(transition.signers) do
            local sig = file.read(signature_path(hash, j))
            if sig == nil then
                print(string.format(colors'Signature check %d: %{red}MISSING', j))
            else
                local pub = crypto.publickey(pubstr)
                if pub:verify(sig, hash) then
                    print(string.format(colors'Signature check %d: %{green}OK', j))
                else
                    print(string.format(colors'Signature check %d: %{red}FAILED', j))
                end
            end
        end
    end

    return env, signers
end

-----------------------------------------------------------------------
-- Top-level command handler implementations
-----------------------------------------------------------------------

local modes = {}

function modes.run(...)

    local flags, params = app.parse_args({...}, {})
    assert(#params == 1)
    local filename = params[1]
    local save = flags.save

    local transition = open_transition(filename)
    local env, signers = get_state(transition.previous)
    local hash = step_transition(transition, env, signers, transition.previous == nil)

    print(colors'Run produced hash: %{green}' .. hash)

    -- save the new state
    if save then
        print 'Saving state...'
        dir.makepath(state_dir(hash))
        file.copy(filename, manifest_path(hash))

        -- sign to state with all relevant private keys
        local my_keys = get_my_keys()
        for i, pub in ipairs(transition.signers) do
            local key = my_keys[pub]
            if key == nil then
                print('Signature ' .. i .. colors': %{red}SKIPPED')
            else
                local sig = key:sign(hash, '')
                file.write(signature_path(hash, i), sig)
                print('Signature ' .. i .. colors': %{green}SIGNED')
            end
        end
    else
        print 'Not saving state (use --save)'
    end

end

-- top-level command: print out all the public key hashes of the local private keys
function modes.keys()
    for filename in dir.dirtree('keys') do
        local key = open_private_key(filename)
        local pub = key:pubstr()
        print(filename, pub)
    end
end

local function dispatch(cmd, ...)
    local mode = assert(modes[cmd], 'unknown command')
    mode(...)
end
dispatch(...)
