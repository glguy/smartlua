local colors = require 'ansicolors'
local crypto = require 'crypto'

local app = require 'pl.app'
local dir = require 'pl.dir'
local file = require 'pl.file'
local pretty = require 'pl.pretty'
local Set = require 'pl.Set'
local stringio = require 'pl.stringio'
local tablex = require 'pl.tablex'

local serialize = require 'serialize'
local deserialize = require 'deserialize'

local my_version = '0.1'

-----------------------------------------------------------------------
-- State directories and file paths
-----------------------------------------------------------------------

-- compute the directory that holds state metadata
local function state_dir(hash)
    return 'states/' .. string.sub(hash, 1, 2) .. '/' .. hash
end


local function head_path(hash)
    return 'heads/' .. hash
end

-- compute the path to a transition manifest file
local function manifest_path(hash)
    return state_dir(hash) .. '/manifest.lua'
end

local function cache_path(hash)
    return state_dir(hash) .. '/cached_env'
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

local function newindex_readonly(_, n)
    error(string.format('Attempt to set `%s` on readonly table', n), 2)
end

local function readonly(t)
    assert(type(t) == 'table')
    local result = {}
    setmetatable(result, {
        __index = t,
        __newindex = newindex_readonly,
        __metatable = 'readonly',
        __len = function() return #t end,
    })
    return result
end

-- printing function used when transition fragments print
local function debug_print(...)
    print(colors'%{magenta}debug>', ...)
end

local function build_env(signers, debugmode, env)

    local print_impl
    if debugmode then
        print_impl = debug_print
    else
        print_impl = function() end
    end

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

        print = print_impl,
    }

    local metaenv = {
        __index = overlay,
        __metatable = true,
    }

    env = env or {}
    setmetatable(env, metaenv)

    return env, metaenv
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
    local content = assert(file.read(filename), 'failed to open manifest')
    local transition = assert(pretty.read(content), 'failed to parse manifest')
    valid_transition(transition)
    return transition
end

local function step_transition(transition, env, metaenv, signers, initial)
    tablex.icopy(signers, transition.signers)
    local chunk = assert(load(transition.code, '=(code)', 't', env))
    local result = {assert(pcall(chunk))}

    if initial then
        metaenv.__newindex = newindex_readonly
    end

    local f = stringio.create()
    serialize(transition, f)
    serialize(env, f)
    local rep = f:value()

    return sha256(rep), table.unpack(result, 2)
end

local function get_state(tophash, debugmode, usecache)

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

    local start_hash = hashes[#hashes]
    if start_hash ~= nil then
        local head_hash = file.read(head_path(start_hash))
        if head_hash == nil then
            print(colors'Head check: %{red}MISSING')
        elseif tablex.find(hashes, head_hash) == nil then
            print(colors'Head check: %{red}FORKED')
        else
            print(colors'Head check: %{green}OK')
        end
    end

    local signers = {}
    local env, metaenv = build_env(signers, debugmode)

    if usecache then
        print(string.format(colors'Deserializing cached state: %{yellow}%s', tophash))
        local cachefile = io.open(cache_path(tophash))
        deserialize(env, cachefile)
        metaenv.__newindex = newindex_readonly
        return env, metaenv, signers, start_hash
    end

    for i = #transitions, 1, -1 do
        local initial = i == #transitions
        local transition = transitions[i]
        local hash = hashes[i]

        print(string.format(colors'Loading state: %{green}%s', hash))

        local got_hash = step_transition(transition, env, metaenv, signers, initial)
        assert(got_hash == hash)

        for j, pubstr in ipairs(transition.signers) do
            local sig = file.read(signature_path(hash, j))
            if sig == nil then
                print(string.format(colors'Signature %d: %{red}MISSING', j))
            else
                local pub = crypto.publickey(pubstr)
                if pub:verify(sig, hash) then
                    print(string.format(colors'Signature %d: %{green}OK', j))
                else
                    print(string.format(colors'Signature %d: %{red}FAILED', j))
                end
            end
        end
    end

    return env, metaenv, signers, start_hash
end

-----------------------------------------------------------------------
-- Top-level command handler implementations
-----------------------------------------------------------------------

local modes = {}

-- flags
--   --debug     - show transition debug print statements
--   --save      - save the resulting state
function modes.run(...)
    local flags, params = app.parse_args({...}, {})
    assert(#params == 1, 'expected a single manifest filename parameter')
    local filename = params[1]
    local save = flags.save
    local debugmode = flags.debug ~= nil
    local usecache = flags.cached ~= nil

    local transition = open_transition(filename)
    local env, metaenv, signers, start_hash = get_state(transition.previous, debugmode, usecache)
    local hash = step_transition(transition, env, metaenv, signers, transition.previous == nil)

    if start_hash == nil then
        start_hash = hash
    end

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

        dir.makepath('heads')
        file.write(head_path(start_hash), hash)

        local cachefile = io.open(cache_path(hash), 'w')
        serialize(env, cachefile)
        cachefile:close()
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

-- Run a bit of Lua code in a specified SmartLua state
-- flags
--   --hash=HASH - load this hash
--   --head=HASH - load the latest head of this named hash
--   --code=CODE - literal Lua code as a string
--   --file=FILE - path to Lua source file
--   --debug     - show transition debug print statements
function modes.inspect(...)
    local flags, params = app.parse_args({...}, Set{'hash', 'head', 'code', 'file'})
    assert(#params == 0, 'no positional parameters expected')
    local debugmode = flags.debug ~= nil
    local usecache = flags.cached ~= nil

    local hash
    if flags.head then
        hash = assert(file.read(head_path(flags.head)), '--head not found')
    else
        hash = flags.hash
    end

    local code
    if flags.code then
        code = flags.code
    elseif flags.file then
        code = assert(file.read(flags.file), 'unable to read code file')
    end

    local env, metaenv, signers, _ = get_state(hash, debugmode, usecache)
    if code then
        print(colors'Inspect fragment: %{green}RUNNING')
        local transition = {signers = {}, code = code}
        local result = {step_transition(transition, env, metaenv, signers, hash == nil)}
        print(table.unpack(result, 2))
    else
        print(colors'Inspect fragment: %{yellow}NONE')
    end
end

local function dispatch(cmd, ...)
    local mode = assert(modes[cmd], 'unknown command')
    mode(...)
end
dispatch(...)
