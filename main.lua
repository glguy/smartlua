local colors = require 'ansicolors'
local crypto = require 'crypto'

local app = require 'pl.app'
local dir = require 'pl.dir'
local file = require 'pl.file'
local path = require 'pl.path'
local Set = require 'pl.Set'
local stringio = require 'pl.stringio'
local tablex = require 'pl.tablex'

local serialize = require 'serialize'
local deserialize = require 'deserialize'

local my_version = '0.1'

local function hexstr(str)
    return (string.gsub(str, '.', function(b) return string.format('%02x', string.byte(b)) end))
end

-----------------------------------------------------------------------
-- State directories and file paths
-----------------------------------------------------------------------

-- compute the directory that holds state metadata
local function state_dir(hash)
    return path.join('states', string.sub(hash, 1, 2), hash)
end

local function head_path()
    return path.join('states', 'head')
end

-- compute the path to a transition manifest file
local function manifest_path(hash)
    return path.join(state_dir(hash), 'manifest')
end

local function cache_path(hash)
    return path.join(state_dir(hash), 'cached_env')
end

-- compute the path to a transition signature
local function signature_path(hash, pubstr)
    local raw = crypto.base64d(pubstr)
    return path.join(state_dir(hash), 'sig_' .. hexstr(raw))
end

local function keys_dir()
    return 'keys'
end

-----------------------------------------------------------------------
-- Crypto support functions
-----------------------------------------------------------------------

local function sha256(x)
    return hexstr(crypto.digest('sha256', x))
end

-- Get the private key object stored in a ed25519 private key PEM
local function open_private_key(filename)
    local pem = assert(file.read(filename))
    return crypto.privatekey_pem(pem)
end

-- Open all the keys in the keys directory and return them in a table
-- indexed by public keys.
local function get_my_keys()
    local my_keys = {}
    local d = keys_dir()
    dir.makepath(d)
    for filename in dir.dirtree(d) do
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
    print(colors'%{magenta}print>', ...)
end

local function build_env(debugmode)

    local signers = {}

    local print_impl, debug_lib
    if debugmode then
        print_impl = debug_print
        debug_lib = debug
    else
        print_impl = function() end
        debug_lib = debug
    end

    local overlay = {
        coroutine = readonly(coroutine),
        math = readonly(math),
        string = readonly(string),
        table = readonly(table),
        utf8 = readonly(utf8),
        crypto = readonly(crypto),

        signers = readonly(signers),

        assert = assert,
        error = error,
        ipairs = ipairs,
        next = next,
        pairs = pairs,
        pcall = pcall,
        select = select,
        tonumber = tonumber,
        tostring = tostring,
        type = type,
        xpcall = xpcall,

        print = print_impl,
        debug = debug_lib,
    }

    local metaenv = {
        __index = overlay,
        __metatable = true,
    }

    local env = {}
    setmetatable(env, metaenv)

    return env, metaenv, signers
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

    if t.parent then
        valid_hash(t.parent)
        t.parent = nil
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

local function open_manifest(hash)
    local manifestfile = io.open(manifest_path(hash))
    local manifest = {}
    deserialize(manifest, manifestfile)
    manifestfile:close()
    valid_transition(manifest)
    return manifest
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

    return sha256(rep), rep, table.unpack(result, 2)
end

local function get_state(tophash, debugmode, usecache)
    local transitions = {}
    local hashes = {}

    do
        local hash = tophash
        while hash ~= nil do
            local transition = open_manifest(hash)
            table.insert(transitions, transition)
            table.insert(hashes, hash)
            hash = transition.parent
        end
    end

    local env, metaenv, signers = build_env(debugmode)

    if usecache then
        print(string.format(colors'Cached state:\t%{yellow}%s', tophash))

        -- verify cached state's hash
        local m = assert(file.read(manifest_path(tophash)))
        local e = assert(file.read(cache_path(tophash)))
        local got_hash = sha256(m .. e)
        assert(got_hash == tophash)

        deserialize(env, stringio.open(e))
        metaenv.__newindex = newindex_readonly
        return env, metaenv, signers
    end

    for i = #transitions, 1, -1 do
        local initial = i == #transitions
        local transition = transitions[i]
        local hash = hashes[i]

        print(string.format(colors'Running state: %{green}%s', hash))
        local got_hash, rep = step_transition(transition, env, metaenv, signers, initial)
        assert(got_hash == hash)

        for j, pubstr in ipairs(transition.signers) do
            local sig = file.read(signature_path(hash, pubstr))
            if sig == nil then
                print(string.format(colors'Signature %d: %{red}MISSING', j))
            else
                local pub = crypto.publickey(pubstr)
                if pub:verify(sig, rep) then
                    print(string.format(colors'Signature %d: %{green}PASSED', j))
                else
                    print(string.format(colors'Signature %d: %{red}FAILED', j))
                end
            end
        end
    end

    return env, metaenv, signers
end

-----------------------------------------------------------------------
-- Top-level command handler implementations
-----------------------------------------------------------------------

local modes = {}

-- Usage: run FILENAME [PUBKEY...]
-- flags
--   --debug     - show transition debug print statements
--   --save      - save the resulting state
--   --head=HASH - override the current chain head
function modes.run(...)
    local flags, params = assert(app.parse_args({...}, Set{'head'}, Set{'save', 'debug', 'cached'}))
    assert(#params > 0, 'expected a single manifest filename parameter')
    local filename = params[1]
    local save = flags.save
    local debugmode = flags.debug ~= nil
    local usecache = flags.cached ~= nil
    local parent = flags.head
    local signers = tablex.sub(params, 2)

    local code
    if filename == '-' then
        code = io.read 'a'
    else
        code = assert(file.read(filename))
    end

    if parent == nil then
        parent = file.read(head_path())
    end

    local manifest = {
        smartlua = my_version,
        signers = signers,
        parent = parent,
        code = code,
    }

    local initial = parent == nil
    local env, metaenv, signers_table = get_state(parent, debugmode, usecache)
    local result = {step_transition(manifest, env, metaenv, signers_table, initial)}
    local hash, rep = table.unpack(result, 1, 2)

    if debugmode and #result > 2 then
        print(colors'%{magenta}result>', table.unpack(result, 3))
    end

    print(string.format(colors'New state:\t%{green}%s', hash))

    -- save the new state
    if save then
        dir.makepath(state_dir(hash))

        local manifestfile = io.open(manifest_path(hash), 'w')
        serialize(manifest, manifestfile)
        manifestfile:close()

        -- sign to state with all relevant private keys
        local my_keys = get_my_keys()
        for i, pub in ipairs(signers) do
            local key = my_keys[pub]
            if key == nil then
                print('Signing ' .. i .. colors':\t%{red}SKIPPED')
            else
                local sig = key:sign(rep, '')
                file.write(signature_path(hash, key:pubstr()), sig)
                print('Signing ' .. i .. colors': %{green}SIGNED')
            end
        end

        local cachefile = io.open(cache_path(hash), 'w')
        serialize(env, cachefile)
        cachefile:close()

        file.write(head_path(), hash)
        print(string.format(colors'Saving state:\t%{green}OK'))
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

function modes.show(hash)
    local manifest = open_manifest(hash)
    print(string.format(colors'Version:\t%{green}%s', manifest.smartlua))
    if manifest.parent then
        print(string.format(colors'Parent state:\t%{green}%s', manifest.parent))
    else
        print(string.format(colors'Parent state:\t%{cyan}ROOT'))
    end
    for i, s in ipairs(manifest.signers) do
        print(string.format(colors'Signer %d:\t%{green}%s', i, s))
    end
    print()
    print(manifest.code)
end

local function dispatch(cmd, ...)
    local mode = assert(modes[cmd], 'unknown command')
    mode(...)
end
dispatch(...)
