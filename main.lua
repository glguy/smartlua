
local openssl = require 'openssl'
local colors = require 'ansicolors'

local dir = require 'pl.dir'
local file = require 'pl.file'
local pretty = require 'pl.pretty'
local tablex = require 'pl.tablex'

local my_version = '0.1'

local function state_dir(hash)
    return 'states/' .. hash
end

local function manifest_path(hash)
    return state_dir(hash) .. '/manifest.lua'
end

local function signature_path(hash, i)
    return state_dir(hash) .. '/sig_' .. i
end

local function x25519_to_raw(pubkey)
    return string.sub(pubkey:export('der'), 13, 44)
end

local function raw_to_x25519(raw)
    -- builds an ed25519 DER encoded public key
    return openssl.pkey.read(
        "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00" .. raw,
        false, 'der')
end

local function get_my_keys()
    local my_keys = {}
    for filename in dir.dirtree('keys') do
        local pem = assert(file.read(filename))
        local key = assert(openssl.pkey.read(pem, true, 'pem'))
        local pub = openssl.base64(x25519_to_raw(key:get_public()))
        my_keys[pub] = key
    end
    return my_keys
end

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

local function valid_transition(t)
    if type(t) ~= 'table' then return false end

    local allowed_keys = {
        previous = true,
        signers = true,
        code = true,
        smartlua = true,
    }

    for k, _ in pairs(t) do
        if not allowed_keys[k] then return false end
        allowed_keys[k] = nil
    end

    -- optional
    allowed_keys.previous = nil

    if next(allowed_keys) ~= nil then return false end

    assert(t.smartlua == my_version, 'smartlua version mismatch')

    return true
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

        print = print, -- XXX: temporary
    }

    local env = {}
    setmetatable(env, {
        __index = overlay,
        __metatable = true,
    })

    return env
end

local function open_transition(filename)
    local content = assert(file.read(filename))
    local transition = assert(pretty.read(content))
    assert(valid_transition(transition))
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
    return openssl.digest.digest('sha256', serialize(transition) .. serialize(env), false)
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

        for k,v in pairs(env) do print(k,v) end
        local got_hash = step_transition(transition, env, signers, initial)
        assert(got_hash == hash)

        for j, pub in ipairs(transition.signers) do
            local key = assert(openssl.base64(pub, false))
            key = assert(raw_to_x25519(key))
            local sig = file.read(signature_path(hash, j))
            if sig == nil then
                print('MISSING SIGNATURE ' .. j)
            else
                assert(key:verify(hash, sig, ''), 'failed verifying ' .. hash .. ' signature ' .. i)
            end
        end
    end

    return env, signers
end

-----------------------------------------------------------------------
-- Top-level command handler implementations
-----------------------------------------------------------------------

local modes = {}

function modes.run(filename)
    local my_keys = get_my_keys()
    local transition = open_transition(filename)
    local env, signers = get_state(transition.previous)
    local hash = step_transition(transition, env, signers, transition.previous == nil)

    print('Run produced hash: ' .. hash)

    -- save the new state
    dir.makepath(state_dir(hash))
    file.copy(filename, manifest_path(hash))

    -- sign to state with all relevant private keys
    for i, pub in ipairs(transition.signers) do
        local key = my_keys[pub]
        if key == nil then
            print('Signature ' .. i .. colors': %{red}SKIPPED%{reset}, private key missing')
        else
            local sig = key:sign(hash, '')
            file.write(signature_path(hash, i), sig)
            print('Signature ' .. i .. colors': %{green}OK')
        end
    end
end

-- top-level command: print out all the public key hashes of the local private keys
function modes.keys()
    for filename in dir.dirtree('keys') do
        local pem = assert(file.read(filename))
        local key = assert(openssl.pkey.read(pem, true, 'pem'))
        local pub = openssl.base64(x25519_to_raw(key:get_public()))
        print(filename, pub)
    end
end

local function dispatch(cmd, ...)
    local mode = modes[cmd]
    if mode == nil then
        error 'invalid mode'
    end
    mode(...)
end
dispatch(...)
