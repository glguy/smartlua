
local openssl = require 'openssl'
local sha256  = openssl.digest.get 'sha256'

local file = require 'pl.file'
local pretty = require 'pl.pretty'


local function x25519_to_raw(pubkey)
    return string.sub(pubkey:export('der'), 13, 44)
end

local function raw_to_x25519(raw)
    return openssl.pkey.read(
        "\x30\x2a\x30\x05\x06\x03\x2b\x65\x6e\x03\x21\x00" .. raw,
        false, 'der')
end

local function readonly(t)
    assert(type(t) == 'table')
    local result = {}
    setmetatable(result, {
        __index = t,
        __newindex = function() error 'readonly' end,
        __metatable = 'readonly',
    })
    return result
end

local function valid_transition(t)
    if type(t) ~= 'table' then return false end

    local allowed_keys = {
        previous = true,
        signers = true,
        code = true,
    }

    for k, _ in pairs(t) do
        if not allowed_keys[k] then return false end
        allowed_keys[k] = nil
    end

    -- optional
    allowed_keys.previous = nil

    if next(allowed_keys) ~= nil then return false end

    return true
end

local function build_env(super)
    local overlay = {
        string = readonly(string),
        table = readonly(table),
        math = readonly(math),
        utf8 = readonly(utf8),

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
    setmetatable(overlay, {
        __index = super,
        __metatable = 'overlay',
    })

    local newindex
    if super ~= nil then
        newindex = function() error 'readonly' end
    end

    local env = {}
    setmetatable(env, {
        __index = overlay,
        __metatable = true,
        __newindex = newindex,
    })

    return env
end

local function step_transition(transition, prev)
    local env = build_env(prev)
    local chunk = load(transition.code, 'transition', 't', env)
    assert(pcall(chunk))
    local env_hash = openssl.digest.digest('sha256', serialize(transition) .. serialize(env), false)
    return env_hash, env
end

local function get_state(hash)

    local transitions = {}
    local hashes = {}

    while hash ~= nil do
        local content = assert(file.read(hash .. '/manifest.lua'))
        local transition = assert(pretty.read(content))
        assert(valid_transition(transition))
        table.insert(transitions, transition)
        table.insert(hashes, hash)
        hash = transition.previous
    end

    local env
    for i = #transitions, 1, -1 do
        local got_hash, e = step_transition(transitions[i], env)
        if env == nil then
            env = e
        end
        assert(got_hash == hashes[i])
    end

    return env
end


local modes = {}

function modes.run(filename)

    local content = assert(file.read(filename))
    local transition = assert(pretty.read(content))
    assert(valid_transition(transition))

    local init = get_state(transition.previous)
    local env = build_env(init)
    local chunk = load(transition.code, 'transition', 't', env)
    assert(pcall(chunk))
    local env_hash = openssl.digest.digest('sha256', serialize(transition) .. serialize(env), false)
    print('Run produced hash: ' .. env_hash)
end

function modes.verify(hash)
end

function modes.genkey()
    local priv = openssl.pkey.new('ec', 'ED25519')
    print(x25519_to_raw(priv))
end

do -- command dispatch
    local cmd, arg = ...
    local mode = modes[cmd]
    if mode == nil then
        error 'invalid mode'
    end
    mode(arg)
end

--[[
local x = {}
local hidden = 5
local function double() hidden = hidden * 2 end
x.double = double
function x.more() double() hidden = hidden - 1 end
print(serialize(x))
--]]

--[[
local x = {}
x.a = x
x.b = {x}
print(serialize(x))
--]]