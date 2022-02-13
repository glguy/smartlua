-- This is a zero-sum balance ledger

--[[
    UTILITY LIBRARY
]]

local function authz(name)
    for _, v in ipairs(signers) do
        if v == name then return end
    end
    error 'unauthorized'
end

local function chain(f)
    return function(...)
        local r = table.pack(f(...))
        f = r[r.n]
        return table.unpack(r, 1, r.n - 1)
    end
end

local function dispatch(M)
    return function(cmd, ...) return M[cmd](...) end
end

--[[
    PRIVATE STATE
]]
local balances = {}
local tokens = {n=0}

--[[
    PUBLIC API
]]
local M = {}

function M.get(name) return balances[name] end

function M.withdraw(name, amount)
    assert(math.type(amount) == 'integer', 'integral amount required')
    assert(0 < amount, 'withdraw requires positive value')

    authz(name)
    local bal = balances[name] or 0

    if bal == amount then
        bal = nil
    else
        bal = bal - amount
    end
    balances[name] = bal

    local tid = tokens.n + 1
    tokens.n = tid
    local token = { tid = tid }
    tokens[tid] = token
    tokens[token] = amount

    return token
end

function M.deposit(name, token)
    local tid = token.tid
    assert(tokens[tid] == token, 'bad token')

    local value = tokens[token]
    balances[name] = (balances[name] or 0) + value
    tokens[token] = nil

    local n = tokens.n
    tokens.n = n - 1
    if tid == n then
        tokens[tid] = nil
    else
        tokens[tid] = tokens[n] 
        tokens[tid].tid = tid
        tokens[n] = nil
    end

    return value
end

return 'ledger', register(dispatch(M))
