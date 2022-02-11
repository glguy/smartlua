local function authz(name)
    for _, v in ipairs(signers) do
        if v == name then return end
    end
    error 'unauthorized'
end

local function chain(f)
    return function(...)
        local r, g = f(...)
        f = g
        return r
    end
end

local function dispatch(M)
    return function(cmd, ...) return M[cmd](...) end
end

local balances = {}
for _, v in ipairs(signers) do
    balances[v] = 100
end

local M = {}

function M.get(name) return balances[name] end

function M.withdraw(name, amount)
    assert(math.type(amount) == 'integer', 'integral amount required')

    authz(name)
    local bal = balances[name]
    assert(bal ~= nil, 'so such account')
    assert(0 < amount, 'nonpositive balance')
    assert(amount <= bal, 'insufficient funds')

    if bal == amount then
        bal = nil
    else
        bal = bal - amount
    end
    balances[name] = bal

    return chain(function(target)
        balances[target] = (balances[target] or 0) + amount
    end)
end

return 'ledger', register(dispatch(M))
