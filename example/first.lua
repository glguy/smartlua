{
    smartlua = '0.1',
    signers = {
        '9LtcVo7q+at5ihEYtbu+YScb6qlbTt4D7GwlO+3kc+k=',
        '68A3esZ9Ausdi05f6OCKs0e4qdwsbGlrSRzcHQ7WLEY=',
    },
    code = [[
-- implementation populates `signers` global variable as an array of public keys

-- sum of initial balances must fit in 64-bit signed integer
local balances = {}

-- All initial signers start with 10 resources
for _, signer in ipairs(signers) do
    print('Initial balance for ' .. signer)
    balances[signer] = 10
end

function transfer(target, amount)
    for k,v in pairs(balances) do print('balance ' .. k .. ' is ' .. v) end
    for i,v in ipairs(signers) do print('signer ' .. i .. ' is ' .. v) end

    assert(#signers == 1, 'Too many signers: ' .. #signers)
    local source = signers[1]
    assert(source ~= target)
    local source_bal = balances[source]
    assert(source_bal ~= nil)

    local target_bal = balances[target]
    assert(target_bal ~= nil)

    assert(math.type(amount) == 'integer')
    assert(0 < amount)
    assert(amount <= source_bal)

    balances[source] = source_bal - amount
    balances[target] = target_bal + amount

    print('Transferred ' .. amount .. ' from ' .. source .. ' to ' .. target)
    print('New source balance: ' .. balances[source])
    print('New target balance: ' .. balances[target])
end

-- anyone can read a current balance
function read(who)
    local balance = balances[who]
    assert(balance ~= nil)
    print('Balance for ' .. who .. ': ' .. balance)
end

-- all the participants can agree to add a new user
function add_account(account)

    -- new account is new
    assert(balances[account] == nil)
    
    local signerset = {}
    
    -- all signers have balances and are unique
    for _, x in ipairs(signers) do
        assert(balances[x] ~= nil)
        assert(signerset[x] == nil)
        signerset[x] = true
    end
    
    -- all balances have signers
    for x, _ in pairs(balances) do
        assert(signerset[x] == true)
    end

    balances[account] = 0
end

-- the remaining participants can close empty accounts
function close_empties()

    local signerset = {}
    
    -- all signers have balances and are unique
    for _, x in ipairs(signers) do
        assert(balances[x] ~= nil)
        assert(signerset[x] == nil)
        signerset[x] = true
    end
    
    -- all balances have signers or are zero and closing
    for k, v in pairs(balances) do
        if not signerset[x] then
           assert(v == 0)
           balances[k] = nil
        end
    end
end
]]
}
