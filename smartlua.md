# Smart Lua

Provide a mechanism to support a secure sequence of execution steps of a Lua program with a verifiable execution chain.

Use serialization of Lua states to allow suspend and resume of these Lua states and to make it possible to securely identify them by hash.

## Transition definition

Each transition uses the following parameters.

- Optional previous state hash
- Lua code fragment
- Zero or more public keys

The previous Lua state is deserialized, the Lua fragment is executed, the resulting state is serialized.

The new state's name is the hash of the transition parameters and the serialized resulting state.

For each public key listed, sign the new state hash.

## Transition Verification

To verify a transition:

- Check that all public keys listed in the transition have corresponding signatures
- Verify the previous state (you can cache this step to remember trusted states)
- Execute the Lua fragment on the previous state to verify the result is the new state.

## Initial states

An initial state works the same way as a transition except it does not specify a previous state hash. In this case no previous state is loaded and the Lua fragment is run with a fresh global hash table. The results of this hash table are stored as the initial state for the next transition.

## Transition execution

When executing a Lua fragment for transition, it is run with a custom global environment. This global environment will pass through reads of undefined variables to the underlying state, but will not pass assignments through. This results in a read-only treatment of the global namespace. Transition fragments must work through pre-defined global methods from the previous state in order to store changes. The temporary global environment the Lua fragment runs in is discarded.

```lua
-- Code to run a fragment
local fragment_env = {}
setmetatable(fragment_env, {
  __index = previous_state,
  __metatable = true,
})
load(lua_fragment, '=(load)', 't', fragment_env)()
```

## Making use of signatures in code

When code is run the list of public keys that will be signing the transition are loaded into a special global variable that code can refer to and branch on. Since transitions will only be treated as valid by the verifier if these public keys correspond to attached signatures, the transition code can believe that the public keys represent valid signers.

## Example: Shared payments

Given 3 private keys:

- `2KgXomoYNRdlBq+CPZcw+mze5UDUp/iCVDBuDIRLym0=`
- `cHute+Qu7HqkIbCqy0FdlHnhU+RRg6vtnlAFdgyZbVw=`
- `oC6x+LFZdNsBpwsKEn6SSoGDrIaMpZ9HD1MKQ0ogqWg=`

We can compute an initial state like:

```lua
-- implementation populates `signers` global variable as an array of public keys

-- sum of initial balances must fit in 64-bit signed integer
local balances = {
  ['HbaGF7h9gqcVvwq+l219m7trwOIk44wuDZpQDSclpCE='] = 10,
  ['Ifni9gFFvIBsyXRJTMSFKPnUJIU+lPpcm+Fn6ixtkTw='] = 10,
  ['ByRn704GWnhgkjZ2/kYBl77oS7cTWNQQxrx6JTt+4FM='] = 10,
}

function transfer(target, amount)
    assert(#signers == 1)
    local source = signers[1]
    assert(source ~= target)
    local source_bal = balances[source]
    assert(source_bal ~= nil)

    local target_bal = balances[target]
    assert(target_bal ~= nil)

    assert(math.type(amount) == 'integer')
    assert(source_bal >= amount)

    balances[source] = source_bal - amount
    balances[target] = target_bal + amount
end

-- anyone can read a current balance
function read(who)
    return balances[who]
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
```
