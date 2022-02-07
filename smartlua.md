# Smart Lua

Provide a mechanism to support a secure sequence of execution steps of a Lua program with a verifiable execution chain.

Use serialization of Lua states to allow suspend and resume of these Lua states and to make it possible to securely identify them by hash.

## Transition definition

Each transition uses the following parameters.

- SmartLua version number
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
- Check that the transition is not a fork from a previously known sequence

## Initial states

An initial state works the same way as a transition except it does not specify a previous state hash. In this case no previous state is loaded and the Lua fragment is run with a fresh global hash table. Only an initial state is allowed to set new entries in the global table.

## Transition execution

Transitions after the initial state are run with a read-only globals table. Transition fragments must work through pre-defined global methods from the previous state in order to store changes. 

## Making use of signatures in code

When code is run the list of public keys that will be signing the transition are loaded into a special global variable that code can refer to and branch on. Since transitions will only be treated as valid by the verifier if these public keys correspond to attached signatures, the transition code can believe that the public keys represent valid signers.

## Example: Balance tracking

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
```
