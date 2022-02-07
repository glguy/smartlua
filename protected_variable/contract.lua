{
    smartlua = '0.1',
    signers = {
        '9LtcVo7q+at5ihEYtbu+YScb6qlbTt4D7GwlO+3kc+k=',
    },
    code = [[
-- This contract identifies the email address of the owner of object X
assert(#signers == 1)

local owner_email
local owner_pubkey = signers[1]

function get_email()
    return owner_email
end

local function check_authorization()
    assert(#signers == 1, 'wrong number of signers')
    assert(signers[1] == owner_pubkey, 'wrong signer')
end

function set_email(email)
    assert(type(email) == 'string', 'wrong type for email')
    check_authorization()
    print('Changing email from ' .. tostring(owner_email) .. ' to ' .. email)
    owner_email = email
end

function set_owner(pubkey)
    assert(type(pubkey) == 'string', 'wrong type for pubkey')
    check_authorization()
    print('Changing owner from ' .. tostring(owner_pubkey) .. ' to ' .. pubkey)
    owner_pubkey = pubkey
    print('Clearing owner_email')
    owner_email = nil
end
]]
}
