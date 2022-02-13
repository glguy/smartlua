local hostpub = '9LtcVo7q+at5ihEYtbu+YScb6qlbTt4D7GwlO+3kc+k='
local playerpub = '68A3esZ9Ausdi05f6OCKs0e4qdwsbGlrSRzcHQ7WLEY='

local function authz(k)
    for _, v in ipairs(signers) do
        if k == v then return end
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

local hoststake = invoke(2, 'withdraw', hostpub, 10)

return 'wager', register(chain(function(cancel)
    if cancel then
        authz(hostpub)
        hoststake(hostpub)
        return
    end

    local playerstake = invoke(2, 'withdraw', playerpub, 10)
    return function(commitment)
        local game = register(invoke(1, commitment, playerpub, hostpub))
        return game, function(dest)
            local outcome = invoke(game, 'getstate')
            if outcome == 'playerwins' then
                authz(playerpub)
            elseif outcome == 'playerlose' then
                authz(hostpub)
            else
                error 'claim not ready'
            end
            invoke(2, 'deposit', dest, playerstake)
            invoke(2, 'deposit', dest, hoststake)
        end
    end
end))
