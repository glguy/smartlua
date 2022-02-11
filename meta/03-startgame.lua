local hostpub = '9LtcVo7q+at5ihEYtbu+YScb6qlbTt4D7GwlO+3kc+k='
local playerpub = '68A3esZ9Ausdi05f6OCKs0e4qdwsbGlrSRzcHQ7WLEY='

local function ishost()
    for _, v in ipairs(signers) do
        if hostpub == key then return end
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

local hoststake = invoke(2, 'withdraw', hostpub, 10)

return 'wager', register(chain(function(cancel)
    if cancel then
        ishost()
        hoststake(hostpub)
        return
    end

    local playerstake = invoke(2, 'withdraw', playerpub, 10)
    return nil, function(commitment)
        local game = register(invoke(1, commitment, playerpub, hostpub))
        return game, function()
            local outcome = invoke(game, 'getstate')
            if outcome == 'playerwins' then
                hoststake(playerpub)
                playerstake(playerpub)
            elseif outcome == 'playerlose' then
                hoststake(hostpub)
                playerstake(hostpub)
            else
                error 'claim not ready'
            end
        end
    end
end))
