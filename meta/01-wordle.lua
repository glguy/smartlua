local function mkcommitment(secret, word)
    assert(type(secret) == 'string')
    assert(#secret == 16)
    assert(type(word) == 'string')
    assert(string.match(word, '^%u%u%u%u%u$'))
    return crypto.base64e(crypto.hmac('sha256', secret, word))
end

local function checkclue(answer, word, clue)
    local sub = string.sub
    local near = {}
    for i = 1, 5 do
        local a = sub(answer, i, i)
        local w = sub(word, i, i)
        local c = sub(clue, i, i)

        if a == w then
            assert(c == 'G')
        else
            assert(c == 'Y' or c == 'B')
            near[a] = (near[a] or 0) + 1
        end
    end
    for i = 1, 5 do
        local w = sub(word, i, i)
        local c = sub(clue, i, i)

        if c == 'B' then
            assert(near[w] == nil)
        elseif c == 'Y' then
            assert(near[w] > 0)
            if near[w] == 1 then
                near[w] = nil
            else
                near[w] = near[w] - 1
            end
        end
    end
end

local function authz(pub)
    for _, signer in ipairs(signers) do
        if signer == pub then return end
    end
    error 'unauthorized'
end

local function newgame(commitment, playerpub, hostpub)
    authz(hostpub)

    local M = {}
    local pending = 'word'
    local words = {}
    local clues = {}

    local function cleanup()
        M = { getstate = M.getstate }
    end    

    function M.giveclue(clue, secret, answer)
        assert(pending == 'clue')
        authz(hostpub)
    
        assert(type(clue) == 'string')
        assert(string.match(clue, '^[BYG][BYG][BYG][BYG][BYG]$'))
    
        table.insert(clues, clue)
    
        if clue == 'GGGGG' then
            pending = 'playerwins'
            cleanup()
        else
            if #clues < 6 then
                pending = 'word'
            else
                assert(mkcommitment(secret, answer) == commitment)
                for i = 1, 6 do
                    checkclue(answer, words[i], clues[i])
                end
                pending = 'playerloses'
                cleanup()
            end
        end
    end

    function M.guessword(word)
        authz(playerpub)
        assert(pending == 'word')
        assert(type(word) == 'string')
        assert(string.match(word, '^%u%u%u%u%u$'))
        table.insert(words, word)
        pending = 'clue'
    end

    function M.getstate()
        return pending, table.concat(words, ','), table.concat(clues, ',')
    end

    return register(function(method, ...) return M[method](...) end)
end

register(newgame)