assert(#signers == 1)

local pending = 'start'
local hostpub = signers[1]
local playerpub
local commitment
local words = {}
local clues = {}

local M = {}

function M.getstate()
    return pending, table.concat(words, ','), table.concat(clues, ',')
end

local function mkcommitment(secret, word)
    assert(type(secret) == 'string')
    assert(#secret == 16)
    assert(type(word) == 'string')
    assert(string.match(word, '^%u%u%u%u%u$'))
    return crypto.base64e(crypto.hmac('sha256', secret, word))
end

M.mkcommitment = mkcommitment

function M.guessword(word)
    assert(pending == 'word')
    assert(#signers == 1)
    assert(signers[1] == playerpub)

    assert(type(word) == 'string')
    assert(string.match(word, '^%u%u%u%u%u$'))
    table.insert(words, word)
    pending = 'clue'
end

local function checkclue(answer, word, clue)
    local near = {}
    for i = 1, 5 do
        local a = string.sub(answer, i, i)
        local w = string.sub(word, i, i)
        local c = string.sub(clue, i, i)

        if a == w then
            assert(c == 'G')
        else
            assert(c == 'Y' or c == 'B')
            near[a] = (near[a] or 0) + 1
        end
    end
    for i = 1, 5 do
        local w = string.sub(word, i, i)
        local c = string.sub(clue, i, i)

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

function M.giveclue(clue, secret, answer)
    assert(pending == 'clue')
    assert(#signers == 1)
    assert(signers[1] == hostpub)

    assert(type(clue) == 'string')
    assert(string.match(clue, '^[BYG][BYG][BYG][BYG][BYG]$'))

    table.insert(clues, clue)

    if clue == 'GGGGG' then
        pending = 'playerwins'
    else
        if #clues < 6 then
            pending = 'word'
        else
            assert(mkcommitment(secret, answer) == commitment)
            for i = 1, 6 do
                checkclue(answer, words[i], clues[i])
            end
            pending = 'playerloses'
        end
    end
end

function M.startgame(commitment_, playerpub_)
    assert(pending == 'start')
    assert(#signers == 1)
    assert(hostpub == signers[1])

    commitment = commitment_
    playerpub = playerpub_
    pending = 'word'
end

register(function(method, ...) return M[method](...) end)