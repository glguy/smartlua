{
    smartlua = '0.1',
    signers = {},
    code = [[
local pending = 'start'
local hostpub
local playerpub
local commitment

local words = {}
local clues = {}

function getstate()
    return pending
end

function startgame(commitment_, playerpub_)
    assert(pending == 'start')
    assert(#signers == 1)
    
    commitment = commitment_
    hostpub = signers[1]
    playerpub = playerpub_
    pending = 'word'
end

function guessword(word)
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

function giveclue(clue, nonce, answer)
    assert(pending == 'clue')
    assert(#signers == 1)
    assert(signers[1] == hostpub)

    assert(type(clue) == 'string')
    assert(string.match(clue, '^[BYG][BYG][BYG][BYG][BYG]$'))
    
    if clue == 'GGGGG' then
        pending = 'playerwins'
    else
        table.insert(clues, clue)

        if #clues < 6 then
            pending = 'word'
        else
            assert(type(nonce) == 'string')
            assert(#nonce == 16)
            assert(type(answer) == 'string')
            assert(string.match(answer, '^%u%u%u%u%u$'))
            assert(sha256(nonce .. answer) == commitment)
            for i = 1, 6 do
                checkclue(answer, words[i], clues[i])
            end
            pending = 'playerloses'
        end
    end
end

]]
}
