# Wordle Smart Contract

This example implements a two-player Wordle conversation.

To play a game you'll select a random 16-character nonce and a 5-letter word.
Commit to picking this word by running:

```lua
print(sha256(nonce .. word))
```

Then start a game from an empty contract with that hash of the word and the public
key of the player who is authorized to make guesses.

```lua
startgame(commithash, playerpubkey)
```

Next exchange guesses and clue responses with the player. The player guessing words
will sign all transitions containing the guess. The game host will sign all replies
containing the clue.

```lua
guessword 'LENDS'
```

```lua
giveclue 'YYBYB'
```

The game proceeds until a player wins by receiving a `'GGGGG'` clue response or
by exhausting all 6 word guesses without getting a winning response.

If the player runs out of turns the host must reveal the nonce and goal word.
These must satisfy the commitment hash given at the beginning of the game, and
the final word much satisfy all the clues issues during the game to confirm that
the player has lost.
