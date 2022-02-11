#!/bin/bash
PUB1="9LtcVo7q+at5ihEYtbu+YScb6qlbTt4D7GwlO+3kc+k="
PUB2="68A3esZ9Ausdi05f6OCKs0e4qdwsbGlrSRzcHQ7WLEY="

rm -r states
build/smartlua run          --debug --save meta/00-root.lua
build/smartlua run --cached --debug --save meta/01-wordle.lua    "$PUB1"
build/smartlua run --cached --debug --save meta/02-ledger.lua    "$PUB1" "$PUB2"
build/smartlua run --cached --debug --save meta/03-startgame.lua "$PUB1"
build/smartlua run --cached --debug --save meta/04-deposit.lua   "$PUB2"
build/smartlua run --cached --debug --save meta/05-begin.lua     "$PUB1"
build/smartlua run --cached --debug --save meta/06-guessword.lua "$PUB2"
build/smartlua run --cached --debug --save meta/07-giveclue.lua  "$PUB1"
build/smartlua run --cached --debug --save meta/08-guessword.lua "$PUB2"
build/smartlua run --cached --debug --save meta/09-giveclue.lua  "$PUB1"
build/smartlua run --cached --debug --save meta/10-guessword.lua "$PUB2"
build/smartlua run --cached --debug --save meta/11-winner.lua    "$PUB1"
