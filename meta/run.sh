#!/bin/bash
PUB1="9LtcVo7q+at5ihEYtbu+YScb6qlbTt4D7GwlO+3kc+k="
PUB2="68A3esZ9Ausdi05f6OCKs0e4qdwsbGlrSRzcHQ7WLEY="

rm states/head
build/smartlua run --save meta/00-root.lua

build/smartlua run --cached --save --debug meta/01-wordle.lua $PUB1

build/smartlua run --cached --save meta/02-startgame.lua $PUB1
build/smartlua run --cached --debug - <<< "return invoke(2, 'getstate')"

build/smartlua run --cached --save meta/03-guessword.lua $PUB2
build/smartlua run --cached --debug - <<< "return invoke(2, 'getstate')"

build/smartlua run --cached --save meta/04-giveclue.lua $PUB1
build/smartlua run --cached --debug - <<< "return invoke(2, 'getstate')"

build/smartlua run --cached --save meta/05-guessword.lua $PUB2
build/smartlua run --cached --debug - <<< "return invoke(2, 'getstate')"

build/smartlua run --cached --save meta/06-giveclue.lua $PUB1
build/smartlua run --cached --debug - <<< "return invoke(2, 'getstate')"

build/smartlua run --cached --save meta/07-guessword.lua $PUB2
build/smartlua run --cached --debug - <<< "return invoke(2, 'getstate')"

build/smartlua run --cached --save meta/08-winner.lua $PUB1
build/smartlua run --cached --debug - <<< "return invoke(2, 'getstate')"
