return {
    std = "lua54+meta+smartlua",
    stds = {
        meta = {
            read_globals = {'register', 'invoke', 'signers', 'index'},
        },
        main = {
            read_globals = {"crypto"},
        },
    }
