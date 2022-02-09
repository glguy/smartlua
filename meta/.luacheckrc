return {
        std = "lua54+meta+smartlua",
        stds = {
            meta = {
                read_globals = {'register', 'invoke'},
            },
            main = {
                read_globals = {"crypto"},
            },
        }
        