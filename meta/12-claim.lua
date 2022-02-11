invoke(3, '68A3esZ9Ausdi05f6OCKs0e4qdwsbGlrSRzcHQ7WLEY=')

local function balcheck(key)
    print(key, invoke(2, 'get', key))
end

print(invoke(4, 'getstate'))
balcheck '68A3esZ9Ausdi05f6OCKs0e4qdwsbGlrSRzcHQ7WLEY='
balcheck '9LtcVo7q+at5ihEYtbu+YScb6qlbTt4D7GwlO+3kc+k='
