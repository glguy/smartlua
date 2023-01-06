local function addref(obj, refs)
    table.insert(refs, obj)
    return #refs
end

local D = {}

local function deserialize_value(file, env, refs, uprefs, upixes)
    local t = file:read()
    return D[t](file, env, refs, uprefs, upixes)
end

D['T'] = function() return true end
D['F'] = function() return false end
D['N'] = function() return nil end

D['I'] = function() return math.huge end
D['i'] = function() return -math.huge end
D['E'] = function() return 0/0 end

D['Z'] = function(file)
    return math.tointeger(file:read())
end

D['D'] = function(file)
    return tonumber(file:read())
end

D['S'] = function(file)
    local len = math.tointeger(file:read())
    local str = file:read(len)
    assert(file:read() == '')
    return str
end

D['t'] = function(file, env, refs, uprefs, upixes)
    local t = {}
    addref(t, refs)
    local n = math.tointeger(file:read())
    for _ = 1, n do
        local key = deserialize_value(file, env, refs)
        local val = deserialize_value(file, env, refs, uprefs, upixes)
        t[key] = val
    end
    return t
end

D['R'] = function(file, _, refs)
    local n = math.tointeger(file:read())
    return assert(refs[n], 'no such ref')
end

D['f'] = function(file, env, refs, uprefs, upixes)
    local n = math.tointeger(file:read())
    local bc = file:read(n)
    assert(file:read() == '')
    local f = load(bc, '=(load)', 'b', env)
    local me = addref(f, refs)
    local u = math.tointeger(file:read())

    for i = 1, u do
        local uid = debug.upvalueid(f, i)
        uprefs[uid] = me
        upixes[uid] = i
    end

    for i = 1, u do
        local tag = file:read()
        if tag == 'U' then
            local refid = math.tointeger(file:read())
            local g = refs[refid]
            local upid = math.tointeger(file:read())
            debug.upvaluejoin(f, i, g, upid)
        else
            local val = D[tag](file, env, refs, uprefs, upixes)
            debug.setupvalue(f, i, val)
        end
    end
    return f
end

return function(t, file)
    local refs, uprefs, upixes = {}, {}, {}
    assert(file:read() == 't')
    addref(t, refs)
    local n = math.tointeger(file:read())
    for _ = 1, n do
        local key = deserialize_value(file)
        local val = deserialize_value(file, t, refs, uprefs, upixes)
        t[key] = val
    end
    assert(file:read() == nil) -- no left-overs allowed
    return t
end
