local function addref(obj, refs)
    table.insert(refs, obj)
    return #refs
end

local D = {}


local function deserialize_value(file, env, refs, uprefs, upixes)
    local t = file:read()
    return D[t](file, env, refs, uprefs, upixes)
end

D['true'] = function() return true end
D['false'] = function() return false end
D['nil'] = function() return nil end

function D.integer(file)
    local line = file:read()
    return math.tointeger(line)
end

function D.number(file)
    local line = file:read()
    return tonumber(line)
end

function D.string(file)
    local len = math.tointeger(file:read())
    local str = file:read(len)
    assert(file:read() == '')
    return str
end

function D.table(file, env, refs, uprefs, upixes)
    local t = {}
    addref(t, refs)
    local n = math.tointeger(file:read())
    for _ = 1, n do
        local key = deserialize_value(file)
        local val = deserialize_value(file, env, refs, uprefs, upixes)
        t[key] = val
    end
    return t
end

function D.ref(file, env, refs, uprefs, upixes)
    local n = math.tointeger(file:read())
    return refs[n]
end

D['function'] = function(file, env, refs, uprefs, upixes)
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
        if tag == 'upref' then
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
    assert(file:read() == 'table')
    addref(t, refs)
    local n = math.tointeger(file:read())
    for _ = 1, n do
        local key = deserialize_value(file)
        local val = deserialize_value(file, t, refs, uprefs, upixes)
        t[key] = val
    end
    assert(file:read() == nil) -- no leftofvers allowed
    return t
end
