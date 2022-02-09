local objs = {}
function register(f)
    table.insert(objs, f)
    return #objs
end
function invoke(i, ...)
    return objs[i](...)
end