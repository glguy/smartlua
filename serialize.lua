local utils = require 'pl.utils'
local tablex = require 'pl.tablex'

local S = {}

local function serialize_value(v, file, refs, uprefs, upixes)
    local t = type(v)
    local h = S[t]
    if h then
        h(v, file, refs, uprefs, upixes)
    else
        error('serialize does not support type: ' .. t)
    end
end

function S.boolean(v, file)
    if v then
        file:write 'T\n'
    else
        file:write 'F\n'
    end
end

S['nil'] = function(_, file)
    file:write 'N\n'
end

function S.string(v, file)
    utils.fprintf(file, "S\n%d\n%s\n", #v, v)
end

function S.number(v, file)
    if v == math.huge then
        utils.fprintf(file, "I\n")
    elseif -v == math.huge then
        utils.fprintf(file, "i\n")
    elseif v ~= v then
        utils.fprintf(file, "E\n")
    elseif math.type(v) == 'integer' then
        utils.fprintf(file, "Z\n%d\n", v)
    else
        utils.fprintf(file, "D\n%a\n", v)
    end
end

local function heap_case(v, file, refs)
    if refs == nil then
        error 'heap object not allowed'
    end
    local me = refs[v]
    if me ~= nil then
        utils.fprintf(file, "R\n%d\n", me)
    else
        me = refs.n + 1
        refs[v] = me
        refs.n = me
        return me
    end
end

local function order(x, y)
    local t1, t2 = type(x), type(y)
    return t1 < t2 or t1 == t2 and x < y
end

function S.table(t, file, refs, uprefs, upixes)
    if heap_case(t, file, refs) then
        local keys = tablex.keys(t)
        utils.fprintf(file, "t\n%d\n", #keys)

        local value_keys = {}
        local heap_keys = {}

        for k in pairs(t) do
            local ty = type(k)
            if ty == 'function' or ty == 'table' then
                table.insert(heap_keys, k)
            else
                table.insert(value_keys, k)
            end
        end

        table.sort(value_keys, order)
        for _, k in ipairs(value_keys) do
            serialize_value(k, file, refs)
            serialize_value(t[k], file, refs, uprefs, upixes)
        end

        table.sort(heap_keys, function(x,y)
            x = assert(refs[x], "keys can't allocate")
            y = assert(refs[y], "keys can't allocate")
            return x < y
        end)
        for _, k in ipairs(heap_keys) do
            serialize_value(k, file, refs)
            serialize_value(t[k], file, refs, uprefs, upixes)
        end
    end
end

S['function'] = function(f, file, refs, uprefs, upixes)
    local me = heap_case(f, file, refs)
    if me then
        local bitcode = string.dump(f, true)
        local nups = debug.getinfo(f, 'u').nups
        utils.fprintf(file, "f\n%d\n%s\n%d\n", #bitcode, bitcode, nups)

        for i = 1, nups do
            local uid = debug.upvalueid(f, i)
            if uprefs[uid] then
                utils.fprintf(file, "U\n%d\n%d\n", uprefs[uid], upixes[uid])
            else
                uprefs[uid] = me
                upixes[uid] = i
                local _, v = debug.getupvalue(f, i)
                serialize_value(v, file, refs, uprefs, upixes)
            end
        end
    end
end

return function(v, file)
    serialize_value(v, file, {n=0}, {}, {})
end
