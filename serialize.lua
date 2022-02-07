local utils = require 'pl.utils'
local tablex = require 'pl.tablex'

local S = {}

local function serialize_value(v, file, refs, uprefs, upixes)
    local t = type(v)
    S[t](v, file, refs, uprefs, upixes)
end

function S.boolean(v, file)
    utils.fprintf(file, "%s\n", v)
end

S['nil'] = function(_, file)
    file:write 'nil\n'
end

function S.string(v, file)
    utils.fprintf(file, "string\n%d\n%s\n", #v, v)
end

function S.number(v, file)
    if math.type(v) == 'integer' then
        utils.fprintf(file, "integer\n%d\n", v)
    else
        utils.fprintf(file, "number\n%a\n", v)
    end
end

local function heap_case(v, file, refs)
    if refs == nil then
        error 'heap object not allowed'
    end
    local me = refs[v]
    if me ~= nil then
        utils.fprintf(file, "ref\n%d\n", me)
    else
        me = refs.n + 1
        refs[v] = me
        refs.n = me
        return me
    end
end

function S.table(t, file, refs, uprefs, upixes)
    if heap_case(t, file, refs) then
        utils.fprintf(file, "table\n%d\n", tablex.size(t))
        for k, v in tablex.sort(t) do
            serialize_value(k, file)
            serialize_value(v, file, refs, uprefs, upixes)
        end
    end
end

S['function'] = function(f, file, refs, uprefs, upixes)
    local me = heap_case(f, file, refs)
    if me then
        local bitcode = string.dump(f, true)
        local nups = debug.getinfo(f, 'u').nups
        utils.fprintf(file, "function\n%d\n%s\n%d\n", #bitcode, bitcode, nups)

        for i = 1, nups do
            local uid = debug.upvalueid(f, i)
            if uprefs[uid] then
                utils.fprintf(file, "upref\n%d\n%d\n", uprefs[uid], upixes[uid])
            else
                uprefs[uid] = me
                upixes[uid] = i
                local v = debug.getupvalue(f, i)
                serialize_value(v, file, refs, uprefs, upixes)
            end
        end
    end
end

return function(v, file)
    serialize_value(v, file, {n=0}, {}, {})
end
