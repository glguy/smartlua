#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include "lua.h"
#include "lauxlib.h"

#include "serialize.h"

enum keytag {
    KEY_FALSE,
    KEY_TRUE,
    KEY_INTEGER,
    KEY_DOUBLE,
    KEY_STRING,
};

struct strlen {
    char const* ptr;
    size_t len;
};

struct tablekey {
    enum keytag tag;
    union {
        lua_Integer i;
        lua_Number n;
        struct strlen s;
    } val;
};

int compar_tablekey(void const* x_, void const* y_)
{
    const struct tablekey *x = x_, *y = y_;
    if (x->tag < y->tag) return -1;
    if (x->tag > y->tag) return 1;
    switch (x->tag){
        default: return 0;
        case KEY_INTEGER:
            if (x->val.i < y->val.i) return -1;
            if (x->val.i > y->val.i) return 1;
            return 0;
        case KEY_DOUBLE:
            if (x->val.n < y->val.n) return -1;
            if (x->val.n > y->val.n) return 1;
            return 0;
        case KEY_STRING:
            if (x->val.s.len < y->val.s.len) return -1;
            if (x->val.s.len > y->val.s.len) return 1;
            return memcmp(x->val.s.ptr, y->val.s.ptr, x->val.s.len);
    }
}

void push_bytes(struct buffer *b, char const* bytes, size_t len)
{
    if (b->size - b->used < len) {
        size_t newlen = b->size * 2;
        while (newlen - b->used < len) { newlen *= 2; }
        b->bytes = realloc(b->bytes, newlen); // XXX: handle failure
    }

    memcpy(b->bytes + b->used, bytes, len);
    b->used += len;
}

void push_buffer(struct buffer *b, char const* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int used = vsnprintf(NULL, 0, fmt, ap);
    // XXX: test used for error
    char *buffer = malloc(used + 1);
    // XXX: test for malloc failure
    va_end(ap);
    va_start(ap, fmt);
    (void)vsnprintf(buffer, used + 1, fmt, ap);
    va_end(ap);
    push_bytes(b, buffer, used);
    free(buffer);
}

void serialize_table(struct serializer *s, lua_State *L, int t);
void serialize_function(struct serializer *s, lua_State *L, int ref, int i);

int serialize_writer(lua_State *L, const void* p, size_t sz, void *ud)
{
    struct buffer *b = ud;
    push_bytes(b, p, sz);
    return 0;
}

void serialize_value(struct serializer *s, lua_State *L, int i)
{
    i = lua_absindex(L, i);
    int t = lua_type(L, i);
    lua_Integer ref;

    if (t == LUA_TTABLE || t == LUA_TFUNCTION) {
        lua_pushvalue(L, i);
        lua_rawget(L, s->refs);
        if (!lua_isnil(L, -1)) {
            ref = lua_tointeger(L, -1);
            lua_pop(L, 1);
            push_buffer(&s->out, "ref %lld\n", ref);
            return;
        }
        lua_pop(L, 1);

        ref = s->next_refid++;
        lua_pushvalue(L, i);
        lua_pushinteger(L, ref);
        lua_rawset(L, s->refs);
    }

    switch (t) {
        case LUA_TBOOLEAN:
            if (lua_toboolean(L, i)) {
                push_buffer(&s->out, "true\n");
            } else {
                push_buffer(&s->out, "false\n");
            }
            break;
        case LUA_TNIL:
            push_buffer(&s->out, "nil\n");
            break;
        case LUA_TNUMBER:
            if (lua_isinteger(L, i)) {
                push_buffer(&s->out, "integer %lld\n", lua_tointeger(L, i));
            } else {
                push_buffer(&s->out, "number %la\n", lua_tonumber(L, i));
            }
            break;
        case LUA_TSTRING:
        {
            size_t len;
            char const* ptr = lua_tolstring(L, i, &len);
            push_buffer(&s->out, "string %zu\n%s\n", len, ptr); // XXX: handle NUL
            break;
        }
        case LUA_TTABLE:
            serialize_table(s, L, i);
            break;

        case LUA_TFUNCTION:
            serialize_function(s, L, ref, i);
            break;
    }
}

void serialize_function(struct serializer *s, lua_State *L, int ref, int i)
{
    lua_Debug debug;
    lua_pushvalue(L, i);
    lua_getinfo(L, ">u", &debug);
    push_buffer(&s->out, "function %hhu\n", debug.nups);

    // yes, upvalue indexes start at 1
    for (int upIx = 1; upIx <= debug.nups; upIx++) {
        void *upid = lua_upvalueid(L, i, upIx);
        lua_rawgetp(L, s->upvalrefs, upid);
        if (lua_isnil(L, -1)) {
            lua_pop(L, 1); // pop the nil

            lua_pushinteger(L, ref);
            lua_rawsetp(L, s->upvalrefs, upid);

            lua_pushinteger(L, upIx);
            lua_rawsetp(L, s->upvalixs, upid);

            lua_getupvalue(L, i, upIx);
            serialize_value(s, L, -1);
            lua_pop(L, 1);
        } else {
            lua_rawgetp(L, s->upvalixs, upid);
            push_buffer(&s->out, "upref %lld %lld\n", lua_tointeger(L, -2), lua_tointeger(L, -1));
            lua_pop(L, 2);
        }
    }

    lua_dump(L, serialize_writer, &s->out, 1/*strip*/);
    push_bytes(&s->out, "\n", 1);
}

void serialize_table(struct serializer *s, lua_State *L, int t)
{
    size_t key_count = 0;
    lua_pushnil(L);
    while (lua_next(L, t) != 0) {
        lua_pop(L, 1); // pop the value - keep the key
        key_count++;
    }

    struct tablekey *keys = calloc(key_count, sizeof *keys);

    size_t i = 0;
    lua_pushnil(L);
    while (lua_next(L, t) != 0) {
        lua_pop(L, 1); // pop the value - keep the key
        switch(lua_type(L, -1)) {
            default: luaL_error(L, "unsupported table key");
            case LUA_TNUMBER:
                if (lua_isinteger(L, -1)) {
                    keys[i].tag = KEY_INTEGER;
                    keys[i].val.i = lua_tointeger(L, -1);
                } else {
                    keys[i].tag = KEY_DOUBLE;
                    keys[i].val.n = lua_tonumber(L, -1);
                }
                break;
            case LUA_TBOOLEAN:
                if (lua_toboolean(L, -1)) {
                    keys[i].tag = KEY_TRUE;
                } else {
                    keys[i].tag = KEY_FALSE;
                }
                break;
            case LUA_TSTRING:
                keys[i].tag = KEY_STRING;
                keys[i].val.s.ptr = lua_tolstring(L, -1, &keys[i].val.s.len);
                break;
        }
        i++;
    }

    qsort(keys, key_count, sizeof *keys, compar_tablekey);

    push_buffer(&s->out, "table %lld\n", key_count);

    for (i = 0; i < key_count; i++) {
        switch(keys[i].tag) {
            case KEY_FALSE:
                push_buffer(&s->out, "false\n");
                lua_pushboolean(L, 0);
                lua_rawget(L, t);
                serialize_value(s, L, -1);
                lua_pop(L, 1);
                break;

            case KEY_TRUE:
                push_buffer(&s->out, "true\n");
                lua_pushboolean(L, 1);
                lua_rawget(L, t);
                serialize_value(s, L, -1);
                lua_pop(L, 1);
                break;

            case KEY_INTEGER:
                push_buffer(&s->out, "integer %lld\n", keys[i].val.i);
                lua_rawgeti(L, t, keys[i].val.i);
                serialize_value(s, L, -1);
                lua_pop(L, 1);
                break;

            case KEY_DOUBLE:
                push_buffer(&s->out, "number %lf\n", keys[i].val.n); // XXX: needs exact encoding, infinity, etc
                lua_pushnumber(L, keys[i].val.n);
                lua_rawget(L, t);
                serialize_value(s, L, -1);
                lua_pop(L, 1);
                break;

            case KEY_STRING:
                push_buffer(&s->out, "string %zu\n%s\n", keys[i].val.s.len, keys[i].val.s.ptr); // XXX: handle NUL
                lua_pushlstring(L, keys[i].val.s.ptr, keys[i].val.s.len);
                lua_rawget(L, t);
                serialize_value(s, L, -1);
                lua_pop(L, 1);
                break;
        }
    }

    // XXX: free on errors
    free(keys);
}