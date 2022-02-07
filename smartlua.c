#include <stdlib.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#include "serialize.h"
#include "crypto.h"

int l_serialize(lua_State *L)
{
    lua_settop(L, 1);
    lua_newtable(L);
    lua_newtable(L);
    lua_newtable(L);

    struct serializer s = {
        .out.bytes = malloc(512),
        .out.size = 512,
        .out.used = 0,
        .refs = 2,
        .upvalrefs = 3,
        .upvalixs = 4,
        .next_refid = 0,
    };

    serialize_value(&s, L, 1);

    lua_pushlstring(L, s.out.bytes, s.out.used);
    return 1;
}

static int backtrace(lua_State *L)
{
    size_t len;
    char const* msg = luaL_tolstring(L, 1, &len);
    luaL_traceback(L, L, msg, 0);
    return 1;
}

int main(int argc, char **argv)
{
    lua_State *L = luaL_newstate();
    luaL_openlibs(L);

    lua_pushcfunction(L, l_serialize);
    lua_setglobal(L, "serialize");

    luaL_requiref(L, "crypto", luaopen_crypto, 0);

    lua_pushcfunction(L, backtrace);
    luaL_loadfile(L, "main.lua");
    for (int i = 1; i < argc; i++) {
        lua_pushstring(L, argv[i]);
    }

    int res = lua_pcall(L, argc-1, 0, -argc-1);

    if (res != LUA_OK) {
        printf("Execution failed: %s\n", lua_tostring(L, -1));
    }

    return 0;
}