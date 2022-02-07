#include <stdlib.h>
#include <stdio.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#include "crypto.h"

static int backtrace(lua_State *L)
{
    size_t len;
    char const* msg = luaL_tolstring(L, 1, &len);
    luaL_traceback(L, L, msg, 1);
    return 1;
}

int main(int argc, char **argv)
{
    lua_State *L = luaL_newstate();
    int res;

    if (L == NULL) {
        fprintf(stderr, "Failed to allocate lua environment\n");
        exit(EXIT_FAILURE);
    }

    luaL_openlibs(L);

    luaL_requiref(L, "crypto", luaopen_crypto, 0);
    lua_pop(L, 1);

    lua_pushcfunction(L, backtrace);

    res = luaL_loadfile(L, "main.lua");
    if (res != LUA_OK) {
        size_t len;
        char const* msg = luaL_tolstring(L, -1, &len);
        fprintf(stderr, "Load failed\n%s\n", msg);
        lua_close(L);
        exit(EXIT_FAILURE);
    }

    for (int i = 1; i < argc; i++) {
        lua_pushstring(L, argv[i]);
    }

    res = lua_pcall(L, argc-1, 0, -argc-1);
    if (res != LUA_OK) {
        size_t len;
        char const* msg = luaL_tolstring(L, -1, &len);
        printf("Execution failed\n%s\n", msg);
        lua_close(L);
        exit(EXIT_FAILURE);
    }

    lua_close(L);

    return 0;
}
