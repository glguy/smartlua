cmake_minimum_required(VERSION 3.13)
set(CMAKE_C_STANDARD 11)

project(smartlua
    VERSION 1
    DESCRIPTION "Smart Lua"
    HOMEPAGE_URL "https://github.com/glguy/smartlua"
    LANGUAGES C
)

find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
pkg_search_module(LUA REQUIRED IMPORTED_TARGET lua5.4 lua-5.4 lua54)

add_executable(smartlua smartlua.c serialize.c crypto.c)
target_link_libraries(smartlua PkgConfig::LUA OpenSSL::Crypto)