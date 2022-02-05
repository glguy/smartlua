cmake_minimum_required(VERSION 3.13)
set(CMAKE_C_STANDARD 11)

project(smartlua
    VERSION 1
    DESCRIPTION "Smart Lua"
    HOMEPAGE_URL "https://github.com/glguy/smartlua"
    LANGUAGES C
)

include(GNUInstallDirs)
include(CTest)
find_package(PkgConfig REQUIRED)

pkg_search_module(LUA      REQUIRED IMPORTED_TARGET lua>=5.3 lua5.3 lua-5.3 lua53 lua5.4 lua-5.4 lua54)

add_executable(smartlua smartlua.c serialize.c)
target_link_libraries(smartlua PkgConfig::LUA)