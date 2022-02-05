#ifndef SMARTLUA_SERIALIZE_H
#define SMARTLUA_SERIALIZE_H


struct buffer {
    size_t size;
    size_t used;
    char *bytes;
};

struct serializer {
    struct buffer out;
    int refs;
    int upvalrefs;
    int upvalixs;
    int next_refid;
};

void serialize_value(struct serializer *s, lua_State *L, int i);

#endif