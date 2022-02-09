#include "lua.h"
#include "lauxlib.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>

#include <stdlib.h>

#include "crypto.h"

static void mybase64_encode(char const* input, size_t len, char *output)
{
  char const* const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";
  size_t i;

  for (i = 0; i + 3 <= len; i += 3)
  {
    uint32_t const buffer
      = (uint32_t)(unsigned char)input[i + 0] << 8 * 2
      | (uint32_t)(unsigned char)input[i + 1] << 8 * 1
      | (uint32_t)(unsigned char)input[i + 2] << 8 * 0;

    *output++ = alphabet[(buffer >> 6 * 3) % 64];
    *output++ = alphabet[(buffer >> 6 * 2) % 64];
    *output++ = alphabet[(buffer >> 6 * 1) % 64];
    *output++ = alphabet[(buffer >> 6 * 0) % 64];
  }

  if (i < len)
  {
    uint32_t buffer = (uint32_t)(unsigned char)input[i + 0] << (8 * 2);
    if (i + 1 < len)
      buffer |= (uint32_t)(unsigned char)input[i + 1] << (8 * 1);

    *output++ = alphabet[(buffer >> 6 * 3) % 64];
    *output++ = alphabet[(buffer >> 6 * 2) % 64];
    *output++ = i + 1 < len ? alphabet[(buffer >> 6 * 1) % 64] : '=';
    *output++ = '=';
  }
  *output = '\0';
}

static int8_t alphabet_values[256] = {
    [0]   =   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
              -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
              -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
              -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
              -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
              -1,   -1,   -1,
    [44]  =   -1,   -1,   -1,
    [58]  =   -1,   -1,   -1,   -1,   -1,   -1,   -1,
    [91]  =   -1,   -1,   -1,   -1,   -1,   -1,
    [123] =   -1,   -1,   -1,   -1,   -1,
    ['A'] = 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19,
    ['a'] =             0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
            0x30, 0x31, 0x32, 0x33,

    ['0'] =                         0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
    ['+'] =                                     0x3e,
    ['/'] =                                           0x3f,
};

static ssize_t mybase64_decode(char const* input, size_t len, char *output)
{
    uint32_t buffer = 0;
    unsigned counter = 0;
    size_t length = 0;

    for (size_t i = 0; i < len; i++) {
        int8_t const value = alphabet_values[input[i]];
        if (0 <= value) {
            buffer = (buffer << 6) | value;

            counter++;

            if (counter == 4) {
                output[length + 0] = buffer >> (8*2);
                output[length + 1] = buffer >> (8*1);
                output[length + 2] = buffer >> (8*0);
                length += 3;
                counter = 0;
                buffer = 0;
            }
        }
    }

    switch (counter)
    {
        default: return -1;
        case 0: return length;
        case 2:
            buffer <<= 6*2;
            output[length + 0] = buffer >> (8*2);
            return length + 1;
        case 3:
            buffer <<= 6*1;
            output[length + 0] = buffer >> (8*2);
            output[length + 1] = buffer >> (8*1);
            return length + 2;
    }
}

static EVP_MD const* digestarg(lua_State *L, int i)
{
    char const* name = luaL_checkstring(L, i);
    EVP_MD const* md = EVP_get_digestbyname(name);
    if (md == NULL) {
        ERR_clear_error();
        luaL_argerror(L, i, "unknown hash");
    }
    return md;
}

static int l_base64e(lua_State *L)
{
    size_t len;
    char const* data = luaL_checklstring(L, 1, &len);
    size_t const out_len = (len+2)/3*4+1;
    luaL_Buffer B;
    luaL_buffinitsize(L, &B, out_len);
    mybase64_encode(data, len, B.b);
    luaL_pushresultsize(&B, out_len-1); // don't push NUL
    return 1;
}

static int l_base64d(lua_State *L)
{
    size_t len;
    char const* data = luaL_checklstring(L, 1, &len);
    luaL_Buffer B;
    luaL_buffinitsize(L, &B, (len+3)/4*3+1);
    ssize_t out_len = mybase64_decode(data, len, B.b);
    if (out_len < 0) {
        return luaL_error(L, "invalid base64");
    }
    luaL_pushresultsize(&B, out_len);
    return 1;
}

static int l_hmac(lua_State *L)
{
    EVP_MD const* md = digestarg(L, 1);
    size_t key_len, data_len;
    char const* key = luaL_checklstring(L, 2, &key_len);
    char const* data = luaL_checklstring(L, 3, &data_len);

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = sizeof digest;
    unsigned char *result = HMAC(md, key, key_len, (unsigned char const*)data, data_len, digest, &digest_len);
    if (result == NULL) {
        unsigned long err = ERR_get_error();
        ERR_clear_error();
        return luaL_error(L, "HMAC error (%lu)", err);
    }

    lua_pushlstring(L, (char const*)digest, digest_len);
    return 1;
}

static int l_digest(lua_State *L)
{
    const EVP_MD *md = digestarg(L, 1);
    size_t data_len;
    char const* data = luaL_checklstring(L, 2, &data_len);

    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int out_len;
    int result = EVP_Digest(data, data_len, out, &out_len, md, NULL);
    if (result == 0) {
        unsigned long err = ERR_get_error();
        ERR_clear_error();
        return luaL_error(L, "digest failed (%lu)", err);
    }

    lua_pushlstring(L, (char*)out, out_len);
    return 1;
}

static int l_privatekey_pem(lua_State *L)
{
    size_t pem_len;
    char const* pem = luaL_checklstring(L, 1, &pem_len);

    BIO *bio = BIO_new_mem_buf(pem, pem_len);
    if (bio == NULL) {
        unsigned long err = ERR_get_error();
        ERR_clear_error();
        return luaL_error(L, "BIO_new_mem_buf failed (%lu)", err);
    }

    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free_all(bio);

    if (key == NULL) {
        unsigned long err = ERR_get_error();
        ERR_clear_error();
        return luaL_error(L, "PEM_read_bio_PrivateKey failed (%lu)", err);
    }

    EVP_PKEY **ud = lua_newuserdatauv(L, sizeof key, 0);
    *ud = key;
    luaL_setmetatable(L, "EVP_PKEY");

    return 1;
}

static int l_privatekey(lua_State *L)
{
    size_t key64_len;
    char const* key64 = luaL_checklstring(L, 1, &key64_len);

    if (key64_len != 44) {
        return luaL_argerror(L, 1, "bad length");
    }

    unsigned char priv[32];
    ssize_t priv_len = mybase64_decode(key64, key64_len, (char*)priv);

    if (priv_len != 32) {
        return luaL_argerror(L, 1, "bad decoded length");
    }

    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, priv, priv_len);
    if (key == NULL) {
        unsigned long err = ERR_get_error();
        ERR_clear_error();
        return luaL_error(L, "EVP_PKEY_new_raw_private_key failed (%lu)", err);
    }

    EVP_PKEY **ud = lua_newuserdatauv(L, sizeof key, 0);
    *ud = key;
    luaL_setmetatable(L, "EVP_PKEY");

    return 1;
}

static int l_pubstr(lua_State *L)
{
    EVP_PKEY **ud = luaL_checkudata(L, 1, "EVP_PKEY");
    EVP_PKEY *key = *ud;

    char pub[32];
    size_t len = 32;

    int result = EVP_PKEY_get_raw_public_key(key, (unsigned char*)pub, &len);
    if (result == 0) {
        unsigned long err = ERR_get_error();
        ERR_clear_error();
        return luaL_error(L, "EVP_PKEY_get_raw_public_key failed (%lu)", err);
    }

    char pub64[45];
    mybase64_encode(pub, len, pub64);

    lua_pushstring(L, pub64);
    return 1;
}

static int l_publickey(lua_State *L)
{
    size_t pub64_len;
    char const* pub64 = luaL_checklstring(L, 1, &pub64_len);
    if (pub64_len != 44) {
        return luaL_argerror(L, 1, "incorrect length");
    }

    char raw[32];
    ssize_t rawlen = mybase64_decode(pub64, pub64_len, raw);
    if (rawlen != 32) {
        return luaL_argerror(L, 1, "incorrect decoded length");
    }

    EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, (unsigned char*)raw, rawlen);
    if (key == NULL) {
        unsigned long err = ERR_get_error();
        ERR_clear_error();
        return luaL_error(L, "EVP_PKEY_new_raw_public_key failed (%lu)", err);
    }

    EVP_PKEY **ud = lua_newuserdatauv(L, sizeof key, 0);
    *ud = key;
    luaL_setmetatable(L, "EVP_PKEY");

    return 1;
}

static int l_free_evp(lua_State *L)
{
    EVP_PKEY **ud = luaL_checkudata(L, 1, "EVP_PKEY");
    EVP_PKEY_free(*ud);
    *ud = NULL;
    return 0;
}

static int l_sign(lua_State *L)
{
    EVP_PKEY **ud = luaL_checkudata(L, 1, "EVP_PKEY");
    EVP_PKEY *pkey = *ud;
    luaL_argcheck(L, pkey != NULL, 1, "invalid private key");

    size_t msg_len;
    char const* msg = luaL_checklstring(L, 2, &msg_len);

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        unsigned long err = ERR_get_error();
        ERR_clear_error();
        return luaL_error(L, "EVP_MD_CTX_new failed (%lu)", err);
    }

    int result = EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey);
    if (result == 0) {
        unsigned long err = ERR_get_error();
        ERR_clear_error();
        EVP_MD_CTX_free(md_ctx);
        return luaL_error(L, "EVP_DigestSignInit failed (%lu)", err);
    }

    size_t sig_len;

    /* Calculate the requires size for the signature by passing a NULL buffer */
    result = EVP_DigestSign(md_ctx, NULL, &sig_len, (unsigned char*)msg, msg_len);
    if (result == 0) {
        unsigned long err = ERR_get_error();
        ERR_clear_error();
        EVP_MD_CTX_free(md_ctx);
        return luaL_error(L, "EVP_DigestSign (1) failed (%lu)", err);
    }

    luaL_Buffer B;
    luaL_buffinitsize(L, &B, sig_len);

    result = EVP_DigestSign(md_ctx, (unsigned char*)B.b, &sig_len, (unsigned char*)msg, msg_len);
    if (result == 0) {
        unsigned long err = ERR_get_error();
        ERR_clear_error();
        EVP_MD_CTX_free(md_ctx);
        return luaL_error(L, "EVP_DigestSign (2) failed (%lu)", err);
    }

    luaL_pushresultsize(&B, sig_len);

    EVP_MD_CTX_free(md_ctx);

    return 1;
}

static int l_verify(lua_State *L)
{
    EVP_PKEY **ud = luaL_checkudata(L, 1, "EVP_PKEY");
    EVP_PKEY *pkey = *ud;
    luaL_argcheck(L, pkey != NULL, 1, "invalid private key");

    size_t sig_len;
    char const* sig = luaL_checklstring(L, 2, &sig_len);

    size_t msg_len;
    char const* msg = luaL_checklstring(L, 3, &msg_len);

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        unsigned long err = ERR_get_error();
        ERR_clear_error();
        return luaL_error(L, "EVP_MD_CTX_new failed (%lu)", err);
    }

    int result = EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey);
    if (result == 0) {
        unsigned long err = ERR_get_error();
        ERR_clear_error();
        EVP_MD_CTX_free(md_ctx);
        return luaL_error(L, "EVP_DigestVerifyInit failed (%lu)", err);
    }

    result = EVP_DigestVerify(md_ctx, (unsigned char const*)sig, sig_len, (unsigned char const*)msg, msg_len);
    if (result == 0) {
        unsigned long err = ERR_get_error();
        ERR_clear_error();
        EVP_MD_CTX_free(md_ctx);
        return luaL_error(L, "EVP_DigestVerify failed (%lu)", err);
    }
    
    EVP_MD_CTX_free(md_ctx);

    lua_pushboolean(L, result == 1);
    return 1;
}

static const luaL_Reg cryptolib[] = {
    {"digest", l_digest},
    {"hmac", l_hmac},
    {"base64e", l_base64e},
    {"base64d", l_base64d},
    {"publickey", l_publickey},
    {"privatekey", l_privatekey},
    {"privatekey_pem", l_privatekey_pem},
    {}
};

static const luaL_Reg pkeylib[] = {
    {"sign", l_sign},
    {"verify", l_verify},
    {"pubstr", l_pubstr},
    {}
};

int luaopen_crypto(lua_State *L)
{
    if (luaL_newmetatable(L, "EVP_PKEY")) {
        lua_pushcfunction(L, l_free_evp);
        lua_setfield(L, -2, "__gc");
        luaL_newlib(L, pkeylib);
        lua_setfield(L, -2, "__index");
    }
    lua_pop(L, 1);

    luaL_newlib(L, cryptolib);
    return 1;
}
