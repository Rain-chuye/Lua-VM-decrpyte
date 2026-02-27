#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
#include "lobject.h"
#include "lstate.h"
#include "lundump.h"

/* --- Layer 1: Base85 / Stream Cipher / LZ77 (Extracted from modified source) --- */

#define B85_ALPHABET_MASTER "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"

typedef struct {
    uint32_t x, y, z, w;
} ChuyeXorState;

static uint32_t chuye_xorshift128(ChuyeXorState *s) {
    uint32_t t = s->x ^ (s->x << 11);
    s->x = s->y; s->y = s->z; s->z = s->w;
    return s->w = s->w ^ (s->w >> 19) ^ t ^ (t >> 8);
}

static void shuffle_alphabet(char *alphabet, uint32_t seed) {
    seed ^= 0x12345678;
    ChuyeXorState s = {seed, seed ^ 0x92D68CA2, seed ^ 0x475EAD11, seed ^ 0x6E0323B9};
    int len = (int)strlen(alphabet);
    for (int pass = 0; pass < 3; pass++) {
        for (int i = len - 1; i > 0; i--) {
            int j = chuye_xorshift128(&s) % (i + 1);
            char t = alphabet[i];
            alphabet[i] = alphabet[j];
            alphabet[j] = t;
        }
        s.x ^= 0x55555555; s.y ^= 0xAAAAAAAA;
    }
}

static int b85_val(const char *alphabet, char c) {
    const char *p = strchr(alphabet, c);
    return p ? (int)(p - alphabet) : -1;
}

static uint32_t recover_seed(const char *in) {
    uint32_t seed = 0;
    for (int i = 0; i < 8; i++) {
        int v = b85_val(B85_ALPHABET_MASTER, in[i]);
        if (v == -1) return 0;
        seed |= ((uint32_t)(v & 0x0F) << (i * 4));
    }
    return seed;
}

unsigned char *chuye_decrypt_layer1(const char *input, size_t in_len, size_t *out_len) {
    if (in_len < 8) return NULL;
    uint32_t seed = recover_seed(input);
    ChuyeXorState s = {seed, seed ^ 0x92D68CA2, seed ^ 0x475EAD11, seed ^ 0x6E0323B9};
    char alphabet[86];
    memcpy(alphabet, B85_ALPHABET_MASTER, 85);
    alphabet[85] = '\0';
    shuffle_alphabet(alphabet, seed);

    unsigned char *decoded = (unsigned char *)malloc(in_len + 1);
    size_t di = 0;
    unsigned char unit[5];
    int ui = 0;
    for (size_t in_pos = 8; in_pos < in_len; ) {
        uint32_t r_noise = chuye_xorshift128(&s);
        if (r_noise % 13 == 0) { chuye_xorshift128(&s); in_pos++; if (in_pos >= in_len) break; }
        if (input[in_pos] == '.') break;
        uint32_t r_data = chuye_xorshift128(&s);
        int v = b85_val(alphabet, input[in_pos++]);
        if (v == -1) continue;
        v = (v + 85 - (int)(r_data % 85)) % 85;
        unit[ui++] = (unsigned char)v;
        if (ui == 5) {
            unsigned long long val = 0;
            for (int j = 0; j < 5; j++) val = val * 85 + unit[j];
            decoded[di++] = (unsigned char)((val >> 24) & 0xFF);
            decoded[di++] = (unsigned char)((val >> 16) & 0xFF);
            decoded[di++] = (unsigned char)((val >> 8) & 0xFF);
            decoded[di++] = (unsigned char)(val & 0xFF);
            ui = 0;
        }
    }
    if (ui > 0) {
        unsigned long long val = 0;
        for (int j = 0; j < ui; j++) val = val * 85 + unit[j];
        for (int j = 0; j < 5 - ui; j++) val = val * 85 + 84;
        for (int j = 0; j < ui - 1; j++) decoded[di++] = (unsigned char)((val >> (24 - j * 8)) & 0xFF);
    }
    ChuyeXorState s2 = {seed, seed ^ 0x92D68CA2, seed ^ 0x475EAD11, seed ^ 0x6E0323B9};
    for (size_t i = 0; i < di; i++) {
        uint32_t r = chuye_xorshift128(&s2);
        int rot = (r >> 8) & 7;
        unsigned char b = decoded[i];
        b = (unsigned char)((b >> rot) | (b << (8 - rot)));
        b ^= (unsigned char)(r & 0xFF);
        decoded[i] = b;
    }
    *out_len = di;
    return decoded;
}

/* --- Layer 2: Standard Bytecode Dumper (Clean) --- */

typedef struct {
  lua_State *L;
  lua_Writer writer;
  void *data;
  int status;
} DumpState;

static void DumpBlock (const void *b, size_t size, DumpState *D) {
  if (D->status == 0 && size > 0) {
    lua_unlock(D->L);
    D->status = (*D->writer)(D->L, b, size, D->data);
    lua_lock(D->L);
  }
}

#define DumpVar(x,D)    DumpBlock(&x,sizeof(x),D)
#define DumpVector(v,n,D) DumpBlock(v,(n)*sizeof((v)[0]),D)
#define DumpLiteral(s,D)  DumpBlock(s, sizeof(s) - sizeof(char), D)

static void DumpByte (int y, DumpState *D) {
  lu_byte x = (lu_byte)y;
  DumpVar(x, D);
}

static void DumpInt (int x, DumpState *D) {
  DumpVar(x, D);
}

static void DumpNumber (lua_Number x, DumpState *D) {
  DumpVar(x, D);
}

static void DumpInteger (lua_Integer x, DumpState *D) {
  DumpVar(x, D);
}

static void DumpString (const TString *s, DumpState *D) {
  if (s == NULL) DumpByte(0, D);
  else {
    size_t size = tsslen(s) + 1;
    const char *str = getstr(s);
    if (size < 0xFF) DumpByte((int)size, D);
    else { DumpByte(0xFF, D); DumpVar(size, D); }
    DumpBlock(str, size - 1, D);
  }
}

static void DumpCode (const Proto *f, DumpState *D) {
  DumpInt(f->sizecode, D);
  DumpVector(f->code, f->sizecode, D);
}

static void DumpFunction(const Proto *f, DumpState *D);

static void DumpConstants (const Proto *f, DumpState *D) {
  int i, n = f->sizek;
  DumpInt(n, D);
  for (i = 0; i < n; i++) {
    const TValue *o = &f->k[i];
    DumpByte(ttype(o), D);
    switch (ttype(o)) {
      case LUA_TNIL: break;
      case LUA_TBOOLEAN: DumpByte(bvalue(o), D); break;
      case LUA_TNUMFLT: DumpNumber(fltvalue(o), D); break;
      case LUA_TNUMINT: DumpInteger(ivalue(o), D); break;
      case LUA_TSHRSTR: case LUA_TLNGSTR: DumpString(tsvalue(o), D); break;
    }
  }
}

static void DumpUpvalues (const Proto *f, DumpState *D) {
  int i, n = f->sizeupvalues;
  DumpInt(n, D);
  for (i = 0; i < n; i++) {
    DumpByte(f->upvalues[i].instack, D);
    DumpByte(f->upvalues[i].idx, D);
  }
}

static void DumpDebug (const Proto *f, DumpState *D) {
  int i, n;
  n = f->sizelineinfo;
  DumpInt(n, D);
  DumpVector(f->lineinfo, n, D);
  n = f->sizelocvars;
  DumpInt(n, D);
  for (i = 0; i < n; i++) {
    DumpString(f->locvars[i].varname, D);
    DumpInt(f->locvars[i].startpc, D);
    DumpInt(f->locvars[i].endpc, D);
  }
  n = f->sizeupvalues;
  DumpInt(n, D);
  for (i = 0; i < n; i++) DumpString(f->upvalues[i].name, D);
}

static void DumpFunction (const Proto *f, DumpState *D) {
  DumpString(f->source, D);
  DumpInt(f->linedefined, D);
  DumpInt(f->lastlinedefined, D);
  DumpByte(f->numparams, D);
  DumpByte(f->is_vararg, D);
  DumpByte(f->maxstacksize, D);
  DumpCode(f, D);
  DumpConstants(f, D);
  DumpUpvalues(f, D);
  DumpInt(f->sizep, D);
  for (int i = 0; i < f->sizep; i++) DumpFunction(f->p[i], D);
  DumpDebug(f, D);
}

static void DumpHeader (DumpState *D) {
  DumpLiteral(LUA_SIGNATURE, D);
  DumpByte(LUAC_VERSION, D);
  DumpByte(LUAC_FORMAT, D);
  DumpLiteral(LUAC_DATA, D);
  DumpByte(sizeof(int), D);
  DumpByte(sizeof(size_t), D);
  DumpByte(sizeof(Instruction), D);
  DumpByte(sizeof(lua_Integer), D);
  DumpByte(sizeof(lua_Number), D);
  DumpInteger(LUAC_INT, D);
  DumpNumber(LUAC_NUM, D);
}

int my_luaU_dump_clean(lua_State *L, const Proto *f, lua_Writer w, void *data) {
  DumpState D;
  D.L = L; D.writer = w; D.data = data; D.status = 0;
  DumpHeader(&D);
  DumpByte(f->sizeupvalues, &D);
  DumpFunction(f, &D);
  return D.status;
}

/* --- Lua Module Interface --- */

static int writer_file(lua_State* L, const void* p, size_t size, void* u) {
  (void)L;
  return (fwrite(p, size, 1, (FILE*)u) != 1) && (size != 0);
}

static int l_normalize(lua_State *L) {
    size_t len;
    const char *src = luaL_checklstring(L, 1, &len);
    const char *out_path = luaL_checkstring(L, 2);

    // Unpack from LuaVMP wrapper if needed
    const char *start = strchr(src, '"');
    if (!start) start = strchr(src, '\'');
    if (start) {
        char q = *start++;
        const char *end = strchr(start, q);
        if (end) { src = start; len = end - start; }
    }

    size_t dlen;
    unsigned char *decoded = chuye_decrypt_layer1(src, len, &dlen);
    if (!decoded) return luaL_error(L, "Layer 1 decryption failed");

    unsigned char *payload = decoded;
    size_t payload_len = dlen;
    unsigned char *decompressed = NULL;
    if (dlen >= 12 && memcmp(decoded, "CHYE", 4) == 0) {
        decompressed = luaL_decompress(decoded + 12, dlen - 12, &payload_len);
        if (decompressed) payload = decompressed;
        else { payload = decoded + 12; payload_len = dlen - 12; }
    }

    // Load into a temporary state to let the VM handle Layer 2 (LUAX -> Proto)
    lua_State *L2 = luaL_newstate();
    if (!L2) { free(decoded); if (decompressed) free(decompressed); return luaL_error(L, "Memory error"); }
    luaL_openlibs(L2);

    int status = luaL_loadbuffer(L2, (const char *)payload, payload_len, "=(chuye)");
    if (status != LUA_OK) {
        const char *err = lua_tostring(L2, -1);
        lua_pushstring(L, err);
        lua_close(L2);
        if (decompressed) free(decompressed); free(decoded);
        return lua_error(L);
    }

    LClosure *cl = (LClosure *)lua_topointer(L2, -1);
    FILE *out = fopen(out_path, "wb");
    if (!out) {
        lua_close(L2);
        if (decompressed) free(decompressed); free(decoded);
        return luaL_error(L, "Failed to open output file");
    }

    my_luaU_dump_clean(L2, cl->p, writer_file, out);
    fclose(out);

    lua_close(L2);
    if (decompressed) free(decompressed);
    free(decoded);
    printf("Successfully normalized to %s\n", out_path);
    return 0;
}

static const struct luaL_Reg chuye_dec_funcs[] = {
    {"normalize", l_normalize},
    {NULL, NULL}
};

LUALIB_API int luaopen_chuye_dec(lua_State *L) {
    luaL_newlib(L, chuye_dec_funcs);
    return 1;
}
