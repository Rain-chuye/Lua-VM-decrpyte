/*
** $Id: ldump.c,v 2.37 2015/10/08 15:53:49 roberto Exp $
** save precompiled Lua chunks
** See Copyright Notice in lua.h
*/

#define ldump_c
#define LUA_CORE

#include "lprefix.h"


#include <stddef.h>

#include "lua.h"

#include "lobfuscator.h"
#include "lopcodes.h"
#include "lobject.h"
#include "lstate.h"
#include "lundump.h"
#include "lsha256.h"


typedef struct {
    lua_State *L;
    lua_Writer writer;
    void *data;
    int strip;
    int status;
    SHA256_CTX sha256_ctx;
} DumpState;


/*
** All high-level dumps go through DumpVector; you can change it to
** change the endianness of the result
*/
#define DumpVector(v,n,D)	DumpBlock(v,(n)*sizeof((v)[0]),D)

#define DumpLiteral(s,D)	DumpBlock(s, sizeof(s) - sizeof(char), D)


static void DumpBlock (const void *b, size_t size, DumpState *D) {
  if (D->status == 0 && size > 0) {
    l_sha256_update(&D->sha256_ctx, (const uint8_t *)b, size);
    lua_unlock(D->L);
    D->status = (*D->writer)(D->L, b, size, D->data);
    lua_lock(D->L);
  }
}


#define DumpVar(x,D)		DumpVector(&x,1,D)


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
  if (s == NULL)
    DumpByte(0, D);
  else {
    unsigned int size = tsslen(s) + 1;  /* include trailing '\0' */
    const char *str = getstr(s);
    if (size < 0xFF)
      DumpByte(cast_int(size), D);
    else {
      DumpByte(0xFF, D);
      DumpVar(size, D);
    }
    // Encrypt string during dump without touching memory
    size_t i;
    for (i = 0; i < size - 1; i++) {
        DumpByte((lu_byte)(str[i] ^ LUA_CONST_XOR), D);
    }
  }
}

static void DumpCode (const Proto *f, DumpState *D) {
  int i;
  DumpInt(f->sizecode, D);
  for (i = 0; i < f->sizecode; i++) {
    DumpInt(f->code[i], D);
  }
}

static void DumpVCode (const Proto *f, DumpState *D) {
  int i;
  DumpInt(f->sizevcode, D);
  for (i = 0; i < f->sizevcode; i++) {
    DumpInt(f->vcode[i], D);
  }
}

static void DumpOpMap (const Proto *f, DumpState *D) {
  if (f->op_map) {
    DumpByte(1, D);
    DumpVector(f->op_map, NUM_OPCODES, D);
  } else {
    DumpByte(0, D);
  }
}

static void DumpFunction(const Proto *f, TString *psource, DumpState *D);

static void DumpConstants (const Proto *f, DumpState *D) {
  int i;
  int n = f->sizek;
  DumpInt(n, D);
  for (i = 0; i < n; i++) {
    const TValue *o = &f->k[i];
    DumpByte(ttype(o), D);
    switch (ttype(o)) {
      case LUA_TNIL:
        break;
      case LUA_TBOOLEAN:
        DumpByte(bvalue(o), D);
            break;
      case LUA_TNUMFLT:
        DumpNumber(fltvalue(o), D);
            break;
      case LUA_TNUMINT:
        DumpInteger(ivalue(o), D);
            break;
      case LUA_TSHRSTR:
      case LUA_TLNGSTR:
        DumpString(tsvalue(o), D);
            break;
      default:
        lua_assert(0);
    }
  }
}


static void DumpProtos (const Proto *f, DumpState *D) {
  int i;
  int n = f->sizep;
  DumpInt(n, D);
  for (i = 0; i < n; i++)
    DumpFunction(f->p[i], f->source, D);
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
  n = 0; // Always strip line info
  DumpInt(n, D);
  DumpVector(f->lineinfo, n, D);
  n = 0; // Always strip local variables
  DumpInt(n, D);
  for (i = 0; i < n; i++) {
    DumpString(f->locvars[i].varname, D);
    DumpInt(f->locvars[i].startpc, D);
    DumpInt(f->locvars[i].endpc, D);
  }
  n = 0; // Always strip upvalue names
  DumpInt(n, D);
  for (i = 0; i < n; i++)
    DumpString(f->upvalues[i].name, D);
}


static void DumpFunction (const Proto *f, TString *psource, DumpState *D) {
  obfuscate_proto(D->L, (Proto *)f, 1);
  if (1) // Always strip source
    DumpString(NULL, D);  /* no debug info or same source as its parent */
  else
    DumpString(f->source, D);
  DumpInt(0, D); // Strip line defined
  DumpInt(0, D); // Strip last line defined
  DumpByte(f->numparams, D);
  DumpByte(f->is_vararg, D);
  DumpByte(f->maxstacksize, D);
  DumpByte(f->obfuscated, D);
  DumpInt(f->scratch_base, D);
  DumpInt(f->inst_seed, D);
  DumpOpMap(f, D);
  DumpCode(f, D);
  DumpVCode(f, D);
  DumpConstants(f, D);
  DumpUpvalues(f, D);
  DumpProtos(f, D);
  DumpDebug(f, D);
}


static void DumpHeader (DumpState *D) {
  DumpLiteral(LUA_CUSTOM_SIGNATURE, D);
  DumpByte(LUAC_VERSION, D);
  DumpByte(LUAC_FORMAT, D);
  DumpLiteral(LUAC_DATA, D);
  DumpByte(sizeof(int), D);
  //nirenr mod
  //DumpByte(sizeof(size_t), D);
  DumpByte(sizeof(unsigned int), D);
  DumpByte(sizeof(Instruction), D);
  DumpByte(sizeof(lua_Integer), D);
  DumpByte(sizeof(lua_Number), D);
  DumpInteger(LUAC_INT, D);
  DumpNumber(LUAC_NUM, D);
}


/*
** dump Lua function as precompiled chunk
*/
int luaU_dump(lua_State *L, const Proto *f, lua_Writer w, void *data,
              int strip) {
  if (G(L)->version == NULL) return 1;
  DumpState D;
  D.L = L;
  D.writer = w;
  D.data = data;
  D.strip = strip;
  D.status = 0;
  l_sha256_init(&D.sha256_ctx);
  DumpHeader(&D);
  DumpByte(f->sizeupvalues, &D);
  DumpFunction(f, NULL, &D);
  if (D.status == 0) {
    uint8_t digest[32];
    l_sha256_final(&D.sha256_ctx, digest);
    DumpVector(digest, 32, &D);
  }
  return D.status;
}
