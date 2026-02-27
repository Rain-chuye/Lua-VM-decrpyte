#define LUA_CORE
#include "lprefix.h"
#include <stddef.h>
#include <string.h>
#include "lua.h"
#include "lobject.h"
#include "lstate.h"
#include "lundump.h"
#include "lopcodes.h"
#include "lobfuscator.h"

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
    else {
      DumpByte(0xFF, D);
      DumpVar(size, D);
    }
    DumpBlock(str, size - 1, D);
  }
}

static void DumpCode (const Proto *f, DumpState *D) {
  DumpInt(f->sizecode, D);
  for (int i = 0; i < f->sizecode; i++) {
    Instruction inst = f->code[i];
    if (f->obfuscated) {
      inst = DECRYPT_INST(inst, i, (uint32_t)f->inst_seed);
      OpCode op = GET_OPCODE(inst);
      if (f->op_map) op = (OpCode)f->op_map[op];
      inst = (inst & ~MASK1(SIZE_OP, POS_OP)) | ((Instruction)op << POS_OP);
    }
    DumpVar(inst, D);
  }
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
      case LUA_TNUMINT: {
          lua_Integer val = ivalue(o);
          if (f->obfuscated) val = (lua_Integer)DECRYPT_INT((uint64_t)val);
          DumpInteger(val, D);
          break;
      }
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
  n = (f->obfuscated) ? 0 : f->sizelineinfo;
  DumpInt(n, D);
  if (n > 0) DumpBlock(f->lineinfo, n * sizeof(int), D);

  n = (f->obfuscated) ? 0 : f->sizelocvars;
  DumpInt(n, D);
  for (i = 0; i < n; i++) {
    DumpString(f->locvars[i].varname, D);
    DumpInt(f->locvars[i].startpc, D);
    DumpInt(f->locvars[i].endpc, D);
  }

  n = (f->obfuscated) ? 0 : f->sizeupvalues;
  DumpInt(n, D);
  for (i = 0; i < n; i++) {
      if (f->obfuscated) DumpString(NULL, D);
      else DumpString(f->upvalues[i].name, D);
  }
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
  static const char signature[] = LUA_SIGNATURE;
  static const char luac_data[] = LUAC_DATA;
  DumpBlock(signature, sizeof(signature) - 1, D);
  DumpByte(LUAC_VERSION, D);
  DumpByte(LUAC_FORMAT, D);
  DumpBlock(luac_data, sizeof(luac_data) - 1, D);
  DumpByte(sizeof(int), D);
  DumpByte(sizeof(size_t), D);
  DumpByte(sizeof(Instruction), D);
  DumpByte(sizeof(lua_Integer), D);
  DumpByte(sizeof(lua_Number), D);
  DumpInteger(LUAC_INT, D);
  DumpNumber(LUAC_NUM, D);
}

int luaU_dump_clean(lua_State *L, const Proto *f, lua_Writer w, void *data) {
  DumpState D;
  D.L = L; D.writer = w; D.data = data; D.status = 0;
  DumpHeader(&D);
  DumpByte(f->sizeupvalues, &D);
  DumpFunction(f, &D);
  return D.status;
}
