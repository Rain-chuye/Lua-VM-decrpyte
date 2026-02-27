/*
** $Id: lundump.c,v 2.44 2015/11/02 16:09:30 roberto Exp $
** load precompiled Lua chunks
** See Copyright Notice in lua.h
*/

#define lundump_c
#define LUA_CORE

#include "lprefix.h"


#include <string.h>

#include "lua.h"

#include "lobfuscator.h"
#include "lopcodes.h"
#include "ldebug.h"
#include "ldo.h"
#include "lfunc.h"
#include "lmem.h"
#include "lobject.h"
#include "lstring.h"
#include "lundump.h"
#include "lzio.h"
#include "lsha256.h"


#if !defined(luai_verifycode)
#define luai_verifycode(L,b,f)  /* empty */
#endif


typedef struct {
    lua_State *L;
    ZIO *Z;
    const char *name;
    SHA256_CTX sha256_ctx;
    int hashing;
} LoadState;


static l_noret error(LoadState *S, const char *why) {
  luaO_pushfstring(S->L, "%s: %s 预编译代码块", S->name, why);
  luaD_throw(S->L, LUA_ERRSYNTAX);
}


/*
** All high-level loads go through LoadVector; you can change it to
** adapt to the endianness of the input
*/
#define LoadVector(S,b,n)	LoadBlock(S,b,(n)*sizeof((b)[0]))

static void LoadBlock (LoadState *S, void *b, size_t size) {
  if (luaZ_read(S->Z, b, size) != 0)
    error(S, "已截断的");
  if (S->hashing) l_sha256_update(&S->sha256_ctx, (const uint8_t *)b, size);
}


#define LoadVar(S,x)		LoadVector(S,&x,1)


static lu_byte LoadByte (LoadState *S) {
  lu_byte x;
  LoadVar(S, x);
  return x;
}


static int LoadInt (LoadState *S) {
  int x;
  LoadVar(S, x);
  return x;
}


static lua_Number LoadNumber (LoadState *S) {
  lua_Number x;
  LoadVar(S, x);
  return x;
}


static lua_Integer LoadInteger (LoadState *S) {
  lua_Integer x;
  LoadVar(S, x);
  return x;
}


static TString *LoadString (LoadState *S) {
  //nirenr mod
  //size_t size = LoadByte(S);
  unsigned int size = LoadByte(S);
  if (size == 0xFF)
    LoadVar(S, size);
  if (size == 0)
    return NULL;
  else if (--size <= LUAI_MAXSHORTLEN) {  /* short string? */
    char buff[LUAI_MAXSHORTLEN];
    unsigned int j;
    LoadVector(S, buff, size);
    for (j = 0; j < size; j++) buff[j] ^= LUA_CONST_XOR;
    return luaS_newlstr(S->L, buff, size);
  }
  else {  /* long string */
    TString *ts = luaS_createlngstrobj(S->L, size);
    unsigned int j;
    char *s;
    LoadVector(S, getstr(ts), size);  /* load directly in final place */
    s = (char *)getstr(ts);
    for (j = 0; j < size; j++) s[j] ^= LUA_CONST_XOR;
    return ts;
  }
}


static void LoadCode (LoadState *S, Proto *f) {
  int n = LoadInt(S);
  f->code = luaM_newvector(S->L, n, Instruction);
  f->sizecode = n;
  LoadVector(S, f->code, n);
}

static void LoadVCode (LoadState *S, Proto *f) {
  int n = LoadInt(S);
  f->vcode = luaM_newvector(S->L, n, Instruction);
  f->sizevcode = n;
  LoadVector(S, f->vcode, n);
}

static void LoadOpMap (LoadState *S, Proto *f) {
  if (LoadByte(S)) {
    f->op_map = luaM_newvector(S->L, NUM_OPCODES, lu_byte);
    LoadVector(S, f->op_map, NUM_OPCODES);
  } else {
    f->op_map = NULL;
  }
}


static void LoadFunction(LoadState *S, Proto *f, TString *psource);


static void LoadConstants (LoadState *S, Proto *f) {
  int i;
  int n = LoadInt(S);
  f->k = luaM_newvector(S->L, n, TValue);
  f->sizek = n;
  for (i = 0; i < n; i++)
    setnilvalue(&f->k[i]);
  for (i = 0; i < n; i++) {
    TValue *o = &f->k[i];
    int t = LoadByte(S);
    switch (t) {
      case LUA_TNIL:
        setnilvalue(o);
            break;
      case LUA_TBOOLEAN:
      setbvalue(o, LoadByte(S));
            break;
      case LUA_TNUMFLT:
      setfltvalue(o, LoadNumber(S));
            break;
      case LUA_TNUMINT:
      setivalue(o, LoadInteger(S));
            break;
      case LUA_TSHRSTR:
      case LUA_TLNGSTR:
        setsvalue2n(S->L, o, LoadString(S));
            break;
      default:
        lua_assert(0);
    }
  }
}


static void LoadProtos (LoadState *S, Proto *f) {
  int i;
  int n = LoadInt(S);
  f->p = luaM_newvector(S->L, n, Proto *);
  f->sizep = n;
  for (i = 0; i < n; i++)
    f->p[i] = NULL;
  for (i = 0; i < n; i++) {
    f->p[i] = luaF_newproto(S->L);
    LoadFunction(S, f->p[i], f->source);
  }
}


static void LoadUpvalues (LoadState *S, Proto *f) {
  int i, n;
  n = LoadInt(S);
  f->upvalues = luaM_newvector(S->L, n, Upvaldesc);
  f->sizeupvalues = n;
  for (i = 0; i < n; i++)
    f->upvalues[i].name = NULL;
  for (i = 0; i < n; i++) {
    f->upvalues[i].instack = LoadByte(S);
    f->upvalues[i].idx = LoadByte(S);
  }
}


static void LoadDebug (LoadState *S, Proto *f) {
  int i, n;
  n = LoadInt(S);
  f->lineinfo = luaM_newvector(S->L, n, int);
  f->sizelineinfo = n;
  LoadVector(S, f->lineinfo, n);
  n = LoadInt(S);
  f->locvars = luaM_newvector(S->L, n, LocVar);
  f->sizelocvars = n;
  for (i = 0; i < n; i++)
    f->locvars[i].varname = NULL;
  for (i = 0; i < n; i++) {
    f->locvars[i].varname = LoadString(S);
    f->locvars[i].startpc = LoadInt(S);
    f->locvars[i].endpc = LoadInt(S);
  }
  n = LoadInt(S);
  for (i = 0; i < n; i++)
    f->upvalues[i].name = LoadString(S);
}


static void LoadFunction (LoadState *S, Proto *f, TString *psource) {
  f->source = LoadString(S);
  if (f->source == NULL)  /* no source in dump? */
    f->source = psource;  /* reuse parent's source */
  f->linedefined = LoadInt(S);
  f->lastlinedefined = LoadInt(S);
  f->numparams = LoadByte(S);
  f->is_vararg = LoadByte(S);
  f->maxstacksize = LoadByte(S);
  f->obfuscated = LoadByte(S);
  f->scratch_base = LoadInt(S);
  f->inst_seed = LoadInt(S);
  LoadOpMap(S, f);
  LoadCode(S, f);
  LoadVCode(S, f);
  LoadConstants(S, f);
  LoadUpvalues(S, f);
  LoadProtos(S, f);
  LoadDebug(S, f);
}


static void checkliteral (LoadState *S, const char *s, const char *msg) {
  char buff[sizeof(LUA_SIGNATURE) + sizeof(LUAC_DATA)]; /* larger than both */
  size_t len = strlen(s);
  LoadVector(S, buff, len);
  if (memcmp(s, buff, len) != 0)
    error(S, msg);
}


static void fchecksize (LoadState *S, size_t size, const char *tname) {
  if (LoadByte(S) != size)
    error(S, luaO_pushfstring(S->L, "%s 大小不匹配于", tname));
}


#define checksize(S,t)	fchecksize(S,sizeof(t),#t)

static void checkHeader (LoadState *S) {
  checkliteral(S, LUA_CUSTOM_SIGNATURE + 1, "不是");  /* 1st char already checked */
  if (LoadByte(S) != LUAC_VERSION)
    error(S, "版本不匹配于");
  if (LoadByte(S) != LUAC_FORMAT)
    error(S, "格式不匹配于");
  checkliteral(S, LUAC_DATA, "损坏的");
  checksize(S, int);
  //nirenr mod
  //checksize(S, size_t);
  checksize(S, unsigned int);
  checksize(S, Instruction);
  checksize(S, lua_Integer);
  checksize(S, lua_Number);
  if (LoadInteger(S) != LUAC_INT)
    error(S, "字节序不匹配于");
  if (LoadNumber(S) != LUAC_NUM)
    error(S, "浮点格式不匹配于");
}


/*
** load precompiled chunk
*/
LClosure *luaU_undump(lua_State *L, ZIO *Z, const char *name) {
  LoadState S;
  LClosure *cl;
  if (*name == '@' || *name == '=')
    S.name = name + 1;
  else if (*name == LUA_SIGNATURE[0])
    S.name = "二进制字符串";
  else
    S.name = name;
  S.L = L;
  S.Z = Z;
  S.hashing = 1;
  l_sha256_init(&S.sha256_ctx);
  {
    uint8_t first = LUA_CUSTOM_SIGNATURE[0];
    l_sha256_update(&S.sha256_ctx, &first, 1);
  }
  checkHeader(&S);
  cl = luaF_newLclosure(L, LoadByte(&S));
  setclLvalue(L, L->top, cl);
  luaD_inctop(L);
  cl->p = luaF_newproto(L);
  LoadFunction(&S, cl->p, NULL);
  lua_assert(cl->nupvalues == cl->p->sizeupvalues);
  luai_verifycode(L, buff, cl->p);
  {
    uint8_t calculated_digest[32];
    uint8_t loaded_digest[32];
    S.hashing = 0;
    l_sha256_final(&S.sha256_ctx, calculated_digest);
    if (luaZ_read(S.Z, loaded_digest, 32) == 0) {
      if (memcmp(calculated_digest, loaded_digest, 32) != 0)
        error(&S, "完整性校验失败 (SHA-256 不匹配)");
    }
  }
  return cl;
}
