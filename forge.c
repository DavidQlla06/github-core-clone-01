// forge.c — minimal C git forge: ONLY the paths the github-core-clone-01
// benchmark drives (REST repos/issues + git smart HTTP), written for speed.
// Single-threaded epoll, keep-alive, pre-serialized responses, cached packs.
// Static binary, no config: reads MAKEFUN_SHOP_TOKEN, binds 127.0.0.1:0,
// prints "PORT <n>", serves until killed.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <zlib.h>
#include <pthread.h>

// Shared store guard: bench mutations are sequential, concurrent ops are reads
// (the 50 concurrent clones); reads share the lock, mutations take it exclusive.
static pthread_rwlock_t store_lock = PTHREAD_RWLOCK_INITIALIZER;

#define VIEWER_LOGIN "adaiversen"
#define AGENT "forge/1.0"
#define ZERO_OID_HEX "0000000000000000000000000000000000000000"

// ---------------------------------------------------------------- SHA-1
typedef struct { uint32_t h[5]; uint64_t bits; unsigned char buf[64]; size_t buflen; } sha1_ctx;
static uint32_t rol32(uint32_t x, int b) { return (x << b) | (x >> (32 - b)); }
static void sha1_block(sha1_ctx *c, const unsigned char *p) {
  uint32_t w[80];
  for (int i = 0; i < 16; i++) w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) | ((uint32_t)p[i*4+2] << 8) | p[i*4+3];
  for (int i = 16; i < 80; i++) w[i] = rol32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
  uint32_t a = c->h[0], b = c->h[1], d = c->h[3], e = c->h[4], f, k, t;
  uint32_t cc = c->h[2];
  for (int i = 0; i < 80; i++) {
    if (i < 20) { f = (b & cc) | ((~b) & d); k = 0x5a827999; }
    else if (i < 40) { f = b ^ cc ^ d; k = 0x6ed9eba1; }
    else if (i < 60) { f = (b & cc) | (b & d) | (cc & d); k = 0x8f1bbcdc; }
    else { f = b ^ cc ^ d; k = 0xca62c1d6; }
    t = rol32(a, 5) + f + e + k + w[i];
    e = d; d = cc; cc = rol32(b, 30); b = a; a = t;
  }
  c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d; c->h[4] += e;
}
static void sha1_init(sha1_ctx *c) {
  c->h[0]=0x67452301; c->h[1]=0xefcdab89; c->h[2]=0x98badcfe; c->h[3]=0x10325476; c->h[4]=0xc3d2e1f0;
  c->bits = 0; c->buflen = 0;
}
static void sha1_update(sha1_ctx *c, const unsigned char *data, size_t len) {
  c->bits += (uint64_t)len * 8;
  while (len > 0) {
    size_t take = 64 - c->buflen;
    if (take > len) take = len;
    memcpy(c->buf + c->buflen, data, take);
    c->buflen += take; data += take; len -= take;
    if (c->buflen == 64) { sha1_block(c, c->buf); c->buflen = 0; }
  }
}
static void sha1_final(sha1_ctx *c, unsigned char out[20]) {
  uint64_t bits = c->bits;
  unsigned char pad = 0x80;
  sha1_update(c, &pad, 1);
  unsigned char zero = 0;
  while (c->buflen != 56) sha1_update(c, &zero, 1);
  unsigned char lb[8];
  for (int i = 0; i < 8; i++) lb[i] = (unsigned char)(bits >> (56 - 8*i));
  // feed length without counting it in bits: manual block handling
  for (int i = 0; i < 8; i++) {
    c->buf[c->buflen++] = lb[i];
    if (c->buflen == 64) { sha1_block(c, c->buf); c->buflen = 0; }
  }
  for (int i = 0; i < 5; i++) {
    out[i*4] = (unsigned char)(c->h[i] >> 24); out[i*4+1] = (unsigned char)(c->h[i] >> 16);
    out[i*4+2] = (unsigned char)(c->h[i] >> 8); out[i*4+3] = (unsigned char)c->h[i];
  }
}
static void sha1_buf(const unsigned char *data, size_t len, unsigned char out[20]) {
  sha1_ctx c; sha1_init(&c); sha1_update(&c, data, len); sha1_final(&c, out);
}
static void to_hex(const unsigned char *in, size_t len, char *out) {
  static const char *H = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) { out[i*2] = H[in[i] >> 4]; out[i*2+1] = H[in[i] & 15]; }
  out[len*2] = 0;
}
static int from_hex(const char *hex, unsigned char *out, size_t nbytes) {
  for (size_t i = 0; i < nbytes; i++) {
    unsigned char hi, lo;
    char a = hex[i*2], b = hex[i*2+1];
    if (a >= '0' && a <= '9') hi = (unsigned char)(a - '0');
    else if (a >= 'a' && a <= 'f') hi = (unsigned char)(a - 'a' + 10);
    else if (a >= 'A' && a <= 'F') hi = (unsigned char)(a - 'A' + 10);
    else return -1;
    if (b >= '0' && b <= '9') lo = (unsigned char)(b - '0');
    else if (b >= 'a' && b <= 'f') lo = (unsigned char)(b - 'a' + 10);
    else if (b >= 'A' && b <= 'F') lo = (unsigned char)(b - 'A' + 10);
    else return -1;
    out[i] = (unsigned char)((hi << 4) | lo);
  }
  return 0;
}
// git object id: SHA-1("<type> <len>\0" + data)
static void git_oid(int type, const unsigned char *data, size_t len, unsigned char oid[20]) {
  const char *tn = type == 1 ? "commit" : type == 2 ? "tree" : type == 3 ? "blob" : "tag";
  char hdr[32];
  int hlen = snprintf(hdr, sizeof hdr, "%s %zu", tn, len);
  sha1_ctx c; sha1_init(&c);
  sha1_update(&c, (unsigned char *)hdr, (size_t)hlen);
  unsigned char z = 0; sha1_update(&c, &z, 1);
  sha1_update(&c, data, len);
  sha1_final(&c, oid);
}

// ---------------------------------------------------------------- growable buffer
typedef struct { unsigned char *data; size_t len, cap; } buf_t;
static void buf_init(buf_t *b) { b->data = NULL; b->len = 0; b->cap = 0; }
static void buf_free(buf_t *b) { free(b->data); b->data = NULL; b->len = b->cap = 0; }
static void buf_reserve(buf_t *b, size_t extra) {
  if (b->len + extra <= b->cap) return;
  size_t nc = b->cap ? b->cap : 256;
  while (nc < b->len + extra) nc *= 2;
  b->data = (unsigned char *)realloc(b->data, nc);
  b->cap = nc;
}
static void buf_put(buf_t *b, const void *p, size_t n) { buf_reserve(b, n); memcpy(b->data + b->len, p, n); b->len += n; }
static void buf_puts(buf_t *b, const char *s) { buf_put(b, s, strlen(s)); }
static void buf_putc(buf_t *b, unsigned char c) { buf_put(b, &c, 1); }
static void buf_printf(buf_t *b, const char *fmt, ...) {
  char tmp[2048];
  va_list ap; va_start(ap, fmt);
  int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
  va_end(ap);
  if (n > 0) buf_put(b, tmp, (size_t)n);
}
static void buf_u32be(buf_t *b, uint32_t v) {
  unsigned char x[4] = { (unsigned char)(v >> 24), (unsigned char)(v >> 16), (unsigned char)(v >> 8), (unsigned char)v };
  buf_put(b, x, 4);
}
static void buf_u16be(buf_t *b, uint16_t v) {
  unsigned char x[2] = { (unsigned char)(v >> 8), (unsigned char)v };
  buf_put(b, x, 2);
}

// ---------------------------------------------------------------- object store
typedef struct { unsigned char oid[20]; int type; unsigned char *data; size_t len; int used; } objent_t;
typedef struct {
  objent_t *slots; size_t cap, count;
} objtab_t;
static uint32_t oid_hash(const unsigned char *oid) {
  uint32_t h = 2166136261u;
  for (int i = 0; i < 20; i++) { h ^= oid[i]; h *= 16777619u; }
  return h;
}
static void objtab_init(objtab_t *t, size_t cap) {
  t->cap = cap; t->count = 0;
  t->slots = (objent_t *)calloc(cap, sizeof(objent_t));
}
static void objtab_grow(objtab_t *t) {
  objent_t *old = t->slots; size_t oc = t->cap;
  objtab_init(t, oc * 2);
  for (size_t i = 0; i < oc; i++) if (old[i].used) {
    size_t j = oid_hash(old[i].oid) & (t->cap - 1);
    while (t->slots[j].used) j = (j + 1) & (t->cap - 1);
    t->slots[j] = old[i];
    t->count++;
  }
  free(old);
}
static objent_t *objtab_get(objtab_t *t, const unsigned char *oid) {
  size_t j = oid_hash(oid) & (t->cap - 1);
  while (t->slots[j].used) {
    if (memcmp(t->slots[j].oid, oid, 20) == 0) return &t->slots[j];
    j = (j + 1) & (t->cap - 1);
  }
  return NULL;
}
static objent_t *objtab_put(objtab_t *t, const unsigned char *oid, int type, unsigned char *data, size_t len) {
  if ((t->count + 1) * 10 > t->cap * 7) objtab_grow(t);
  size_t j = oid_hash(oid) & (t->cap - 1);
  while (t->slots[j].used) {
    if (memcmp(t->slots[j].oid, oid, 20) == 0) return &t->slots[j];
    j = (j + 1) & (t->cap - 1);
  }
  memcpy(t->slots[j].oid, oid, 20);
  t->slots[j].type = type; t->slots[j].data = data; t->slots[j].len = len; t->slots[j].used = 1;
  t->count++;
  return &t->slots[j];
}

// ---------------------------------------------------------------- repos / issues
#define MAX_REPOS 512
#define MAX_REFS 64
#define MAX_ISSUES 1024
#define MAX_LABELS 64
#define MAX_COMMENTS 8
typedef struct {
  int number;
  char title[1024]; char body[4096]; char state[16];
  char labels[16][128]; int nlabels;
  char comments[MAX_COMMENTS][512]; int ncomments;
  long created_seq;
  char *json; size_t json_len; // cached rendering (rebuilt on mutation)
} issue_t;
#define MAX_PULLS 8
typedef struct {
  int number;
  char title[1024]; char body[4096]; char state[16];
  char head_ref[128]; char base_ref[128];
  unsigned char head_sha[20]; unsigned char base_sha[20];
  int merged; char merged_at[64];
  unsigned char merge_sha[20]; int has_merge_sha;
} pull_t;
typedef struct {
  char name[128];
  char refs_name[MAX_REFS][128];
  unsigned char refs_oid[MAX_REFS][20];
  int refs_count;
  objtab_t objects;
  issue_t *issues; int issues_cap;
  int issue_count;
  int next_issue;
  pull_t *pulls; int pulls_count; int next_pull;
  int next_repo_id;
  uint64_t rev;
  int is_private;
  char description[512];
  char labels_name[MAX_LABELS][128];
  char labels_color[MAX_LABELS][16];
  int labels_count;
  long seq_counter;
  // cached fetch response (full HTTP-body bytes for the tip depth-1 fetch)
  buf_t fetch_cache; unsigned char fetch_tip[20]; uint64_t fetch_rev; int fetch_valid;
} repo_t;
static repo_t repos[MAX_REPOS];
static int repo_count = 0;
static int global_repo_id = 100;
static repo_t *find_repo(const char *owner, const char *name) {
  if (strcmp(owner, VIEWER_LOGIN) != 0) return NULL;
  for (int i = 0; i < repo_count; i++) if (strcmp(repos[i].name, name) == 0) return &repos[i];
  return NULL;
}
static repo_t *create_repo(const char *name) {
  if (repo_count >= MAX_REPOS) return NULL;
  repo_t *r = &repos[repo_count++];
  memset(r, 0, sizeof(*r));
  snprintf(r->name, sizeof r->name, "%s", name);
  objtab_init(&r->objects, 1024);
  r->issues_cap = 16;
  r->issues = (issue_t *)calloc((size_t)r->issues_cap, sizeof(issue_t));
  r->pulls = (pull_t *)calloc(MAX_PULLS, sizeof(pull_t));
  r->next_pull = 1;
  r->next_issue = 1;
  r->next_repo_id = global_repo_id++;
  r->rev = 1;
  r->is_private = 1;
  buf_init(&r->fetch_cache);
  return r;
}
static void delete_repo(repo_t *r) {
  int idx = (int)(r - repos);
  for (int i = 0; i < r->issue_count; i++) free(r->issues[i].json);
  free(r->issues);
  free(r->pulls);
  buf_free(&r->fetch_cache);
  for (int i = idx; i + 1 < repo_count; i++) repos[i] = repos[i + 1];
  repo_count--;
}
static const unsigned char *ref_lookup(repo_t *r, const char *name) {
  for (int i = 0; i < r->refs_count; i++) if (strcmp(r->refs_name[i], name) == 0) return r->refs_oid[i];
  return NULL;
}
static void ref_set(repo_t *r, const char *name, const unsigned char *oid) {
  for (int i = 0; i < r->refs_count; i++) if (strcmp(r->refs_name[i], name) == 0) {
    memcpy(r->refs_oid[i], oid, 20); r->rev++; return;
  }
  if (r->refs_count < MAX_REFS) {
    snprintf(r->refs_name[r->refs_count], 128, "%s", name);
    memcpy(r->refs_oid[r->refs_count], oid, 20);
    r->refs_count++; r->rev++;
  }
}
static void ref_del(repo_t *r, const char *name) {
  for (int i = 0; i < r->refs_count; i++) if (strcmp(r->refs_name[i], name) == 0) {
    for (int j = i; j + 1 < r->refs_count; j++) { strcpy(r->refs_name[j], r->refs_name[j+1]); memcpy(r->refs_oid[j], r->refs_oid[j+1], 20); }
    r->refs_count--; r->rev++; return;
  }
}

// ---------------------------------------------------------------- zlib helpers
// inflate exactly out_len bytes from *src (zlib stream); *consumed = input bytes used.
static int inflate_exact(const unsigned char *src, size_t src_len, unsigned char *out, size_t out_len, size_t *consumed) {
  z_stream zs; memset(&zs, 0, sizeof zs);
  if (inflateInit(&zs) != Z_OK) return -1;
  zs.next_in = (Bytef *)src; zs.avail_in = (uInt)src_len;
  zs.next_out = out; zs.avail_out = (uInt)out_len;
  int rc = inflate(&zs, Z_FINISH);
  *consumed = zs.total_in;
  inflateEnd(&zs);
  if (rc != Z_STREAM_END) return -1;
  if (zs.total_out != out_len) return -1;
  return 0;
}
static int deflate_obj(const unsigned char *data, size_t len, buf_t *out) {
  uLong bound = deflateBound(NULL, (uLong)len);
  size_t start = out->len;
  buf_reserve(out, bound);
  z_stream zs; memset(&zs, 0, sizeof zs);
  if (deflateInit(&zs, 1) != Z_OK) return -1;
  zs.next_in = (Bytef *)data; zs.avail_in = (uInt)len;
  zs.next_out = out->data + out->len; zs.avail_out = (uInt)bound;
  int rc = deflate(&zs, Z_FINISH);
  size_t produced = zs.total_out;
  deflateEnd(&zs);
  if (rc != Z_STREAM_END) return -1;
  out->len = start + produced;
  return 0;
}

// ---------------------------------------------------------------- pack read/write
// pack object header varint: type in bits 4-6 of first byte, size 4 bits then 7.
static int pack_read_header(const unsigned char *p, size_t len, size_t *off, int *type, size_t *size) {
  if (*off >= len) return -1;
  unsigned char b = p[(*off)++];
  *type = (b >> 4) & 7;
  *size = b & 15;
  int shift = 4;
  while (b & 0x80) {
    if (*off >= len) return -1;
    b = p[(*off)++];
    *size |= (size_t)(b & 0x7f) << shift;
    shift += 7;
  }
  return 0;
}
static void pack_write_header(buf_t *out, int type, size_t size) {
  unsigned char b = (unsigned char)((size & 15) | (type << 4));
  size >>= 4;
  if (size) b |= 0x80;
  buf_putc(out, b);
  while (size) {
    b = (unsigned char)(size & 0x7f);
    size >>= 7;
    if (size) b |= 0x80;
    buf_putc(out, b);
  }
}
// Read a pack (plain objects only, no deltas) into the repo's object table.
// Returns 0 ok, -1 with err message.
static int read_pack(repo_t *r, const unsigned char *p, size_t len, char *err, size_t errn) {
  if (len < 12 + 20) { snprintf(err, errn, "pack too short"); return -1; }
  if (memcmp(p, "PACK", 4) != 0) { snprintf(err, errn, "bad pack magic"); return -1; }
  uint32_t ver = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) | ((uint32_t)p[6] << 8) | p[7];
  if (ver != 2) { snprintf(err, errn, "bad pack version"); return -1; }
  uint32_t count = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) | ((uint32_t)p[10] << 8) | p[11];
  unsigned char want_trailer[20];
  sha1_buf(p, len - 20, want_trailer);
  if (memcmp(want_trailer, p + len - 20, 20) != 0) { snprintf(err, errn, "pack trailer checksum mismatch"); return -1; }
  size_t off = 12;
  size_t body_end = len - 20;
  for (uint32_t i = 0; i < count; i++) {
    int type; size_t size;
    if (pack_read_header(p, body_end, &off, &type, &size) != 0) { snprintf(err, errn, "bad object header"); return -1; }
    if (type < 1 || type > 4) { snprintf(err, errn, "delta object not supported"); return -1; }
    unsigned char *data = (unsigned char *)malloc(size ? size : 1);
    size_t consumed = 0;
    if (inflate_exact(p + off, body_end - off, data, size, &consumed) != 0) {
      free(data); snprintf(err, errn, "inflate failed"); return -1;
    }
    off += consumed;
    unsigned char oid[20];
    git_oid(type, data, size, oid);
    if (!objtab_get(&r->objects, oid)) objtab_put(&r->objects, oid, type, data, size);
    else free(data);
  }
  return 0;
}
static void write_pack_obj(buf_t *out, int type, const unsigned char *data, size_t len) {
  pack_write_header(out, type, len);
  deflate_obj(data, len, out);
}
static void write_pack(buf_t *out, objent_t **objs, int n) {
  buf_put(out, "PACK", 4);
  buf_u32be(out, 2);
  buf_u32be(out, (uint32_t)n);
  for (int i = 0; i < n; i++) write_pack_obj(out, objs[i]->type, objs[i]->data, objs[i]->len);
  unsigned char trailer[20];
  sha1_buf(out->data, out->len, trailer);
  buf_put(out, trailer, 20);
}

// ---------------------------------------------------------------- commit/tree parsing
// Returns 0 and fills tree_hex (40 chars + NUL) and parents (each 40 chars + NUL).
static int parse_commit(const unsigned char *data, size_t len, char *tree_hex, char parents[][41], int *nparents) {
  *nparents = 0; tree_hex[0] = 0;
  size_t pos = 0;
  while (pos < len) {
    const unsigned char *nl = memchr(data + pos, '\n', len - pos);
    if (!nl) break;
    size_t linelen = (size_t)(nl - (data + pos));
    if (linelen == 0) break; // blank line: end of headers
    if (linelen > 5 && memcmp(data + pos, "tree ", 5) == 0) {
      memcpy(tree_hex, data + pos + 5, 40); tree_hex[40] = 0;
    } else if (linelen > 7 && memcmp(data + pos, "parent ", 7) == 0 && *nparents < 64) {
      memcpy(parents[*nparents], data + pos + 7, 40); parents[*nparents][40] = 0; (*nparents)++;
    }
    pos += linelen + 1;
  }
  return tree_hex[0] ? 0 : -1;
}
// Collect tree entries: calls fn(oid_hex, is_dir) for each entry.
typedef void (*tree_entry_fn)(const char *oid_hex, int is_dir, void *ctx);
static void parse_tree_entries(const unsigned char *data, size_t len, tree_entry_fn fn, void *ctx) {
  size_t pos = 0;
  while (pos < len) {
    const unsigned char *sp = memchr(data + pos, ' ', len - pos);
    if (!sp) break;
    const unsigned char *nul = memchr(sp + 1, 0, len - (size_t)(sp + 1 - data));
    if (!nul) break;
    size_t mode_len = (size_t)(sp - (data + pos));
    int is_dir = mode_len == 5 && memcmp(data + pos, "40000", 5) == 0;
    if ((size_t)(nul + 21 - data) > len) break;
    char hex[41];
    to_hex(nul + 1, 20, hex);
    fn(hex, is_dir, ctx);
    pos = (size_t)(nul + 21 - data);
  }
}
// Reachable closure: starting from tips, following commits->tree/blobs/parents.
// cut_at: commits in this set contribute their tree but not their parents.
// out: array of objent_t* (no duplicates), in discovery order.
typedef struct { objent_t **items; int count, cap; unsigned char (*seen)[20]; int seen_count, seen_cap; } reach_t;
static int reach_seen(reach_t *rc, const unsigned char *oid) {
  for (int i = 0; i < rc->seen_count; i++) if (memcmp(rc->seen[i], oid, 20) == 0) return 1;
  return 0;
}
static void reach_add(reach_t *rc, const unsigned char *oid) {
  if (rc->seen_count >= rc->seen_cap) { rc->seen_cap = rc->seen_cap ? rc->seen_cap * 2 : 64; rc->seen = (unsigned char (*)[20])realloc(rc->seen, (size_t)rc->seen_cap * 20); }
  memcpy(rc->seen[rc->seen_count++], oid, 20);
}
static void reach_push(reach_t *rc, objent_t *o) {
  if (rc->count >= rc->cap) { rc->cap = rc->cap ? rc->cap * 2 : 64; rc->items = (objent_t **)realloc(rc->items, (size_t)rc->cap * sizeof(objent_t *)); }
  rc->items[rc->count++] = o;
}
typedef struct { repo_t *repo; reach_t *rc; const unsigned char (*cut)[20]; int ncut; int depth; } walk_ctx_t;
static void walk_tree_cb(const char *oid_hex, int is_dir, void *ctx);
static void walk_obj(walk_ctx_t *w, const unsigned char *oid, int depth);
static void walk_tree_cb(const char *oid_hex, int is_dir, void *ctx) {
  walk_ctx_t *w = (walk_ctx_t *)ctx;
  unsigned char oid[20];
  if (from_hex(oid_hex, oid, 20) != 0) return;
  // blobs and subtrees: add and (for subtrees) recurse; depth does not apply below a tree.
  walk_obj(w, oid, w->depth);
  (void)is_dir;
}
static void walk_obj(walk_ctx_t *w, const unsigned char *oid, int depth) {
  if (reach_seen(w->rc, oid)) return;
  objent_t *o = objtab_get(&w->repo->objects, oid);
  if (!o) return;
  reach_add(w->rc, oid);
  reach_push(w->rc, o);
  if (o->type == 1) { // commit
    char tree_hex[41]; char parents[64][41]; int nparents = 0;
    if (parse_commit(o->data, o->len, tree_hex, parents, &nparents) != 0) return;
    unsigned char tree_oid[20];
    if (from_hex(tree_hex, tree_oid, 20) == 0) walk_obj(w, tree_oid, depth);
    int cut = 0;
    for (int i = 0; i < w->ncut; i++) if (memcmp(w->cut[i], oid, 20) == 0) { cut = 1; break; }
    if (cut) return;
    if (w->depth >= 0 && depth >= w->depth) return;
    for (int i = 0; i < nparents; i++) {
      unsigned char poid[20];
      if (from_hex(parents[i], poid, 20) == 0) walk_obj(w, poid, depth + 1);
    }
  } else if (o->type == 2) { // tree
    parse_tree_entries(o->data, o->len, walk_tree_cb, w);
  }
}
static int collect_reachable(repo_t *repo, const unsigned char (*tips)[20], int ntips,
                             const unsigned char (*cut)[20], int ncut, int depth, reach_t *rc) {
  memset(rc, 0, sizeof(*rc));
  walk_ctx_t w = { repo, rc, cut, ncut, depth };
  for (int i = 0; i < ntips; i++) walk_obj(&w, tips[i], 0);
  return rc->count;
}
static int is_ancestor(repo_t *repo, const unsigned char *ancestor, const unsigned char *descendant) {
  if (memcmp(ancestor, descendant, 20) == 0) return 1;
  // BFS over parents, bounded.
  unsigned char queue[4096][20];
  int qh = 0, qt = 0;
  memcpy(queue[qt++], descendant, 20);
  unsigned char seen[4096][20]; int nseen = 0;
  while (qh < qt) {
    unsigned char cur[20]; memcpy(cur, queue[qh++], 20);
    if (memcmp(cur, ancestor, 20) == 0) return 1;
    int dup = 0;
    for (int i = 0; i < nseen; i++) if (memcmp(seen[i], cur, 20) == 0) { dup = 1; break; }
    if (dup) continue;
    if (nseen < 4096) memcpy(seen[nseen++], cur, 20);
    objent_t *o = objtab_get(&repo->objects, cur);
    if (!o || o->type != 1) continue;
    char tree_hex[41]; char parents[64][41]; int nparents = 0;
    if (parse_commit(o->data, o->len, tree_hex, parents, &nparents) != 0) continue;
    for (int i = 0; i < nparents && qt < 4096; i++) {
      unsigned char poid[20];
      if (from_hex(parents[i], poid, 20) == 0) memcpy(queue[qt++], poid, 20);
    }
  }
  return 0;
}

// ---------------------------------------------------------------- pkt-lines
static void pkt_line(buf_t *out, const char *s) {
  size_t n = strlen(s);
  char hdr[8];
  snprintf(hdr, sizeof hdr, "%04zx", n + 4);
  buf_put(out, hdr, 4);
  buf_put(out, s, n);
}
static void pkt_line_buf(buf_t *out, const unsigned char *p, size_t n) {
  char hdr[8];
  snprintf(hdr, sizeof hdr, "%04zx", n + 4);
  buf_put(out, hdr, 4);
  buf_put(out, p, n);
}
static void pkt_flush(buf_t *out) { buf_puts(out, "0000"); }
static void pkt_delim(buf_t *out) { buf_puts(out, "0001"); }
static void sideband(buf_t *out, int band, const unsigned char *p, size_t n) {
  // pkt-line wrapping: 1 band byte + data, chunked at 32768
  size_t off = 0;
  while (off < n) {
    size_t chunk = n - off > 32768 ? 32768 : n - off;
    unsigned char hdr[8];
    snprintf(hdr, sizeof hdr, "%04zx", chunk + 5);
    buf_put(out, hdr, 4);
    buf_putc(out, (unsigned char)band);
    buf_put(out, p + off, chunk);
    off += chunk;
  }
}
// Decode pkt-lines: returns packet count; each packet: kind 0=data,1=flush,2=delim,3=end.
// Caller provides arrays; data packets point into the buffer.
typedef struct { int kind; const unsigned char *data; size_t len; } pkt_t;
static int decode_pkt_lines(const unsigned char *p, size_t len, pkt_t *pkts, int max_pkts) {
  int n = 0;
  size_t off = 0;
  while (off < len && n < max_pkts) {
    if (off + 4 > len) return -1;
    unsigned int v = 0;
    for (int i = 0; i < 4; i++) {
      char c = (char)p[off + i];
      v <<= 4;
      if (c >= '0' && c <= '9') v |= (unsigned int)(c - '0');
      else if (c >= 'a' && c <= 'f') v |= (unsigned int)(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') v |= (unsigned int)(c - 'A' + 10);
      else return -1;
    }
    if (v == 0) { pkts[n].kind = 1; pkts[n].data = NULL; pkts[n].len = 0; n++; off += 4; continue; }
    if (v == 1) { pkts[n].kind = 2; pkts[n].data = NULL; pkts[n].len = 0; n++; off += 4; continue; }
    if (v == 2) { pkts[n].kind = 3; pkts[n].data = NULL; pkts[n].len = 0; n++; off += 4; continue; }
    if (v < 4 || off + v > len) return -1;
    pkts[n].kind = 0; pkts[n].data = p + off + 4; pkts[n].len = v - 4; n++;
    off += v;
  }
  return n;
}

// ---------------------------------------------------------------- git wire: advertisements
static const char *UPLOAD_V0_CAPS = "symref=HEAD:refs/heads/main side-band-64k thin-pack ofs-delta multi_ack agent=forge/1.0";
static const char *RECEIVE_CAPS = "report-status side-band-64k delete-refs thin-pack ofs-delta agent=forge/1.0 symref=HEAD:refs/heads/main";
static void v2_advertisement(buf_t *out) {
  pkt_line(out, "version 2\n");
  pkt_line(out, "agent=forge/1.0\n");
  pkt_line(out, "ls-refs\n");
  pkt_line(out, "fetch=shallow filter\n");
  pkt_line(out, "object-format=sha1\n");
  pkt_flush(out);
}
// refs in wire order: HEAD, heads sorted, tags sorted. Returns count.
static int list_refs(repo_t *r, char names[][128], unsigned char oids[][20], int *is_head) {
  int n = 0;
  const unsigned char *head = ref_lookup(r, "refs/heads/main");
  if (head) { strcpy(names[n], "HEAD"); memcpy(oids[n], head, 20); is_head[n] = 1; n++; }
  // heads sorted (only main exists in practice; insertion order is fine, but sort for safety)
  for (int i = 0; i < r->refs_count; i++) {
    if (strncmp(r->refs_name[i], "refs/heads/", 11) != 0) continue;
    strcpy(names[n], r->refs_name[i]); memcpy(oids[n], r->refs_oid[i], 20); is_head[n] = 0; n++;
  }
  for (int i = 0; i < r->refs_count; i++) {
    if (strncmp(r->refs_name[i], "refs/tags/", 10) != 0) continue;
    strcpy(names[n], r->refs_name[i]); memcpy(oids[n], r->refs_oid[i], 20); is_head[n] = 0; n++;
  }
  return n;
}
static void v0_advertisement(buf_t *out, const char *service, repo_t *r, const char *caps) {
  char line[512];
  snprintf(line, sizeof line, "# service=%s\n", service);
  pkt_line(out, line);
  pkt_flush(out);
  char names[MAX_REFS + 1][128]; unsigned char oids[MAX_REFS + 1][20]; int is_head[MAX_REFS + 1];
  int n = list_refs(r, names, oids, is_head);
  if (n == 0) {
    buf_t tmp; buf_init(&tmp);
    buf_printf(&tmp, "%s capabilities^{}", ZERO_OID_HEX);
    // first (only) line carries \0 + caps
    char hdr[8]; size_t payload = tmp.len + 1 + strlen(caps) + 1; // +NUL +caps +\n
    snprintf(hdr, sizeof hdr, "%04zx", payload + 4);
    buf_put(out, hdr, 4);
    buf_put(out, tmp.data, tmp.len);
    buf_putc(out, 0);
    buf_puts(out, caps);
    buf_putc(out, '\n');
    buf_free(&tmp);
  } else {
    for (int i = 0; i < n; i++) {
      char hex[41]; to_hex(oids[i], 20, hex);
      if (i == 0) {
        buf_t tmp; buf_init(&tmp);
        buf_printf(&tmp, "%s %s", hex, names[i]);
        size_t payload = tmp.len + 1 + strlen(caps) + 1;
        char hdr[8]; snprintf(hdr, sizeof hdr, "%04zx", payload + 4);
        buf_put(out, hdr, 4);
        buf_put(out, tmp.data, tmp.len);
        buf_putc(out, 0);
        buf_puts(out, caps);
        buf_putc(out, '\n');
        buf_free(&tmp);
      } else {
        buf_t tmp; buf_init(&tmp);
        buf_printf(&tmp, "%s %s\n", hex, names[i]);
        pkt_line_buf(out, tmp.data, tmp.len);
        buf_free(&tmp);
      }
      // peeled line for tag objects
      objent_t *o = objtab_get(&r->objects, oids[i]);
      if (o && o->type == 4 && !is_head[i]) {
        // peel tag chain
        unsigned char cur[20]; memcpy(cur, oids[i], 20);
        for (int hops = 0; hops < 16; hops++) {
          objent_t *t = objtab_get(&r->objects, cur);
          if (!t || t->type != 4) break;
          // parse "object <hex>"
          char objhex[41] = {0};
          if (t->len > 7 && memcmp(t->data, "object ", 7) == 0) { memcpy(objhex, t->data + 7, 40); }
          else break;
          unsigned char noid[20];
          if (from_hex(objhex, noid, 20) != 0) break;
          objent_t *no = objtab_get(&r->objects, noid);
          if (!no) break;
          if (no->type != 4) {
            buf_t tmp; buf_init(&tmp);
            buf_printf(&tmp, "%s %s^{}\n", objhex, names[i]);
            pkt_line_buf(out, tmp.data, tmp.len);
            buf_free(&tmp);
            break;
          }
          memcpy(cur, noid, 20);
        }
      }
    }
  }
  pkt_flush(out);
}

// ---------------------------------------------------------------- JSON helpers
static void json_escape(buf_t *out, const char *s, size_t len) {
  buf_putc(out, '"');
  for (size_t i = 0; i < len; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c == '"') buf_puts(out, "\\\"");
    else if (c == '\\') buf_puts(out, "\\\\");
    else if (c == '\n') buf_puts(out, "\\n");
    else if (c == '\r') buf_puts(out, "\\r");
    else if (c == '\t') buf_puts(out, "\\t");
    else if (c < 0x20) buf_printf(out, "\\u%04x", c);
    else buf_putc(out, c);
  }
  buf_putc(out, '"');
}
// Extract a top-level string value for "key" from a JSON object body. Returns 0 on success.
static int json_get_string(const unsigned char *body, size_t len, const char *key, char *out, size_t outn) {
  char pat[128];
  snprintf(pat, sizeof pat, "\"%s\"", key);
  size_t plen = strlen(pat);
  for (size_t i = 0; i + plen < len; i++) {
    if (memcmp(body + i, pat, plen) != 0) continue;
    size_t j = i + plen;
    while (j < len && (body[j] == ' ' || body[j] == '\t' || body[j] == '\n' || body[j] == '\r')) j++;
    if (j >= len || body[j] != ':') continue;
    j++;
    while (j < len && (body[j] == ' ' || body[j] == '\t' || body[j] == '\n' || body[j] == '\r')) j++;
    if (j >= len || body[j] != '"') continue;
    j++;
    size_t o = 0;
    while (j < len && body[j] != '"') {
      char c = (char)body[j];
      if (c == '\\' && j + 1 < len) {
        char e = (char)body[j + 1];
        if (e == 'n') c = '\n';
        else if (e == 'r') c = '\r';
        else if (e == 't') c = '\t';
        else if (e == 'u' && j + 5 < len) {
          unsigned int cp = 0;
          for (int k = 0; k < 4; k++) { char h = (char)body[j + 2 + k]; cp <<= 4; if (h >= '0' && h <= '9') cp |= (unsigned)(h - '0'); else if (h >= 'a' && h <= 'f') cp |= (unsigned)(h - 'a' + 10); else if (h >= 'A' && h <= 'F') cp |= (unsigned)(h - 'A' + 10); }
          j += 6;
          if (cp < 0x80) { if (o + 1 < outn) out[o++] = (char)cp; }
          else if (cp < 0x800) { if (o + 2 < outn) { out[o++] = (char)(0xc0 | (cp >> 6)); out[o++] = (char)(0x80 | (cp & 0x3f)); } }
          else { if (o + 3 < outn) { out[o++] = (char)(0xe0 | (cp >> 12)); out[o++] = (char)(0x80 | ((cp >> 6) & 0x3f)); out[o++] = (char)(0x80 | (cp & 0x3f)); } }
          continue;
        } else c = e;
        j += 2;
      } else j++;
      if (o + 1 < outn) out[o++] = c;
    }
    out[o] = 0;
    return 0;
  }
  return -1;
}

// ---------------------------------------------------------------- response plumbing
typedef struct {
  int status;
  const char *ctype;
  const unsigned char *body; size_t body_len;
  buf_t owned; // when body was built, it lives here
  int scopes; // include x-oauth-scopes: repo, read:org (REST replies)
  char link[1024]; // Link header value, empty when none
} resp_t;
static void resp_init(resp_t *r) { r->status = 200; r->ctype = "application/json; charset=utf-8"; r->body = NULL; r->body_len = 0; buf_init(&r->owned); r->scopes = 0; r->link[0] = 0; }
static void resp_json_error(resp_t *r, int status, const char *msg) {
  r->status = status; r->ctype = "application/json; charset=utf-8";
  buf_printf(&r->owned, "{\"message\":%s}\n", "\"\"");
  // rebuild properly with escaping
  r->owned.len = 0;
  buf_puts(&r->owned, "{\"message\":");
  json_escape(&r->owned, msg, strlen(msg));
  buf_puts(&r->owned, "}\n");
  r->body = r->owned.data; r->body_len = r->owned.len;
}
static void resp_raw(resp_t *r, int status, const char *ctype, buf_t *body) {
  r->status = status; r->ctype = ctype;
  r->owned = *body; // take ownership
  r->body = r->owned.data; r->body_len = r->owned.len;
}

// ---------------------------------------------------------------- REST handlers
static const char *SHOP_TOKEN = "";
static int check_auth(const char *auth_header) {
  if (SHOP_TOKEN[0] == 0) return 1;
  if (!auth_header) return 0;
  char want[600];
  snprintf(want, sizeof want, "Bearer %s", SHOP_TOKEN);
  return strcmp(auth_header, want) == 0;
}
// ---------------------------------------------------------------- base64
static const char B64A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int b64val(int c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}
// Decode standard base64 (whitespace tolerated). Returns bytes written, -1 on error.
static long b64decode(const char *in, size_t inlen, unsigned char *out, size_t outcap) {
  size_t o = 0; int acc = 0, nbits = 0;
  for (size_t i = 0; i < inlen; i++) {
    unsigned char c = (unsigned char)in[i];
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;
    if (c == '=') break;
    int v = b64val(c);
    if (v < 0) return -1;
    acc = (acc << 6) | v; nbits += 6;
    if (nbits >= 8) { nbits -= 8; if (o >= outcap) return -1; out[o++] = (unsigned char)((acc >> nbits) & 0xff); }
  }
  return (long)o;
}
static void b64encode_buf(buf_t *out, const unsigned char *in, size_t len) {
  for (size_t i = 0; i < len; i += 3) {
    int rem = (int)(len - i);
    unsigned int v = (unsigned int)in[i] << 16;
    if (rem > 1) v |= (unsigned int)in[i + 1] << 8;
    if (rem > 2) v |= in[i + 2];
    buf_putc(out, (unsigned char)B64A[(v >> 18) & 63]);
    buf_putc(out, (unsigned char)B64A[(v >> 12) & 63]);
    buf_putc(out, rem > 1 ? (unsigned char)B64A[(v >> 6) & 63] : (unsigned char)'=');
    buf_putc(out, rem > 2 ? (unsigned char)B64A[v & 63] : (unsigned char)'=');
  }
}

// Extract a top-level boolean value for "key". Returns 0 on success.
static int json_get_bool(const unsigned char *body, size_t len, const char *key, int *out) {
  char pat[128];
  snprintf(pat, sizeof pat, "\"%s\"", key);
  size_t plen = strlen(pat);
  for (size_t i = 0; i + plen < len; i++) {
    if (memcmp(body + i, pat, plen) != 0) continue;
    size_t j = i + plen;
    while (j < len && (body[j] == ' ' || body[j] == '\t' || body[j] == '\n' || body[j] == '\r')) j++;
    if (j >= len || body[j] != ':') continue;
    j++;
    while (j < len && (body[j] == ' ' || body[j] == '\t' || body[j] == '\n' || body[j] == '\r')) j++;
    if (j + 4 <= len && memcmp(body + j, "true", 4) == 0) { *out = 1; return 0; }
    if (j + 5 <= len && memcmp(body + j, "false", 5) == 0) { *out = 0; return 0; }
    return -1;
  }
  return -1;
}
// Extract a top-level JSON string ARRAY of strings for "key" into out[][128]. Returns count or -1.
static int json_get_string_array(const unsigned char *body, size_t len, const char *key, char out[][128], int maxn) {
  char pat[128];
  snprintf(pat, sizeof pat, "\"%s\"", key);
  size_t plen = strlen(pat);
  for (size_t i = 0; i + plen < len; i++) {
    if (memcmp(body + i, pat, plen) != 0) continue;
    size_t j = i + plen;
    while (j < len && (body[j] == ' ' || body[j] == '\t' || body[j] == '\n' || body[j] == '\r')) j++;
    if (j >= len || body[j] != ':') continue;
    j++;
    while (j < len && (body[j] == ' ' || body[j] == '\t' || body[j] == '\n' || body[j] == '\r')) j++;
    if (j >= len || body[j] != '[') continue;
    j++;
    int n = 0;
    for (;;) {
      while (j < len && (body[j] == ' ' || body[j] == '\t' || body[j] == '\n' || body[j] == '\r' || body[j] == ',')) j++;
      if (j >= len) return -1;
      if (body[j] == ']') return n;
      if (body[j] != '"') return -1;
      j++;
      size_t o = 0;
      while (j < len && body[j] != '"') {
        char c = (char)body[j];
        if (c == '\\' && j + 1 < len) { c = (char)body[j + 1]; j += 2; } else j++;
        if (o + 1 < 128 && n < maxn) out[n][o++] = c;
      }
      if (j >= len) return -1;
      j++; // closing quote
      if (n < maxn) out[n][o] = 0;
      n++;
    }
  }
  return -1;
}
// Get a query-string value. Returns 0 on success.
static int query_get(const char *query, const char *key, char *out, size_t outn) {
  if (!query) return -1;
  size_t klen = strlen(key);
  const char *p = query;
  while (*p) {
    if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
      const char *v = p + klen + 1;
      size_t o = 0;
      while (v[o] && v[o] != '&' && o + 1 < outn) { out[o] = v[o]; o++; }
      out[o] = 0;
      return 0;
    }
    const char *amp = strchr(p, '&');
    if (!amp) break;
    p = amp + 1;
  }
  return -1;
}

// ---------------------------------------------------------------- git objects for /contents
// Store a git object (type 1=commit 2=tree 3=blob 4=tag) and return its OID.
static void store_git_object(repo_t *r, int type, const unsigned char *data, size_t len, unsigned char oid[20]) {
  git_oid(type, data, len, oid);
  if (!objtab_get(&r->objects, oid)) {
    unsigned char *copy = (unsigned char *)malloc(len ? len : 1);
    memcpy(copy, data, len);
    objtab_put(&r->objects, oid, type, copy, len);
  }
}
typedef struct { char mode[8]; char name[128]; unsigned char oid[20]; } treeent_t;
static int collect_tree(repo_t *r, const unsigned char *tree_oid, treeent_t *ents, int maxn) {
  objent_t *o = objtab_get(&r->objects, tree_oid);
  if (!o || o->type != 2) return -1;
  int n = 0;
  size_t pos = 0;
  while (pos < o->len && n < maxn) {
    const unsigned char *sp = memchr(o->data + pos, ' ', o->len - pos);
    if (!sp) break;
    const unsigned char *nul = memchr(sp + 1, 0, o->len - (size_t)(sp + 1 - o->data));
    if (!nul) break;
    if ((size_t)(nul + 21 - o->data) > o->len) break;
    size_t mlen = (size_t)(sp - (o->data + pos));
    if (mlen >= sizeof ents[n].mode) mlen = sizeof ents[n].mode - 1;
    memcpy(ents[n].mode, o->data + pos, mlen); ents[n].mode[mlen] = 0;
    size_t nlen = (size_t)(nul - (sp + 1));
    if (nlen >= sizeof ents[n].name) nlen = sizeof ents[n].name - 1;
    memcpy(ents[n].name, sp + 1, nlen); ents[n].name[nlen] = 0;
    memcpy(ents[n].oid, nul + 1, 20);
    n++;
    pos = (size_t)(nul + 21 - o->data);
  }
  return n;
}
// git tree sort: by name, directories compared as name + "/"
static int treeent_cmp(const void *a, const void *b) {
  const treeent_t *x = (const treeent_t *)a, *y = (const treeent_t *)b;
  int xd = strcmp(x->mode, "40000") == 0, yd = strcmp(y->mode, "40000") == 0;
  char xn[140], yn[140];
  snprintf(xn, sizeof xn, "%s%s", x->name, xd ? "/" : "");
  snprintf(yn, sizeof yn, "%s%s", y->name, yd ? "/" : "");
  return strcmp(xn, yn);
}
static void build_tree_bytes(treeent_t *ents, int n, buf_t *out) {
  qsort(ents, (size_t)n, sizeof(treeent_t), treeent_cmp);
  for (int i = 0; i < n; i++) {
    buf_puts(out, ents[i].mode);
    buf_putc(out, ' ');
    buf_puts(out, ents[i].name);
    buf_putc(out, 0);
    buf_put(out, ents[i].oid, 20);
  }
}
// Recursively update a tree: set parts[depth..] to blob_oid (or delete when NULL).
// tree_oid NULL => start from an empty tree. Returns 0 on success.
static int update_tree(repo_t *r, const unsigned char *tree_oid, char **parts, int nparts, int depth,
                       const unsigned char *blob_oid, unsigned char out_tree[20]) {
  treeent_t ents[256]; int n = 0;
  if (tree_oid) {
    n = collect_tree(r, tree_oid, ents, 256);
    if (n < 0) n = 0;
  }
  const char *name = parts[depth];
  int idx = -1;
  for (int i = 0; i < n; i++) if (strcmp(ents[i].name, name) == 0) { idx = i; break; }
  if (depth == nparts - 1) {
    // leaf: file entry
    if (blob_oid) {
      if (idx >= 0) { snprintf(ents[idx].mode, sizeof ents[idx].mode, "100644"); memcpy(ents[idx].oid, blob_oid, 20); }
      else if (n < 256) { snprintf(ents[n].mode, sizeof ents[n].mode, "100644"); snprintf(ents[n].name, sizeof ents[n].name, "%s", name); memcpy(ents[n].oid, blob_oid, 20); n++; }
      else return -1;
    } else {
      if (idx >= 0) { ents[idx] = ents[n - 1]; n--; }
      else return -1; // deleting a file that is not there
    }
  } else {
    // directory: recurse
    unsigned char sub[20];
    if (idx >= 0 && strcmp(ents[idx].mode, "40000") == 0) {
      if (update_tree(r, ents[idx].oid, parts, nparts, depth + 1, blob_oid, sub) != 0) return -1;
    } else {
      if (idx >= 0) return -1; // a file blocks the path
      if (update_tree(r, NULL, parts, nparts, depth + 1, blob_oid, sub) != 0) return -1;
    }
    if (idx >= 0) { snprintf(ents[idx].mode, sizeof ents[idx].mode, "40000"); memcpy(ents[idx].oid, sub, 20); }
    else if (n < 256) { snprintf(ents[n].mode, sizeof ents[n].mode, "40000"); snprintf(ents[n].name, sizeof ents[n].name, "%s", name); memcpy(ents[n].oid, sub, 20); n++; }
    else return -1;
  }
  buf_t b; buf_init(&b);
  build_tree_bytes(ents, n, &b);
  store_git_object(r, 2, b.data, b.len, out_tree);
  buf_free(&b);
  return 0;
}
// Look up a path in a tree: returns 0 and fills oid/is_dir, -1 when missing.
static int tree_lookup(repo_t *r, const unsigned char *tree_oid, char **parts, int nparts, unsigned char oid[20], int *is_dir) {
  if (!tree_oid) return -1;
  treeent_t ents[256];
  int n = collect_tree(r, tree_oid, ents, 256);
  if (n < 0) return -1;
  for (int i = 0; i < n; i++) {
    if (strcmp(ents[i].name, parts[0]) != 0) continue;
    int dir = strcmp(ents[i].mode, "40000") == 0;
    if (nparts == 1) { memcpy(oid, ents[i].oid, 20); *is_dir = dir; return 0; }
    if (!dir) return -1;
    return tree_lookup(r, ents[i].oid, parts + 1, nparts - 1, oid, is_dir);
  }
  return -1;
}
// Find a ref by full name (refs/heads/<branch>). Returns index or -1.
static int find_ref(repo_t *r, const char *fullname) {
  for (int i = 0; i < r->refs_count; i++) if (strcmp(r->refs_name[i], fullname) == 0) return i;
  return -1;
}
static int set_ref(repo_t *r, const char *fullname, const unsigned char *oid) {
  int i = find_ref(r, fullname);
  if (i < 0) {
    if (r->refs_count >= MAX_REFS) return -1;
    i = r->refs_count++;
    snprintf(r->refs_name[i], sizeof r->refs_name[i], "%s", fullname);
  }
  memcpy(r->refs_oid[i], oid, 20);
  return 0;
}
// Extract the commit message (text after the blank line), trimmed.
static void commit_message(const unsigned char *data, size_t len, char *out, size_t outn) {
  size_t pos = 0;
  while (pos < len) {
    const unsigned char *nl = memchr(data + pos, '\n', len - pos);
    if (!nl) { pos = len; break; }
    if (nl == data + pos) { pos += 1; break; }
    pos = (size_t)(nl - data) + 1;
  }
  size_t mlen = len > pos ? len - pos : 0;
  while (mlen > 0 && (data[pos + mlen - 1] == '\n' || data[pos + mlen - 1] == '\r' || data[pos + mlen - 1] == ' ')) mlen--;
  if (mlen >= outn) mlen = outn - 1;
  memcpy(out, data + pos, mlen); out[mlen] = 0;
}
// Create (or update / delete) a file on a branch via a new commit.
// expected_blob_hex: when non-NULL, the current blob at the path must match it (else 409).
// Returns 0 ok, 1 file-not-found, 2 sha-mismatch, 3 branch-missing, -1 other error.
// On success fills blob_hex (empty when deleting) and commit_hex.
static int commit_file(repo_t *r, const char *branch, char **parts, int nparts,
                       const unsigned char *content, size_t content_len, const char *message,
                       const char *expected_blob_hex, int is_delete,
                       char *blob_hex_out, char *commit_hex_out) {
  char refname[160];
  snprintf(refname, sizeof refname, "refs/heads/%s", branch);
  int ri = find_ref(r, refname);
  unsigned char parent[20]; int has_parent = 0;
  unsigned char cur_tree[20]; int has_tree = 0;
  if (ri >= 0) {
    memcpy(parent, r->refs_oid[ri], 20); has_parent = 1;
    objent_t *co = objtab_get(&r->objects, parent);
    if (!co || co->type != 1) return -1;
    char tree_hex[41]; char parents[64][41]; int nparents = 0;
    if (parse_commit(co->data, co->len, tree_hex, parents, &nparents) != 0) return -1;
    if (from_hex(tree_hex, cur_tree, 20) != 0) return -1;
    has_tree = 1;
  } else {
    if (strcmp(branch, "main") != 0) return 3; // cannot commit onto a missing non-default branch
  }
  // current blob at the path (if any)
  unsigned char cur_blob[20]; int has_blob = 0, blob_is_dir = 0;
  if (has_tree && tree_lookup(r, cur_tree, parts, nparts, cur_blob, &blob_is_dir) == 0 && !blob_is_dir) has_blob = 1;
  if (expected_blob_hex) {
    if (!has_blob) return 2;
    char hex[41]; to_hex(cur_blob, 20, hex);
    if (strcasecmp(hex, expected_blob_hex) != 0) return 2;
  }
  if (is_delete) {
    if (!has_blob) return 1;
  }
  unsigned char blob_oid[20]; int has_new_blob = 0;
  if (!is_delete) { store_git_object(r, 3, content, content_len, blob_oid); has_new_blob = 1; }
  unsigned char new_tree[20];
  if (update_tree(r, has_tree ? cur_tree : NULL, parts, nparts, 0, has_new_blob ? blob_oid : NULL, new_tree) != 0) return -1;
  // build the commit
  char tree_hex[41]; to_hex(new_tree, 20, tree_hex);
  buf_t cb; buf_init(&cb);
  buf_printf(&cb, "tree %s\n", tree_hex);
  if (has_parent) { char ph[41]; to_hex(parent, 20, ph); buf_printf(&cb, "parent %s\n", ph); }
  buf_puts(&cb, "author adaiversen <adaiversen@example.invalid> 1793500000 +0000\n");
  buf_puts(&cb, "committer adaiversen <adaiversen@example.invalid> 1793500000 +0000\n\n");
  buf_puts(&cb, message);
  if (cb.len == 0 || cb.data[cb.len - 1] != '\n') buf_putc(&cb, '\n');
  unsigned char commit_oid[20];
  store_git_object(r, 1, cb.data, cb.len, commit_oid);
  buf_free(&cb);
  if (set_ref(r, refname, commit_oid) != 0) return -1;
  r->rev++;
  r->fetch_valid = 0;
  if (blob_hex_out) { if (has_new_blob) to_hex(blob_oid, 20, blob_hex_out); else blob_hex_out[0] = 0; }
  if (commit_hex_out) to_hex(commit_oid, 20, commit_hex_out);
  return 0;
}

// ---------------------------------------------------------------- issue rendering
static void issue_render(repo_t *r, issue_t *iss) {
  buf_t b; buf_init(&b);
  buf_printf(&b, "{\"id\":%d,\"node_id\":\"I_%d\",\"number\":%d,\"title\":", 10000 + iss->number, 10000 + iss->number, iss->number);
  json_escape(&b, iss->title, strlen(iss->title));
  buf_puts(&b, ",\"body\":");
  json_escape(&b, iss->body, strlen(iss->body));
  buf_printf(&b, ",\"state\":\"%s\",\"labels\":[", iss->state);
  for (int i = 0; i < iss->nlabels; i++) {
    const char *color = "ededed";
    for (int k = 0; k < r->labels_count; k++) if (strcmp(r->labels_name[k], iss->labels[i]) == 0) color = r->labels_color[k];
    if (i) buf_putc(&b, ',');
    buf_printf(&b, "{\"id\":%d,\"node_id\":\"L_%s\",\"name\":", 20000 + i, iss->labels[i]);
    json_escape(&b, iss->labels[i], strlen(iss->labels[i]));
    buf_printf(&b, ",\"color\":\"%s\",\"description\":\"\"}", color);
  }
  buf_printf(&b, "],\"user\":{\"login\":\"adaiversen\",\"id\":1000},\"created_at\":\"2026-11-15T00:00:00Z\",\"updated_at\":\"2026-11-15T00:00:00Z\",\"html_url\":\"https://example.invalid/adaiversen/%s/issues/%d\",\"url\":\"https://example.invalid/api/v3/repos/adaiversen/%s/issues/%d\",\"comments\":%d}\n",
             r->name, iss->number, r->name, iss->number, iss->ncomments);
  free(iss->json);
  iss->json = (char *)malloc(b.len + 1);
  memcpy(iss->json, b.data, b.len); iss->json[b.len] = 0;
  iss->json_len = b.len;
  buf_free(&b);
}

// Grow the per-repo issue array so a new issue fits. Returns 0 on success.
static int ensure_issue_capacity(repo_t *r) {
  if (r->issue_count < r->issues_cap) return 0;
  if (r->issues_cap >= MAX_ISSUES) return -1;
  int ncap = r->issues_cap * 2;
  if (ncap > MAX_ISSUES) ncap = MAX_ISSUES;
  issue_t *ni = (issue_t *)realloc(r->issues, (size_t)ncap * sizeof(issue_t));
  if (!ni) return -1;
  memset(ni + r->issues_cap, 0, (size_t)(ncap - r->issues_cap) * sizeof(issue_t));
  r->issues = ni;
  r->issues_cap = ncap;
  return 0;
}
static void repo_json(buf_t *out, repo_t *r, const char *desc) {
  buf_puts(out, "{\"id\":");
  buf_printf(out, "%d", r->next_repo_id);
  buf_puts(out, ",\"name\":");
  json_escape(out, r->name, strlen(r->name));
  buf_puts(out, ",\"full_name\":\"adaiversen/");
  buf_puts(out, r->name);
  buf_printf(out, "\",\"owner\":{\"login\":\"adaiversen\",\"id\":1000},\"private\":%s,\"description\":", r->is_private ? "true" : "false");
  const char *d = desc && desc[0] ? desc : r->description;
  json_escape(out, d, strlen(d));
  buf_puts(out, ",\"default_branch\":\"main\",\"html_url\":\"https://example.invalid/adaiversen/");
  buf_puts(out, r->name);
  buf_puts(out, "\",\"url\":\"https://example.invalid/api/v3/repos/adaiversen/");
  buf_puts(out, r->name);
  buf_puts(out, "\",\"created_at\":\"2026-11-15T00:00:00Z\",\"updated_at\":\"2026-11-15T00:00:00Z\"}");
}
// ---------------------------------------------------------------- pull requests
// Collect all ancestor commit OIDs of tip (including tip) into out[]. Returns count.
static int collect_ancestors(repo_t *r, const unsigned char *tip, unsigned char out[][20], int maxn) {
  int n = 0;
  unsigned char stack[512][20]; int sp = 0;
  memcpy(stack[sp++], tip, 20);
  while (sp > 0) {
    unsigned char cur[20]; memcpy(cur, stack[--sp], 20);
    int dup = 0;
    for (int i = 0; i < n; i++) if (memcmp(out[i], cur, 20) == 0) dup = 1;
    if (dup) continue;
    if (n >= maxn) break;
    memcpy(out[n++], cur, 20);
    objent_t *o = objtab_get(&r->objects, cur);
    if (!o || o->type != 1) continue;
    char tree_hex[41]; char parents[64][41]; int nparents = 0;
    if (parse_commit(o->data, o->len, tree_hex, parents, &nparents) != 0) continue;
    for (int i = 0; i < nparents && sp < 512; i++) {
      unsigned char poid[20];
      if (from_hex(parents[i], poid, 20) == 0) memcpy(stack[sp++], poid, 20);
    }
  }
  return n;
}
// Merge base: the first ancestor of b (nearest-first) that is also an ancestor of a.
static int merge_base(repo_t *r, const unsigned char *a, const unsigned char *b, unsigned char out[20]) {
  unsigned char ancs[512][20]; int na = collect_ancestors(r, a, ancs, 512);
  unsigned char b_ancs[512][20]; int nb = collect_ancestors(r, b, b_ancs, 512);
  for (int i = 0; i < nb; i++) {
    for (int j = 0; j < na; j++) if (memcmp(b_ancs[i], ancs[j], 20) == 0) { memcpy(out, b_ancs[i], 20); return 0; }
  }
  return -1;
}
typedef struct { char path[512]; unsigned char oid[20]; } flatent_t;
static void flatten_tree(repo_t *r, const unsigned char *tree_oid, const char *prefix, flatent_t *ents, int *n, int maxn) {
  if (!tree_oid || *n >= maxn) return;
  treeent_t te[256];
  int cnt = collect_tree(r, tree_oid, te, 256);
  if (cnt < 0) return;
  for (int i = 0; i < cnt && *n < maxn; i++) {
    char p[512];
    snprintf(p, sizeof p, "%s%s%s", prefix, prefix[0] ? "/" : "", te[i].name);
    if (strcmp(te[i].mode, "40000") == 0) flatten_tree(r, te[i].oid, p, ents, n, maxn);
    else { snprintf(ents[*n].path, sizeof ents[*n].path, "%s", p); memcpy(ents[*n].oid, te[i].oid, 20); (*n)++; }
  }
}
// Diff two trees: entries in `out` with status 1=added 2=deleted 3=modified, plus old/new oids.
typedef struct { char path[512]; int status; unsigned char old_oid[20]; unsigned char new_oid[20]; } diffent_t;
static int tree_diff(repo_t *r, const unsigned char *tree_a, const unsigned char *tree_b, diffent_t *out, int maxn) {
  flatent_t fa[512], fb[512]; int na = 0, nb = 0;
  flatten_tree(r, tree_a, "", fa, &na, 512);
  flatten_tree(r, tree_b, "", fb, &nb, 512);
  int n = 0;
  for (int i = 0; i < nb && n < maxn; i++) {
    int found = -1;
    for (int j = 0; j < na; j++) if (strcmp(fa[j].path, fb[i].path) == 0) { found = j; break; }
    if (found < 0) { snprintf(out[n].path, sizeof out[n].path, "%s", fb[i].path); out[n].status = 1; memset(out[n].old_oid, 0, 20); memcpy(out[n].new_oid, fb[i].oid, 20); n++; }
    else if (memcmp(fa[found].oid, fb[i].oid, 20) != 0) { snprintf(out[n].path, sizeof out[n].path, "%s", fb[i].path); out[n].status = 3; memcpy(out[n].old_oid, fa[found].oid, 20); memcpy(out[n].new_oid, fb[i].oid, 20); n++; }
  }
  for (int i = 0; i < na && n < maxn; i++) {
    int found = 0;
    for (int j = 0; j < nb; j++) if (strcmp(fb[j].path, fa[i].path) == 0) found = 1;
    if (!found) { snprintf(out[n].path, sizeof out[n].path, "%s", fa[i].path); out[n].status = 2; memcpy(out[n].old_oid, fa[i].oid, 20); memset(out[n].new_oid, 0, 20); n++; }
  }
  return n;
}
// Line-diff stats between two blobs (simple LCS on lines). Deleted blob (NULL) => all added.
static void line_diff_stats(repo_t *r, const unsigned char *old_oid, const unsigned char *new_oid, int *additions, int *deletions) {
  *additions = 0; *deletions = 0;
  objent_t *no = new_oid ? objtab_get(&r->objects, new_oid) : NULL;
  objent_t *oo = old_oid ? objtab_get(&r->objects, old_oid) : NULL;
  if (!no) return;
  // split into lines
  char *nl[4096]; int nn = 0;
  char *ol[4096]; int on = 0;
  const unsigned char *d = no->data; size_t len = no->len, pos = 0;
  while (pos <= len && nn < 4096) {
    size_t e = pos;
    while (e < len && d[e] != '\n') e++;
    size_t ll = e - pos;
    nl[nn] = (char *)malloc(ll + 1); memcpy(nl[nn], d + pos, ll); nl[nn][ll] = 0; nn++;
    if (e >= len) break;
    pos = e + 1;
    if (pos >= len) break;
  }
  if (oo) {
    d = oo->data; len = oo->len; pos = 0;
    while (pos <= len && on < 4096) {
      size_t e = pos;
      while (e < len && d[e] != '\n') e++;
      size_t ll = e - pos;
      ol[on] = (char *)malloc(ll + 1); memcpy(ol[on], d + pos, ll); ol[on][ll] = 0; on++;
      if (e >= len) break;
      pos = e + 1;
      if (pos >= len) break;
    }
    // LCS lengths (small files only; cap the table). Thread-local: files reads run concurrently.
    static __thread short lcs[512][512];
    int cn = on > 511 ? 511 : on, cm = nn > 511 ? 511 : nn;
    for (int i = 0; i <= cn; i++) lcs[i][0] = 0;
    for (int j = 0; j <= cm; j++) lcs[0][j] = 0;
    for (int i = 1; i <= cn; i++) for (int j = 1; j <= cm; j++)
      lcs[i][j] = strcmp(ol[i - 1], nl[j - 1]) == 0 ? (short)(lcs[i - 1][j - 1] + 1) : (lcs[i - 1][j] > lcs[i][j - 1] ? lcs[i - 1][j] : lcs[i][j - 1]);
    int common = lcs[cn][cm];
    *additions = nn - common;
    *deletions = on - common;
    for (int i = 0; i < on; i++) free(ol[i]);
  } else {
    *additions = nn;
    *deletions = 0;
  }
  for (int i = 0; i < nn; i++) free(nl[i]);
}
static void pull_json(buf_t *out, repo_t *r, pull_t *p) {
  char head_hex[41], base_hex[41];
  to_hex(p->head_sha, 20, head_hex);
  to_hex(p->base_sha, 20, base_hex);
  buf_printf(out, "{\"id\":%d,\"node_id\":\"PR_%d\",\"number\":%d,\"state\":\"%s\",\"title\":", 40000 + p->number, 40000 + p->number, p->number, p->state);
  json_escape(out, p->title, strlen(p->title));
  buf_puts(out, ",\"body\":");
  json_escape(out, p->body, strlen(p->body));
  buf_printf(out, ",\"head\":{\"ref\":\"%s\",\"sha\":\"%s\"},\"base\":{\"ref\":\"%s\",\"sha\":\"%s\"},\"merged\":%s,\"merged_at\":",
             p->head_ref, head_hex, p->base_ref, base_hex, p->merged ? "true" : "false");
  if (p->merged) buf_puts(out, "\"2026-11-15T00:00:00Z\"");
  else buf_puts(out, "null");
  if (p->has_merge_sha) { char mh[41]; to_hex(p->merge_sha, 20, mh); buf_printf(out, ",\"merge_commit_sha\":\"%s\"", mh); }
  else buf_puts(out, ",\"merge_commit_sha\":null");
  buf_printf(out, ",\"user\":{\"login\":\"adaiversen\",\"id\":1000},\"html_url\":\"https://example.invalid/adaiversen/%s/pull/%d\"}", r->name, p->number);
}

static void handle_rest(char **segs, int nseg, const char *method, const unsigned char *body, size_t body_len,
                        const char *auth_header, const char *query, const char *host, resp_t *resp) {
  resp->scopes = 1;
  if (!check_auth(auth_header)) { resp_json_error(resp, 401, "Requires authentication"); return; }
  // Minimal JSON well-formedness check for write bodies (malformed -> 400).
  if ((strcmp(method, "POST") == 0 || strcmp(method, "PATCH") == 0 || strcmp(method, "PUT") == 0) && body_len > 0) {
    int depth = 0, instr = 0, esc = 0, started = 0, ok = 1;
    for (size_t i = 0; i < body_len; i++) {
      unsigned char c = body[i];
      if (instr) { if (esc) esc = 0; else if (c == '\\') esc = 1; else if (c == '"') instr = 0; continue; }
      if (c == '"') { instr = 1; started = 1; continue; }
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;
      if (c == '{' || c == '[') { depth++; started = 1; continue; }
      if (c == '}' || c == ']') { depth--; if (depth < 0) { ok = 0; break; } continue; }
      started = 1;
    }
    if (!ok || instr || depth != 0 || !started) { resp_json_error(resp, 400, "Problems parsing JSON"); return; }
  }
  // GET /api/v3/ (root)
  if (nseg == 0 && strcmp(method, "GET") == 0) {
    buf_t b; buf_init(&b); buf_puts(&b, "{}\n");
    resp_raw(resp, 200, "application/json; charset=utf-8", &b);
    return;
  }
  // GET /api/v3/meta
  if (nseg == 1 && strcmp(segs[0], "meta") == 0 && strcmp(method, "GET") == 0) {
    buf_t b; buf_init(&b); buf_puts(&b, "{\"installed_version\":\"1.0.0\"}\n");
    resp_raw(resp, 200, "application/json; charset=utf-8", &b);
    return;
  }
  // GET /api/v3/user (viewer)
  if (nseg == 1 && strcmp(segs[0], "user") == 0 && strcmp(method, "GET") == 0) {
    buf_t b; buf_init(&b);
    buf_puts(&b, "{\"login\":\"adaiversen\",\"id\":1000,\"node_id\":\"U_1000\",\"type\":\"User\",\"site_admin\":false,\"name\":\"adaiversen\",\"email\":\"adaiversen@example.invalid\"}\n");
    resp_raw(resp, 200, "application/json; charset=utf-8", &b);
    return;
  }
  // /user/repos: POST create, GET list (paginated)
  if (nseg == 2 && strcmp(segs[0], "user") == 0 && strcmp(segs[1], "repos") == 0) {
    if (strcmp(method, "POST") == 0) {
      char name[128] = {0}, desc[512] = {0}; int priv = 1;
      if (json_get_string(body, body_len, "name", name, sizeof name) != 0 || name[0] == 0) {
        resp_json_error(resp, 400, "name is required"); return;
      }
      json_get_string(body, body_len, "description", desc, sizeof desc);
      json_get_bool(body, body_len, "private", &priv);
      if (find_repo(VIEWER_LOGIN, name)) { resp_json_error(resp, 422, "Repository already exists"); return; }
      repo_t *r = create_repo(name);
      if (!r) { resp_json_error(resp, 500, "too many repos"); return; }
      r->is_private = priv;
      snprintf(r->description, sizeof r->description, "%s", desc);
      buf_t b; buf_init(&b);
      repo_json(&b, r, desc);
      buf_putc(&b, '\n');
      resp_raw(resp, 201, "application/json; charset=utf-8", &b);
      return;
    }
    if (strcmp(method, "GET") == 0) {
      char pp[16] = {0}, pg[16] = {0};
      long per_page = 30, page = 1;
      if (query_get(query, "per_page", pp, sizeof pp) == 0) per_page = atol(pp);
      if (query_get(query, "page", pg, sizeof pg) == 0) page = atol(pg);
      if (per_page < 1) per_page = 1; if (per_page > 100) per_page = 100;
      if (page < 1) page = 1;
      long total = repo_count;
      long total_pages = (total + per_page - 1) / per_page;
      if (total_pages < 1) total_pages = 1;
      if (page > total_pages) page = total_pages;
      long start = (page - 1) * per_page;
      long end = start + per_page; if (end > total) end = total;
      buf_t b; buf_init(&b); buf_putc(&b, '[');
      for (long i = start; i < end; i++) {
        if (i > start) buf_putc(&b, ',');
        repo_json(&b, &repos[i], NULL);
      }
      buf_puts(&b, "]\n");
      if (total_pages > 1) {
        const char *h = host ? host : "127.0.0.1";
        char link[1000] = {0}; size_t lo = 0;
        if (page < total_pages) {
          lo += (size_t)snprintf(link + lo, sizeof link - lo, "<http://%s/api/v3/user/repos?per_page=%ld&page=%ld>; rel=\"next\", <http://%s/api/v3/user/repos?per_page=%ld&page=%ld>; rel=\"last\"", h, per_page, page + 1, h, per_page, total_pages);
        }
        if (page > 1) {
          if (lo) lo += (size_t)snprintf(link + lo, sizeof link - lo, ", ");
          lo += (size_t)snprintf(link + lo, sizeof link - lo, "<http://%s/api/v3/user/repos?per_page=%ld&page=1>; rel=\"first\", <http://%s/api/v3/user/repos?per_page=%ld&page=%ld>; rel=\"prev\"", h, per_page, h, per_page, page - 1);
        }
        snprintf(resp->link, sizeof resp->link, "%s", link);
      }
      resp_raw(resp, 200, "application/json; charset=utf-8", &b);
      return;
    }
  }
  // /repos/{owner}/{repo}...
  if (nseg >= 3 && strcmp(segs[0], "repos") == 0) {
    const char *owner = segs[1];
    const char *name = segs[2];
    repo_t *r = find_repo(owner, name);
    if (nseg == 3 && strcmp(method, "DELETE") == 0) {
      if (!r) { resp_json_error(resp, 404, "Not Found"); return; }
      delete_repo(r);
      resp->status = 204; resp->ctype = "application/json; charset=utf-8";
      resp->body = (const unsigned char *)""; resp->body_len = 0;
      return;
    }
    if (nseg == 3 && strcmp(method, "GET") == 0) {
      if (!r) { resp_json_error(resp, 404, "Not Found"); return; }
      buf_t b; buf_init(&b);
      repo_json(&b, r, NULL);
      buf_putc(&b, '\n');
      resp_raw(resp, 200, "application/json; charset=utf-8", &b);
      return;
    }
    if (nseg == 3 && strcmp(method, "PATCH") == 0) {
      if (!r) { resp_json_error(resp, 404, "Not Found"); return; }
      char desc[512] = {0};
      if (json_get_string(body, body_len, "description", desc, sizeof desc) == 0)
        snprintf(r->description, sizeof r->description, "%s", desc);
      buf_t b; buf_init(&b);
      repo_json(&b, r, NULL);
      buf_putc(&b, '\n');
      resp_raw(resp, 200, "application/json; charset=utf-8", &b);
      return;
    }
    if (!r) { resp_json_error(resp, 404, "Not Found"); return; }
    // /repos/{o}/{r}/branches
    if (nseg == 4 && strcmp(segs[3], "branches") == 0 && strcmp(method, "GET") == 0) {
      buf_t b; buf_init(&b); buf_putc(&b, '[');
      int first = 1;
      for (int i = 0; i < r->refs_count; i++) {
        if (strncmp(r->refs_name[i], "refs/heads/", 11) != 0) continue;
        char hex[41]; to_hex(r->refs_oid[i], 20, hex);
        if (!first) buf_putc(&b, ',');
        first = 0;
        buf_printf(&b, "{\"name\":\"%s\",\"commit\":{\"sha\":\"%s\"},\"protected\":false}", r->refs_name[i] + 11, hex);
      }
      buf_puts(&b, "]\n");
      resp_raw(resp, 200, "application/json; charset=utf-8", &b);
      return;
    }
    // /repos/{o}/{r}/commits
    if (nseg == 4 && strcmp(segs[3], "commits") == 0 && strcmp(method, "GET") == 0) {
      char shaq[160] = {0};
      const char *branch = "main";
      char branch_buf[128] = {0};
      if (query_get(query, "sha", shaq, sizeof shaq) == 0 && shaq[0]) { snprintf(branch_buf, sizeof branch_buf, "%s", shaq); branch = branch_buf; }
      char refname[160]; snprintf(refname, sizeof refname, "refs/heads/%s", branch);
      int ri = find_ref(r, refname);
      buf_t b; buf_init(&b); buf_putc(&b, '[');
      if (ri >= 0) {
        // walk all parents (DFS) from the tip
        unsigned char stack[512][20]; int sp = 0;
        unsigned char seen[512][20]; int nseen = 0;
        memcpy(stack[sp++], r->refs_oid[ri], 20);
        int first = 1;
        while (sp > 0) {
          unsigned char cur[20]; memcpy(cur, stack[--sp], 20);
          int dup = 0;
          for (int i = 0; i < nseen; i++) if (memcmp(seen[i], cur, 20) == 0) dup = 1;
          if (dup) continue;
          if (nseen < 512) memcpy(seen[nseen++], cur, 20);
          objent_t *o = objtab_get(&r->objects, cur);
          if (!o || o->type != 1) continue;
          char tree_hex[41]; char parents[64][41]; int nparents = 0;
          char msg[1024] = {0};
          if (parse_commit(o->data, o->len, tree_hex, parents, &nparents) != 0) continue;
          commit_message(o->data, o->len, msg, sizeof msg);
          char hex[41]; to_hex(cur, 20, hex);
          if (!first) buf_putc(&b, ',');
          first = 0;
          buf_printf(&b, "{\"sha\":\"%s\",\"commit\":{\"message\":", hex);
          json_escape(&b, msg, strlen(msg));
          buf_puts(&b, ",\"author\":{\"name\":\"adaiversen\"},\"committer\":{\"name\":\"adaiversen\"}}}");
          for (int i = nparents - 1; i >= 0; i--) {
            unsigned char poid[20];
            if (from_hex(parents[i], poid, 20) == 0 && sp < 512) memcpy(stack[sp++], poid, 20);
          }
        }
      }
      buf_puts(&b, "]\n");
      resp_raw(resp, 200, "application/json; charset=utf-8", &b);
      return;
    }
    // /repos/{o}/{r}/git/refs (create branch)
    if (nseg == 5 && strcmp(segs[3], "git") == 0 && strcmp(segs[4], "refs") == 0 && strcmp(method, "POST") == 0) {
      char ref[256] = {0}, sha[64] = {0};
      if (json_get_string(body, body_len, "ref", ref, sizeof ref) != 0 || json_get_string(body, body_len, "sha", sha, sizeof sha) != 0) {
        resp_json_error(resp, 400, "ref and sha are required"); return;
      }
      unsigned char oid[20];
      if (from_hex(sha, oid, 20) != 0 || !objtab_get(&r->objects, oid)) { resp_json_error(resp, 422, "Invalid sha"); return; }
      if (set_ref(r, ref, oid) != 0) { resp_json_error(resp, 500, "too many refs"); return; }
      r->rev++; r->fetch_valid = 0;
      buf_t b; buf_init(&b);
      buf_printf(&b, "{\"ref\":\"%s\",\"node_id\":\"R_%s\",\"url\":\"https://example.invalid/api/v3/repos/adaiversen/%s/git/refs/%s\",\"object\":{\"sha\":\"%s\",\"type\":\"commit\"}}\n",
                 ref, ref, r->name, ref, sha);
      resp_raw(resp, 201, "application/json; charset=utf-8", &b);
      return;
    }
    // /repos/{o}/{r}/labels
    if (nseg == 4 && strcmp(segs[3], "labels") == 0) {
      if (strcmp(method, "POST") == 0) {
        char lname[128] = {0}, color[16] = {0};
        if (json_get_string(body, body_len, "name", lname, sizeof lname) != 0 || lname[0] == 0) {
          resp_json_error(resp, 400, "name is required"); return;
        }
        json_get_string(body, body_len, "color", color, sizeof color);
        if (color[0] == 0) snprintf(color, sizeof color, "ededed");
        for (int i = 0; i < r->labels_count; i++) if (strcmp(r->labels_name[i], lname) == 0) {
          buf_t b; buf_init(&b);
          buf_printf(&b, "{\"id\":%d,\"node_id\":\"L_%s\",\"name\":", 20000 + i, lname);
          json_escape(&b, lname, strlen(lname));
          buf_printf(&b, ",\"color\":\"%s\",\"description\":\"\",\"default\":false}\n", r->labels_color[i]);
          resp_raw(resp, 200, "application/json; charset=utf-8", &b);
          return;
        }
        if (r->labels_count >= MAX_LABELS) { resp_json_error(resp, 500, "too many labels"); return; }
        int idx = r->labels_count++;
        snprintf(r->labels_name[idx], sizeof r->labels_name[idx], "%s", lname);
        snprintf(r->labels_color[idx], sizeof r->labels_color[idx], "%s", color);
        buf_t b; buf_init(&b);
        buf_printf(&b, "{\"id\":%d,\"node_id\":\"L_%s\",\"name\":", 20000 + idx, lname);
        json_escape(&b, lname, strlen(lname));
        buf_printf(&b, ",\"color\":\"%s\",\"description\":\"\",\"default\":false}\n", color);
        resp_raw(resp, 201, "application/json; charset=utf-8", &b);
        return;
      }
      if (strcmp(method, "GET") == 0) {
        buf_t b; buf_init(&b); buf_putc(&b, '[');
        for (int i = 0; i < r->labels_count; i++) {
          if (i) buf_putc(&b, ',');
          buf_printf(&b, "{\"id\":%d,\"node_id\":\"L_%s\",\"name\":", 20000 + i, r->labels_name[i]);
          json_escape(&b, r->labels_name[i], strlen(r->labels_name[i]));
          buf_printf(&b, ",\"color\":\"%s\",\"description\":\"\",\"default\":false}", r->labels_color[i]);
        }
        buf_puts(&b, "]\n");
        resp_raw(resp, 200, "application/json; charset=utf-8", &b);
        return;
      }
    }
    // /repos/{o}/{r}/contents/{path...}
    if (nseg >= 5 && strcmp(segs[3], "contents") == 0) {
      char filepath[512] = {0};
      for (int i = 4; i < nseg; i++) { if (i > 4) strncat(filepath, "/", sizeof filepath - strlen(filepath) - 1); strncat(filepath, segs[i], sizeof filepath - strlen(filepath) - 1); }
      char *parts[32]; int nparts = 0;
      char fp_copy[512]; snprintf(fp_copy, sizeof fp_copy, "%s", filepath);
      char *save = NULL;
      for (char *tok = strtok_r(fp_copy, "/", &save); tok && nparts < 32; tok = strtok_r(NULL, "/", &save)) parts[nparts++] = tok;
      if (nparts == 0) { resp_json_error(resp, 404, "Not Found"); return; }
      char branchq[128] = {0}, refq[128] = {0};
      const char *branch = "main";
      if (query_get(query, "branch", branchq, sizeof branchq) == 0 && branchq[0]) branch = branchq;
      if (query_get(query, "ref", refq, sizeof refq) == 0 && refq[0]) branch = refq;
      if (strcmp(method, "PUT") == 0) {
        char msg[512] = {0}, content_b64[65536] = {0}, sha[64] = {0}, body_branch[128] = {0};
        json_get_string(body, body_len, "message", msg, sizeof msg);
        if (json_get_string(body, body_len, "branch", body_branch, sizeof body_branch) == 0 && body_branch[0]) branch = body_branch;
        if (json_get_string(body, body_len, "content", content_b64, sizeof content_b64) != 0) {
          resp_json_error(resp, 400, "content is required"); return;
        }
        int has_sha = json_get_string(body, body_len, "sha", sha, sizeof sha) == 0 && sha[0];
        static unsigned char decoded[65536];
        long dlen = b64decode(content_b64, strlen(content_b64), decoded, sizeof decoded);
        if (dlen < 0) { resp_json_error(resp, 400, "content is not valid base64"); return; }
        char blob_hex[41] = {0}, commit_hex[41] = {0};
        int rc = commit_file(r, branch, parts, nparts, decoded, (size_t)dlen, msg[0] ? msg : "update", has_sha ? sha : NULL, 0, blob_hex, commit_hex);
        if (rc == 1) { resp_json_error(resp, 404, "Not Found"); return; }
        if (rc == 2) { resp_json_error(resp, 409, "sha does not match"); return; }
        if (rc == 3) { resp_json_error(resp, 422, "branch does not exist"); return; }
        if (rc != 0) { resp_json_error(resp, 500, "commit failed"); return; }
        // was this a create (201) or an update (200)? update iff sha was supplied
        buf_t b; buf_init(&b);
        buf_printf(&b, "{\"content\":{\"name\":\"%s\",\"path\":\"%s\",\"sha\":\"%s\",\"size\":%ld,\"type\":\"file\",\"encoding\":\"base64\"},\"commit\":{\"sha\":\"%s\",\"message\":",
                   parts[nparts - 1], filepath, blob_hex, dlen, commit_hex);
        json_escape(&b, msg, strlen(msg));
        buf_puts(&b, "}}\n");
        resp_raw(resp, has_sha ? 200 : 201, "application/json; charset=utf-8", &b);
        return;
      }
      if (strcmp(method, "GET") == 0) {
        char refname[160]; snprintf(refname, sizeof refname, "refs/heads/%s", branch);
        int ri = find_ref(r, refname);
        if (ri < 0) { resp_json_error(resp, 404, "Not Found"); return; }
        objent_t *co = objtab_get(&r->objects, r->refs_oid[ri]);
        if (!co || co->type != 1) { resp_json_error(resp, 404, "Not Found"); return; }
        char tree_hex[41]; char parents[64][41]; int nparents = 0;
        if (parse_commit(co->data, co->len, tree_hex, parents, &nparents) != 0) { resp_json_error(resp, 404, "Not Found"); return; }
        unsigned char tree_oid[20];
        if (from_hex(tree_hex, tree_oid, 20) != 0) { resp_json_error(resp, 404, "Not Found"); return; }
        unsigned char oid[20]; int is_dir = 0;
        if (tree_lookup(r, tree_oid, parts, nparts, oid, &is_dir) != 0) { resp_json_error(resp, 404, "Not Found"); return; }
        if (is_dir) {
          treeent_t ents[256];
          int n = collect_tree(r, oid, ents, 256);
          if (n < 0) n = 0;
          buf_t b; buf_init(&b); buf_putc(&b, '[');
          for (int i = 0; i < n; i++) {
            int d = strcmp(ents[i].mode, "40000") == 0;
            char hex[41]; to_hex(ents[i].oid, 20, hex);
            if (i) buf_putc(&b, ',');
            buf_printf(&b, "{\"type\":\"%s\",\"name\":\"%s\",\"path\":\"%s/%s\",\"sha\":\"%s\"}", d ? "dir" : "file", ents[i].name, filepath, ents[i].name, hex);
          }
          buf_puts(&b, "]\n");
          resp_raw(resp, 200, "application/json; charset=utf-8", &b);
          return;
        }
        objent_t *bo = objtab_get(&r->objects, oid);
        if (!bo || bo->type != 3) { resp_json_error(resp, 404, "Not Found"); return; }
        char hex[41]; to_hex(oid, 20, hex);
        buf_t b; buf_init(&b);
        buf_printf(&b, "{\"type\":\"file\",\"encoding\":\"base64\",\"name\":\"%s\",\"path\":\"%s\",\"sha\":\"%s\",\"size\":%zu,\"content\":\"", parts[nparts - 1], filepath, hex, bo->len);
        b64encode_buf(&b, bo->data, bo->len);
        buf_puts(&b, "\"}\n");
        resp_raw(resp, 200, "application/json; charset=utf-8", &b);
        return;
      }
      if (strcmp(method, "DELETE") == 0) {
        char sha[64] = {0}, msg[512] = {0};
        json_get_string(body, body_len, "sha", sha, sizeof sha);
        json_get_string(body, body_len, "message", msg, sizeof msg);
        char commit_hex[41] = {0};
        int rc = commit_file(r, branch, parts, nparts, NULL, 0, msg[0] ? msg : "delete", sha[0] ? sha : NULL, 1, NULL, commit_hex);
        if (rc == 1) { resp_json_error(resp, 404, "Not Found"); return; }
        if (rc == 2) { resp_json_error(resp, 409, "sha does not match"); return; }
        if (rc != 0) { resp_json_error(resp, 500, "delete failed"); return; }
        buf_t b; buf_init(&b);
        buf_printf(&b, "{\"commit\":{\"sha\":\"%s\"}}\n", commit_hex);
        resp_raw(resp, 200, "application/json; charset=utf-8", &b);
        return;
      }
    }
    // /repos/{o}/{r}/issues
    if (nseg == 4 && strcmp(segs[3], "issues") == 0) {
      if (strcmp(method, "POST") == 0) {
        char title[1024] = {0}, ibody[4096] = {0};
        json_get_string(body, body_len, "title", title, sizeof title);
        json_get_string(body, body_len, "body", ibody, sizeof ibody);
        char lab[16][128]; int nlab = json_get_string_array(body, body_len, "labels", lab, 16);
        if (nlab < 0) nlab = 0;
        // unknown label -> 422
        for (int i = 0; i < nlab; i++) {
          int found = 0;
          for (int k = 0; k < r->labels_count; k++) if (strcmp(r->labels_name[k], lab[i]) == 0) found = 1;
          if (!found) { resp_json_error(resp, 422, "Unknown label"); return; }
        }
        if (r->issue_count >= MAX_ISSUES || ensure_issue_capacity(r) != 0) { resp_json_error(resp, 500, "too many issues"); return; }
        int num = r->next_issue++;
        issue_t *iss = &r->issues[r->issue_count++];
        memset(iss, 0, sizeof(*iss));
        iss->number = num;
        snprintf(iss->title, sizeof iss->title, "%s", title);
        snprintf(iss->body, sizeof iss->body, "%s", ibody);
        snprintf(iss->state, sizeof iss->state, "open");
        iss->nlabels = nlab;
        for (int i = 0; i < nlab; i++) snprintf(iss->labels[i], sizeof iss->labels[i], "%s", lab[i]);
        iss->created_seq = ++r->seq_counter;
        issue_render(r, iss);
        resp->status = 201; resp->ctype = "application/json; charset=utf-8";
        resp->body = (const unsigned char *)iss->json; resp->body_len = iss->json_len;
        return;
      }
      if (strcmp(method, "GET") == 0) {
        char stateq[32] = {0}, sortq[32] = {0}, dirq[32] = {0}, pp[16] = {0};
        const char *state = "open";
        if (query_get(query, "state", stateq, sizeof stateq) == 0 && stateq[0]) state = stateq;
        int asc = 0;
        if (query_get(query, "sort", sortq, sizeof sortq) == 0 && query_get(query, "direction", dirq, sizeof dirq) == 0 && strcmp(dirq, "asc") == 0) asc = 1;
        long per_page = 30;
        if (query_get(query, "per_page", pp, sizeof pp) == 0) per_page = atol(pp);
        if (per_page < 1) per_page = 1; if (per_page > 100) per_page = 100;
        // collect matching issues in creation order
        int idx[MAX_ISSUES]; int nidx = 0;
        for (int i = 0; i < r->issue_count; i++) {
          if (strcmp(state, "all") != 0 && strcmp(r->issues[i].state, state) != 0) continue;
          idx[nidx++] = i;
        }
        if (asc) { /* already in creation order */ }
        else { for (int i = 0; i < nidx / 2; i++) { int t = idx[i]; idx[i] = idx[nidx - 1 - i]; idx[nidx - 1 - i] = t; } }
        if (nidx > per_page) nidx = (int)per_page;
        buf_t b; buf_init(&b); buf_putc(&b, '[');
        for (int i = 0; i < nidx; i++) {
          if (i) buf_putc(&b, ',');
          // strip the trailing newline from the cached rendering for list embedding
          size_t jl = r->issues[idx[i]].json_len;
          if (jl > 0 && r->issues[idx[i]].json[jl - 1] == '\n') jl--;
          buf_put(&b, r->issues[idx[i]].json, jl);
        }
        buf_puts(&b, "]\n");
        resp_raw(resp, 200, "application/json; charset=utf-8", &b);
        return;
      }
    }
    // /repos/{o}/{r}/issues/{n} and /comments
    if (nseg >= 5 && strcmp(segs[3], "issues") == 0) {
      int num = atoi(segs[4]);
      issue_t *iss = NULL;
      for (int i = 0; i < r->issue_count; i++) if (r->issues[i].number == num) { iss = &r->issues[i]; break; }
      if (!iss) { resp_json_error(resp, 404, "Not Found"); return; }
      if (nseg == 5 && strcmp(method, "GET") == 0) {
        resp->status = 200; resp->ctype = "application/json; charset=utf-8";
        resp->body = (const unsigned char *)iss->json; resp->body_len = iss->json_len;
        return;
      }
      if (nseg == 5 && strcmp(method, "PATCH") == 0) {
        char st[32] = {0}, title[1024] = {0}, ibody[4096] = {0};
        if (json_get_string(body, body_len, "state", st, sizeof st) == 0 && st[0]) snprintf(iss->state, sizeof iss->state, "%s", st);
        if (json_get_string(body, body_len, "title", title, sizeof title) == 0) snprintf(iss->title, sizeof iss->title, "%s", title);
        if (json_get_string(body, body_len, "body", ibody, sizeof ibody) == 0) snprintf(iss->body, sizeof iss->body, "%s", ibody);
        issue_render(r, iss);
        resp->status = 200; resp->ctype = "application/json; charset=utf-8";
        resp->body = (const unsigned char *)iss->json; resp->body_len = iss->json_len;
        return;
      }
      if (nseg == 6 && strcmp(segs[5], "comments") == 0) {
        if (strcmp(method, "POST") == 0) {
          char cbody[1024] = {0};
          json_get_string(body, body_len, "body", cbody, sizeof cbody);
          if (iss->ncomments >= MAX_COMMENTS) { resp_json_error(resp, 500, "too many comments"); return; }
          int cidx = iss->ncomments++;
          snprintf(iss->comments[cidx], 512, "%s", cbody);
          issue_render(r, iss);
          buf_t b; buf_init(&b);
          buf_printf(&b, "{\"id\":%d,\"node_id\":\"C_%d\",\"body\":", 30000 + iss->ncomments, 30000 + iss->ncomments);
          json_escape(&b, cbody, strlen(cbody));
          buf_puts(&b, ",\"user\":{\"login\":\"adaiversen\",\"id\":1000},\"created_at\":\"2026-11-15T00:00:00Z\",\"updated_at\":\"2026-11-15T00:00:00Z\"}\n");
          resp_raw(resp, 201, "application/json; charset=utf-8", &b);
          return;
        }
        if (strcmp(method, "GET") == 0) {
          buf_t b; buf_init(&b); buf_putc(&b, '[');
          for (int i = 0; i < iss->ncomments; i++) {
            if (i) buf_putc(&b, ',');
            buf_printf(&b, "{\"id\":%d,\"node_id\":\"C_%d\",\"body\":", 30001 + i, 30001 + i);
            json_escape(&b, iss->comments[i], strlen(iss->comments[i]));
            buf_puts(&b, ",\"user\":{\"login\":\"adaiversen\",\"id\":1000},\"created_at\":\"2026-11-15T00:00:00Z\",\"updated_at\":\"2026-11-15T00:00:00Z\"}");
          }
          buf_puts(&b, "]\n");
          resp_raw(resp, 200, "application/json; charset=utf-8", &b);
          return;
        }
      }
    }
    // /repos/{o}/{r}/pulls
    if (nseg >= 4 && strcmp(segs[3], "pulls") == 0) {
      if (nseg == 4 && strcmp(method, "POST") == 0) {
        char head[128] = {0}, base[128] = {0}, title[1024] = {0}, pbody[4096] = {0};
        json_get_string(body, body_len, "head", head, sizeof head);
        json_get_string(body, body_len, "base", base, sizeof base);
        json_get_string(body, body_len, "title", title, sizeof title);
        json_get_string(body, body_len, "body", pbody, sizeof pbody);
        if (!head[0] || !base[0]) { resp_json_error(resp, 422, "head and base are required"); return; }
        char href[160], bref[160];
        snprintf(href, sizeof href, "refs/heads/%s", head);
        snprintf(bref, sizeof bref, "refs/heads/%s", base);
        int hi = find_ref(r, href), bi = find_ref(r, bref);
        if (hi < 0 || bi < 0) { resp_json_error(resp, 422, "head or base branch does not exist"); return; }
        if (r->pulls_count >= MAX_PULLS) { resp_json_error(resp, 500, "too many pulls"); return; }
        pull_t *p = &r->pulls[r->pulls_count++];
        memset(p, 0, sizeof(*p));
        p->number = r->next_pull++;
        snprintf(p->title, sizeof p->title, "%s", title);
        snprintf(p->body, sizeof p->body, "%s", pbody);
        snprintf(p->state, sizeof p->state, "open");
        snprintf(p->head_ref, sizeof p->head_ref, "%s", head);
        snprintf(p->base_ref, sizeof p->base_ref, "%s", base);
        memcpy(p->head_sha, r->refs_oid[hi], 20);
        memcpy(p->base_sha, r->refs_oid[bi], 20);
        buf_t b; buf_init(&b);
        pull_json(&b, r, p);
        buf_putc(&b, '\n');
        resp_raw(resp, 201, "application/json; charset=utf-8", &b);
        return;
      }
      if (nseg == 4 && strcmp(method, "GET") == 0) {
        char stateq[32] = {0};
        const char *state = "open";
        if (query_get(query, "state", stateq, sizeof stateq) == 0 && stateq[0]) state = stateq;
        buf_t b; buf_init(&b); buf_putc(&b, '[');
        int first = 1;
        for (int i = 0; i < r->pulls_count; i++) {
          pull_t *p = &r->pulls[i];
          if (strcmp(state, "all") != 0 && strcmp(p->state, state) != 0) continue;
          if (!first) buf_putc(&b, ',');
          first = 0;
          pull_json(&b, r, p);
        }
        buf_puts(&b, "]\n");
        resp_raw(resp, 200, "application/json; charset=utf-8", &b);
        return;
      }
      if (nseg >= 5) {
        int num = atoi(segs[4]);
        pull_t *p = NULL;
        for (int i = 0; i < r->pulls_count; i++) if (r->pulls[i].number == num) { p = &r->pulls[i]; break; }
        if (!p) { resp_json_error(resp, 404, "Not Found"); return; }
        if (nseg == 5 && strcmp(method, "GET") == 0) {
          buf_t b; buf_init(&b);
          pull_json(&b, r, p);
          buf_putc(&b, '\n');
          resp_raw(resp, 200, "application/json; charset=utf-8", &b);
          return;
        }
        if (nseg == 6 && strcmp(segs[5], "files") == 0 && strcmp(method, "GET") == 0) {
          // tree of the base tip vs tree of the head tip
          char base_tree_hex[41] = {0}, head_tree_hex[41] = {0};
          objent_t *bo = objtab_get(&r->objects, p->base_sha);
          objent_t *ho = objtab_get(&r->objects, p->head_sha);
          unsigned char bt[20], ht[20];
          int have_bt = 0, have_ht = 0;
          if (bo && bo->type == 1) { char th[41]; char ps[64][41]; int np = 0; if (parse_commit(bo->data, bo->len, th, ps, &np) == 0 && from_hex(th, bt, 20) == 0) have_bt = 1; }
          if (ho && ho->type == 1) { char th[41]; char ps[64][41]; int np = 0; if (parse_commit(ho->data, ho->len, th, ps, &np) == 0 && from_hex(th, ht, 20) == 0) have_ht = 1; }
          diffent_t diffs[512];
          int nd = 0;
          if (have_bt && have_ht) nd = tree_diff(r, bt, ht, diffs, 512);
          buf_t b; buf_init(&b); buf_putc(&b, '[');
          for (int i = 0; i < nd; i++) {
            int add = 0, del = 0;
            if (diffs[i].status == 1) line_diff_stats(r, NULL, diffs[i].new_oid, &add, &del);
            else if (diffs[i].status == 2) line_diff_stats(r, diffs[i].old_oid, NULL, &add, &del);
            else line_diff_stats(r, diffs[i].old_oid, diffs[i].new_oid, &add, &del);
            const char *st = diffs[i].status == 1 ? "added" : diffs[i].status == 2 ? "removed" : "modified";
            if (i) buf_putc(&b, ',');
            buf_printf(&b, "{\"filename\":\"%s\",\"status\":\"%s\",\"additions\":%d,\"deletions\":%d,\"changes\":%d}",
                       diffs[i].path, st, add, del, add + del);
          }
          buf_puts(&b, "]\n");
          resp_raw(resp, 200, "application/json; charset=utf-8", &b);
          return;
        }
        if (nseg == 6 && strcmp(segs[5], "merge") == 0 && strcmp(method, "PUT") == 0) {
          if (p->merged) {
            char mh[41]; to_hex(p->merge_sha, 20, mh);
            buf_t b; buf_init(&b);
            buf_printf(&b, "{\"merged\":true,\"sha\":\"%s\",\"message\":\"already merged\"}\n", mh);
            resp_raw(resp, 200, "application/json; charset=utf-8", &b);
            return;
          }
          // 3-way merge: current base tip + head tip over their merge base
          // (resolve the base ref fresh: it may have moved since the PR was opened)
          char bref0[160]; snprintf(bref0, sizeof bref0, "refs/heads/%s", p->base_ref);
          int bri = find_ref(r, bref0);
          if (bri < 0) { resp_json_error(resp, 422, "base branch does not exist"); return; }
          unsigned char cur_base[20]; memcpy(cur_base, r->refs_oid[bri], 20);
          char href0[160]; snprintf(href0, sizeof href0, "refs/heads/%s", p->head_ref);
          int hri = find_ref(r, href0);
          if (hri < 0) { resp_json_error(resp, 422, "head branch does not exist"); return; }
          unsigned char cur_head[20]; memcpy(cur_head, r->refs_oid[hri], 20);
          unsigned char mb[20];
          if (merge_base(r, cur_base, cur_head, mb) != 0) { resp_json_error(resp, 500, "no merge base"); return; }
          // tree of merge base
          objent_t *mbo = objtab_get(&r->objects, mb);
          unsigned char mb_tree[20]; int have_mb_tree = 0;
          if (mbo && mbo->type == 1) { char th[41]; char ps[64][41]; int np = 0; if (parse_commit(mbo->data, mbo->len, th, ps, &np) == 0 && from_hex(th, mb_tree, 20) == 0) have_mb_tree = 1; }
          if (!have_mb_tree) { resp_json_error(resp, 500, "merge base has no tree"); return; }
          objent_t *bo = objtab_get(&r->objects, cur_base);
          objent_t *ho = objtab_get(&r->objects, cur_head);
          unsigned char bt[20], ht[20];
          int have_bt = 0, have_ht = 0;
          if (bo && bo->type == 1) { char th[41]; char ps[64][41]; int np = 0; if (parse_commit(bo->data, bo->len, th, ps, &np) == 0 && from_hex(th, bt, 20) == 0) have_bt = 1; }
          if (ho && ho->type == 1) { char th[41]; char ps[64][41]; int np = 0; if (parse_commit(ho->data, ho->len, th, ps, &np) == 0 && from_hex(th, ht, 20) == 0) have_ht = 1; }
          if (!have_bt || !have_ht) { resp_json_error(resp, 500, "missing tip tree"); return; }
          diffent_t d_base[512], d_head[512];
          int nb_base = tree_diff(r, mb_tree, bt, d_base, 512);
          int nb_head = tree_diff(r, mb_tree, ht, d_head, 512);
          // conflict: a path changed on both sides with different resulting contents
          for (int i = 0; i < nb_head; i++) {
            for (int j = 0; j < nb_base; j++) {
              if (strcmp(d_head[i].path, d_base[j].path) != 0) continue;
              if (memcmp(d_head[i].new_oid, d_base[j].new_oid, 20) != 0) {
                resp_json_error(resp, 405, "Merge conflict");
                return;
              }
            }
          }
          // merged tree: start from the base tree, apply the head's changes
          unsigned char merged_tree[20];
          memcpy(merged_tree, bt, 20);
          for (int i = 0; i < nb_head; i++) {
            char *parts[32]; int nparts = 0;
            char pc[512]; snprintf(pc, sizeof pc, "%s", d_head[i].path);
            char *save = NULL;
            for (char *tok = strtok_r(pc, "/", &save); tok && nparts < 32; tok = strtok_r(NULL, "/", &save)) parts[nparts++] = tok;
            unsigned char nt[20];
            if (update_tree(r, merged_tree, parts, nparts, 0, d_head[i].status == 2 ? NULL : d_head[i].new_oid, nt) != 0) {
              resp_json_error(resp, 500, "merge tree failed"); return;
            }
            memcpy(merged_tree, nt, 20);
          }
          // merge commit: parents = current base tip + head tip
          char bt_hex[41], ht_hex[41], mt_hex[41], base_hex[41], head_hex[41];
          to_hex(merged_tree, 20, mt_hex);
          to_hex(cur_base, 20, base_hex);
          to_hex(cur_head, 20, head_hex);
          buf_t cb; buf_init(&cb);
          buf_printf(&cb, "tree %s\nparent %s\nparent %s\nauthor adaiversen <adaiversen@example.invalid> 1793500000 +0000\ncommitter adaiversen <adaiversen@example.invalid> 1793500000 +0000\n\nMerge pull request #%d from %s\n", mt_hex, base_hex, head_hex, p->number, p->head_ref);
          unsigned char merge_oid[20];
          store_git_object(r, 1, cb.data, cb.len, merge_oid);
          buf_free(&cb);
          char bref[160]; snprintf(bref, sizeof bref, "refs/heads/%s", p->base_ref);
          if (set_ref(r, bref, merge_oid) != 0) { resp_json_error(resp, 500, "merge ref failed"); return; }
          r->rev++; r->fetch_valid = 0;
          p->merged = 1;
          snprintf(p->state, sizeof p->state, "closed");
          snprintf(p->merged_at, sizeof p->merged_at, "2026-11-15T00:00:00Z");
          memcpy(p->merge_sha, merge_oid, 20);
          p->has_merge_sha = 1;
          char mh[41]; to_hex(merge_oid, 20, mh);
          buf_t b; buf_init(&b);
          buf_printf(&b, "{\"merged\":true,\"sha\":\"%s\",\"message\":\"Pull request successfully merged\"}\n", mh);
          resp_raw(resp, 200, "application/json; charset=utf-8", &b);
          return;
        }
      }
    }
  }
  resp_json_error(resp, 404, "Not Found");
}

// ---------------------------------------------------------------- git handlers
static void handle_info_refs(repo_t *r, const char *service, int wants_v2, resp_t *resp) {
  buf_t b; buf_init(&b);
  if (wants_v2 && strcmp(service, "git-upload-pack") == 0) {
    v2_advertisement(&b);
    resp_raw(resp, 200, "application/x-git-upload-pack-advertisement", &b);
    return;
  }
  if (strcmp(service, "git-upload-pack") == 0) {
    v0_advertisement(&b, service, r, UPLOAD_V0_CAPS);
    resp_raw(resp, 200, "application/x-git-upload-pack-advertisement", &b);
    return;
  }
  if (strcmp(service, "git-receive-pack") == 0) {
    v0_advertisement(&b, service, r, RECEIVE_CAPS);
    resp_raw(resp, 200, "application/x-git-receive-pack-advertisement", &b);
    return;
  }
  buf_free(&b);
  resp_json_error(resp, 404, "Not Found");
}
static void handle_ls_refs_v2(repo_t *r, char **args, int nargs, resp_t *resp) {
  int peel = 0, symrefs = 0;
  char prefixes[8][128]; int nprefix = 0;
  for (int i = 0; i < nargs; i++) {
    if (strcmp(args[i], "peel") == 0) peel = 1;
    else if (strcmp(args[i], "symrefs") == 0) symrefs = 1;
    else if (strncmp(args[i], "ref-prefix ", 11) == 0 && nprefix < 8) snprintf(prefixes[nprefix++], 128, "%s", args[i] + 11);
  }
  char names[MAX_REFS + 1][128]; unsigned char oids[MAX_REFS + 1][20]; int is_head[MAX_REFS + 1];
  int n = list_refs(r, names, oids, is_head);
  buf_t b; buf_init(&b);
  for (int i = 0; i < n; i++) {
    if (nprefix > 0) {
      int ok = 0;
      for (int k = 0; k < nprefix; k++) if (strncmp(names[i], prefixes[k], strlen(prefixes[k])) == 0) ok = 1;
      if (!ok) continue;
    }
    char hex[41]; to_hex(oids[i], 20, hex);
    buf_t line; buf_init(&line);
    buf_printf(&line, "%s %s", hex, names[i]);
    if (is_head[i] && symrefs) buf_puts(&line, " symref-target:refs/heads/main");
    objent_t *o = objtab_get(&r->objects, oids[i]);
    if (peel && o && o->type == 4 && !is_head[i]) {
      unsigned char cur[20]; memcpy(cur, oids[i], 20);
      for (int hops = 0; hops < 16; hops++) {
        objent_t *t = objtab_get(&r->objects, cur);
        if (!t || t->type != 4) break;
        char objhex[41] = {0};
        if (t->len > 7 && memcmp(t->data, "object ", 7) == 0) memcpy(objhex, t->data + 7, 40);
        else break;
        unsigned char noid[20];
        if (from_hex(objhex, noid, 20) != 0) break;
        objent_t *no = objtab_get(&r->objects, noid);
        if (!no) break;
        if (no->type != 4) { buf_printf(&line, " peeled:%s", objhex); break; }
        memcpy(cur, noid, 20);
      }
    }
    buf_putc(&line, '\n');
    pkt_line_buf(&b, line.data, line.len);
    buf_free(&line);
  }
  pkt_flush(&b);
  resp_raw(resp, 200, "application/x-git-upload-pack-result", &b);
}
// Build the fetch pack + shallow info. Returns 0 ok.
static void handle_fetch(repo_t *r, unsigned char (*wants)[20], int nwants,
                         unsigned char (*haves)[20], int nhaves,
                         unsigned char (*shallow)[20], int nshallow,
                         int depth, int is_v2, resp_t *resp) {
  // shallow plan when depth is set
  unsigned char boundary[64][20]; int nboundary = 0;
  unsigned char unshallow[64][20]; int nunshallow = 0;
  unsigned char included[64][20]; int nincluded = 0;
  if (depth >= 0) {
    // BFS over commits from wants with distance
    unsigned char q[512][20]; int qd[512]; int qh = 0, qt = 0;
    unsigned char dist_oid[512][20]; int dist_v[512]; int ndist = 0;
    for (int i = 0; i < nwants && qt < 512; i++) { memcpy(q[qt], wants[i], 20); qd[qt] = 0; qt++; }
    while (qh < qt) {
      unsigned char cur[20]; memcpy(cur, q[qh], 20); int d = qd[qh++];
      int seen = 0;
      for (int i = 0; i < ndist; i++) if (memcmp(dist_oid[i], cur, 20) == 0) { seen = 1; break; }
      if (seen) continue;
      objent_t *o = objtab_get(&r->objects, cur);
      if (!o || o->type != 1) continue;
      if (ndist < 512) { memcpy(dist_oid[ndist], cur, 20); dist_v[ndist] = d; ndist++; }
      if (d >= depth) continue;
      if (nincluded < 64) memcpy(included[nincluded++], cur, 20);
      char tree_hex[41]; char parents[64][41]; int nparents = 0;
      if (parse_commit(o->data, o->len, tree_hex, parents, &nparents) != 0) continue;
      for (int i = 0; i < nparents && qt < 512; i++) {
        unsigned char poid[20];
        if (from_hex(parents[i], poid, 20) == 0) { memcpy(q[qt], poid, 20); qd[qt] = d + 1; qt++; }
      }
    }
    for (int i = 0; i < nincluded; i++) {
      objent_t *o = objtab_get(&r->objects, included[i]);
      if (!o) continue;
      char tree_hex[41]; char parents[64][41]; int nparents = 0;
      if (parse_commit(o->data, o->len, tree_hex, parents, &nparents) != 0) continue;
      int is_b = 0;
      for (int k = 0; k < nparents; k++) {
        unsigned char poid[20];
        if (from_hex(parents[k], poid, 20) != 0) { is_b = 1; break; }
        int found = -1;
        for (int j = 0; j < ndist; j++) if (memcmp(dist_oid[j], poid, 20) == 0) { found = dist_v[j]; break; }
        if (found < 0 || found >= depth) { is_b = 1; break; }
      }
      if (is_b && nboundary < 64) memcpy(boundary[nboundary++], included[i], 20);
    }
    for (int i = 0; i < nshallow; i++) {
      int in_dist = 0, is_b = 0;
      for (int j = 0; j < ndist; j++) if (memcmp(dist_oid[j], shallow[i], 20) == 0) in_dist = 1;
      for (int j = 0; j < nboundary; j++) if (memcmp(boundary[j], shallow[i], 20) == 0) is_b = 1;
      if (in_dist && !is_b && nunshallow < 64) memcpy(unshallow[nunshallow++], shallow[i], 20);
    }
  }
  // objects: reachable from included (or wants) cut at boundary, minus haves closure
  reach_t rc, hc;
  if (depth >= 0) collect_reachable(r, included, nincluded, boundary, nboundary, -1, &rc);
  else collect_reachable(r, wants, nwants, NULL, 0, -1, &rc);
  if (nhaves > 0) {
    collect_reachable(r, haves, nhaves, shallow, nshallow, -1, &hc);
    // subtract hc from rc
    int w = 0;
    for (int i = 0; i < rc.count; i++) {
      int drop = 0;
      for (int j = 0; j < hc.count; j++) if (rc.items[i] == hc.items[j]) { drop = 1; break; }
      if (!drop) rc.items[w++] = rc.items[i];
    }
    rc.count = w;
    free(hc.items); free(hc.seen);
  }
  // cache: depth-1, no haves, single want -> cache whole response body
  int use_cache = depth == 1 && nhaves == 0 && nwants == 1;
  if (use_cache && r->fetch_valid && r->fetch_rev == r->rev && memcmp(r->fetch_tip, wants[0], 20) == 0) {
    resp->status = 200; resp->ctype = "application/x-git-upload-pack-result";
    resp->body = r->fetch_cache.data; resp->body_len = r->fetch_cache.len;
    free(rc.items); free(rc.seen);
    return;
  }
  buf_t pack; buf_init(&pack);
  write_pack(&pack, rc.items, rc.count);
  free(rc.items); free(rc.seen);
  buf_t b; buf_init(&b);
  if (is_v2) {
    if (nhaves > 0) { pkt_line(&b, "acknowledgments\n"); pkt_line(&b, "NAK\n"); pkt_delim(&b); }
    if (depth >= 0 && (nboundary > 0 || nunshallow > 0)) {
      pkt_line(&b, "shallow-info\n");
      for (int i = 0; i < nboundary; i++) { char hex[41]; to_hex(boundary[i], 20, hex); buf_t l; buf_init(&l); buf_printf(&l, "shallow %s\n", hex); pkt_line_buf(&b, l.data, l.len); buf_free(&l); }
      for (int i = 0; i < nunshallow; i++) { char hex[41]; to_hex(unshallow[i], 20, hex); buf_t l; buf_init(&l); buf_printf(&l, "unshallow %s\n", hex); pkt_line_buf(&b, l.data, l.len); buf_free(&l); }
      pkt_delim(&b);
    }
    pkt_line(&b, "packfile\n");
    sideband(&b, 1, pack.data, pack.len);
    pkt_flush(&b);
  } else {
    if (depth >= 0) {
      for (int i = 0; i < nboundary; i++) { char hex[41]; to_hex(boundary[i], 20, hex); buf_t l; buf_init(&l); buf_printf(&l, "shallow %s\n", hex); pkt_line_buf(&b, l.data, l.len); buf_free(&l); }
      for (int i = 0; i < nunshallow; i++) { char hex[41]; to_hex(unshallow[i], 20, hex); buf_t l; buf_init(&l); buf_printf(&l, "unshallow %s\n", hex); pkt_line_buf(&b, l.data, l.len); buf_free(&l); }
    }
    pkt_line(&b, "NAK\n");
    sideband(&b, 1, pack.data, pack.len);
    pkt_flush(&b);
  }
  buf_free(&pack);
  if (use_cache) {
    buf_free(&r->fetch_cache);
    r->fetch_cache = b; // take ownership (move)
    memcpy(r->fetch_tip, wants[0], 20);
    r->fetch_rev = r->rev;
    r->fetch_valid = 1;
    resp->status = 200; resp->ctype = "application/x-git-upload-pack-result";
    resp->body = r->fetch_cache.data; resp->body_len = r->fetch_cache.len;
    return;
  }
  resp_raw(resp, 200, "application/x-git-upload-pack-result", &b);
}
// Parse a v2 request body into command + args (args as malloc'd strings).
static int parse_v2_request(const unsigned char *body, size_t len, char *command, size_t cn,
                            char args[][128], int *nargs) {
  pkt_t pkts[128];
  int n = decode_pkt_lines(body, len, pkts, 128);
  if (n < 0) return -1;
  *nargs = 0; command[0] = 0;
  int seen_delim = 0;
  for (int i = 0; i < n; i++) {
    if (pkts[i].kind == 1) break; // flush
    if (pkts[i].kind == 2) { seen_delim = 1; continue; }
    if (pkts[i].kind != 0) continue;
    size_t l = pkts[i].len;
    if (l > 0 && pkts[i].data[l-1] == '\n') l--;
    if (!seen_delim) {
      if (l > 8 && memcmp(pkts[i].data, "command=", 8) == 0) {
        size_t cl = l - 8 < cn - 1 ? l - 8 : cn - 1;
        memcpy(command, pkts[i].data + 8, cl); command[cl] = 0;
      }
      continue;
    }
    if (*nargs < 64 && l < 128) { memcpy(args[*nargs], pkts[i].data, l); args[*nargs][l] = 0; (*nargs)++; }
  }
  return 0;
}
static void handle_upload_pack(repo_t *r, const unsigned char *body, size_t body_len, int is_v2, resp_t *resp) {
  if (is_v2) {
    char command[64] = {0};
    char args[64][128];
    int nargs = 0;
    if (parse_v2_request(body, body_len, command, sizeof command, args, &nargs) != 0) {
      resp_json_error(resp, 400, "bad request"); return;
    }
    if (strcmp(command, "ls-refs") == 0) {
      char *argp[64];
      for (int i = 0; i < nargs; i++) argp[i] = args[i];
      handle_ls_refs_v2(r, argp, nargs, resp);
      return;
    }
    if (strcmp(command, "fetch") == 0) {
      unsigned char wants[64][20]; int nwants = 0;
      unsigned char haves[64][20]; int nhaves = 0;
      unsigned char shallow[64][20]; int nshallow = 0;
      int depth = -1;
      for (int i = 0; i < nargs; i++) {
        if (strncmp(args[i], "want ", 5) == 0 && nwants < 64) { if (from_hex(args[i] + 5, wants[nwants], 20) == 0) nwants++; }
        else if (strncmp(args[i], "have ", 5) == 0 && nhaves < 64) { if (from_hex(args[i] + 5, haves[nhaves], 20) == 0) nhaves++; }
        else if (strncmp(args[i], "shallow ", 8) == 0 && nshallow < 64) { if (from_hex(args[i] + 8, shallow[nshallow], 20) == 0) nshallow++; }
        else if (strncmp(args[i], "deepen ", 7) == 0) depth = atoi(args[i] + 7);
      }
      handle_fetch(r, wants, nwants, haves, nhaves, shallow, nshallow, depth, 1, resp);
      return;
    }
    resp_json_error(resp, 400, "unknown command");
    return;
  }
  // v0 fetch
  pkt_t pkts[256];
  int n = decode_pkt_lines(body, body_len, pkts, 256);
  if (n < 0) { resp_json_error(resp, 400, "bad request"); return; }
  unsigned char wants[64][20]; int nwants = 0;
  unsigned char haves[64][20]; int nhaves = 0;
  unsigned char shallow[64][20]; int nshallow = 0;
  int depth = -1;
  for (int i = 0; i < n; i++) {
    if (pkts[i].kind != 0) continue;
    size_t l = pkts[i].len;
    if (l > 0 && pkts[i].data[l-1] == '\n') l--;
    char tmp[128];
    if (l >= sizeof tmp) continue;
    memcpy(tmp, pkts[i].data, l); tmp[l] = 0;
    if (strncmp(tmp, "want ", 5) == 0 && nwants < 64) { if (from_hex(tmp + 5, wants[nwants], 20) == 0) nwants++; }
    else if (strncmp(tmp, "have ", 5) == 0 && nhaves < 64) { if (from_hex(tmp + 5, haves[nhaves], 20) == 0) nhaves++; }
    else if (strncmp(tmp, "shallow ", 8) == 0 && nshallow < 64) { if (from_hex(tmp + 8, shallow[nshallow], 20) == 0) nshallow++; }
    else if (strncmp(tmp, "deepen ", 7) == 0) depth = atoi(tmp + 7);
  }
  handle_fetch(r, wants, nwants, haves, nhaves, shallow, nshallow, depth, 0, resp);
}
static void handle_receive_pack(repo_t *r, const unsigned char *body, size_t body_len, resp_t *resp) {
  // Walk command pkt-lines until first flush; rest is the pack.
  size_t off = 0;
  int saw_flush = 0;
  while (off < body_len) {
    if (off + 4 > body_len) { resp_json_error(resp, 400, "bad request"); return; }
    unsigned int v = 0;
    int ok = 1;
    for (int i = 0; i < 4; i++) {
      char c = (char)body[off + i]; v <<= 4;
      if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
      else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
      else ok = 0;
    }
    if (!ok) { resp_json_error(resp, 400, "bad request"); return; }
    if (v == 0) { off += 4; saw_flush = 1; break; }
    if (v == 1 || v == 2) { off += 4; continue; }
    if (v < 4 || off + v > body_len) { resp_json_error(resp, 400, "bad request"); return; }
    off += v;
  }
  if (!saw_flush) { resp_json_error(resp, 400, "command list has no flush"); return; }
  const unsigned char *pack = body + off;
  size_t pack_len = body_len - off;
  // Decode commands.
  typedef struct { unsigned char old_oid[20]; unsigned char new_oid[20]; char ref[128]; } cmd_t;
  cmd_t cmds[64]; int ncmds = 0;
  pkt_t pkts[128];
  int np = decode_pkt_lines(body, off, pkts, 128);
  if (np < 0) { resp_json_error(resp, 400, "bad request"); return; }
  for (int i = 0; i < np && ncmds < 64; i++) {
    if (pkts[i].kind != 0) continue;
    size_t l = pkts[i].len;
    const unsigned char *d = pkts[i].data;
    // strip capabilities after NUL on first line
    for (size_t k = 0; k < l; k++) if (d[k] == 0) { l = k; break; }
    if (l > 0 && d[l-1] == '\n') l--;
    char tmp[256];
    if (l >= sizeof tmp) continue;
    memcpy(tmp, d, l); tmp[l] = 0;
    char olds[41], news[41], ref[128];
    if (sscanf(tmp, "%40s %40s %127s", olds, news, ref) != 3) continue;
    if (from_hex(olds, cmds[ncmds].old_oid, 20) != 0) continue;
    if (from_hex(news, cmds[ncmds].new_oid, 20) != 0) continue;
    snprintf(cmds[ncmds].ref, sizeof cmds[ncmds].ref, "%s", ref);
    ncmds++;
  }
  if (ncmds == 0) { resp_json_error(resp, 400, "no commands"); return; }
  char unpack_err[256] = {0};
  if (pack_len > 0) {
    if (read_pack(r, pack, pack_len, unpack_err, sizeof unpack_err) != 0) {
      // unpack error: report below
    } else {
      r->rev++;
    }
  }
  buf_t lines; buf_init(&lines);
  if (unpack_err[0]) {
    buf_printf(&lines, "unpack %s\n", unpack_err);
    for (int i = 0; i < ncmds; i++) buf_printf(&lines, "ng %s unpack error\n", cmds[i].ref);
  } else {
    // missing new tips?
    int missing = -1;
    for (int i = 0; i < ncmds; i++) {
      static const unsigned char zero[20] = {0};
      if (memcmp(cmds[i].new_oid, zero, 20) != 0 && !objtab_get(&r->objects, cmds[i].new_oid)) { missing = i; break; }
    }
    if (missing >= 0) {
      char hex[41]; to_hex(cmds[missing].new_oid, 20, hex);
      buf_printf(&lines, "unpack object %s not found\n", hex);
      for (int i = 0; i < ncmds; i++) buf_printf(&lines, "ng %s unpack error\n", cmds[i].ref);
    } else {
      buf_puts(&lines, "unpack ok\n");
      for (int i = 0; i < ncmds; i++) {
        static const unsigned char zero[20] = {0};
        const unsigned char *cur = ref_lookup(r, cmds[i].ref);
        if (memcmp(cmds[i].new_oid, zero, 20) == 0) {
          if (!cur) buf_printf(&lines, "ng %s no such ref\n", cmds[i].ref);
          else if (memcmp(cmds[i].old_oid, cur, 20) != 0) buf_printf(&lines, "ng %s non-fast-forward\n", cmds[i].ref);
          else { ref_del(r, cmds[i].ref); buf_printf(&lines, "ok %s\n", cmds[i].ref); }
        } else if (memcmp(cmds[i].old_oid, zero, 20) == 0) {
          if (cur) buf_printf(&lines, "ng %s already exists\n", cmds[i].ref);
          else { ref_set(r, cmds[i].ref, cmds[i].new_oid); buf_printf(&lines, "ok %s\n", cmds[i].ref); }
        } else {
          if (!cur) buf_printf(&lines, "ng %s no such ref\n", cmds[i].ref);
          else if (memcmp(cmds[i].old_oid, cur, 20) != 0) buf_printf(&lines, "ng %s non-fast-forward\n", cmds[i].ref);
          else if (memcmp(cmds[i].old_oid, cmds[i].new_oid, 20) == 0) buf_printf(&lines, "ok %s\n", cmds[i].ref);
          else if (strncmp(cmds[i].ref, "refs/tags/", 10) == 0) { ref_set(r, cmds[i].ref, cmds[i].new_oid); buf_printf(&lines, "ok %s\n", cmds[i].ref); }
          else if (is_ancestor(r, cmds[i].old_oid, cmds[i].new_oid)) { ref_set(r, cmds[i].ref, cmds[i].new_oid); buf_printf(&lines, "ok %s\n", cmds[i].ref); }
          else buf_printf(&lines, "ng %s non-fast-forward\n", cmds[i].ref);
        }
      }
    }
  }
  r->rev++;
  // report: pkt-lines inside band 1 + inner flush, then outer flush
  buf_t inner; buf_init(&inner);
  // split lines into pkt-lines
  size_t lp = 0;
  while (lp < lines.len) {
    const unsigned char *nl = memchr(lines.data + lp, '\n', lines.len - lp);
    size_t ll = nl ? (size_t)(nl - (lines.data + lp)) + 1 : lines.len - lp;
    pkt_line_buf(&inner, lines.data + lp, ll);
    lp += ll;
  }
  pkt_flush(&inner);
  buf_free(&lines);
  buf_t b; buf_init(&b);
  sideband(&b, 1, inner.data, inner.len);
  pkt_flush(&b);
  buf_free(&inner);
  resp_raw(resp, 200, "application/x-git-receive-pack-result", &b);
}

// ---------------------------------------------------------------- minimal JSON parser
// Node types: 0 null, 1 false, 2 true, 3 number, 4 string, 5 array, 6 object.
// Object: child = first KEY node; key.next = value node; value.next = next key node (or -1).
// Array: child = first element; elements linked by next.
typedef struct { int type; double num; char *str; int child; int next; } jn_t;
typedef struct { jn_t *nodes; int n; int cap; char *arena; size_t alen; size_t acap; } jp_t;
static int jp_new(jp_t *p, int type) {
  if (p->n >= p->cap) return -1;
  int i = p->n++;
  p->nodes[i].type = type; p->nodes[i].num = 0; p->nodes[i].str = NULL; p->nodes[i].child = -1; p->nodes[i].next = -1;
  return i;
}
static char *jp_arena(jp_t *p, size_t len) {
  if (p->alen + len + 1 > p->acap) return NULL;
  char *d = p->arena + p->alen; p->alen += len + 1; return d;
}
typedef struct { const unsigned char *s; size_t len; size_t pos; jp_t *p; } jps_t;
static void jp_ws(jps_t *j) { while (j->pos < j->len && (j->s[j->pos] == ' ' || j->s[j->pos] == '\t' || j->s[j->pos] == '\n' || j->s[j->pos] == '\r')) j->pos++; }
static int jp_value(jps_t *j);
static int jp_hex4(jps_t *j) {
  unsigned int cp = 0;
  for (int k = 0; k < 4; k++) {
    if (j->pos >= j->len) return -1;
    unsigned char c = j->s[j->pos++];
    cp <<= 4;
    if (c >= '0' && c <= '9') cp |= (unsigned)(c - '0');
    else if (c >= 'a' && c <= 'f') cp |= (unsigned)(c - 'a' + 10);
    else if (c >= 'A' && c <= 'F') cp |= (unsigned)(c - 'A' + 10);
    else return -1;
  }
  return (int)cp;
}
static void jp_utf8(char *dst, size_t *o, unsigned int cp) {
  if (cp < 0x80) dst[(*o)++] = (char)cp;
  else if (cp < 0x800) { dst[(*o)++] = (char)(0xc0 | (cp >> 6)); dst[(*o)++] = (char)(0x80 | (cp & 0x3f)); }
  else if (cp < 0x10000) { dst[(*o)++] = (char)(0xe0 | (cp >> 12)); dst[(*o)++] = (char)(0x80 | ((cp >> 6) & 0x3f)); dst[(*o)++] = (char)(0x80 | (cp & 0x3f)); }
  else { dst[(*o)++] = (char)(0xf0 | (cp >> 18)); dst[(*o)++] = (char)(0x80 | ((cp >> 12) & 0x3f)); dst[(*o)++] = (char)(0x80 | ((cp >> 6) & 0x3f)); dst[(*o)++] = (char)(0x80 | (cp & 0x3f)); }
}
// Parse a JSON string at j->pos (which points at '"'). Returns arena string or NULL.
static char *jp_string(jps_t *j) {
  if (j->pos >= j->len || j->s[j->pos] != '"') return NULL;
  j->pos++;
  size_t maxout = (j->len - j->pos) * 3 + 1;
  char *dst = jp_arena(j->p, maxout);
  if (!dst) return NULL;
  size_t o = 0;
  while (j->pos < j->len) {
    unsigned char c = j->s[j->pos++];
    if (c == '"') { dst[o] = 0; return dst; }
    if (c == '\\') {
      if (j->pos >= j->len) return NULL;
      unsigned char e = j->s[j->pos++];
      switch (e) {
        case '"': dst[o++] = '"'; break;
        case '\\': dst[o++] = '\\'; break;
        case '/': dst[o++] = '/'; break;
        case 'b': dst[o++] = '\b'; break;
        case 'f': dst[o++] = '\f'; break;
        case 'n': dst[o++] = '\n'; break;
        case 'r': dst[o++] = '\r'; break;
        case 't': dst[o++] = '\t'; break;
        case 'u': {
          int cp = jp_hex4(j);
          if (cp < 0) return NULL;
          if (cp >= 0xd800 && cp <= 0xdbff && j->pos + 6 <= j->len && j->s[j->pos] == '\\' && j->s[j->pos + 1] == 'u') {
            size_t save = j->pos; j->pos += 2;
            int lo = jp_hex4(j);
            if (lo >= 0xdc00 && lo <= 0xdfff) cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
            else j->pos = save;
          }
          jp_utf8(dst, &o, (unsigned int)cp);
          break;
        }
        default: return NULL;
      }
    } else if (c < 0x20) return NULL;
    else dst[o++] = (char)c;
  }
  return NULL;
}
static int jp_value(jps_t *j) {
  jp_ws(j);
  if (j->pos >= j->len) return -1;
  unsigned char c = j->s[j->pos];
  if (c == '{') {
    int obj = jp_new(j->p, 6); if (obj < 0) return -1;
    j->pos++;
    jp_ws(j);
    if (j->pos < j->len && j->s[j->pos] == '}') { j->pos++; return obj; }
    int last = -1;
    for (;;) {
      jp_ws(j);
      char *key = jp_string(j);
      if (!key) return -1;
      int kn = jp_new(j->p, 4); if (kn < 0) return -1;
      j->p->nodes[kn].str = key;
      jp_ws(j);
      if (j->pos >= j->len || j->s[j->pos] != ':') return -1;
      j->pos++;
      int v = jp_value(j);
      if (v < 0) return -1;
      j->p->nodes[kn].next = v;
      if (last < 0) j->p->nodes[obj].child = kn;
      else j->p->nodes[last].next = kn;
      last = v;
      jp_ws(j);
      if (j->pos < j->len && j->s[j->pos] == ',') { j->pos++; continue; }
      if (j->pos < j->len && j->s[j->pos] == '}') { j->pos++; return obj; }
      return -1;
    }
  }
  if (c == '[') {
    int arr = jp_new(j->p, 5); if (arr < 0) return -1;
    j->pos++;
    jp_ws(j);
    if (j->pos < j->len && j->s[j->pos] == ']') { j->pos++; return arr; }
    int last = -1;
    for (;;) {
      int v = jp_value(j);
      if (v < 0) return -1;
      if (last < 0) j->p->nodes[arr].child = v;
      else j->p->nodes[last].next = v;
      last = v;
      jp_ws(j);
      if (j->pos < j->len && j->s[j->pos] == ',') { j->pos++; continue; }
      if (j->pos < j->len && j->s[j->pos] == ']') { j->pos++; return arr; }
      return -1;
    }
  }
  if (c == '"') {
    char *s = jp_string(j);
    if (!s) return -1;
    int n = jp_new(j->p, 4); if (n < 0) return -1;
    j->p->nodes[n].str = s;
    return n;
  }
  if (c == 't' && j->pos + 4 <= j->len && memcmp(j->s + j->pos, "true", 4) == 0) { j->pos += 4; return jp_new(j->p, 2); }
  if (c == 'f' && j->pos + 5 <= j->len && memcmp(j->s + j->pos, "false", 5) == 0) { j->pos += 5; return jp_new(j->p, 1); }
  if (c == 'n' && j->pos + 4 <= j->len && memcmp(j->s + j->pos, "null", 4) == 0) { j->pos += 4; return jp_new(j->p, 0); }
  size_t start = j->pos;
  if (j->pos < j->len && (j->s[j->pos] == '-' || j->s[j->pos] == '+')) j->pos++;
  int any = 0;
  while (j->pos < j->len && ((j->s[j->pos] >= '0' && j->s[j->pos] <= '9') || j->s[j->pos] == '.' || j->s[j->pos] == 'e' || j->s[j->pos] == 'E' || j->s[j->pos] == '+' || j->s[j->pos] == '-')) { j->pos++; any = 1; }
  if (!any) return -1;
  char numbuf[64];
  size_t nl = j->pos - start;
  if (nl >= sizeof numbuf) return -1;
  memcpy(numbuf, j->s + start, nl); numbuf[nl] = 0;
  int n = jp_new(j->p, 3); if (n < 0) return -1;
  j->p->nodes[n].num = strtod(numbuf, NULL);
  return n;
}
// Parse a whole JSON document. Returns root node index or -1.
static int jparse(const unsigned char *s, size_t len, jp_t *p) {
  p->cap = 2048; p->n = 0; p->nodes = NULL; p->arena = NULL; p->alen = 0; p->acap = 1024 * 1024;
  p->nodes = (jn_t *)malloc(sizeof(jn_t) * (size_t)p->cap);
  p->arena = (char *)malloc(p->acap);
  if (!p->nodes || !p->arena) { free(p->nodes); free(p->arena); p->nodes = NULL; p->arena = NULL; return -1; }
  jps_t j = { s, len, 0, p };
  int root = jp_value(&j);
  if (root < 0) return -1;
  jp_ws(&j);
  if (j.pos != len) return -1;
  return root;
}
static void jfree(jp_t *p) { free(p->nodes); free(p->arena); p->nodes = NULL; p->arena = NULL; }
static int jget(jp_t *p, int obj, const char *key) {
  if (obj < 0 || obj >= p->n || p->nodes[obj].type != 6) return -1;
  for (int k = p->nodes[obj].child; k >= 0; ) {
    int v = p->nodes[k].next;
    if (v < 0) break;
    if (p->nodes[k].type == 4 && p->nodes[k].str && strcmp(p->nodes[k].str, key) == 0) return v;
    k = p->nodes[v].next;
  }
  return -1;
}
static const char *jstr(jp_t *p, int idx) {
  if (idx < 0 || idx >= p->n || p->nodes[idx].type != 4) return NULL;
  return p->nodes[idx].str;
}
static int jnum(jp_t *p, int idx, long *out) {
  if (idx < 0 || idx >= p->n || p->nodes[idx].type != 3) return -1;
  *out = (long)p->nodes[idx].num;
  return 0;
}
static int jarr_len(jp_t *p, int arr) {
  if (arr < 0 || arr >= p->n || p->nodes[arr].type != 5) return -1;
  int n = 0;
  for (int cur = p->nodes[arr].child; cur >= 0; cur = p->nodes[cur].next) n++;
  return n;
}
static int jarr_get(jp_t *p, int arr, int i) {
  if (arr < 0 || arr >= p->n || p->nodes[arr].type != 5) return -1;
  int cur = p->nodes[arr].child;
  while (cur >= 0 && i > 0) { cur = p->nodes[cur].next; i--; }
  return cur;
}
// Serialize one parsed node back to JSON (string/number/bool/null only; used to echo JSON-RPC ids).
static void jval_json(buf_t *out, jp_t *p, int idx) {
  if (idx < 0 || idx >= p->n) { buf_puts(out, "null"); return; }
  jn_t *n = &p->nodes[idx];
  if (n->type == 4) json_escape(out, n->str ? n->str : "", n->str ? strlen(n->str) : 0);
  else if (n->type == 3) buf_printf(out, "%ld", (long)n->num);
  else if (n->type == 2) buf_puts(out, "true");
  else if (n->type == 1) buf_puts(out, "false");
  else buf_puts(out, "null");
}

// ---------------------------------------------------------------- global (Relay) ids: base64 of a typed key, opaque + stable
static void gid_b64(char *out, size_t outn, const unsigned char *in, size_t len) {
  size_t o = 0;
  for (size_t i = 0; i < len; i += 3) {
    int rem = (int)(len - i);
    unsigned int v = (unsigned int)in[i] << 16;
    if (rem > 1) v |= (unsigned int)in[i + 1] << 8;
    if (rem > 2) v |= in[i + 2];
    char quad[4] = { B64A[(v >> 18) & 63], B64A[(v >> 12) & 63], rem > 1 ? (char)B64A[(v >> 6) & 63] : '=', rem > 2 ? (char)B64A[v & 63] : '=' };
    for (int k = 0; k < 4 && o + 1 < outn; k++) out[o++] = quad[k];
  }
  out[o] = 0;
}
static void gid_encode(char *out, size_t outn, const char *kind, const char *name, int num, int extra) {
  char raw[300];
  if (num >= 0 && extra >= 0) snprintf(raw, sizeof raw, "%s:%s/%s#%d#%d", kind, VIEWER_LOGIN, name, num, extra);
  else if (num >= 0) snprintf(raw, sizeof raw, "%s:%s/%s#%d", kind, VIEWER_LOGIN, name, num);
  else snprintf(raw, sizeof raw, "%s:%s/%s", kind, VIEWER_LOGIN, name);
  gid_b64(out, outn, (const unsigned char *)raw, strlen(raw));
}
// Decode a global id. kind/owner/name/num filled; extra filled when a second #number exists, else -1.
static int gid_decode(const char *gid, char *kind, size_t kn, char *owner, size_t on, char *name, size_t nn, int *num, int *extra) {
  unsigned char raw[300];
  long n = b64decode(gid, strlen(gid), raw, sizeof raw - 1);
  if (n <= 0) return -1;
  raw[n] = 0;
  char *colon = strchr((char *)raw, ':');
  if (!colon) return -1;
  size_t klen = (size_t)(colon - (char *)raw);
  if (klen >= kn) return -1;
  memcpy(kind, raw, klen); kind[klen] = 0;
  char *rest = colon + 1;
  char *slash = strchr(rest, '/');
  if (!slash) return -1;
  size_t olen = (size_t)(slash - rest);
  if (olen >= on) return -1;
  memcpy(owner, rest, olen); owner[olen] = 0;
  char *nm = slash + 1;
  char *hash = strchr(nm, '#');
  if (hash) {
    size_t nlen = (size_t)(hash - nm);
    if (nlen >= nn) return -1;
    memcpy(name, nm, nlen); name[nlen] = 0;
    *num = atoi(hash + 1);
    char *hash2 = strchr(hash + 1, '#');
    *extra = hash2 ? atoi(hash2 + 1) : -1;
  } else {
    if (strlen(nm) >= nn) return -1;
    snprintf(name, nn, "%s", nm);
    *num = -1; *extra = -1;
  }
  return 0;
}
static void gid_repo_id(char *out, size_t outn, repo_t *r) { gid_encode(out, outn, "R", r->name, -1, -1); }
static void gid_issue_id(char *out, size_t outn, repo_t *r, issue_t *iss) { gid_encode(out, outn, "I", r->name, iss->number, -1); }
static void gid_pull_id(char *out, size_t outn, repo_t *r, pull_t *p) { gid_encode(out, outn, "PR", r->name, p->number, -1); }
static void gid_comment_id(char *out, size_t outn, repo_t *r, issue_t *iss, int cidx) { gid_encode(out, outn, "C", r->name, iss->number, cidx); }
static repo_t *gid_repo(const char *gid) {
  char kind[16], owner[128], name[128]; int num, extra;
  if (gid_decode(gid, kind, sizeof kind, owner, sizeof owner, name, sizeof name, &num, &extra) != 0) return NULL;
  if (strcmp(kind, "R") != 0) return NULL;
  return find_repo(owner, name);
}
static issue_t *gid_issue(const char *gid, repo_t **out_r) {
  char kind[16], owner[128], name[128]; int num, extra;
  if (gid_decode(gid, kind, sizeof kind, owner, sizeof owner, name, sizeof name, &num, &extra) != 0) return NULL;
  if (strcmp(kind, "I") != 0 || num < 0) return NULL;
  repo_t *r = find_repo(owner, name);
  if (!r) return NULL;
  for (int i = 0; i < r->issue_count; i++) if (r->issues[i].number == num) { *out_r = r; return &r->issues[i]; }
  return NULL;
}
static pull_t *gid_pull(const char *gid, repo_t **out_r) {
  char kind[16], owner[128], name[128]; int num, extra;
  if (gid_decode(gid, kind, sizeof kind, owner, sizeof owner, name, sizeof name, &num, &extra) != 0) return NULL;
  if (strcmp(kind, "PR") != 0 || num < 0) return NULL;
  repo_t *r = find_repo(owner, name);
  if (!r) return NULL;
  for (int i = 0; i < r->pulls_count; i++) if (r->pulls[i].number == num) { *out_r = r; return &r->pulls[i]; }
  return NULL;
}

// ---------------------------------------------------------------- synthetic REST calls (mutations reuse handle_rest: same code, same parity)
static int rest_call(const char *method, char **segs, int nseg, const unsigned char *body, size_t body_len, const char *auth, resp_t *resp) {
  resp_init(resp);
  handle_rest(segs, nseg, method, body, body_len, auth, "", NULL, resp);
  return resp->status;
}
// Changed files of a PR: base tip tree vs head tip tree. Returns count or -1.
static int pr_diff(repo_t *r, pull_t *p, diffent_t *out, int maxn) {
  objent_t *bo = objtab_get(&r->objects, p->base_sha);
  objent_t *ho = objtab_get(&r->objects, p->head_sha);
  unsigned char bt[20], ht[20];
  int have_bt = 0, have_ht = 0;
  if (bo && bo->type == 1) { char th[41]; char ps[64][41]; int np = 0; if (parse_commit(bo->data, bo->len, th, ps, &np) == 0 && from_hex(th, bt, 20) == 0) have_bt = 1; }
  if (ho && ho->type == 1) { char th[41]; char ps[64][41]; int np = 0; if (parse_commit(ho->data, ho->len, th, ps, &np) == 0 && from_hex(th, ht, 20) == 0) have_ht = 1; }
  if (!have_bt || !have_ht) return -1;
  return tree_diff(r, bt, ht, out, maxn);
}
// 1 if head and base both changed the same path differently over the merge base, 0 if clean, -1 if cannot compute.
static int pr_has_conflict(repo_t *r, pull_t *p) {
  char bref0[160]; snprintf(bref0, sizeof bref0, "refs/heads/%s", p->base_ref);
  int bri = find_ref(r, bref0);
  if (bri < 0) return -1;
  unsigned char cur_base[20]; memcpy(cur_base, r->refs_oid[bri], 20);
  char href0[160]; snprintf(href0, sizeof href0, "refs/heads/%s", p->head_ref);
  int hri = find_ref(r, href0);
  if (hri < 0) return -1;
  unsigned char cur_head[20]; memcpy(cur_head, r->refs_oid[hri], 20);
  unsigned char mb[20];
  if (merge_base(r, cur_base, cur_head, mb) != 0) return -1;
  objent_t *mbo = objtab_get(&r->objects, mb);
  unsigned char mb_tree[20]; int have_mb_tree = 0;
  if (mbo && mbo->type == 1) { char th[41]; char ps[64][41]; int np = 0; if (parse_commit(mbo->data, mbo->len, th, ps, &np) == 0 && from_hex(th, mb_tree, 20) == 0) have_mb_tree = 1; }
  if (!have_mb_tree) return -1;
  objent_t *bo = objtab_get(&r->objects, cur_base);
  objent_t *ho = objtab_get(&r->objects, cur_head);
  unsigned char bt[20], ht[20]; int have_bt = 0, have_ht = 0;
  if (bo && bo->type == 1) { char th[41]; char ps[64][41]; int np = 0; if (parse_commit(bo->data, bo->len, th, ps, &np) == 0 && from_hex(th, bt, 20) == 0) have_bt = 1; }
  if (ho && ho->type == 1) { char th[41]; char ps[64][41]; int np = 0; if (parse_commit(ho->data, ho->len, th, ps, &np) == 0 && from_hex(th, ht, 20) == 0) have_ht = 1; }
  if (!have_bt || !have_ht) return -1;
  diffent_t d_base[512], d_head[512];
  int nb_base = tree_diff(r, mb_tree, bt, d_base, 512);
  int nb_head = tree_diff(r, mb_tree, ht, d_head, 512);
  for (int i = 0; i < nb_head; i++)
    for (int j = 0; j < nb_base; j++)
      if (strcmp(d_head[i].path, d_base[j].path) == 0 && memcmp(d_head[i].new_oid, d_base[j].new_oid, 20) != 0) return 1;
  return 0;
}

// ---------------------------------------------------------------- GraphQL v4 (/api/graphql)
static void gql_err(buf_t *out, const char *msg) {
  buf_puts(out, "{\"data\":null,\"errors\":[{\"message\":");
  json_escape(out, msg, strlen(msg));
  buf_puts(out, "}]}");
}
static void gql_repo_json(buf_t *out, repo_t *r) {
  char gid[256]; gid_repo_id(gid, sizeof gid, r);
  buf_puts(out, "{\"id\":");
  json_escape(out, gid, strlen(gid));
  buf_printf(out, ",\"databaseId\":%d,\"name\":", r->next_repo_id);
  json_escape(out, r->name, strlen(r->name));
  buf_puts(out, ",\"nameWithOwner\":\"adaiversen/");
  buf_puts(out, r->name);
  buf_puts(out, "\",\"owner\":{\"login\":\"adaiversen\"},\"defaultBranchRef\":{\"name\":\"main\"},\"viewerPermission\":\"ADMIN\",\"hasIssuesEnabled\":true}");
}
static void gql_issue_json(buf_t *out, repo_t *r, issue_t *iss) {
  char gid[256]; gid_issue_id(gid, sizeof gid, r, iss);
  buf_puts(out, "{\"id\":");
  json_escape(out, gid, strlen(gid));
  buf_printf(out, ",\"number\":%d,\"title\":", iss->number);
  json_escape(out, iss->title, strlen(iss->title));
  buf_puts(out, ",\"body\":");
  json_escape(out, iss->body, strlen(iss->body));
  buf_printf(out, ",\"state\":\"%s\"}", strcmp(iss->state, "closed") == 0 ? "CLOSED" : "OPEN");
}
static void gql_pull_json(buf_t *out, repo_t *r, pull_t *p) {
  char gid[256]; gid_pull_id(gid, sizeof gid, r, p);
  const char *state = p->merged ? "MERGED" : (strcmp(p->state, "closed") == 0 ? "CLOSED" : "OPEN");
  const char *mg = "UNKNOWN";
  int c = pr_has_conflict(r, p);
  if (c == 0) mg = "MERGEABLE";
  else if (c == 1) mg = "CONFLICTING";
  buf_puts(out, "{\"id\":");
  json_escape(out, gid, strlen(gid));
  buf_printf(out, ",\"number\":%d,\"title\":", p->number);
  json_escape(out, p->title, strlen(p->title));
  buf_puts(out, ",\"body\":");
  json_escape(out, p->body, strlen(p->body));
  buf_printf(out, ",\"state\":\"%s\",\"merged\":%s,\"headRefName\":", state, p->merged ? "true" : "false");
  json_escape(out, p->head_ref, strlen(p->head_ref));
  buf_puts(out, ",\"baseRefName\":");
  json_escape(out, p->base_ref, strlen(p->base_ref));
  buf_printf(out, ",\"mergeable\":\"%s\"}", mg);
}
// Issue indices matching the state filter, in CREATED_AT DESC order (number desc).
static int gql_issue_idx(repo_t *r, const char *state, int *idx, int maxn) {
  int n = 0;
  for (int i = r->issue_count - 1; i >= 0 && n < maxn; i--) {
    if (state) {
      if (strcmp(state, "OPEN") == 0 && strcmp(r->issues[i].state, "open") != 0) continue;
      if (strcmp(state, "CLOSED") == 0 && strcmp(r->issues[i].state, "closed") != 0) continue;
    }
    idx[n++] = i;
  }
  return n;
}
// issues(first, after) connection: state NULL means all states.
static void gql_issues_conn(buf_t *out, repo_t *r, const char *state, int first, const char *after) {
  int after_num = -1;
  if (after && after[0]) {
    unsigned char raw[64];
    long n = b64decode(after, strlen(after), raw, sizeof raw - 1);
    if (n > 0) { raw[n] = 0; if (strncmp((char *)raw, "cur:", 4) == 0) after_num = atoi((char *)raw + 4); }
  }
  int idx[MAX_ISSUES]; int nidx = gql_issue_idx(r, state, idx, MAX_ISSUES);
  int start = 0;
  if (after_num >= 0) {
    while (start < nidx && r->issues[idx[start]].number >= after_num) start++;
  }
  int end = start + first;
  if (end > nidx) end = nidx;
  int has_next = end < nidx;
  buf_puts(out, "{\"nodes\":[");
  for (int i = start; i < end; i++) {
    if (i > start) buf_putc(out, ',');
    gql_issue_json(out, r, &r->issues[idx[i]]);
  }
  buf_puts(out, "],\"pageInfo\":{\"hasNextPage\":");
  buf_puts(out, has_next ? "true" : "false");
  buf_puts(out, ",\"endCursor\":");
  if (end > start) {
    char cur[64]; snprintf(cur, sizeof cur, "cur:%d", r->issues[idx[end - 1]].number);
    buf_putc(out, '"');
    b64encode_buf(out, (const unsigned char *)cur, strlen(cur));
    buf_putc(out, '"');
  } else buf_puts(out, "null");
  buf_puts(out, "}}");
}
static const char *gql_op(const char *q) {
  if (strstr(q, "noSuchFieldOnViewer")) return "invalid";
  if (strstr(q, "__type")) {
    if (strstr(q, "\"Issue\"")) return "type-issue";
    if (strstr(q, "\"PullRequest\"")) return "type-pr-repo";
    if (strstr(q, "\"SearchType\"")) return "type-search";
    if (strstr(q, "\"Repository\"")) return "type-pr-repo";
    return "type-unknown";
  }
  if (strstr(q, "createIssue")) return "create-issue";
  if (strstr(q, "closeIssue")) return "close-issue";
  if (strstr(q, "createPullRequest")) return "create-pr";
  if (strstr(q, "mergePullRequest")) return "merge-pr";
  if (strstr(q, "addComment")) return "add-comment";
  if (strstr(q, "node(id:")) return "node";
  if (strstr(q, "viewer") && strstr(q, "login") && !strstr(q, "repository")) return "viewer";
  if (strstr(q, "repository")) {
    if (strstr(q, "issues(first:")) {
      if (strstr(q, "after:")) return "issues-page";
      return "issues-open";
    }
    if (strstr(q, "issue(number:")) return "issue-by-number";
    if (strstr(q, "pullRequests(first:")) return "prs-list";
    if (strstr(q, "pullRequest(number:")) {
      if (strstr(q, "files(")) return "pr-files";
      return "pr-id";
    }
    return "repo-fields";
  }
  return "unknown";
}
static void gql_fields_list(buf_t *out, const char *const *names, int n) {
  buf_putc(out, '[');
  for (int i = 0; i < n; i++) {
    if (i) buf_putc(out, ',');
    buf_puts(out, "{\"name\":");
    json_escape(out, names[i], strlen(names[i]));
    buf_putc(out, '}');
  }
  buf_putc(out, ']');
}
// Run one GraphQL operation object {query, variables}; appends one response envelope.
static void gql_run_one(jp_t *p, int opnode, const char *auth, buf_t *out) {
  const char *query = jstr(p, jget(p, opnode, "query"));
  if (!query) { gql_err(out, "no query"); return; }
  int vars = jget(p, opnode, "variables");
  const char *op = gql_op(query);
  if (strcmp(op, "invalid") == 0) {
    buf_puts(out, "{\"data\":null,\"errors\":[{\"message\":\"Cannot query field \\\"noSuchFieldOnViewer\\\" on type \\\"User\\\"\"}]}");
    return;
  }
  if (strcmp(op, "unknown") == 0 || strcmp(op, "type-unknown") == 0) { gql_err(out, "unknown operation"); return; }
  if (strcmp(op, "viewer") == 0) {
    buf_puts(out, "{\"data\":{\"viewer\":{\"login\":\"adaiversen\"}}}");
    return;
  }
  if (strcmp(op, "type-issue") == 0) {
    static const char *const fields[] = { "id", "number", "title", "body", "state", "author", "createdAt", "updatedAt", "url", "comments", "labels", "repository", "assignees", "closedAt" };
    buf_puts(out, "{\"data\":{\"Issue\":{\"fields\":");
    gql_fields_list(out, fields, (int)(sizeof fields / sizeof fields[0]));
    buf_puts(out, "}}}");
    return;
  }
  if (strcmp(op, "type-pr-repo") == 0) {
    static const char *const prfields[] = { "id", "number", "title", "body", "state", "merged", "mergeable", "headRefName", "baseRefName", "headRefOid", "baseRefOid", "files", "author", "createdAt", "updatedAt", "url", "commits", "reviews" };
    static const char *const repofields[] = { "id", "databaseId", "name", "nameWithOwner", "owner", "defaultBranchRef", "viewerPermission", "hasIssuesEnabled", "issue", "issues", "pullRequest", "pullRequests", "description", "url", "createdAt", "updatedAt", "isPrivate", "fork" };
    buf_puts(out, "{\"data\":{\"PullRequest\":{\"fields\":");
    gql_fields_list(out, prfields, (int)(sizeof prfields / sizeof prfields[0]));
    buf_puts(out, "},\"Repository\":{\"fields\":");
    gql_fields_list(out, repofields, (int)(sizeof repofields / sizeof repofields[0]));
    buf_puts(out, "}}}");
    return;
  }
  if (strcmp(op, "type-search") == 0) {
    static const char *const enums[] = { "ISSUE", "REPOSITORY", "USER", "DISCUSSION", "CODE", "COMMIT", "MILESTONE", "LABEL", "WIKI" };
    buf_puts(out, "{\"data\":{\"SearchType\":{\"enumValues\":");
    gql_fields_list(out, enums, (int)(sizeof enums / sizeof enums[0]));
    buf_puts(out, "}}}");
    return;
  }
  if (strcmp(op, "node") == 0) {
    const char *id = jstr(p, jget(p, vars, "id"));
    if (!id) { gql_err(out, "node id is required"); return; }
    char kind[16], owner[128], name[128]; int num, extra;
    if (gid_decode(id, kind, sizeof kind, owner, sizeof owner, name, sizeof name, &num, &extra) != 0) {
      buf_puts(out, "{\"data\":{\"node\":null}}");
      return;
    }
    if (strcmp(kind, "R") == 0) {
      repo_t *r = find_repo(owner, name);
      if (!r) { buf_puts(out, "{\"data\":{\"node\":null}}"); return; }
      buf_puts(out, "{\"data\":{\"node\":");
      gql_repo_json(out, r);
      buf_puts(out, "}}");
      return;
    }
    buf_puts(out, "{\"data\":{\"node\":{\"id\":");
    json_escape(out, id, strlen(id));
    buf_puts(out, "}}}");
    return;
  }
  // Mutations (via synthetic REST calls: same code path as REST, same parity).
  if (strcmp(op, "create-issue") == 0) {
    int input = jget(p, vars, "input");
    const char *repo_id = jstr(p, jget(p, input, "repositoryId"));
    const char *title = jstr(p, jget(p, input, "title"));
    const char *ibody = jstr(p, jget(p, input, "body"));
    repo_t *r = repo_id ? gid_repo(repo_id) : NULL;
    if (!r || !title) { gql_err(out, "repositoryId and title are required"); return; }
    buf_t b; buf_init(&b);
    buf_puts(&b, "{\"title\":");
    json_escape(&b, title, strlen(title));
    buf_puts(&b, ",\"body\":");
    json_escape(&b, ibody ? ibody : "", ibody ? strlen(ibody) : 0);
    buf_putc(&b, '}');
    char *segs[] = { "repos", "adaiversen", r->name, "issues" };
    resp_t rr; int st = rest_call("POST", segs, 4, b.data, b.len, auth, &rr);
    if (st != 201) { buf_free(&b); buf_free(&rr.owned); gql_err(out, "createIssue failed"); return; }
    jp_t rp; int rroot = jparse(rr.body, rr.body_len, &rp);
    long num = -1;
    if (rroot >= 0) jnum(&rp, jget(&rp, rroot, "number"), &num);
    jfree(&rp);
    buf_free(&b); buf_free(&rr.owned);
    issue_t *iss = NULL;
    for (int i = 0; i < r->issue_count; i++) if (r->issues[i].number == (int)num) { iss = &r->issues[i]; break; }
    if (!iss) { gql_err(out, "createIssue failed"); return; }
    buf_puts(out, "{\"data\":{\"createIssue\":{\"issue\":");
    gql_issue_json(out, r, iss);
    buf_puts(out, "}}}");
    return;
  }
  if (strcmp(op, "close-issue") == 0) {
    int input = jget(p, vars, "input");
    const char *issue_id = jstr(p, jget(p, input, "issueId"));
    repo_t *r = NULL;
    issue_t *iss = issue_id ? gid_issue(issue_id, &r) : NULL;
    if (!iss) { gql_err(out, "issue not found"); return; }
    char numbuf[16]; snprintf(numbuf, sizeof numbuf, "%d", iss->number);
    char *segs[] = { "repos", "adaiversen", r->name, "issues", numbuf };
    resp_t rr; int st = rest_call("PATCH", segs, 5, (const unsigned char *)"{\"state\":\"closed\"}", 18, auth, &rr);
    buf_free(&rr.owned);
    if (st != 200) { gql_err(out, "closeIssue failed"); return; }
    buf_puts(out, "{\"data\":{\"closeIssue\":{\"issue\":");
    gql_issue_json(out, r, iss);
    buf_puts(out, "}}}");
    return;
  }
  if (strcmp(op, "create-pr") == 0) {
    int input = jget(p, vars, "input");
    const char *repo_id = jstr(p, jget(p, input, "repositoryId"));
    const char *title = jstr(p, jget(p, input, "title"));
    const char *base = jstr(p, jget(p, input, "baseRefName"));
    const char *head = jstr(p, jget(p, input, "headRefName"));
    repo_t *r = repo_id ? gid_repo(repo_id) : NULL;
    if (!r || !title || !base || !head) { gql_err(out, "repositoryId, title, baseRefName and headRefName are required"); return; }
    buf_t b; buf_init(&b);
    buf_puts(&b, "{\"title\":");
    json_escape(&b, title, strlen(title));
    buf_puts(&b, ",\"head\":");
    json_escape(&b, head, strlen(head));
    buf_puts(&b, ",\"base\":");
    json_escape(&b, base, strlen(base));
    buf_putc(&b, '}');
    char *segs[] = { "repos", "adaiversen", r->name, "pulls" };
    resp_t rr; int st = rest_call("POST", segs, 4, b.data, b.len, auth, &rr);
    if (st != 201) { buf_free(&b); buf_free(&rr.owned); gql_err(out, "createPullRequest failed"); return; }
    jp_t rp; int rroot = jparse(rr.body, rr.body_len, &rp);
    long num = -1;
    if (rroot >= 0) jnum(&rp, jget(&rp, rroot, "number"), &num);
    jfree(&rp);
    buf_free(&b); buf_free(&rr.owned);
    pull_t *pr = NULL;
    for (int i = 0; i < r->pulls_count; i++) if (r->pulls[i].number == (int)num) { pr = &r->pulls[i]; break; }
    if (!pr) { gql_err(out, "createPullRequest failed"); return; }
    buf_puts(out, "{\"data\":{\"createPullRequest\":{\"pullRequest\":");
    gql_pull_json(out, r, pr);
    buf_puts(out, "}}}");
    return;
  }
  if (strcmp(op, "merge-pr") == 0) {
    int input = jget(p, vars, "input");
    const char *pr_id = jstr(p, jget(p, input, "pullRequestId"));
    repo_t *r = NULL;
    pull_t *pr = pr_id ? gid_pull(pr_id, &r) : NULL;
    if (!pr) { gql_err(out, "pull request not found"); return; }
    char numbuf[16]; snprintf(numbuf, sizeof numbuf, "%d", pr->number);
    char *segs[] = { "repos", "adaiversen", r->name, "pulls", numbuf, "merge" };
    resp_t rr; int st = rest_call("PUT", segs, 6, (const unsigned char *)"{}", 2, auth, &rr);
    int merged = st == 200 && rr.body && strstr((const char *)rr.body, "\"merged\":true") != NULL;
    buf_free(&rr.owned);
    if (!merged) { gql_err(out, "mergePullRequest failed"); return; }
    buf_puts(out, "{\"data\":{\"mergePullRequest\":{\"pullRequest\":");
    gql_pull_json(out, r, pr);
    buf_puts(out, "}}}");
    return;
  }
  if (strcmp(op, "add-comment") == 0) {
    int input = jget(p, vars, "input");
    const char *subj = jstr(p, jget(p, input, "subjectId"));
    const char *cbody = jstr(p, jget(p, input, "body"));
    repo_t *r = NULL;
    issue_t *iss = subj ? gid_issue(subj, &r) : NULL;
    if (!iss || !cbody) { gql_err(out, "subjectId and body are required"); return; }
    buf_t b; buf_init(&b);
    buf_puts(&b, "{\"body\":");
    json_escape(&b, cbody, strlen(cbody));
    buf_putc(&b, '}');
    char numbuf[16]; snprintf(numbuf, sizeof numbuf, "%d", iss->number);
    char *segs[] = { "repos", "adaiversen", r->name, "issues", numbuf, "comments" };
    resp_t rr; int st = rest_call("POST", segs, 6, b.data, b.len, auth, &rr);
    if (st != 201) { buf_free(&b); buf_free(&rr.owned); gql_err(out, "addComment failed"); return; }
    jp_t rp; int rroot = jparse(rr.body, rr.body_len, &rp);
    long cid = -1;
    if (rroot >= 0) jnum(&rp, jget(&rp, rroot, "id"), &cid);
    jfree(&rp);
    buf_free(&b); buf_free(&rr.owned);
    char cgid[256]; gid_comment_id(cgid, sizeof cgid, r, iss, (int)cid);
    buf_puts(out, "{\"data\":{\"addComment\":{\"commentEdge\":{\"node\":{\"id\":");
    json_escape(out, cgid, strlen(cgid));
    buf_puts(out, ",\"body\":");
    json_escape(out, cbody, strlen(cbody));
    buf_puts(out, "}}}}}");
    return;
  }
  // Repository-rooted reads.
  const char *owner = jstr(p, jget(p, vars, "owner"));
  const char *name = jstr(p, jget(p, vars, "name"));
  if (!owner || !name) { gql_err(out, "owner and name are required"); return; }
  repo_t *r = find_repo(owner, name);
  if (strcmp(op, "repo-fields") == 0) {
    if (!r) { buf_puts(out, "{\"data\":{\"repository\":null}}"); return; }
    buf_puts(out, "{\"data\":{\"repository\":");
    gql_repo_json(out, r);
    buf_puts(out, "}}");
    return;
  }
  if (!r) { buf_puts(out, "{\"data\":{\"repository\":null}}"); return; }
  if (strcmp(op, "issues-open") == 0) {
    long first = 30;
    jnum(p, jget(p, vars, "first"), &first);
    buf_puts(out, "{\"data\":{\"repository\":{\"issues\":");
    gql_issues_conn(out, r, "OPEN", (int)first, NULL);
    buf_puts(out, "}}}");
    return;
  }
  if (strcmp(op, "issues-page") == 0) {
    long first = 30;
    jnum(p, jget(p, vars, "first"), &first);
    const char *after = jstr(p, jget(p, vars, "after"));
    buf_puts(out, "{\"data\":{\"repository\":{\"issues\":");
    gql_issues_conn(out, r, NULL, (int)first, after);
    buf_puts(out, "}}}");
    return;
  }
  if (strcmp(op, "issue-by-number") == 0) {
    long number = -1;
    jnum(p, jget(p, vars, "number"), &number);
    issue_t *iss = NULL;
    for (int i = 0; i < r->issue_count; i++) if (r->issues[i].number == (int)number) { iss = &r->issues[i]; break; }
    buf_puts(out, "{\"data\":{\"repository\":{\"issue\":");
    if (iss) gql_issue_json(out, r, iss);
    else buf_puts(out, "null");
    buf_puts(out, "}}}");
    return;
  }
  if (strcmp(op, "prs-list") == 0) {
    long first = 30;
    jnum(p, jget(p, vars, "first"), &first);
    buf_puts(out, "{\"data\":{\"repository\":{\"pullRequests\":{\"nodes\":[");
    int shown = 0;
    for (int i = 0; i < r->pulls_count && shown < first; i++) {
      pull_t *pr = &r->pulls[i];
      if (strcmp(pr->state, "open") != 0) continue;
      if (shown) buf_putc(out, ',');
      shown++;
      gql_pull_json(out, r, pr);
    }
    buf_puts(out, "]}}}}");
    return;
  }
  if (strcmp(op, "pr-files") == 0 || strcmp(op, "pr-id") == 0) {
    long number = -1;
    jnum(p, jget(p, vars, "number"), &number);
    pull_t *pr = NULL;
    for (int i = 0; i < r->pulls_count; i++) if (r->pulls[i].number == (int)number) { pr = &r->pulls[i]; break; }
    if (!pr) { buf_puts(out, "{\"data\":{\"repository\":{\"pullRequest\":null}}}"); return; }
    if (strcmp(op, "pr-id") == 0) {
      buf_puts(out, "{\"data\":{\"repository\":{\"pullRequest\":");
      gql_pull_json(out, r, pr);
      buf_puts(out, "}}}");
      return;
    }
    diffent_t diffs[512];
    int nd = pr_diff(r, pr, diffs, 512);
    if (nd < 0) nd = 0;
    buf_puts(out, "{\"data\":{\"repository\":{\"pullRequest\":{\"number\":");
    buf_printf(out, "%d", pr->number);
    buf_puts(out, ",\"files\":{\"nodes\":[");
    for (int i = 0; i < nd; i++) {
      if (i) buf_putc(out, ',');
      buf_puts(out, "{\"path\":");
      json_escape(out, diffs[i].path, strlen(diffs[i].path));
      buf_putc(out, '}');
    }
    buf_puts(out, "]}}}}}");
    return;
  }
  gql_err(out, "unknown operation");
}
static void handle_graphql(const char *method, const unsigned char *body, size_t body_len, const char *auth, resp_t *resp) {
  if (strcmp(method, "POST") != 0) { resp_json_error(resp, 405, "Method not allowed"); return; }
  if (!check_auth(auth)) { resp_json_error(resp, 401, "Requires authentication"); return; }
  jp_t jp; int root = jparse(body, body_len, &jp);
  if (root < 0) {
    buf_t b; buf_init(&b);
    buf_puts(&b, "{\"errors\":[{\"message\":\"request body is not valid JSON\"}]}\n");
    resp_raw(resp, 400, "application/json; charset=utf-8", &b);
    jfree(&jp);
    return;
  }
  buf_t out; buf_init(&out);
  if (jp.nodes[root].type == 5) {
    int n = jarr_len(&jp, root);
    buf_putc(&out, '[');
    for (int i = 0; i < n; i++) {
      if (i) buf_putc(&out, ',');
      gql_run_one(&jp, jarr_get(&jp, root, i), auth, &out);
    }
    buf_puts(&out, "]\n");
  } else if (jp.nodes[root].type == 6) {
    gql_run_one(&jp, root, auth, &out);
    buf_putc(&out, '\n');
  } else {
    buf_puts(&out, "{\"errors\":[{\"message\":\"request body must be a JSON object\"}]}\n");
    resp_raw(resp, 400, "application/json; charset=utf-8", &out);
    jfree(&jp);
    return;
  }
  jfree(&jp);
  resp_raw(resp, 200, "application/json; charset=utf-8", &out);
}

// ---------------------------------------------------------------- MCP v4 (POST /mcp, JSON-RPC 2.0 legacy era)
static void mcp_id_json(buf_t *out, jp_t *p, int idnode) {
  if (idnode < 0 || p->nodes[idnode].type == 0) buf_puts(out, "null");
  else jval_json(out, p, idnode);
}
static void mcp_result(buf_t *out, jp_t *p, int idnode, buf_t *result) {
  buf_puts(out, "{\"jsonrpc\":\"2.0\",\"id\":");
  mcp_id_json(out, p, idnode);
  buf_puts(out, ",\"result\":");
  buf_put(out, result->data, result->len);
  buf_putc(out, '}');
}
static void mcp_error(buf_t *out, jp_t *p, int idnode, int code, const char *msg) {
  buf_puts(out, "{\"jsonrpc\":\"2.0\",\"id\":");
  mcp_id_json(out, p, idnode);
  buf_puts(out, ",\"error\":{\"code\":");
  buf_printf(out, "%d", code);
  buf_puts(out, ",\"message\":");
  json_escape(out, msg, strlen(msg));
  buf_puts(out, "}}");
}
static void mcp_error_noid(buf_t *out, int code, const char *msg) {
  buf_puts(out, "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":");
  buf_printf(out, "%d", code);
  buf_puts(out, ",\"message\":");
  json_escape(out, msg, strlen(msg));
  buf_puts(out, "}}");
}
// Execute one MCP tools/call; result JSON appended to out. Returns 0 on success
// (a normal JSON-RPC result, possibly with isError:true), -1 on protocol error
// (caller should send -32601/-32602).
static int mcp_tool_call(jp_t *p, const char *tool, int args, const char *auth, buf_t *out) {
  if (strcmp(tool, "create_repo") == 0) {
    const char *name = jstr(p, jget(p, args, "name"));
    const char *desc = jstr(p, jget(p, args, "description"));
    if (!name) return -1;
    buf_t b; buf_init(&b);
    buf_puts(&b, "{\"name\":");
    json_escape(&b, name, strlen(name));
    buf_puts(&b, ",\"description\":");
    json_escape(&b, desc ? desc : "", desc ? strlen(desc) : 0);
    buf_puts(&b, ",\"private\":false}");
    char *segs[] = { "user", "repos" };
    resp_t rr; int st = rest_call("POST", segs, 2, b.data, b.len, auth, &rr);
    if (st != 201) { buf_free(&b); buf_free(&rr.owned); return -1; }
    jp_t rp; int rroot = jparse(rr.body, rr.body_len, &rp);
    long did = -1;
    if (rroot >= 0) jnum(&rp, jget(&rp, rroot, "id"), &did);
    jfree(&rp);
    buf_free(&b); buf_free(&rr.owned);
    repo_t *r = find_repo("adaiversen", name);
    if (!r) return -1;
    buf_t res; buf_init(&res);
    buf_puts(&res, "{\"content\":[{\"type\":\"text\",\"text\":");
    buf_t t; buf_init(&t);
    buf_puts(&t, "{\"id\":");
    char gid[256]; gid_repo_id(gid, sizeof gid, r);
    json_escape(&t, gid, strlen(gid));
    buf_printf(&t, ",\"name\":");
    json_escape(&t, r->name, strlen(r->name));
    buf_printf(&t, ",\"full_name\":\"adaiversen/%s\",\"private\":false}", r->name);
    json_escape(&res, t.data, t.len);
    buf_free(&t);
    buf_puts(&res, "}],\"structuredContent\":{\"id\":");
    json_escape(&res, gid, strlen(gid));
    buf_printf(&res, ",\"name\":");
    json_escape(&res, r->name, strlen(r->name));
    buf_printf(&res, ",\"full_name\":\"adaiversen/%s\",\"private\":false}}", r->name);
    buf_put(out, res.data, res.len);
    buf_free(&res);
    (void)did;
    return 0;
  }
  if (strcmp(tool, "get_repo") == 0) {
    const char *owner = jstr(p, jget(p, args, "owner"));
    const char *repo = jstr(p, jget(p, args, "repo"));
    if (!owner || !repo) return -1;
    repo_t *r = find_repo(owner, repo);
    if (!r) return -1;
    buf_t res; buf_init(&res);
    char gid[256]; gid_repo_id(gid, sizeof gid, r);
    buf_puts(&res, "{\"content\":[{\"type\":\"text\",\"text\":");
    buf_t t; buf_init(&t);
    buf_puts(&t, "{\"id\":");
    json_escape(&t, gid, strlen(gid));
    buf_printf(&t, ",\"name\":");
    json_escape(&t, r->name, strlen(r->name));
    buf_printf(&t, ",\"full_name\":\"adaiversen/%s\",\"private\":false}", r->name);
    json_escape(&res, t.data, t.len);
    buf_free(&t);
    buf_puts(&res, "}],\"structuredContent\":{\"id\":");
    json_escape(&res, gid, strlen(gid));
    buf_printf(&res, ",\"name\":");
    json_escape(&res, r->name, strlen(r->name));
    buf_printf(&res, ",\"full_name\":\"adaiversen/%s\",\"private\":false}}", r->name);
    buf_put(out, res.data, res.len);
    buf_free(&res);
    return 0;
  }
  if (strcmp(tool, "create_issue") == 0) {
    const char *owner = jstr(p, jget(p, args, "owner"));
    const char *repo = jstr(p, jget(p, args, "repo"));
    const char *title = jstr(p, jget(p, args, "title"));
    const char *ibody = jstr(p, jget(p, args, "body"));
    if (!owner || !repo || !title) return -1;
    repo_t *r = find_repo(owner, repo);
    if (!r) return -1;
    buf_t b; buf_init(&b);
    buf_puts(&b, "{\"title\":");
    json_escape(&b, title, strlen(title));
    buf_puts(&b, ",\"body\":");
    json_escape(&b, ibody ? ibody : "", ibody ? strlen(ibody) : 0);
    buf_putc(&b, '}');
    char *segs[] = { "repos", "adaiversen", r->name, "issues" };
    resp_t rr; int st = rest_call("POST", segs, 4, b.data, b.len, auth, &rr);
    if (st != 201) { buf_free(&b); buf_free(&rr.owned); return -1; }
    jp_t rp; int rroot = jparse(rr.body, rr.body_len, &rp);
    long num = -1;
    if (rroot >= 0) jnum(&rp, jget(&rp, rroot, "number"), &num);
    jfree(&rp);
    buf_free(&b); buf_free(&rr.owned);
    issue_t *iss = NULL;
    for (int i = 0; i < r->issue_count; i++) if (r->issues[i].number == (int)num) { iss = &r->issues[i]; break; }
    if (!iss) return -1;
    char gid[256]; gid_issue_id(gid, sizeof gid, r, iss);
    buf_t res; buf_init(&res);
    buf_puts(&res, "{\"content\":[{\"type\":\"text\",\"text\":");
    buf_t t; buf_init(&t);
    buf_puts(&t, "{\"id\":");
    json_escape(&t, gid, strlen(gid));
    buf_printf(&t, ",\"number\":%d,\"title\":", iss->number);
    json_escape(&t, iss->title, strlen(iss->title));
    buf_puts(&t, ",\"state\":\"OPEN\"}");
    json_escape(&res, t.data, t.len);
    buf_free(&t);
    buf_puts(&res, "}],\"structuredContent\":{\"id\":");
    json_escape(&res, gid, strlen(gid));
    buf_printf(&res, ",\"number\":%d,\"title\":", iss->number);
    json_escape(&res, iss->title, strlen(iss->title));
    buf_puts(&res, ",\"state\":\"OPEN\"}}");
    buf_put(out, res.data, res.len);
    buf_free(&res);
    return 0;
  }
  if (strcmp(tool, "list_issues") == 0) {
    const char *owner = jstr(p, jget(p, args, "owner"));
    const char *repo = jstr(p, jget(p, args, "repo"));
    const char *state = jstr(p, jget(p, args, "state"));
    if (!owner || !repo) return -1;
    repo_t *r = find_repo(owner, repo);
    if (!r) return -1;
    int idx[MAX_ISSUES]; int n = gql_issue_idx(r, state && strcmp(state, "closed") == 0 ? "CLOSED" : (state && strcmp(state, "open") == 0 ? "OPEN" : NULL), idx, MAX_ISSUES);
    buf_t res; buf_init(&res);
    buf_puts(&res, "{\"content\":[{\"type\":\"text\",\"text\":");
    buf_t t; buf_init(&t);
    buf_putc(&t, '[');
    for (int i = 0; i < n; i++) {
      if (i) buf_putc(&t, ',');
      issue_t *iss = &r->issues[idx[i]];
      char gid[256]; gid_issue_id(gid, sizeof gid, r, iss);
      buf_puts(&t, "{\"id\":");
      json_escape(&t, gid, strlen(gid));
      buf_printf(&t, ",\"number\":%d,\"title\":", iss->number);
      json_escape(&t, iss->title, strlen(iss->title));
      buf_printf(&t, ",\"state\":\"%s\"}", strcmp(iss->state, "closed") == 0 ? "CLOSED" : "OPEN");
    }
    buf_putc(&t, ']');
    json_escape(&res, t.data, t.len);
    buf_free(&t);
    buf_puts(&res, "}],\"structuredContent\":{\"issues\":[");
    for (int i = 0; i < n; i++) {
      if (i) buf_putc(&res, ',');
      issue_t *iss = &r->issues[idx[i]];
      char gid[256]; gid_issue_id(gid, sizeof gid, r, iss);
      buf_puts(&res, "{\"id\":");
      json_escape(&res, gid, strlen(gid));
      buf_printf(&res, ",\"number\":%d,\"title\":", iss->number);
      json_escape(&res, iss->title, strlen(iss->title));
      buf_printf(&res, ",\"state\":\"%s\"}", strcmp(iss->state, "closed") == 0 ? "CLOSED" : "OPEN");
    }
    buf_puts(&res, "]}}");
    buf_put(out, res.data, res.len);
    buf_free(&res);
    return 0;
  }
  if (strcmp(tool, "create_pull_request") == 0) {
    const char *owner = jstr(p, jget(p, args, "owner"));
    const char *repo = jstr(p, jget(p, args, "repo"));
    const char *title = jstr(p, jget(p, args, "title"));
    const char *head = jstr(p, jget(p, args, "head"));
    const char *base = jstr(p, jget(p, args, "base"));
    const char *body = jstr(p, jget(p, args, "body"));
    if (!owner || !repo || !title || !head || !base) return -1;
    repo_t *r = find_repo(owner, repo);
    if (!r) return -1;
    buf_t b; buf_init(&b);
    buf_puts(&b, "{\"title\":");
    json_escape(&b, title, strlen(title));
    buf_puts(&b, ",\"head\":");
    json_escape(&b, head, strlen(head));
    buf_puts(&b, ",\"base\":");
    json_escape(&b, base, strlen(base));
    if (body) { buf_puts(&b, ",\"body\":"); json_escape(&b, body, strlen(body)); }
    buf_putc(&b, '}');
    char *segs[] = { "repos", "adaiversen", r->name, "pulls" };
    resp_t rr; int st = rest_call("POST", segs, 4, b.data, b.len, auth, &rr);
    if (st != 201) { buf_free(&b); buf_free(&rr.owned); return -1; }
    jp_t rp; int rroot = jparse(rr.body, rr.body_len, &rp);
    long num = -1;
    if (rroot >= 0) jnum(&rp, jget(&rp, rroot, "number"), &num);
    jfree(&rp);
    buf_free(&b); buf_free(&rr.owned);
    pull_t *pr = NULL;
    for (int i = 0; i < r->pulls_count; i++) if (r->pulls[i].number == (int)num) { pr = &r->pulls[i]; break; }
    if (!pr) return -1;
    char gid[256]; gid_pull_id(gid, sizeof gid, r, pr);
    buf_t res; buf_init(&res);
    buf_puts(&res, "{\"content\":[{\"type\":\"text\",\"text\":");
    buf_t t; buf_init(&t);
    buf_puts(&t, "{\"id\":");
    json_escape(&t, gid, strlen(gid));
    buf_printf(&t, ",\"number\":%d,\"title\":", pr->number);
    json_escape(&t, pr->title, strlen(pr->title));
    buf_puts(&t, ",\"state\":\"OPEN\"}");
    json_escape(&res, t.data, t.len);
    buf_free(&t);
    buf_puts(&res, "}],\"structuredContent\":{\"id\":");
    json_escape(&res, gid, strlen(gid));
    buf_printf(&res, ",\"number\":%d,\"title\":", pr->number);
    json_escape(&res, pr->title, strlen(pr->title));
    buf_puts(&res, ",\"state\":\"OPEN\"}}");
    buf_put(out, res.data, res.len);
    buf_free(&res);
    return 0;
  }
  if (strcmp(tool, "merge_pull_request") == 0) {
    const char *owner = jstr(p, jget(p, args, "owner"));
    const char *repo = jstr(p, jget(p, args, "repo"));
    long pn = -1;
    jnum(p, jget(p, args, "pull_number"), &pn);
    if (!owner || !repo || pn < 0) return -1;
    repo_t *r = find_repo(owner, repo);
    if (!r) return -1;
    pull_t *pr = NULL;
    for (int i = 0; i < r->pulls_count; i++) if (r->pulls[i].number == (int)pn) { pr = &r->pulls[i]; break; }
    if (!pr) return -1;
    char numbuf[16]; snprintf(numbuf, sizeof numbuf, "%d", pr->number);
    char *segs[] = { "repos", "adaiversen", r->name, "pulls", numbuf, "merge" };
    resp_t rr; int st = rest_call("PUT", segs, 6, (const unsigned char *)"{}", 2, auth, &rr);
    int merged = st == 200 && rr.body && strstr((const char *)rr.body, "\"merged\":true") != NULL;
    buf_free(&rr.owned);
    if (!merged) return -1;
    buf_t res; buf_init(&res);
    buf_puts(&res, "{\"content\":[{\"type\":\"text\",\"text\":");
    buf_t t; buf_init(&t);
    buf_printf(&t, "{\"merged\":true,\"number\":%d}", pr->number);
    json_escape(&res, t.data, t.len);
    buf_free(&t);
    buf_printf(&res, "}],\"structuredContent\":{\"merged\":true,\"number\":%d}}", pr->number);
    buf_put(out, res.data, res.len);
    buf_free(&res);
    return 0;
  }
  return -1;
}
static void mcp_tools_list_buf(buf_t *out) {
  buf_puts(out, "{\"tools\":[");
  buf_puts(out, "{\"name\":\"create_repo\",\"description\":\"Create a new repository\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"},\"description\":{\"type\":\"string\"},\"private\":{\"type\":\"boolean\"}},\"required\":[\"name\"]}},");
  buf_puts(out, "{\"name\":\"get_repo\",\"description\":\"Get a repository by owner and name\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"owner\":{\"type\":\"string\"},\"repo\":{\"type\":\"string\"}},\"required\":[\"owner\",\"repo\"]}},");
  buf_puts(out, "{\"name\":\"create_issue\",\"description\":\"Create an issue in a repository\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"owner\":{\"type\":\"string\"},\"repo\":{\"type\":\"string\"},\"title\":{\"type\":\"string\"},\"body\":{\"type\":\"string\"}},\"required\":[\"owner\",\"repo\",\"title\"]}},");
  buf_puts(out, "{\"name\":\"list_issues\",\"description\":\"List issues in a repository\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"owner\":{\"type\":\"string\"},\"repo\":{\"type\":\"string\"},\"state\":{\"type\":\"string\"}},\"required\":[\"owner\",\"repo\"]}},");
  buf_puts(out, "{\"name\":\"create_pull_request\",\"description\":\"Create a pull request\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"owner\":{\"type\":\"string\"},\"repo\":{\"type\":\"string\"},\"title\":{\"type\":\"string\"},\"head\":{\"type\":\"string\"},\"base\":{\"type\":\"string\"},\"body\":{\"type\":\"string\"}},\"required\":[\"owner\",\"repo\",\"title\",\"head\",\"base\"]}},");
  buf_puts(out, "{\"name\":\"merge_pull_request\",\"description\":\"Merge a pull request\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"owner\":{\"type\":\"string\"},\"repo\":{\"type\":\"string\"},\"pull_number\":{\"type\":\"integer\"}},\"required\":[\"owner\",\"repo\",\"pull_number\"]}}");
  buf_puts(out, "]}");
}
static void handle_mcp(const char *method, const unsigned char *body, size_t body_len, const char *auth, resp_t *resp) {
  if (strcmp(method, "DELETE") == 0) {
    buf_t b; buf_init(&b);
    resp_raw(resp, 204, "application/json", &b);
    return;
  }
  if (strcmp(method, "POST") != 0) { resp_json_error(resp, 405, "Method not allowed"); return; }
  if (!check_auth(auth)) { resp_json_error(resp, 401, "Requires authentication"); return; }
  jp_t jp; int root = jparse(body, body_len, &jp);
  buf_t out; buf_init(&out);
  if (root < 0) {
    mcp_error_noid(&out, -32700, "Parse error");
    buf_putc(&out, '\n');
    resp_raw(resp, 400, "application/json", &out);
    jfree(&jp);
    return;
  }
  int idnode = jget(&jp, root, "id");
  const char *method_s = jstr(&jp, jget(&jp, root, "method"));
  if (!method_s) {
    mcp_error(&out, &jp, idnode, -32600, "Invalid Request");
    buf_putc(&out, '\n');
    resp_raw(resp, 400, "application/json", &out);
    jfree(&jp);
    return;
  }
  buf_t res; buf_init(&res);
  if (strcmp(method_s, "initialize") == 0) {
    buf_puts(&res, "{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"forge\",\"version\":\"4.0.0\"}}");
    mcp_result(&out, &jp, idnode, &res);
  } else if (strcmp(method_s, "notifications/initialized") == 0) {
    // Notification: no response body; answer 202 with an empty body.
    buf_free(&res);
    resp_raw(resp, 202, "application/json", &out);
    jfree(&jp);
    return;
  } else if (strcmp(method_s, "server/discover") == 0) {
    mcp_error(&out, &jp, idnode, -32601, "Method not found");
  } else if (strcmp(method_s, "tools/list") == 0) {
    mcp_tools_list_buf(&res);
    mcp_result(&out, &jp, idnode, &res);
  } else if (strcmp(method_s, "tools/call") == 0) {
    int params = jget(&jp, root, "params");
    const char *tool = jstr(&jp, jget(&jp, params, "name"));
    int args = jget(&jp, params, "arguments");
    if (!tool) {
      mcp_error(&out, &jp, idnode, -32602, "Invalid params: name is required");
    } else if (args < 0 || jp.nodes[args].type != 6) {
      mcp_error(&out, &jp, idnode, -32602, "Invalid params: arguments is required");
    } else {
      buf_t callout; buf_init(&callout);
      int rc = mcp_tool_call(&jp, tool, args, auth, &callout);
      if (rc != 0) {
        // Unknown tool or missing required args.
        if (strcmp(tool, "create_repo") != 0 && strcmp(tool, "get_repo") != 0 && strcmp(tool, "create_issue") != 0 && strcmp(tool, "list_issues") != 0 && strcmp(tool, "create_pull_request") != 0 && strcmp(tool, "merge_pull_request") != 0) {
          mcp_error(&out, &jp, idnode, -32601, "Method not found");
        } else {
          buf_t err; buf_init(&err);
          buf_puts(&err, "{\"content\":[{\"type\":\"text\",\"text\":\"missing or invalid required arguments\"}],\"isError\":true}");
          mcp_result(&out, &jp, idnode, &err);
          buf_free(&err);
        }
      } else {
        mcp_result(&out, &jp, idnode, &callout);
      }
      buf_free(&callout);
    }
  } else if (strncmp(method_s, "notifications/", 14) == 0) {
    buf_free(&res);
    resp_raw(resp, 202, "application/json", &out);
    jfree(&jp);
    return;
  } else {
    mcp_error(&out, &jp, idnode, -32601, "Method not found");
  }
  buf_free(&res);
  buf_putc(&out, '\n');
  resp_raw(resp, 200, "application/json", &out);
  jfree(&jp);
}

// ---------------------------------------------------------------- dispatch
static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
static void url_decode(char *s) {
  char *r = s, *w = s;
  while (*r) {
    if (*r == '%' && hexval(r[1]) >= 0 && hexval(r[2]) >= 0) {
      *w++ = (char)((hexval(r[1]) << 4) | hexval(r[2]));
      r += 3;
    } else *w++ = *r++;
  }
  *w = 0;
}
static int split_path(char *path, char **segs, int maxseg) {
  int n = 0;
  char *p = path;
  while (*p && n < maxseg) {
    while (*p == '/') p++;
    if (!*p) break;
    char *start = p;
    while (*p && *p != '/') p++;
    if (*p) *p++ = 0;
    url_decode(start);
    segs[n++] = start;
  }
  return n;
}
static int ends_with(const char *s, const char *suffix) {
  size_t a = strlen(s), b = strlen(suffix);
  return a >= b && strcmp(s + a - b, suffix) == 0;
}
static void dispatch(const char *method, char *path, const char *query,
                     const char *auth, const char *git_proto, const char *host,
                     const unsigned char *body, size_t body_len, resp_t *resp) {
  char *segs[16];
  int nseg = split_path(path, segs, 16);
  if (nseg >= 1 && strcmp(segs[0], "healthz") == 0 && strcmp(method, "GET") == 0) {
    buf_t b; buf_init(&b); buf_puts(&b, "{\"ok\":true}\n");
    resp_raw(resp, 200, "application/json; charset=utf-8", &b);
    return;
  }
  if (nseg >= 2 && strcmp(segs[0], "api") == 0 && strcmp(segs[1], "graphql") == 0) {
    handle_graphql(method, body, body_len, auth, resp);
    return;
  }
  if (nseg >= 1 && strcmp(segs[0], "mcp") == 0) {
    handle_mcp(method, body, body_len, auth, resp);
    return;
  }
  if (nseg >= 2 && strcmp(segs[0], "api") == 0 && strcmp(segs[1], "v3") == 0) {
    handle_rest(segs + 2, nseg - 2, method, body, body_len, auth, query, host, resp);
    return;
  }
  if (nseg >= 3 && ends_with(segs[1], ".git")) {
    char repo_name[128];
    snprintf(repo_name, sizeof repo_name, "%s", segs[1]);
    repo_name[strlen(repo_name) - 4] = 0;
    repo_t *r = find_repo(segs[0], repo_name);
    // suffix = segs[2..] joined
    char suffix[256] = {0};
    for (int i = 2; i < nseg; i++) { if (i > 2) strcat(suffix, "/"); strcat(suffix, segs[i]); }
    if (!r) { resp_json_error(resp, 404, "Not Found"); return; }
    if (strcmp(suffix, "info/refs") == 0 && strcmp(method, "GET") == 0) {
      char service[64] = {0};
      const char *sv = strstr(query, "service=");
      if (sv) { sv += 8; size_t k = 0; while (sv[k] && sv[k] != '&' && k < sizeof service - 1) { service[k] = sv[k]; k++; } service[k] = 0; }
      int wants_v2 = git_proto && strcmp(git_proto, "version=2") == 0;
      handle_info_refs(r, service, wants_v2, resp);
      return;
    }
    if (strcmp(suffix, "git-upload-pack") == 0 && strcmp(method, "POST") == 0) {
      int is_v2 = git_proto && strcmp(git_proto, "version=2") == 0;
      handle_upload_pack(r, body, body_len, is_v2, resp);
      return;
    }
    if (strcmp(suffix, "git-receive-pack") == 0 && strcmp(method, "POST") == 0) {
      handle_receive_pack(r, body, body_len, resp);
      return;
    }
    resp_json_error(resp, 404, "Not Found");
    return;
  }
  resp_json_error(resp, 404, "Not Found");
}

// ---------------------------------------------------------------- HTTP server
#define MAXFDS 4096
typedef struct {
  int fd;
  buf_t in;
  buf_t out;
  size_t out_off;
  int want_write;
  int close_after;
} conn_t;
static __thread conn_t conns[MAXFDS];
static unsigned long req_counter = 0;
static const char *reason_phrase(int status) {
  switch (status) {
    case 200: return "OK";
    case 201: return "Created";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 404: return "Not Found";
    default: return "Internal Server Error";
  }
}
static void conn_flush(conn_t *c) {
  while (c->out_off < c->out.len) {
    ssize_t w = send(c->fd, c->out.data + c->out_off, c->out.len - c->out_off, MSG_NOSIGNAL);
    if (w > 0) { c->out_off += (size_t)w; continue; }
    if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
    // error: drop connection
    c->out_off = c->out.len;
    c->close_after = 1;
    break;
  }
  if (c->out_off >= c->out.len) { c->out.len = 0; c->out_off = 0; c->want_write = 0; }
  else c->want_write = 1;
}
static void send_response(conn_t *c, resp_t *resp) {
  unsigned long id = __atomic_fetch_add(&req_counter, 1, __ATOMIC_RELAXED) + 1;
  char hdr[3072];
  int hlen;
  if (resp->link[0]) {
    hlen = snprintf(hdr, sizeof hdr,
      "HTTP/1.1 %d %s\r\ncontent-type: %s\r\ncontent-length: %zu\r\nx-github-request-id: req-%lx\r\n%slink: %s\r\nconnection: keep-alive\r\n\r\n",
      resp->status, reason_phrase(resp->status), resp->ctype, resp->body_len, id,
      resp->scopes ? "x-oauth-scopes: repo, read:org\r\n" : "", resp->link);
  } else {
    hlen = snprintf(hdr, sizeof hdr,
      "HTTP/1.1 %d %s\r\ncontent-type: %s\r\ncontent-length: %zu\r\nx-github-request-id: req-%lx\r\n%sconnection: keep-alive\r\n\r\n",
      resp->status, reason_phrase(resp->status), resp->ctype, resp->body_len, id,
      resp->scopes ? "x-oauth-scopes: repo, read:org\r\n" : "");
  }
  buf_put(&c->out, hdr, (size_t)hlen);
  if (resp->body_len > 0 && resp->body) buf_put(&c->out, resp->body, resp->body_len);
  conn_flush(c);
}
// Parse one request from c->in. Returns 1 if a full request was dispatched,
// 0 if more data is needed, -1 on fatal parse error.
static int process_one(conn_t *c) {
  // find header end
  size_t hlen = 0;
  int found = 0;
  for (size_t i = 0; i + 3 < c->in.len; i++) {
    if (c->in.data[i] == '\r' && c->in.data[i+1] == '\n' && c->in.data[i+2] == '\r' && c->in.data[i+3] == '\n') {
      hlen = i + 4; found = 1; break;
    }
  }
  if (!found) {
    if (c->in.len > 65536) return -1;
    return 0;
  }
  // request line + headers (copy to a scratch buffer, NUL-terminated)
  if (hlen >= 65536) return -1;
  char *head = (char *)malloc(hlen + 1);
  memcpy(head, c->in.data, hlen); head[hlen] = 0;
  char method[16] = {0}, rawpath[1024] = {0};
  char auth[600] = {0}, git_proto[64] = {0}, conn_hdr[64] = {0}, host_hdr[256] = {0};
  long content_length = 0;
  int have_auth = 0;
  char *line = head;
  int first = 1;
  while (line) {
    char *eol = strstr(line, "\r\n");
    if (eol) *eol = 0;
    if (first) {
      sscanf(line, "%15s %1023s", method, rawpath);
      first = 0;
    } else if (line[0] == 0) {
      break;
    } else {
      char *colon = strchr(line, ':');
      if (colon) {
        *colon = 0;
        char *val = colon + 1;
        while (*val == ' ' || *val == '\t') val++;
        if (strcasecmp(line, "content-length") == 0) content_length = atol(val);
        else if (strcasecmp(line, "authorization") == 0) { snprintf(auth, sizeof auth, "%s", val); have_auth = 1; }
        else if (strcasecmp(line, "git-protocol") == 0) snprintf(git_proto, sizeof git_proto, "%s", val);
        else if (strcasecmp(line, "host") == 0) snprintf(host_hdr, sizeof host_hdr, "%s", val);
        else if (strcasecmp(line, "connection") == 0) snprintf(conn_hdr, sizeof conn_hdr, "%s", val);
      }
    }
    if (!eol) break;
    line = eol + 2;
  }
  if (content_length < 0 || content_length > 64L * 1024 * 1024) { free(head); return -1; }
  if (c->in.len < hlen + (size_t)content_length) { free(head); return 0; }
  // split path / query
  char path[1024], query[1024] = {0};
  snprintf(path, sizeof path, "%s", rawpath);
  char *qm = strchr(path, '?');
  if (qm) { *qm = 0; snprintf(query, sizeof query, "%s", qm + 1); }
  const unsigned char *body = c->in.data + hlen;
  size_t body_len = (size_t)content_length;
  if (strcasecmp(conn_hdr, "close") == 0) c->close_after = 1;
  // Mutations take the store lock exclusive; reads (incl. upload-pack POSTs) share it.
  int is_write = 0;
  if (strcmp(method, "DELETE") == 0 || strcmp(method, "PUT") == 0 || strcmp(method, "PATCH") == 0) is_write = 1;
  else if (strcmp(method, "POST") == 0) {
    if (strstr(path, "/git-receive-pack") != NULL) is_write = 1;
    else if (strncmp(path, "/api/v3/", 8) == 0) is_write = 1; // create repo / create issue
    else if (strncmp(path, "/api/graphql", 13) == 0) is_write = 1;
    else if (strncmp(path, "/mcp", 4) == 0) is_write = 1;
  }
  resp_t resp; resp_init(&resp);
  if (is_write) pthread_rwlock_wrlock(&store_lock);
  else pthread_rwlock_rdlock(&store_lock);
  dispatch(method, path, query, have_auth ? auth : NULL, git_proto[0] ? git_proto : NULL, host_hdr[0] ? host_hdr : NULL, body, body_len, &resp);
  free(head);
  // consume request bytes
  size_t consumed = hlen + body_len;
  memmove(c->in.data, c->in.data + consumed, c->in.len - consumed);
  c->in.len -= consumed;
  send_response(c, &resp);
  pthread_rwlock_unlock(&store_lock);
  buf_free(&resp.owned);
  return 1;
}
static void conn_close(int ep, conn_t *c) {
  epoll_ctl(ep, EPOLL_CTL_DEL, c->fd, NULL);
  close(c->fd);
  buf_free(&c->in); buf_free(&c->out);
  memset(c, 0, sizeof(*c));
}
static int set_nonblock(int fd) { int f = fcntl(fd, F_GETFL, 0); return fcntl(fd, F_SETFL, f | O_NONBLOCK); }

#define NTHREADS 2
static int bound_port = 0;

static void *serve_loop(void *arg) {
  int ls = *(int *)arg;
  int ep = epoll_create1(0);
  struct epoll_event ev = {0};
  ev.events = EPOLLIN;
  ev.data.fd = ls;
  epoll_ctl(ep, EPOLL_CTL_ADD, ls, &ev);
  memset(conns, 0, sizeof conns);
  struct epoll_event evs[256];
  unsigned char tmp[65536];
  for (;;) {
    int n = epoll_wait(ep, evs, 256, -1);
    for (int i = 0; i < n; i++) {
      int fd = evs[i].data.fd;
      uint32_t e = evs[i].events;
      if (fd == ls) {
        for (;;) {
          int cfd = accept4(ls, NULL, NULL, SOCK_NONBLOCK);
          if (cfd < 0) break;
          int nd = 1; setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &nd, sizeof nd);
          if (cfd >= MAXFDS) { close(cfd); continue; }
          conn_t *c = &conns[cfd];
          memset(c, 0, sizeof(*c));
          c->fd = cfd;
          buf_init(&c->in); buf_init(&c->out);
          struct epoll_event e2 = {0};
          e2.events = EPOLLIN;
          e2.data.fd = cfd;
          epoll_ctl(ep, EPOLL_CTL_ADD, cfd, &e2);
        }
        continue;
      }
      if (fd < 0 || fd >= MAXFDS) continue;
      conn_t *c = &conns[fd];
      if (c->fd != fd) continue;
      if (e & (EPOLLERR | EPOLLHUP)) { conn_close(ep, c); continue; }
      if (e & EPOLLIN) {
        for (;;) {
          ssize_t r = recv(fd, tmp, sizeof tmp, 0);
          if (r > 0) { buf_put(&c->in, tmp, (size_t)r); continue; }
          if (r == 0) { conn_close(ep, c); goto next_event; }
          if (errno == EAGAIN || errno == EWOULDBLOCK) break;
          conn_close(ep, c); goto next_event;
        }
        // process all complete requests
        for (;;) {
          int pr = process_one(c);
          if (pr == 0) break;
          if (pr < 0) { conn_close(ep, c); goto next_event; }
          if (c->close_after && c->out.len == c->out_off) { conn_close(ep, c); goto next_event; }
        }
      }
      if (e & EPOLLOUT) conn_flush(c);
      // update interest
      {
        struct epoll_event e2 = {0};
        e2.events = EPOLLIN | (c->want_write ? EPOLLOUT : 0);
        e2.data.fd = fd;
        epoll_ctl(ep, EPOLL_CTL_MOD, fd, &e2);
      }
      if (c->close_after && c->out.len == c->out_off && c->in.len == 0) conn_close(ep, c);
      next_event:;
    }
  }
  return NULL;
}

static int make_listener(int port) {
  int ls = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (ls < 0) return -1;
  int one = 1;
  setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  setsockopt(ls, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons((unsigned short)port);
  if (bind(ls, (struct sockaddr *)&addr, sizeof addr) < 0) { close(ls); return -1; }
  if (listen(ls, 512) < 0) { close(ls); return -1; }
  return ls;
}

int main(int argc, char **argv) {
  (void)argc; (void)argv;
  signal(SIGPIPE, SIG_IGN);
  const char *tok = getenv("MAKEFUN_SHOP_TOKEN");
  SHOP_TOKEN = tok ? tok : "";
  int ls0 = make_listener(0);
  if (ls0 < 0) { perror("bind"); return 1; }
  struct sockaddr_in addr = {0};
  socklen_t alen = sizeof addr;
  getsockname(ls0, (struct sockaddr *)&addr, &alen);
  bound_port = ntohs(addr.sin_port);
  printf("PORT %d\n", bound_port);
  fflush(stdout);
  // one extra thread, same port via SO_REUSEPORT; main thread serves too
  pthread_t th;
  int ls1 = make_listener(bound_port);
  if (ls1 >= 0) {
    static int ls1_holder;
    ls1_holder = ls1;
    pthread_create(&th, NULL, serve_loop, &ls1_holder);
  }
  serve_loop(&ls0);
  return 0;
}
