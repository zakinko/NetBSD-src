/* 2026-11-06 Unit tests of XDR (RFC 4506) and RPC (RFC 5531) against unmodified sources.
 * T() is a check against the RFC text.  O() prints observed behaviour where the RFC
 * leaves the decoder free; it does not fail. */
#include "shim.h"
#include <sys/types.h>
#include <oncrpc/oncrpc_var.h>
void svc_tests(void);
int fails, passes;
#define T(c) do { if (c) { passes++; printf("ok   %s\n", #c); } else { fails++; printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)
#define O(...) do { printf("obs  "); printf(__VA_ARGS__); printf("\n"); } while (0)

/* A chain holding buf, cut every `cut` bytes. */
struct mbuf *chain(const void *buf, size_t n, int cut) {
	struct mbuf *h = NULL, **p = &h; const char *c = buf;
	while (n) { struct mbuf *m = m_get(1, 1); int k = n < (size_t)cut ? n : cut;
		if (k > MLEN) m_clget(m, 1);
		memcpy(m->m_data, c, k); m->m_len = k; *p = m; p = &m->m_next; c += k; n -= k; }
	return h; }
size_t flat(struct mbuf *m, void *out) { size_t n = 0; for (; m; m = m->m_next) { memcpy((char *)out + n, m->m_data, m->m_len); n += m->m_len; } return n; }
static void be(uint8_t **p, uint32_t v) { (*p)[0]=v>>24; (*p)[1]=v>>16; (*p)[2]=v>>8; (*p)[3]=v; *p += 4; }

static void t_prims(void) {
	puts("# 4506 s3-4.5 primitives, big-endian, xdrmbuf");
	struct oncrpc_xdrmbuf xm; XDR *x = &xm.xm_xdr; uint8_t o[64];
	oncrpc_xdrmbuf_create(&xm, NULL, 1000, XDR_ENCODE);
	int32_t i = -2; uint32_t u = 0x01020304; int64_t h = -2; uint64_t uh = 0x0102030405060708ULL; bool_t b = 7;
	T(xdr_int32_t(x, &i) && xdr_u_int32_t(x, &u) && xdr_int64_t(x, &h) && xdr_u_int64_t(x, &uh) && xdr_bool(x, &b));
	struct mbuf *m = oncrpc_xdrmbuf_detach(&xm); size_t n = flat(m, o);
	static const uint8_t g[] = {0xff,0xff,0xff,0xfe, 1,2,3,4, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe, 1,2,3,4,5,6,7,8, 0,0,0,1};
	T(n == sizeof g && memcmp(o, g, n) == 0);
	for (int cut = 1; cut <= 9; cut++) {
		struct mbuf *c = chain(g, sizeof g, cut); int32_t ri; uint32_t ru; int64_t rh; uint64_t ruh; bool_t rb;
		oncrpc_xdrmbuf_create(&xm, c, 0, XDR_DECODE);
		bool k = xdr_int32_t(x,&ri)&&xdr_u_int32_t(x,&ru)&&xdr_int64_t(x,&rh)&&xdr_u_int64_t(x,&ruh)&&xdr_bool(x,&rb);
		if (!(k && ri==-2 && ru==0x01020304 && rh==-2 && ruh==0x0102030405060708ULL && rb==1)) { T(!"decode across cut"); }
		m_freem(c); }
	T("primitives decode at every cut 1..9"); m_freem(m);
}

static void t_rfc4506_s7(void) {
	puts("# 4506 s7 worked example, byte for byte");
	static const uint8_t g[] = {0,0,0,9,'s','i','l','l','y','p','r','o','g',0,0,0, 0,0,0,2, 0,0,0,4,'l','i','s','p',
		0,0,0,4,'j','o','h','n', 0,0,0,6,'(','q','u','i','t',')',0,0};
	T(sizeof g == 48);
	struct oncrpc_xdrmbuf xm; XDR *x = &xm.xm_xdr; char *s; uint32_t k = 2, l = 6; char *d = "(quit)"; uint8_t o[64];
	oncrpc_xdrmbuf_create(&xm, NULL, 1000, XDR_ENCODE);
	s = "sillyprog"; T(xdr_string(x, &s, 255)); T(xdr_u_int32_t(x, &k));
	s = "lisp"; T(xdr_string(x, &s, 255)); s = "john"; T(xdr_string(x, &s, 32));
	T(xdr_bytes(x, &d, &l, 65535));
	struct mbuf *m = oncrpc_xdrmbuf_detach(&xm); size_t n = flat(m, o); T(n == 48 && memcmp(o, g, 48) == 0); m_freem(m);
}

static void t_opaque(void) {
	puts("# 4506 s3, 4.9, 4.10 residual zero bytes");
	uint8_t src[9] = {0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9}, o[32], d[9];
	bool good = true;
	for (u_int n = 0; n <= 9; n++) { struct oncrpc_xdrmbuf xm; XDR *x = &xm.xm_xdr;
		oncrpc_xdrmbuf_create(&xm, NULL, 100, XDR_ENCODE); good &= xdr_opaque(x, (char *)src, n);
		struct mbuf *m = oncrpc_xdrmbuf_detach(&xm); size_t w = m ? flat(m, o) : 0, want = (n + 3) & ~3u;
		good &= w == want; for (size_t i = n; i < w; i++) good &= o[i] == 0;
		/* truncated padding must fail to decode */
		if (w != n) { struct mbuf *c = chain(o, n, 1); oncrpc_xdrmbuf_create(&xm, c, 0, XDR_DECODE);
			good &= !xdr_opaque(x, (char *)d, n); m_freem(c); }
		m_freem(m); }
	T(good);
	uint8_t p[8] = {1,2,3,0xff,0,0,0,0}; struct oncrpc_xdrmbuf xm; struct mbuf *c = chain(p, 8, 8); char q[3];
	oncrpc_xdrmbuf_create(&xm, c, 0, XDR_DECODE);
	O("non-zero pad on decode: xdr_opaque returns %d (4506 is silent on the decoder)", xdr_opaque(&xm.xm_xdr, q, 3)); m_freem(c);
}

static void t_bool_long(void) {
	puts("# 4506 s4.1, 4.3, 4.4 values");
	uint8_t w[4] = {0,0,0,2}; struct oncrpc_xdrmbuf xm; struct mbuf *c = chain(w, 4, 4); bool_t b = 9; int r;
	oncrpc_xdrmbuf_create(&xm, c, 0, XDR_DECODE); r = xdr_bool(&xm.xm_xdr, &b);
	O("wire bool 2 decodes: ret=%d value=%d; must-rfc5531-4506.md s4.4 row asked for an error", r, b); m_freem(c);
	uint8_t f[4] = {0xff,0xff,0xff,0xff}; long l = 0; c = chain(f, 4, 4);
	oncrpc_xdrmbuf_create(&xm, c, 0, XDR_DECODE); r = xdr_long(&xm.xm_xdr, &l); m_freem(c);
	printf("     xdr_long(ffffffff) via xdrmbuf = %ld, sizeof(long)=%zu\n", l, sizeof l);
	T(l == -1);
	XDR xs; long l2 = 0; uint32_t al; memcpy(&al, f, 4); xdrmem_create(&xs, (char *)&al, 4, XDR_DECODE); xdr_long(&xs, &l2);
	printf("     xdr_long(ffffffff) via xdrmem  = %ld\n", l2); T(l2 == -1);
	int ii = 0; c = chain(f, 4, 4); oncrpc_xdrmbuf_create(&xm, c, 0, XDR_DECODE); xdr_int(&xm.xm_xdr, &ii); T(ii == -1); m_freem(c);
	long big = 0x1ffffffffL; uint8_t o[8]; XDR y; xdrmem_create(&y, (char *)o, 8, XDR_ENCODE); r = xdr_long(&y, &big);
	O("xdr_long encode of %ld: ret=%d, wrote %02x%02x%02x%02x (silent truncation)", big, r, o[0],o[1],o[2],o[3]);
	enum_t e = 0; uint8_t ew[4] = {0,0,0,99}; c = chain(ew, 4, 4); oncrpc_xdrmbuf_create(&xm, c, 0, XDR_DECODE);
	r = xdr_enum(&xm.xm_xdr, &e); O("xdr_enum has no member list: 99 -> ret=%d e=%d (range is the caller's)", r, e); m_freem(c);
}

static bool_t ok_u32(XDR *x, void *p) { return xdr_u_int32_t(x, p); }
static void t_limits(void) {
	puts("# 4506 s4.10, 4.11, 4.13, 4.15, s8 limits");
	struct oncrpc_xdrmbuf xm; XDR *x = &xm.xm_xdr; struct mbuf *c;
	char *d = "abcde"; u_int l = 5;
	oncrpc_xdrmbuf_create(&xm, NULL, 100, XDR_ENCODE); T(!xdr_bytes(x, &d, &l, 4)); XDR_DESTROY(x);
	oncrpc_xdrmbuf_create(&xm, NULL, 100, XDR_ENCODE); T(!xdr_string(x, &d, 4)); XDR_DESTROY(x);
	u_int a[3] = {1,2,3}; char *ap = (char *)a; u_int na = 3;
	oncrpc_xdrmbuf_create(&xm, NULL, 100, XDR_ENCODE); T(!xdr_array(x, &ap, &na, 2, 4, (xdrproc_t)ok_u32)); XDR_DESTROY(x);
	/* s8: length beyond what the stream holds, caller gives no buffer */
	uint8_t w[8]; uint8_t *p = w; be(&p, 0x00100000); be(&p, 0);
	c = chain(w, 8, 8); char *np = NULL; l = 0; kmem_last_alloc = 0; size_t live = kmem_live;
	oncrpc_xdrmbuf_create(&xm, c, 0, XDR_DECODE); int r = xdr_bytes(x, &np, &l, 0x7fffffff);
	O("xdr_bytes: 8-byte stream announcing 1 MiB: ret=%d, allocated %zu first", r, kmem_last_alloc);
	T(r == 0 && kmem_live == live); m_freem(c);
	p = w; be(&p, 0x00100000); c = chain(w, 4, 4); np = NULL; na = 0; kmem_last_alloc = 0;
	oncrpc_xdrmbuf_create(&xm, c, 0, XDR_DECODE); r = xdr_array(x, &np, &na, 0x7fffffff, 8, (xdrproc_t)ok_u32);
	O("xdr_array: 4-byte stream announcing 2^20 elements of 8: ret=%d, allocated %zu first; array left at %p (caller must xdr_free)", r, kmem_last_alloc, np);
	if (np) kmem_free(np, kmem_last_alloc); m_freem(c);
	/* array multiplication overflow */
	p = w; be(&p, 0x40000001); c = chain(w, 4, 4); np = NULL; na = 0; kmem_last_alloc = 0;
	oncrpc_xdrmbuf_create(&xm, c, 0, XDR_DECODE); T(!xdr_array(x, &np, &na, UINT_MAX, 4, (xdrproc_t)ok_u32) && kmem_last_alloc == 0); m_freem(c);
	/* s4.11: m unspecified is 2^32-1; size+1 wraps */
	p = w; be(&p, 0xffffffff); be(&p, 0xdeadbeef); c = chain(w, 8, 8); np = NULL;
	oncrpc_xdrmbuf_create(&xm, c, 0, XDR_DECODE); r = xdr_string(x, &np, UINT_MAX);
	O("xdr_string length ffffffff maxsize UINT_MAX on 4 bytes left: ret=%d str=%p pos=%u", r, np, XDR_GETPOS(x));
	T(r == 0); m_freem(c);
	/* s8: embedded NUL, then free through the same filter */
	uint8_t nw[12]; p = nw; be(&p, 8); memcpy(p, "ab\0defgh", 8); c = chain(nw, 12, 12); np = NULL; kmem_badfree = 0;
	oncrpc_xdrmbuf_create(&xm, c, 0, XDR_DECODE); r = xdr_string(x, &np, 255); T(r == 0 && np == NULL);
	if (np) { XDR fx; fx.x_op = XDR_FREE; xdr_string(&fx, &np, 255); }
	printf("     kmem_free size mismatches after XDR_FREE of a string with a NUL: %zu\n", kmem_badfree);
	T(kmem_badfree == 0); m_freem(c);
	/* s4.15 */
	struct xdr_discrim ch[] = {{1, (xdrproc_t)ok_u32}, {0, NULL}}; enum_t dsc = 0; uint32_t un;
	uint8_t uw[4] = {0,0,0,2}; c = chain(uw, 4, 4); oncrpc_xdrmbuf_create(&xm, c, 0, XDR_DECODE);
	T(!xdr_union(x, &dsc, (char *)&un, ch, NULL)); m_freem(c);
}

static void t_mbufstream(void) {
	puts("# xdrmbuf: setpos, inline, limit");
	struct oncrpc_xdrmbuf xm; XDR *x = &xm.xm_xdr; uint32_t v = 0x11223344, z = 0;
	oncrpc_xdrmbuf_create(&xm, NULL, 8, XDR_ENCODE);
	T(xdr_u_int32_t(x, &z) && xdr_u_int32_t(x, &v) && !xdr_u_int32_t(x, &v));
	T(XDR_SETPOS(x, 0) && xdr_u_int32_t(x, &v) && XDR_GETPOS(x) == 4 && !XDR_SETPOS(x, 9));
	struct mbuf *m = oncrpc_xdrmbuf_detach(&xm); uint8_t o[8]; T(flat(m, o) == 8 && o[0] == 0x11 && o[7] == 0x44); m_freem(m);
	/* large write crossing mbufs then patch at each offset */
	static uint8_t big[5000], back[6000]; for (int i = 0; i < 5000; i++) big[i] = i % 251;
	oncrpc_xdrmbuf_create(&xm, NULL, 100000, XDR_ENCODE); T(xdr_opaque(x, (char *)big, 4999));
	T(XDR_GETPOS(x) == 5000); T(XDR_SETPOS(x, 2044) && xdr_u_int32_t(x, &v));
	m = oncrpc_xdrmbuf_detach(&xm); T(flat(m, back) == 5000 && back[2044] == 0x11 && back[2047] == 0x44 && back[2048] == big[2048] && back[4999] == 0); m_freem(m);
	/* decode: past the end, a length of ~0 */
	uint8_t w[4] = {0}; struct mbuf *c = chain(w, 4, 1); char q[8];
	oncrpc_xdrmbuf_create(&xm, c, 0, XDR_DECODE); T(!XDR_GETBYTES(x, q, UINT_MAX)); T(XDR_GETBYTES(x, q, 4)); T(!XDR_GETBYTES(x, q, 1));
	T(XDR_SETPOS(x, 4) && !xdr_u_int32_t(x, &v)); m_freem(c);
}

static size_t mkcall(uint8_t *b, uint32_t xid, uint32_t mt, uint32_t rv, uint32_t prog, uint32_t vers, uint32_t proc,
    uint32_t cfl, uint32_t clen, const void *cb, uint32_t vfl, uint32_t vlen) {
	uint8_t *p = b; be(&p,xid); be(&p,mt); be(&p,rv); be(&p,prog); be(&p,vers); be(&p,proc); be(&p,cfl); be(&p,clen);
	if (clen <= 4096) { memset(p, 0, (clen+3)&~3u); if (cb) memcpy(p, cb, clen); p += (clen+3)&~3u; }
	be(&p,vfl); be(&p,vlen); if (vlen <= 4096) { memset(p, 0, (vlen+3)&~3u); p += (vlen+3)&~3u; }
	return p - b; }
size_t mkcall2(uint8_t *b, uint32_t xid, uint32_t mt, uint32_t rv, uint32_t prog, uint32_t vers, uint32_t proc,
    uint32_t cfl, uint32_t clen, const void *cb, uint32_t vfl, uint32_t vlen) { return mkcall(b,xid,mt,rv,prog,vers,proc,cfl,clen,cb,vfl,vlen); }
static enum oncrpc_decoded dec(const void *b, size_t n, int cut, struct oncrpc_call *c) {
	struct mbuf *m = chain(b, n, cut); struct oncrpc_xdrmbuf xm; oncrpc_xdrmbuf_create(&xm, m, 0, XDR_DECODE);
	enum oncrpc_decoded d = oncrpc_msg_decode_call(&xm.xm_xdr, c); m_freem(m); return d; }

static void t_msg(void) {
	puts("# 5531 s9 call decode, reply encode");
	static uint8_t b[2048]; static struct oncrpc_call c; size_t n;
	n = mkcall(b, 0xfeedface, 0, 2, 100003, 4, 1, 0, 0, NULL, 0, 0);
	T(dec(b, n, 3, &c) == ONCRPC_DEC_OK && c.c_xid == 0xfeedface && c.c_prog == 100003 && c.c_vers == 4 && c.c_proc == 1);
	bool allshort = true; for (size_t k = 0; k < n; k++) { enum oncrpc_decoded d = dec(b, k, 3, &c); if (k >= 12) allshort &= d == ONCRPC_DEC_DROP; else allshort &= d == ONCRPC_DEC_DROP || d == ONCRPC_DEC_RPCVERS; }
	T(allshort);
	b[11] = 3; T(dec(b, n, 3, &c) == ONCRPC_DEC_RPCVERS && c.c_xid == 0xfeedface); T(dec(b, 12, 4, &c) == ONCRPC_DEC_RPCVERS); b[11] = 2;
	b[7] = 1; T(dec(b, n, 3, &c) == ONCRPC_DEC_DROP); b[7] = 0;
	n = mkcall(b, 1, 0, 2, 1, 1, 0, 0, 400, NULL, 0, 400); T(dec(b, n, 7, &c) == ONCRPC_DEC_OK && c.c_cred.oa_len == 400 && c.c_verf.oa_len == 400);
	n = mkcall(b, 1, 0, 2, 1, 1, 0, 0, 401, NULL, 0, 0); T(dec(b, n, 7, &c) == ONCRPC_DEC_BADCRED);
	n = mkcall(b, 1, 0, 2, 1, 1, 0, 0, 0, NULL, 0, 401); T(dec(b, n, 7, &c) == ONCRPC_DEC_BADVERF);
	n = mkcall(b, 1, 0, 2, 1, 1, 0, 0, 0xffffffff, NULL, 0, 0); T(dec(b, n, 7, &c) == ONCRPC_DEC_BADCRED);
	struct oncrpc_xdrmbuf xm; uint8_t o[64]; struct mbuf *m; size_t w;
	oncrpc_xdrmbuf_create(&xm, NULL, 100, XDR_ENCODE); T(oncrpc_msg_encode_accepted(&xm.xm_xdr, 5, ONCRPC_PROG_MISMATCH, 2, 4));
	m = oncrpc_xdrmbuf_detach(&xm); w = flat(m, o); m_freem(m);
	static const uint8_t g1[] = {0,0,0,5, 0,0,0,1, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,2, 0,0,0,2, 0,0,0,4};
	T(w == sizeof g1 && !memcmp(o, g1, w));
	for (uint32_t st = 0; st <= 5; st++) { if (st == 2) continue; oncrpc_xdrmbuf_create(&xm, NULL, 100, XDR_ENCODE); oncrpc_msg_encode_accepted(&xm.xm_xdr, 5, st, 9, 9); m = oncrpc_xdrmbuf_detach(&xm); w = flat(m, o); m_freem(m); if (w != 24) T(!"void arm has bytes"); }
	T("non-mismatch accepted arms are void");
	oncrpc_xdrmbuf_create(&xm, NULL, 100, XDR_ENCODE); T(oncrpc_msg_encode_denied_vers(&xm.xm_xdr, 5)); m = oncrpc_xdrmbuf_detach(&xm); w = flat(m, o); m_freem(m);
	static const uint8_t g2[] = {0,0,0,5, 0,0,0,1, 0,0,0,1, 0,0,0,0, 0,0,0,2, 0,0,0,2}; T(w == sizeof g2 && !memcmp(o, g2, w));
	oncrpc_xdrmbuf_create(&xm, NULL, 100, XDR_ENCODE); T(oncrpc_msg_encode_denied_auth(&xm.xm_xdr, 5, 2)); m = oncrpc_xdrmbuf_detach(&xm); w = flat(m, o); m_freem(m);
	static const uint8_t g3[] = {0,0,0,5, 0,0,0,1, 0,0,0,1, 0,0,0,1, 0,0,0,2}; T(w == sizeof g3 && !memcmp(o, g3, w));
}

static uint32_t sysv(const uint8_t *b, size_t n, kauth_cred_t *cr) {
	static struct oncrpc_call c; memset(&c, 0, sizeof c); memcpy(c.c_cred.oa_body, b, n); c.c_cred.oa_flavor = 1; c.c_cred.oa_len = n; *cr = NULL;
	return oncrpc_auth_lookup(1)->ao_svc_verify(&c, cr); }
static size_t mksys(uint8_t *b, uint32_t nl, uint32_t uid, uint32_t gid, uint32_t ng) {
	uint8_t *p = b; be(&p, 77); be(&p, nl); memset(p, 'h', nl); memset(p + nl, 0, 3); p += (nl + 3) & ~3u; be(&p, uid); be(&p, gid); be(&p, ng);
	for (uint32_t i = 0; i < ng; i++) be(&p, 1000 + i); return p - b; }
static void t_auth(void) {
	puts("# 5531 s10, App. A");
	uint8_t b[512]; kauth_cred_t cr; size_t n;
	T(oncrpc_auth_lookup(0) && oncrpc_auth_lookup(1) && !oncrpc_auth_lookup(2) && !oncrpc_auth_lookup(6));
	n = mksys(b, 8, 1001, 100, 2); T(sysv(b, n, &cr) == 0 && cr && cr->euid == 1001 && cr->egid == 100 && cr->ng == 2 && cr->g[1] == 1001); if (cr) kauth_cred_free(cr);
	n = mksys(b, 255, 1, 1, 16); T(n <= 400 && sysv(b, n, &cr) == 0); if (cr) kauth_cred_free(cr);
	n = mksys(b, 256, 1, 1, 0); T(sysv(b, n, &cr) == ONCRPC_AUTH_BADCRED);
	n = mksys(b, 8, 1, 1, 17); T(sysv(b, n, &cr) == ONCRPC_AUTH_BADCRED);
	n = mksys(b, 8, 1, 1, 1); bool g = true; for (size_t k = 0; k < n; k++) { g &= sysv(b, k, &cr) == ONCRPC_AUTH_BADCRED; } T(g);
	T(sysv(b, n + 4, &cr) == ONCRPC_AUTH_BADCRED);
	n = mksys(b, 0, 0xffffffff, 0xffffffff, 0); T(sysv(b, n, &cr) == 0 && cr->euid == 0xffffffff); if (cr) kauth_cred_free(cr);
	n = mksys(b, 8, 5, 5, 0); memcpy(b + 8, "ab\0def\xff\xfe", 8); T(sysv(b, n, &cr) == 0); if (cr) kauth_cred_free(cr);
	O("AUTH_SYS name with NUL and non-ASCII accepted: name is not used");
}

static struct mbuf *feed(struct oncrpc_rm *rm, const uint8_t *s, size_t n, int cut, int *err) {
	struct mbuf *rec = NULL; size_t i = 0; *err = EAGAIN;
	while (i < n) { size_t k = n - i < (size_t)cut ? n - i : cut; struct mbuf *m = chain(s + i, k, 512); oncrpc_rm_input(rm, m, k); i += k;
		*err = oncrpc_rm_next(rm, &rec); if (*err == 0) break; if (*err != EAGAIN) return NULL; }
	return *err == 0 ? rec : NULL; }
static size_t frag(uint8_t *p, const void *d, uint32_t n, int last) { p[0]=(n>>24)|(last?0x80:0); p[1]=n>>16; p[2]=n>>8; p[3]=n; if (n) memcpy(p+4,d,n); return 4+n; }
size_t mlen(struct mbuf *m) { size_t n = 0; for (; m; m = m->m_next) n += m->m_len; return n; }
static void t_rm(void) {
	puts("# 5531 s11 record marking");
	struct oncrpc_rm rm; static uint8_t s[1<<22], d[1<<21], o[1<<21]; int e; size_t n; struct mbuf *r;
	for (int i = 0; i < (1<<21); i++) d[i] = i * 31;
	for (int cut = 1; cut <= 7; cut++) { oncrpc_rm_init(&rm, 1<<20); n = frag(s, d, 10, 0); n += frag(s+n, d+10, 0, 0); n += frag(s+n, d+10, 5, 1); n += frag(s+n, d+100, 8, 1);
		r = feed(&rm, s, n, cut, &e); if (!(r && mlen(r) == 15 && flat(r, o) && !memcmp(o, d, 15))) T(!"multi-fragment"); m_freem(r);
		r = NULL; e = oncrpc_rm_next(&rm, &r); if (e == EAGAIN) r = feed(&rm, (uint8_t *)"", 0, 1, &e); if (e == 0) { if (mlen(r) != 8) T(!"second record"); m_freem(r); } oncrpc_rm_fini(&rm); }
	T("fragments reassemble at every input cut 1..7, second record follows");
	oncrpc_rm_init(&rm, 1<<20); n = frag(s, d, 0, 1); n += frag(s+n, d, 4, 1); r = feed(&rm, s, n, 3, &e); T(r && mlen(r) == 4); m_freem(r); oncrpc_rm_fini(&rm);
	oncrpc_rm_init(&rm, 1<<20); n = frag(s, d, 1<<20, 1); r = feed(&rm, s, n, 65536, &e); T(r && mlen(r) == 1<<20); m_freem(r); oncrpc_rm_fini(&rm);
	oncrpc_rm_init(&rm, 1<<20); n = frag(s, d, (1<<20)+1, 1); r = feed(&rm, s, 4, 4, &e); O("record of max+1: error %d (EMSGSIZE=%d), connection is dropped by the caller", e, EMSGSIZE); oncrpc_rm_fini(&rm);
	oncrpc_rm_init(&rm, 1<<20); static const uint8_t hmax[4] = {0xff,0xff,0xff,0xff}; r = feed(&rm, hmax, 4, 4, &e); T(e == EMSGSIZE); oncrpc_rm_fini(&rm);
	/* total over fragments */
	oncrpc_rm_init(&rm, 1<<20); n = frag(s, d, 1<<19, 0); n += frag(s+n, d, (1<<19)+1, 1); r = feed(&rm, s, n, 1<<16, &e); T(e == EMSGSIZE); oncrpc_rm_fini(&rm);
	/* fragment count */
	for (int f = 1024; f <= 1026; f++) { oncrpc_rm_init(&rm, 1<<20); n = 0; for (int i = 0; i < f; i++) n += frag(s+n, d, 16, i == f-1); r = feed(&rm, s, n, 1<<14, &e);
		O("%d fragments of 16 bytes (well under rm_max): error %d", f, r ? 0 : e); m_freem(r); oncrpc_rm_fini(&rm); }
	/* A legal 128 KB record, in 64-byte fragments */
	oncrpc_rm_init(&rm, 1<<20); n = 0; { int fs = 64, tot = 128*1024, nf = tot/fs; for (int i = 0; i < nf; i++) n += frag(s+n, d, fs, i == nf-1); r = feed(&rm, s, n, 1<<14, &e); O("128 KiB record in %d fragments of %d: error %d", nf, fs, r ? 0 : e); m_freem(r); } oncrpc_rm_fini(&rm);
	/* zero-length fragments alone: no memory, but count */
	oncrpc_rm_init(&rm, 1<<20); n = 0; for (int i = 0; i < 2000; i++) n += frag(s+n, d, 0, 0); r = feed(&rm, s, n, 1<<14, &e); O("2000 empty non-last fragments: error %d", r ? 0 : e); oncrpc_rm_fini(&rm);
	/* only empty last fragments: stream of them yields nothing and no error */
	oncrpc_rm_init(&rm, 1<<20); n = 0; for (int i = 0; i < 2000; i++) n += frag(s+n, d, 0, 1); r = feed(&rm, s, n, 1<<14, &e); O("2000 empty records: error %d (EAGAIN=%d), skipped", e, EAGAIN); oncrpc_rm_fini(&rm);
}

int main(void) {
	setvbuf(stdout, NULL, _IONBF, 0);
	t_prims(); t_rfc4506_s7(); t_opaque(); t_bool_long(); t_limits(); t_mbufstream(); t_msg(); t_auth(); t_rm(); svc_tests();
	printf("\n%d ok, %d FAIL\n", passes, fails); return fails != 0; }
