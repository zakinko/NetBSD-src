/* 2026-11-06 svc_serve() and the receive and send paths, from the real oncrpc_svc.c,
 * on a fake socket and one thread.  Locks and sleeping are stubs: nothing here
 * says anything about concurrency. */
#include "shim2.h"
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "oncrpc/oncrpc_svc.c"
extern int fails, passes;
#define T(c) do { if (c) { passes++; printf("ok   %s\n", #c); } else { fails++; printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)
#define O(...) do { printf("obs  "); printf(__VA_ARGS__); printf("\n"); } while (0)
struct mbuf *chain(const void *, size_t, int); size_t flat(struct mbuf *, void *);
size_t mkcall2(uint8_t *, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, const void *, uint32_t, uint32_t);
struct lwp *curlwp;
static uint8_t sent[1<<21]; static size_t nsent; static int nsends, send_err;
static int f_send(struct socket *so, struct sockaddr *to, struct uio *u, struct mbuf *m, struct mbuf *c, int fl, struct lwp *l) {
	nsends++; if (send_err) { m_freem(m); return send_err; } nsent += flat(m, sent + nsent); m_freem(m); return 0; }
static int rx_nam, rx_seq;
static int f_recv_eof(struct socket *so, struct mbuf **np, struct uio *u, struct mbuf **mp, struct mbuf **c, int *f) { *mp = NULL; return 0; }
static int f_recv_dg(struct socket *so, struct mbuf **np, struct uio *u, struct mbuf **mp, struct mbuf **c, int *f) {
	*mp = NULL; switch (rx_seq++) { case 0: *np = m_get(1, 1); return 0; case 1: *np = m_get(1, 1); *mp = chain("abcd", 4, 4); return 0; default: return EWOULDBLOCK; } }
static struct dom d4 = { AF_INET }; static struct proto pr = { &d4, IPPROTO_TCP };
static struct socket so; static struct file fl; static int disp_calls, disp_flav; static enum oncrpc_dispatch disp_ret; static uint32_t disp_cred;
static enum oncrpc_dispatch disp(struct oncrpc_req *rq) { disp_calls++; disp_flav = rq->rq_flavor; disp_cred = rq->rq_cred != NULL; if (disp_ret == ONCRPC_DONE) { uint32_t v = 0xabcd; xdr_u_int32_t(rq->rq_res, &v); } return disp_ret; }
static const struct oncrpc_program p1 = { 1000, 2, 3, 3, disp, NULL }, p2 = { 1000, 5, 5, 3, disp, NULL };
static struct oncrpc_svc *svc; static struct oncrpc_xprt *xp;
static uint32_t rd(size_t off) { return (uint32_t)sent[off]<<24|sent[off+1]<<16|sent[off+2]<<8|sent[off+3]; }
static void serve(const void *b, size_t n) { nsent = 0; nsends = 0; disp_calls = 0;
	struct oncrpc_ireq *ir = kmem_zalloc(sizeof *ir, KM_SLEEP); xp->xp_refs++; xp->xp_nreqs++; ir->ir_xprt = xp; ir->ir_msg = chain(b, n, 13); svc_serve(svc, ir); }
void svc_tests(void) {
	puts("# 5531 s8.1, s9, s12.1 through svc_serve(), stream");
	static uint8_t b[2048]; size_t n;
	T(oncrpc_svc_create("t", 1, &svc) == 0);
	so.so_type = SOCK_STREAM; so.so_proto = &pr; so.so_send = f_send; fl.f_type = DTYPE_SOCKET; fl.f_socket = &so;
	T(oncrpc_svc_addsock(svc, &fl, NULL) == 0); xp = LIST_FIRST(&svc->svc_xprts); TAILQ_REMOVE(&svc->svc_pending, xp, xp_pending); xp->xp_flags &= ~XP_QUEUED;
	static struct oncrpc_program z; z = p1; z.op_vers_low = 0; T(oncrpc_svc_register(svc, &z) == EINVAL);
	T(oncrpc_svc_register(svc, &p1) == 0 && oncrpc_svc_register(svc, &p2) == 0 && oncrpc_svc_register(svc, &p1) == EEXIST);
	static struct oncrpc_program r0; r0 = p1; r0.op_prog = 0; int e0 = oncrpc_svc_register(svc, &r0); O("program number 0 (8.3 reserved) registers: error %d", e0); if (e0 == 0) oncrpc_svc_unregister(svc, &r0);
	static struct oncrpc_program r8; r8 = p1; r8.op_prog = 0x80000000; e0 = oncrpc_svc_register(svc, &r8); O("program number 0x80000000 (8.3 reserved) registers: error %d", e0); if (e0 == 0) oncrpc_svc_unregister(svc, &r8);
	disp_ret = ONCRPC_DONE;
	n = mkcall2(b, 0x12345678, 0, 2, 1000, 2, 1, 0, 0, NULL, 0, 0); serve(b, n);
	T(disp_calls == 1 && nsent == 4 + 28 && rd(0) == (0x80000000u | 28) && rd(4) == 0x12345678 && rd(8) == 1 && rd(12) == 0 && rd(16) == 0 && rd(20) == 0 && rd(24) == 0 && rd(28) == 0xabcd);
	n = mkcall2(b, 7, 0, 2, 999, 2, 1, 0, 0, NULL, 0, 0); serve(b, n); T(rd(24) == ONCRPC_PROG_UNAVAIL && nsent == 28);
	n = mkcall2(b, 7, 0, 2, 1000, 4, 1, 0, 0, NULL, 0, 0); serve(b, n); T(rd(24) == ONCRPC_PROG_MISMATCH && disp_calls == 0);
	O("gap version 4 of ranges 2-3 and 5: mismatch low=%u high=%u", rd(28), rd(32));
	n = mkcall2(b, 7, 0, 2, 1000, 0, 1, 0, 0, NULL, 0, 0); serve(b, n); T(rd(24) == ONCRPC_PROG_MISMATCH);
	n = mkcall2(b, 7, 0, 2, 1000, 2, 3, 0, 0, NULL, 0, 0); serve(b, n); T(rd(24) == ONCRPC_PROC_UNAVAIL && disp_calls == 0);
	n = mkcall2(b, 7, 0, 3, 1000, 2, 3, 0, 0, NULL, 0, 0); serve(b, n); T(rd(12) == ONCRPC_MSG_DENIED && rd(16) == ONCRPC_RPC_MISMATCH && rd(20) == 2 && rd(24) == 2);
	disp_ret = ONCRPC_ERR_ARGS; n = mkcall2(b, 7, 0, 2, 1000, 2, 1, 0, 0, NULL, 0, 0); serve(b, n); T(rd(24) == ONCRPC_GARBAGE_ARGS && nsent == 28);
	disp_ret = ONCRPC_ERR_SYSTEM; serve(b, n); T(rd(24) == ONCRPC_SYSTEM_ERR && nsent == 28);
	disp_ret = ONCRPC_NOREPLY; serve(b, n); T(disp_calls == 1 && nsends == 0);
	disp_ret = ONCRPC_DONE;
	puts("# credentials");
	n = mkcall2(b, 7, 0, 2, 1000, 2, 1, 2, 0, NULL, 0, 0); serve(b, n); T(disp_calls == 0 && rd(12) == 1 && rd(16) == 1 && rd(20) == ONCRPC_AUTH_REJECTEDCRED); /* App. A for AUTH_SHORT */
	n = mkcall2(b, 7, 0, 2, 1000, 2, 1, 6, 0, NULL, 0, 0); serve(b, n); O("RPCSEC_GSS call, proc 1: denied auth_stat=%u, dispatched=%d", rd(20), disp_calls);
	n = mkcall2(b, 7, 0, 2, 1000, 2, 0, 2, 0, NULL, 0, 0); serve(b, n); T(disp_calls == 1 && rd(24) == 0); /* 12.1 */
	O("proc 0 with unknown flavor 2: dispatched=%d rq_flavor=%d cred=%u reply verf flavor=%u len=%u", disp_calls, disp_flav, disp_cred, rd(16), rd(20));
	static const uint8_t bad[4]; n = mkcall2(b, 7, 0, 2, 1000, 2, 0, 1, 4, bad, 0, 0); serve(b, n); T(disp_calls == 1 && disp_cred == 0 && rd(24) == 0);
	O("proc 0 with broken AUTH_SYS: dispatched=%d rq_flavor=%d with no credential", disp_calls, disp_flav);
	n = mkcall2(b, 7, 0, 2, 1000, 2, 1, 1, 4, bad, 0, 0); serve(b, n); T(disp_calls == 0 && rd(20) == ONCRPC_AUTH_BADCRED);
	n = mkcall2(b, 7, 0, 2, 1000, 2, 1, 7, 0, NULL, 0, 0); serve(b, n); O("AUTH_TLS on proc 1: auth_stat=%u (9289 s4 MUST is AUTH_BADCRED=1 for an implementation of it)", rd(20));
	n = mkcall2(b, 7, 0, 2, 1000, 2, 0, 7, 0, NULL, 0, 0); serve(b, n); O("AUTH_TLS probe on NULL: reply_stat=%u verf len=%u, no STARTTLS, so clients stay plain", rd(8), rd(20));
	n = mkcall2(b, 7, 0, 2, 1000, 2, 1, 0, 0, NULL, 6, 8); serve(b, n); O("AUTH_NONE cred with RPCSEC_GSS-flavored verf: dispatched=%d (accepted unlooked)", disp_calls);
	puts("# order");
	n = mkcall2(b, 7, 0, 2, 999, 2, 1, 2, 0, NULL, 0, 0); serve(b, n); O("unknown program and bad flavor: reply_stat=%u (program first)", rd(8));
	n = mkcall2(b, 7, 0, 2, 1000, 2, 3, 2, 0, NULL, 0, 0); serve(b, n); O("bad proc and bad flavor: reply_stat=%u (auth first)", rd(8));
	puts("# large reply and send failure");
	nsent = 0; nsends = 0; struct oncrpc_ireq *ir = kmem_zalloc(sizeof *ir, KM_SLEEP); xp->xp_refs++; xp->xp_nreqs++; ir->ir_xprt = xp;
	struct oncrpc_xdrmbuf x; static char big[300000]; oncrpc_xdrmbuf_create(&x, NULL, UINT_MAX, XDR_ENCODE); xdr_opaque(&x.xm_xdr, big, sizeof big); ir->ir_reply = oncrpc_xdrmbuf_detach(&x); xprt_send(ir);
	T(nsent == 4 + sizeof big && rd(0) == (0x80000000u | sizeof big)); O("300000-byte reply: one RM fragment, %d so_send calls", nsends);
	puts("# rpcfix: TOOWEAK, reserved programs, end of stream");
	disp_ret = ONCRPC_ERR_TOOWEAK; n = mkcall2(b, 7, 0, 2, 1000, 2, 1, 0, 0, NULL, 0, 0); serve(b, n);
	T(rd(8) == 1 && rd(12) == 1 && rd(16) == 1 && rd(20) == ONCRPC_AUTH_TOOWEAK && nsent == 24); disp_ret = ONCRPC_DONE;
	T(oncrpc_svc_register(svc, &r0) == EINVAL && oncrpc_svc_register(svc, &r8) == EINVAL);
	static struct oncrpc_program r6; r6 = p1; r6.op_prog = 0x7effffff; T(oncrpc_svc_register(svc, &r6) == EINVAL);
	r6.op_prog = 0x7f000000; T(oncrpc_svc_register(svc, &r6) == 0); oncrpc_svc_unregister(svc, &r6);
	/* EOF with one in progress: the reply goes out and the xprt lives until then */
	so.so_receive = f_recv_eof; rx_nam = 0;
	struct oncrpc_ireq *ir2 = kmem_zalloc(sizeof *ir2, KM_SLEEP); xp->xp_refs++; xp->xp_nreqs++; ir2->ir_xprt = xp; nsent = 0;
	T(xprt_getmsg_stream(xp) == NULL && (xp->xp_flags & XP_EOF) && !(xp->xp_flags & XP_DEAD));
	oncrpc_xdrmbuf_create(&x, NULL, 100, XDR_ENCODE); uint32_t w = 1; xdr_u_int32_t(&x.xm_xdr, &w); ir2->ir_reply = oncrpc_xdrmbuf_detach(&x);
	xp->xp_refs++; xprt_send(ir2); T(nsent == 8 && (xp->xp_flags & XP_DEAD));
	puts("# empty datagram, then a real one (fake so_receive, shaped on soreceive())");
	struct oncrpc_xprt dx; memset(&dx, 0, sizeof dx); static struct socket ds; ds.so_type = SOCK_DGRAM; ds.so_receive = f_recv_dg; dx.xp_so = &ds; rx_seq = 0;
	struct mbuf *nam = NULL, *dm = xprt_getmsg_dgram(&dx, &nam); T(dm != NULL && nam != NULL); m_freem(dm); m_freem(nam);
	dm = xprt_getmsg_dgram(&dx, &nam); T(dm == NULL);
}
