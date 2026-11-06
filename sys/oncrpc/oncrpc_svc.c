/*	$NetBSD$	*/

/*-
 * Copyright (c) 2026 Showta Ishizaki
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * The server side of the RPC layer: sockets, a pool of worker threads,
 * and dispatch by (program, version).  The socket handling follows
 * nfssvc_addsock(), nfsrv_rcv() and nfsdsock_sendreply().
 *
 * A socket is an xprt.  Its upcall runs with the socket locked and
 * cannot receive, so it only marks the xprt and queues it for a worker.
 * One worker at a time receives on an xprt, as a connection has one
 * record marking state.  Having got a message it puts the xprt back on
 * the queue for the next one, and goes off to serve the call, so calls
 * on one connection run in parallel and replies go out in any order.
 *
 * svc_lock covers everything below that is not marked otherwise.  It
 * is taken in the upcall with the socket lock held, so the order is
 * socket lock, then svc_lock, and nothing may lock a socket holding it.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/atomic.h>
#include <sys/cprng.h>
#include <sys/condvar.h>
#include <sys/domain.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kauth.h>
#include <sys/kmem.h>
#include <sys/kthread.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/protosw.h>
#include <sys/queue.h>
#include <sys/signalvar.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <oncrpc/gss_krb5.h>
#include <oncrpc/oncrpc_gss.h>
#include <oncrpc/oncrpc_var.h>

/*
 * None of these come from the RFC.  ONCRPC_MAXMSG is the largest record
 * accepted, and ONCRPC_SOCKBUF what to ask of the socket: soreserve()
 * refuses much more than this at the default sb_max, and a stream
 * message may be larger than its buffer anyway.  ONCRPC_XPRT_MAXREQS
 * bounds the calls one peer can have in progress; beyond that its data
 * stays in the socket and TCP pushes back.
 */
#define	ONCRPC_MAXMSG		(1024 * 1024)
#define	ONCRPC_SOCKBUF		(128 * 1024)
#define	ONCRPC_XPRT_MAXREQS	64
#define	ONCRPC_BCALL_MAX	(64 * 1024)	/* a call of ours */

#define	ONCRPC_RCVALL		1000000000	/* as nfsrv_rcv() */

struct oncrpc_ireq;
struct oncrpc_xprt;

/* A call of ours on a peer's connection; see oncrpc_svc_call(). */
struct oncrpc_bcall {
	LIST_ENTRY(oncrpc_bcall) bc_list;
	uint32_t		 bc_xid;
	struct mbuf		*bc_reply;
};

static volatile uint64_t oncrpc_nextconn;

/* A registered program. */
struct oncrpc_prog {
	LIST_ENTRY(oncrpc_prog)	 pg_list;
	const struct oncrpc_program *pg_prog;
	u_int			 pg_refs;
};

struct oncrpc_worker {
	SLIST_ENTRY(oncrpc_worker) wk_list;
	struct lwp		*wk_lwp;
};

struct oncrpc_svc {
	kmutex_t		 svc_lock;
	kcondvar_t		 svc_cv;	/* work for the workers */
	kcondvar_t		 svc_progcv;	/* a pg_refs went to 0 */
	kcondvar_t		 svc_bcv;	/* a reply came, or an xprt died */
	TAILQ_HEAD(, oncrpc_xprt) svc_pending;
	LIST_HEAD(, oncrpc_xprt) svc_xprts;
	LIST_HEAD(, oncrpc_prog) svc_progs;
	SLIST_HEAD(, oncrpc_worker) svc_workers;
	u_int			 svc_nxprt;
	u_int			 svc_nworkers;
	bool			 svc_dying;
	/* Under oncrpc_named_lock, for oncrpc_svc_hold(). */
	LIST_ENTRY(oncrpc_svc)	 svc_named;
	char			 svc_name[16];
	u_int			 svc_refs;
};

/* xp_flags */
#define	XP_READABLE	0x01	/* the socket may have something */
#define	XP_QUEUED	0x02	/* on svc_pending */
#define	XP_RECEIVING	0x04	/* a worker is in xprt_getmsg() */
#define	XP_SENDING	0x08	/* a worker is in xprt_send() */
#define	XP_DEAD		0x10	/* shut down, off svc_xprts */

struct oncrpc_xprt {
	struct oncrpc_svc	*xp_svc;
	file_t			*xp_fp;
	struct socket		*xp_so;
	struct mbuf		*xp_nam;	/* the peer, if connected */
	const void		*xp_tag;	/* for closesocks */
	const struct oncrpc_program *xp_lastop;	/* served last */
	bool			 xp_mixed;	/* has served more than one */
	void			*xp_ctx;	/* see oncrpc_req_ctx() */
	void			(*xp_ctxdtor)(void *);
	u_int			 xp_refs;
	u_int			 xp_flags;
	u_int			 xp_nreqs;	/* calls in progress */
	uint64_t		 xp_id;		/* rq_connid */
	LIST_HEAD(, oncrpc_bcall) xp_bcalls;	/* waiting for a reply */
	TAILQ_ENTRY(oncrpc_xprt) xp_pending;
	LIST_ENTRY(oncrpc_xprt)	 xp_list;
	SIMPLEQ_HEAD(, oncrpc_ireq) xp_sendq;
	struct oncrpc_rm	 xp_rm;		/* XP_RECEIVING holder's */
};

/* A request, with what the program does not see. */
struct oncrpc_ireq {
	struct oncrpc_req	 ir_req;
	struct oncrpc_xprt	*ir_xprt;
	struct mbuf		*ir_msg;	/* the message; ir_args reads it */
	struct mbuf		*ir_nam;	/* the sender, if dgram */
	struct mbuf		*ir_reply;
	SIMPLEQ_ENTRY(oncrpc_ireq) ir_sendq;
	struct oncrpc_xdrmbuf	 ir_args;
	struct oncrpc_xdrmbuf	 ir_res;
	struct oncrpc_call	 ir_call;
	struct oncrpc_gss_call	 ir_gss;
};

static u_int oncrpc_nsvc;
static kmutex_t oncrpc_named_lock;
static LIST_HEAD(, oncrpc_svc) oncrpc_named =
    LIST_HEAD_INITIALIZER(oncrpc_named);

static void
xprt_queue(struct oncrpc_xprt *xp)
{
	struct oncrpc_svc *svc = xp->xp_svc;

	KASSERT(mutex_owned(&svc->svc_lock));

	if ((xp->xp_flags & (XP_QUEUED | XP_RECEIVING | XP_DEAD)) != 0 ||
	    xp->xp_nreqs >= ONCRPC_XPRT_MAXREQS)
		return;
	xp->xp_flags |= XP_QUEUED;
	TAILQ_INSERT_TAIL(&svc->svc_pending, xp, xp_pending);
	cv_signal(&svc->svc_cv);
}

/*
 * Runs with the socket locked, and must neither sleep nor touch the
 * socket.
 */
static void
xprt_upcall(struct socket *so, void *arg, int events, int waitflag)
{
	struct oncrpc_xprt *xp = arg;
	struct oncrpc_svc *svc = xp->xp_svc;

	mutex_enter(&svc->svc_lock);
	xp->xp_flags |= XP_READABLE;
	xprt_queue(xp);
	mutex_exit(&svc->svc_lock);
}

static void
xprt_rele(struct oncrpc_xprt *xp)
{
	struct oncrpc_svc *svc = xp->xp_svc;

	mutex_enter(&svc->svc_lock);
	KASSERT(xp->xp_refs > 0);
	if (--xp->xp_refs > 0) {
		mutex_exit(&svc->svc_lock);
		return;
	}
	mutex_exit(&svc->svc_lock);

	KASSERT((xp->xp_flags & XP_DEAD) != 0);
	KASSERT(SIMPLEQ_EMPTY(&xp->xp_sendq));
	if (xp->xp_ctx != NULL)
		(*xp->xp_ctxdtor)(xp->xp_ctx);
	oncrpc_rm_fini(&xp->xp_rm);
	m_freem(xp->xp_nam);
	closef(xp->xp_fp);
	kmem_free(xp, sizeof(*xp));
}

/*
 * Shut the socket and drop the reference held by being on svc_xprts.
 * Requests in progress hold their own and finish; their replies fail
 * at the socket.
 */
static void
xprt_zap(struct oncrpc_xprt *xp)
{
	struct oncrpc_svc *svc = xp->xp_svc;
	struct socket *so = xp->xp_so;

	mutex_enter(&svc->svc_lock);
	if ((xp->xp_flags & XP_DEAD) != 0) {
		mutex_exit(&svc->svc_lock);
		return;
	}
	xp->xp_flags |= XP_DEAD;
	if ((xp->xp_flags & XP_QUEUED) != 0) {
		TAILQ_REMOVE(&svc->svc_pending, xp, xp_pending);
		xp->xp_flags &= ~XP_QUEUED;
	}
	LIST_REMOVE(xp, xp_list);
	svc->svc_nxprt--;
	cv_broadcast(&svc->svc_bcv);
	mutex_exit(&svc->svc_lock);

	solock(so);
	so->so_upcall = NULL;
	so->so_upcallarg = NULL;
	so->so_rcv.sb_flags &= ~SB_UPCALL;
	soshutdown(so, SHUT_RDWR);
	sounlock(so);

	xprt_rele(xp);
}

/*
 * The next message on a stream socket, or NULL with nothing to do yet.
 * A stream that ends or breaks takes the xprt with it.
 */
static struct mbuf *
xprt_getmsg_stream(struct oncrpc_xprt *xp)
{
	struct socket *so = xp->xp_so;
	struct mbuf *m, *nam;
	struct uio auio;
	u_int cc;
	int error, flags;

	for (;;) {
		error = oncrpc_rm_next(&xp->xp_rm, &m);
		if (error == 0)
			return m;
		if (error != EAGAIN)
			goto bad;

		m = nam = NULL;
		auio.uio_resid = ONCRPC_RCVALL;
		/* not need to setup uio_vmspace */
		flags = MSG_DONTWAIT;
		error = (*so->so_receive)(so, &nam, &auio, &m, NULL, &flags);
		m_freem(nam);
		if (m == NULL) {
			if (error == EWOULDBLOCK)
				return NULL;
			goto bad;	/* an error, or the end of the stream */
		}
		cc = ONCRPC_RCVALL - auio.uio_resid;
		oncrpc_rm_input(&xp->xp_rm, m, cc);
	}
bad:
	xprt_zap(xp);
	return NULL;
}

/* The next datagram, with its sender in *namp. */
static struct mbuf *
xprt_getmsg_dgram(struct oncrpc_xprt *xp, struct mbuf **namp)
{
	struct socket *so = xp->xp_so;
	struct mbuf *m, *nam;
	struct uio auio;
	int flags;

	for (;;) {
		m = nam = NULL;
		auio.uio_resid = ONCRPC_RCVALL;
		/* not need to setup uio_vmspace */
		flags = MSG_DONTWAIT;
		(void)(*so->so_receive)(so, &nam, &auio, &m, NULL, &flags);
		if (m == NULL) {
			m_freem(nam);
			return NULL;
		}
		if (nam != NULL) {
			*namp = nam;
			return m;
		}
		m_freem(m);	/* nowhere to reply */
	}
}

static void
req_free(struct oncrpc_ireq *ir)
{
	struct oncrpc_xprt *xp = ir->ir_xprt;
	struct oncrpc_svc *svc = xp->xp_svc;
	struct oncrpc_req *rq = &ir->ir_req;

	oncrpc_gss_done(&ir->ir_gss);
	if (rq->rq_cred != NULL)
		kauth_cred_free(rq->rq_cred);
	m_freem(ir->ir_msg);
	m_freem(ir->ir_nam);
	kmem_free(ir, sizeof(*ir));

	mutex_enter(&svc->svc_lock);
	KASSERT(xp->xp_nreqs > 0);
	xp->xp_nreqs--;
	xprt_queue(xp);		/* in case it was at the limit */
	mutex_exit(&svc->svc_lock);
	xprt_rele(xp);
}

/*
 * Send the reply of ir, consuming it.  A worker finding one already
 * sending leaves its reply for that one rather than wait behind a peer
 * that does not read.
 */
static void
xprt_send(struct oncrpc_ireq *ir)
{
	struct oncrpc_xprt *xp = ir->ir_xprt;
	struct oncrpc_svc *svc = xp->xp_svc;
	struct socket *so = xp->xp_so;
	struct sockaddr *to;
	struct mbuf *m, *n;
	uint32_t *rm;
	bool zap = false;
	u_int len;
	int error;

	mutex_enter(&svc->svc_lock);
	if ((xp->xp_flags & XP_SENDING) != 0) {
		SIMPLEQ_INSERT_TAIL(&xp->xp_sendq, ir, ir_sendq);
		mutex_exit(&svc->svc_lock);
		return;
	}
	xp->xp_flags |= XP_SENDING;
	mutex_exit(&svc->svc_lock);

	for (;;) {
		m = ir->ir_reply;
		ir->ir_reply = NULL;
		len = m->m_pkthdr.len;
		to = NULL;
		if (so->so_type == SOCK_STREAM) {
			/* Always one fragment; RFC 5531 s11 allows it. */
			KASSERT(len <= ONCRPC_RM_LENMASK);
			M_PREPEND(m, ONCRPC_RM_HDRSIZE, M_WAIT);
			rm = mtod(m, uint32_t *);
			*rm = htonl(ONCRPC_RM_LAST | len);
		} else if (ir->ir_nam != NULL &&
		    (so->so_state & SS_ISCONNECTED) == 0)
			to = mtod(ir->ir_nam, struct sockaddr *);

		/*
		 * sosend() takes a chain whole or refuses it with EMSGSIZE,
		 * and a reply may be larger than the buffer.
		 */
		do {
			n = NULL;
			if (so->so_type == SOCK_STREAM &&
			    m->m_pkthdr.len > ONCRPC_SOCKBUF &&
			    (n = m_split(m, ONCRPC_SOCKBUF, M_WAIT)) == NULL) {
				m_freem(m);
				error = ENOBUFS;
				break;
			}
			error = (*so->so_send)(so, to, NULL, m, NULL, 0,
			    curlwp);
			m = n;
		} while (error == 0 && m != NULL);
		m_freem(m);
		if (error != 0 && so->so_type == SOCK_STREAM)
			zap = true;
		req_free(ir);

		mutex_enter(&svc->svc_lock);
		ir = SIMPLEQ_FIRST(&xp->xp_sendq);
		if (ir == NULL)
			break;
		SIMPLEQ_REMOVE_HEAD(&xp->xp_sendq, ir_sendq);
		mutex_exit(&svc->svc_lock);
	}
	xp->xp_flags &= ~XP_SENDING;
	mutex_exit(&svc->svc_lock);
	if (zap)
		xprt_zap(xp);
}

/*
 * A message that is the reply to a call of ours goes to whoever waits for
 * it, and with nobody waiting is dropped: RFC 5531 s9 tells a reply from
 * a call by the word after the xid.  True if m was one, and is gone.
 */
static bool
xprt_reply(struct oncrpc_xprt *xp, struct mbuf *m)
{
	struct oncrpc_svc *svc = xp->xp_svc;
	struct oncrpc_bcall *bc;
	uint32_t head[2];

	if (m_length(m) < sizeof(head))
		return false;
	m_copydata(m, 0, sizeof(head), head);
	if (ntohl(head[1]) != ONCRPC_REPLY)
		return false;
	mutex_enter(&svc->svc_lock);
	LIST_FOREACH(bc, &xp->xp_bcalls, bc_list) {
		if (bc->bc_xid == ntohl(head[0]) && bc->bc_reply == NULL) {
			bc->bc_reply = m;
			m = NULL;
			cv_broadcast(&svc->svc_bcv);
			break;
		}
	}
	mutex_exit(&svc->svc_lock);
	m_freem(m);
	return true;
}

static struct oncrpc_xprt *
xprt_byid(struct oncrpc_svc *svc, uint64_t id)
{
	struct oncrpc_xprt *xp;

	KASSERT(mutex_owned(&svc->svc_lock));

	LIST_FOREACH(xp, &svc->svc_xprts, xp_list) {
		if (xp->xp_id == id)
			return xp;
	}
	return NULL;
}

/* Is that connection still up. */
bool
oncrpc_svc_alive(struct oncrpc_svc *svc, uint64_t id)
{
	bool alive;

	mutex_enter(&svc->svc_lock);
	alive = xprt_byid(svc, id) != NULL;
	mutex_exit(&svc->svc_lock);
	return alive;
}

/*
 * A call to the peer of a connection it made to us, as the backchannel of
 * RFC 8881 s2.10.3 has it, within timeo seconds.  As oncrpc_clnt_call(),
 * but on the stream the calls come in on, so the worker that reads it
 * sorts replies from calls.  The call goes out by the way of a reply.
 */
int
oncrpc_svc_call(struct oncrpc_svc *svc, uint64_t id,
    const struct oncrpc_clnt_call *cc, int timeo)
{
	struct oncrpc_xdrmbuf ax, rx;
	struct oncrpc_bcall bc;
	struct oncrpc_xprt *xp;
	struct oncrpc_ireq *ir;
	struct mbuf *m;
	time_t end;
	int error;

	memset(&bc, 0, sizeof(bc));
	bc.bc_xid = cprng_fast32();
	oncrpc_xdrmbuf_create(&ax, NULL, ONCRPC_BCALL_MAX, XDR_ENCODE);
	if (!oncrpc_msg_encode_call(&ax.xm_xdr, bc.bc_xid, cc) ||
	    (cc->cc_encode != NULL &&
	    !(*cc->cc_encode)(&ax.xm_xdr, cc->cc_arg))) {
		XDR_DESTROY(&ax.xm_xdr);
		return EMSGSIZE;
	}
	m = oncrpc_xdrmbuf_detach(&ax);
	ir = kmem_zalloc(sizeof(*ir), KM_SLEEP);

	mutex_enter(&svc->svc_lock);
	xp = xprt_byid(svc, id);
	if (xp == NULL || xp->xp_so->so_type != SOCK_STREAM) {
		mutex_exit(&svc->svc_lock);
		kmem_free(ir, sizeof(*ir));
		m_freem(m);
		return ENOTCONN;
	}
	xp->xp_refs += 2;	/* for this, and for ir */
	xp->xp_nreqs++;
	LIST_INSERT_HEAD(&xp->xp_bcalls, &bc, bc_list);
	mutex_exit(&svc->svc_lock);

	ir->ir_xprt = xp;
	ir->ir_reply = m;
	xprt_send(ir);

	end = time_uptime + timeo;
	error = 0;
	mutex_enter(&svc->svc_lock);
	while (bc.bc_reply == NULL) {
		if ((xp->xp_flags & XP_DEAD) != 0) {
			error = ECONNRESET;
			break;
		}
		if (time_uptime >= end) {
			error = ETIMEDOUT;
			break;
		}
		(void)cv_timedwait(&svc->svc_bcv, &svc->svc_lock, hz);
	}
	LIST_REMOVE(&bc, bc_list);
	mutex_exit(&svc->svc_lock);

	if (bc.bc_reply != NULL) {
		oncrpc_xdrmbuf_create(&rx, bc.bc_reply, 0, XDR_DECODE);
		error = oncrpc_msg_decode_reply(&rx.xm_xdr, bc.bc_xid);
		if (error == 0 && cc->cc_decode != NULL &&
		    !(*cc->cc_decode)(&rx.xm_xdr, cc->cc_res))
			error = EBADRPC;
		m_freem(bc.bc_reply);
	}
	xprt_rele(xp);
	return error;
}

/*
 * A message a program made whole.  nfs_rephead() does not fill in the
 * packet header, and a copy from a reply cache has a stale one.
 */
static void
req_setraw(struct oncrpc_ireq *ir, struct mbuf *raw)
{
	struct mbuf *m;
	u_int len;

	KASSERT((raw->m_flags & M_PKTHDR) != 0);
	len = 0;
	for (m = raw; m != NULL; m = m->m_next)
		len += m->m_len;
	raw->m_pkthdr.len = len;
	m_reset_rcvif(raw);
	ir->ir_reply = raw;
}

/*
 * A reply a program made whole, header and all, for a request under
 * RPCSEC_GSS, which must have the header's verifier and the results
 * sealed.  The program's header is an accepted one with an empty
 * verifier, six words, or else a denial, which goes as it is.  Replies
 * from a cache come this way too, and so are sealed for this request,
 * whose sequence number is its own: RFC 2203 s5.3.3.1.
 */
static bool
svc_gss_raw(struct oncrpc_ireq *ir, struct mbuf **rawp)
{
	struct oncrpc_xdrmbuf hdr;
	struct oncrpc_gss_call *gg = &ir->ir_gss;
	struct mbuf *res = *rawp, *m;
	uint32_t w[6], stat;

	/* A denial is shorter than the words looked for. */
	if (res->m_pkthdr.len < 3 * (int)sizeof(w[0])) {
		m_freem(res);
		return false;
	}
	m_copydata(res, 0, 3 * sizeof(w[0]), w);
	if (ntohl(w[2]) != ONCRPC_MSG_ACCEPTED)
		return true;
	if (res->m_pkthdr.len < (int)sizeof(w)) {
		m_freem(res);
		return false;
	}
	m_copydata(res, 0, sizeof(w), w);
	stat = ntohl(w[5]);
	m_adj(res, sizeof(w));
	if (stat == ONCRPC_SUCCESS && !oncrpc_gss_wrap_results(gg, &res))
		return false;
	oncrpc_xdrmbuf_create(&hdr, NULL, UINT_MAX, XDR_ENCODE);
	if (!oncrpc_gss_verifier(gg) ||
	    !oncrpc_msg_encode_accepted_verf(&hdr.xm_xdr, ir->ir_call.c_xid,
	    gg->gg_verf, gg->gg_verfbody, gg->gg_verflen, stat, 0, 0)) {
		XDR_DESTROY(&hdr.xm_xdr);
		m_freem(res);
		return false;
	}
	m = oncrpc_xdrmbuf_detach(&hdr);
	if (res != NULL) {
		m->m_pkthdr.len += res->m_pkthdr.len;
		m_remove_pkthdr(res);
		m_cat(m, res);
	}
	*rawp = m;
	return true;
}

static struct oncrpc_prog *
svc_prog_hold(struct oncrpc_svc *svc, const struct oncrpc_call *c,
    uint32_t *lowp, uint32_t *highp, bool *known)
{
	struct oncrpc_prog *pg;
	const struct oncrpc_program *op;

	*known = false;
	mutex_enter(&svc->svc_lock);
	LIST_FOREACH(pg, &svc->svc_progs, pg_list) {
		op = pg->pg_prog;
		if (op->op_prog != c->c_prog)
			continue;
		if (c->c_vers >= op->op_vers_low &&
		    c->c_vers <= op->op_vers_high) {
			pg->pg_refs++;
			break;
		}
		/* PROG_MISMATCH gives the span of all the ranges. */
		if (!*known || op->op_vers_low < *lowp)
			*lowp = op->op_vers_low;
		if (!*known || op->op_vers_high > *highp)
			*highp = op->op_vers_high;
		*known = true;
	}
	mutex_exit(&svc->svc_lock);
	return pg;
}

static void
svc_prog_rele(struct oncrpc_svc *svc, struct oncrpc_prog *pg)
{

	mutex_enter(&svc->svc_lock);
	if (--pg->pg_refs == 0)
		cv_broadcast(&svc->svc_progcv);
	mutex_exit(&svc->svc_lock);
}

/*
 * Serve one message, consuming ir.  This is the whole of RFC 5531 s8.1:
 * in order, the RPC version, the program, its version, the credential,
 * the procedure, then what the procedure makes of the arguments.  A
 * result chain is kept apart from the header so that an error from the
 * program can forget it.
 */
static void
svc_serve(struct oncrpc_svc *svc, struct oncrpc_ireq *ir)
{
	struct oncrpc_req *rq = &ir->ir_req;
	struct oncrpc_call *c = &ir->ir_call;
	struct oncrpc_xdrmbuf hdr;
	const struct oncrpc_auth_ops *ao;
	const struct oncrpc_program *op;
	struct oncrpc_prog *pg;
	struct mbuf *res = NULL, *m;
	enum oncrpc_dispatch disp;
	uint32_t low = 0, high = 0, why, stat;
	bool gss, known, ok;
	XDR *x;

	oncrpc_xdrmbuf_create(&ir->ir_args, ir->ir_msg, 0, XDR_DECODE);
	oncrpc_xdrmbuf_create(&hdr, NULL, UINT_MAX, XDR_ENCODE);
	x = &hdr.xm_xdr;
	ok = false;

	switch (oncrpc_msg_decode_call(&ir->ir_args.xm_xdr, c)) {
	case ONCRPC_DEC_DROP:
		goto drop;
	case ONCRPC_DEC_RPCVERS:
		ok = oncrpc_msg_encode_denied_vers(x, c->c_xid);
		goto reply;
	case ONCRPC_DEC_BADCRED:
		ok = oncrpc_msg_encode_denied_auth(x, c->c_xid,
		    ONCRPC_AUTH_BADCRED);
		goto reply;
	case ONCRPC_DEC_BADVERF:
		ok = oncrpc_msg_encode_denied_auth(x, c->c_xid,
		    ONCRPC_AUTH_BADVERF);
		goto reply;
	case ONCRPC_DEC_OK:
		break;
	}

	pg = svc_prog_hold(svc, c, &low, &high, &known);
	if (pg == NULL) {
		ok = oncrpc_msg_encode_accepted(x, c->c_xid,
		    known ? ONCRPC_PROG_MISMATCH : ONCRPC_PROG_UNAVAIL,
		    low, high);
		goto reply;
	}
	op = pg->pg_prog;

	mutex_enter(&svc->svc_lock);
	if (ir->ir_xprt->xp_lastop != NULL && ir->ir_xprt->xp_lastop != op)
		ir->ir_xprt->xp_mixed = true;
	ir->ir_xprt->xp_lastop = op;
	mutex_exit(&svc->svc_lock);

	gss = c->c_cred.oa_flavor == RPCSEC_GSS;
	if (gss) {
		/*
		 * Before the procedure's own checks: a control message is
		 * not the program's to see, RFC 2203 s5, and may replace
		 * ir_msg and ir_args.
		 */
		switch (oncrpc_gss_accept(&ir->ir_gss, c, &ir->ir_args,
		    &ir->ir_msg, rq, &res, &why)) {
		case ONCRPC_GSS_DISPATCH:
			break;
		case ONCRPC_GSS_REPLY:
			svc_prog_rele(svc, pg);
			stat = ONCRPC_SUCCESS;
			goto accepted;
		case ONCRPC_GSS_GARBAGE:
			svc_prog_rele(svc, pg);
			stat = ONCRPC_GARBAGE_ARGS;
			goto accepted;
		case ONCRPC_GSS_DENY:
			svc_prog_rele(svc, pg);
			ok = oncrpc_msg_encode_denied_auth(x, c->c_xid, why);
			goto reply;
		case ONCRPC_GSS_DROP:
			svc_prog_rele(svc, pg);
			goto drop;
		}
	} else {
		rq->rq_secflavor = c->c_cred.oa_flavor;
		ao = oncrpc_auth_lookup(c->c_cred.oa_flavor);
		why = ao != NULL ? (*ao->ao_svc_verify)(c, &rq->rq_cred) :
		    ONCRPC_AUTH_REJECTEDCRED;
		/* RFC 5531 s12.1: procedure 0 never requires authentication. */
		if (why != ONCRPC_AUTH_OK && c->c_proc != 0) {
			svc_prog_rele(svc, pg);
			ok = oncrpc_msg_encode_denied_auth(x, c->c_xid, why);
			goto reply;
		}
	}

	rq->rq_xid = c->c_xid;
	rq->rq_prog = c->c_prog;
	rq->rq_vers = c->c_vers;
	rq->rq_proc = c->c_proc;
	rq->rq_flavor = c->c_cred.oa_flavor;
	rq->rq_nam = ir->ir_nam != NULL ? ir->ir_nam : ir->ir_xprt->xp_nam;
	rq->rq_connid = ir->ir_xprt->xp_id;
	rq->rq_arg = op->op_arg;
	rq->rq_args = &ir->ir_args.xm_xdr;
	oncrpc_xdrmbuf_create(&ir->ir_res, NULL, ONCRPC_MAXMSG, XDR_ENCODE);
	rq->rq_res = &ir->ir_res.xm_xdr;

	if (op->op_nprocs != 0 && c->c_proc >= op->op_nprocs)
		disp = ONCRPC_ERR_PROC;
	else
		disp = (*op->op_dispatch)(rq);
	svc_prog_rele(svc, pg);

	switch (disp) {
	case ONCRPC_DONE:
		stat = ONCRPC_SUCCESS;
		res = oncrpc_xdrmbuf_detach(&ir->ir_res);
		break;
	case ONCRPC_NOREPLY:
		XDR_DESTROY(rq->rq_res);
		goto drop;
	case ONCRPC_RAWREPLY:
		XDR_DESTROY(rq->rq_res);
		XDR_DESTROY(&hdr.xm_xdr);
		req_setraw(ir, rq->rq_raw);
		rq->rq_raw = NULL;
		if (gss) {
			if (!svc_gss_raw(ir, &ir->ir_reply)) {
				ir->ir_reply = NULL;
				req_free(ir);
				return;
			}
		}
		xprt_send(ir);
		return;
	case ONCRPC_DEFERRED:
		/* ir may be gone already; oncrpc_req_finish() has it. */
		XDR_DESTROY(&hdr.xm_xdr);
		return;
	case ONCRPC_ERR_PROC:
		stat = ONCRPC_PROC_UNAVAIL;
		break;
	case ONCRPC_ERR_ARGS:
		stat = ONCRPC_GARBAGE_ARGS;
		break;
	default:
		stat = ONCRPC_SYSTEM_ERR;
		break;
	}
	if (stat != ONCRPC_SUCCESS)
		XDR_DESTROY(rq->rq_res);
	/* RFC 2203 s5.3.3.4.1, .4: no reply if the results cannot be sealed. */
	if (gss && stat == ONCRPC_SUCCESS &&
	    !oncrpc_gss_wrap_results(&ir->ir_gss, &res))
		goto drop;
accepted:
	if (gss) {
		/* RFC 2203 s5.3.3.4.1 */
		if (!oncrpc_gss_verifier(&ir->ir_gss)) {
			m_freem(res);
			res = NULL;
			ok = oncrpc_msg_encode_denied_auth(x, c->c_xid,
			    RPCSEC_GSS_CTXPROBLEM);
		} else {
			ok = oncrpc_msg_encode_accepted_verf(x, c->c_xid,
			    ir->ir_gss.gg_verf, ir->ir_gss.gg_verfbody,
			    ir->ir_gss.gg_verflen, stat, 0, 0);
		}
	} else
		ok = oncrpc_msg_encode_accepted(x, c->c_xid, stat, 0, 0);

reply:
	if (!ok) {
		m_freem(res);
		goto drop;
	}
	m = oncrpc_xdrmbuf_detach(&hdr);
	if (res != NULL) {
		m->m_pkthdr.len += res->m_pkthdr.len;
		m_remove_pkthdr(res);
		m_cat(m, res);
	}
	ir->ir_reply = m;
	xprt_send(ir);
	return;

drop:
	XDR_DESTROY(&hdr.xm_xdr);
	req_free(ir);
}

/*
 * Serve until the server goes.  With sig also until a signal, which
 * does not wait for a queue that never empties; a signal taken instead
 * of a wakeup passes the wakeup on.
 */
static int
svc_loop(struct oncrpc_svc *svc, bool sig)
{
	struct oncrpc_xprt *xp;
	struct oncrpc_ireq *ir;
	struct mbuf *m, *nam;
	bool replied;
	int error = 0;

	mutex_enter(&svc->svc_lock);
	for (;;) {
		if (sig && sigispending(curlwp, 0)) {
			error = EINTR;
			break;
		}
		while ((xp = TAILQ_FIRST(&svc->svc_pending)) == NULL &&
		    !svc->svc_dying) {
			if (!sig) {
				cv_wait(&svc->svc_cv, &svc->svc_lock);
				continue;
			}
			error = cv_wait_sig(&svc->svc_cv, &svc->svc_lock);
			if (error != 0)
				break;
		}
		if (error != 0) {
			if (!TAILQ_EMPTY(&svc->svc_pending))
				cv_signal(&svc->svc_cv);
			break;
		}
		if (xp == NULL)
			break;
		TAILQ_REMOVE(&svc->svc_pending, xp, xp_pending);
		xp->xp_flags &= ~(XP_QUEUED | XP_READABLE);
		xp->xp_flags |= XP_RECEIVING;
		xp->xp_refs++;
		mutex_exit(&svc->svc_lock);

		nam = NULL;
		if (xp->xp_so->so_type == SOCK_STREAM)
			m = xprt_getmsg_stream(xp);
		else
			m = xprt_getmsg_dgram(xp, &nam);

		ir = NULL;
		replied = m != NULL && nam == NULL && xprt_reply(xp, m);
		if (m != NULL && !replied)
			ir = kmem_zalloc(sizeof(*ir), KM_SLEEP);

		mutex_enter(&svc->svc_lock);
		xp->xp_flags &= ~XP_RECEIVING;
		if (ir != NULL) {
			xp->xp_nreqs++;
			xp->xp_refs++;
		}
		/* There may be another message behind this one. */
		if (ir != NULL || replied || (xp->xp_flags & XP_READABLE) != 0)
			xprt_queue(xp);
		mutex_exit(&svc->svc_lock);

		if (ir != NULL) {
			ir->ir_xprt = xp;
			ir->ir_msg = m;
			ir->ir_nam = nam;
			svc_serve(svc, ir);
		}
		xprt_rele(xp);
		mutex_enter(&svc->svc_lock);
	}
	mutex_exit(&svc->svc_lock);
	return error;
}

static void
svc_worker(void *arg)
{

	(void)svc_loop(arg, false);
	kthread_exit(0);
}

/* Lend the calling thread to the server until it is signalled. */
int
oncrpc_svc_run(struct oncrpc_svc *svc)
{

	return svc_loop(svc, true);
}

static struct oncrpc_svc *
svc_alloc(void)
{
	struct oncrpc_svc *svc;

	svc = kmem_zalloc(sizeof(*svc), KM_SLEEP);
	mutex_init(&svc->svc_lock, MUTEX_DRIVER, IPL_SOFTNET);
	cv_init(&svc->svc_cv, "oncrpc");
	cv_init(&svc->svc_progcv, "oncrpcpg");
	cv_init(&svc->svc_bcv, "oncrpcbc");
	TAILQ_INIT(&svc->svc_pending);
	LIST_INIT(&svc->svc_xprts);
	LIST_INIT(&svc->svc_progs);
	SLIST_INIT(&svc->svc_workers);
	atomic_inc_uint(&oncrpc_nsvc);
	return svc;
}

/* Bring the pool up to nworkers.  Not to be called concurrently. */
static int
svc_addworkers(struct oncrpc_svc *svc, const char *name, u_int nworkers)
{
	struct oncrpc_worker *wk;
	int error;

	while (svc->svc_nworkers < nworkers) {
		wk = kmem_alloc(sizeof(*wk), KM_SLEEP);
		error = kthread_create(PRI_NONE,
		    KTHREAD_MPSAFE | KTHREAD_MUSTJOIN, NULL, svc_worker, svc,
		    &wk->wk_lwp, "%s/%u", name, svc->svc_nworkers);
		if (error != 0) {
			kmem_free(wk, sizeof(*wk));
			return error;
		}
		SLIST_INSERT_HEAD(&svc->svc_workers, wk, wk_list);
		svc->svc_nworkers++;
	}
	return 0;
}

/*
 * Create a server with nworkers threads.  It listens to nothing until
 * given sockets, and calls get PROG_UNAVAIL until given programs.
 */
int
oncrpc_svc_create(const char *name, u_int nworkers, struct oncrpc_svc **svcp)
{
	struct oncrpc_svc *svc;
	int error;

	if (nworkers == 0)
		return EINVAL;

	svc = svc_alloc();
	error = svc_addworkers(svc, name, nworkers);
	if (error != 0) {
		oncrpc_svc_destroy(svc);
		return error;
	}
	*svcp = svc;
	return 0;
}

/*
 * Stop everything.  The programs must already be unregistered, so a
 * call arriving from now on is answered with PROG_UNAVAIL, or not at
 * all.
 */
void
oncrpc_svc_destroy(struct oncrpc_svc *svc)
{
	struct oncrpc_xprt *xp;
	struct oncrpc_worker *wk;

	KASSERT(LIST_EMPTY(&svc->svc_progs));

	mutex_enter(&svc->svc_lock);
	while ((xp = LIST_FIRST(&svc->svc_xprts)) != NULL) {
		xp->xp_refs++;
		mutex_exit(&svc->svc_lock);
		xprt_zap(xp);
		xprt_rele(xp);
		mutex_enter(&svc->svc_lock);
	}
	svc->svc_dying = true;
	cv_broadcast(&svc->svc_cv);
	mutex_exit(&svc->svc_lock);

	while ((wk = SLIST_FIRST(&svc->svc_workers)) != NULL) {
		SLIST_REMOVE_HEAD(&svc->svc_workers, wk_list);
		kthread_join(wk->wk_lwp);
		kmem_free(wk, sizeof(*wk));
	}

	cv_destroy(&svc->svc_cv);
	cv_destroy(&svc->svc_progcv);
	cv_destroy(&svc->svc_bcv);
	mutex_destroy(&svc->svc_lock);
	kmem_free(svc, sizeof(*svc));
	atomic_dec_uint(&oncrpc_nsvc);
}

/*
 * The server called name, made if it is not there yet, with at least
 * nworkers threads.
 */
int
oncrpc_svc_hold(const char *name, u_int nworkers, struct oncrpc_svc **svcp)
{
	struct oncrpc_svc *svc;
	int error;

	KASSERT(strlen(name) < sizeof(svc->svc_name));

	mutex_enter(&oncrpc_named_lock);
	LIST_FOREACH(svc, &oncrpc_named, svc_named) {
		if (strcmp(svc->svc_name, name) == 0)
			break;
	}
	if (svc == NULL) {
		svc = svc_alloc();
		strlcpy(svc->svc_name, name, sizeof(svc->svc_name));
		LIST_INSERT_HEAD(&oncrpc_named, svc, svc_named);
	}
	svc->svc_refs++;
	error = svc_addworkers(svc, name, nworkers);
	mutex_exit(&oncrpc_named_lock);
	if (error != 0) {
		oncrpc_svc_rele(svc);
		return error;
	}
	*svcp = svc;
	return 0;
}

/* The caller's programs must be unregistered. */
void
oncrpc_svc_rele(struct oncrpc_svc *svc)
{

	mutex_enter(&oncrpc_named_lock);
	KASSERT(svc->svc_refs > 0);
	if (--svc->svc_refs > 0) {
		mutex_exit(&oncrpc_named_lock);
		return;
	}
	LIST_REMOVE(svc, svc_named);
	mutex_exit(&oncrpc_named_lock);
	oncrpc_svc_destroy(svc);
}

/*
 * Offer a program.  The version must not be 0 (RFC 5531 s8.1), and op
 * must stay valid until oncrpc_svc_unregister().
 */
int
oncrpc_svc_register(struct oncrpc_svc *svc, const struct oncrpc_program *op)
{
	struct oncrpc_prog *pg, *new;

	if (op->op_vers_low == 0 || op->op_vers_low > op->op_vers_high ||
	    op->op_dispatch == NULL)
		return EINVAL;

	new = kmem_zalloc(sizeof(*new), KM_SLEEP);
	new->pg_prog = op;

	mutex_enter(&svc->svc_lock);
	LIST_FOREACH(pg, &svc->svc_progs, pg_list) {
		if (pg->pg_prog->op_prog == op->op_prog &&
		    pg->pg_prog->op_vers_low <= op->op_vers_high &&
		    op->op_vers_low <= pg->pg_prog->op_vers_high) {
			mutex_exit(&svc->svc_lock);
			kmem_free(new, sizeof(*new));
			return EEXIST;
		}
	}
	LIST_INSERT_HEAD(&svc->svc_progs, new, pg_list);
	mutex_exit(&svc->svc_lock);
	return 0;
}

/* Withdraw a program, waiting for its calls in progress. */
void
oncrpc_svc_unregister(struct oncrpc_svc *svc, const struct oncrpc_program *op)
{
	struct oncrpc_prog *pg;

	mutex_enter(&svc->svc_lock);
	LIST_FOREACH(pg, &svc->svc_progs, pg_list) {
		if (pg->pg_prog == op)
			break;
	}
	KASSERT(pg != NULL);
	LIST_REMOVE(pg, pg_list);
	while (pg->pg_refs > 0)
		cv_wait(&svc->svc_progcv, &svc->svc_lock);
	mutex_exit(&svc->svc_lock);
	kmem_free(pg, sizeof(*pg));
}

/*
 * Serve a socket: a connected stream, or a datagram socket shared by
 * all its peers.  The file gets a reference of its own, as the caller
 * will close it.  nam, the peer of a stream if known, is consumed.
 */
int
oncrpc_svc_addsock(struct oncrpc_svc *svc, file_t *fp, struct mbuf *nam)
{

	return oncrpc_svc_addsock_tag(svc, fp, nam, NULL);
}

/*
 * The same, with a tag for oncrpc_svc_closesocks(): whoever added a
 * socket to a shared server closes its own and no other holder's.
 */
int
oncrpc_svc_addsock_tag(struct oncrpc_svc *svc, file_t *fp, struct mbuf *nam,
    const void *tag)
{
	struct socket *so;
	struct oncrpc_xprt *xp;
	int error, val;

	if (fp->f_type != DTYPE_SOCKET) {
		error = ENOTSOCK;
		goto bad;
	}
	so = fp->f_socket;
	if (so->so_type != SOCK_STREAM && so->so_type != SOCK_DGRAM) {
		error = EPROTOTYPE;
		goto bad;
	}

	if (so->so_type == SOCK_STREAM) {
		val = 1;
		so_setsockopt(NULL, so, SOL_SOCKET, SO_KEEPALIVE, &val,
		    sizeof(val));
	}
	if ((so->so_proto->pr_domain->dom_family == AF_INET ||
	    so->so_proto->pr_domain->dom_family == AF_INET6) &&
	    so->so_proto->pr_protocol == IPPROTO_TCP) {
		val = 1;
		so_setsockopt(NULL, so, IPPROTO_TCP, TCP_NODELAY, &val,
		    sizeof(val));
	}

	xp = kmem_zalloc(sizeof(*xp), KM_SLEEP);
	xp->xp_svc = svc;
	xp->xp_id = atomic_inc_64_nv(&oncrpc_nextconn);
	xp->xp_fp = fp;
	xp->xp_so = so;
	xp->xp_nam = nam;
	xp->xp_tag = tag;
	xp->xp_refs = 1;
	xp->xp_flags = XP_READABLE;
	SIMPLEQ_INIT(&xp->xp_sendq);
	oncrpc_rm_init(&xp->xp_rm, ONCRPC_MAXMSG);

	/*
	 * All at once under the socket lock: the upcall may run as soon as
	 * it is unlocked, and the test keeps two xprts off one socket.
	 */
	solock(so);
	error = so->so_upcall != NULL ? EBUSY :
	    soreserve(so, ONCRPC_SOCKBUF, ONCRPC_SOCKBUF);
	if (error != 0) {
		sounlock(so);
		oncrpc_rm_fini(&xp->xp_rm);
		kmem_free(xp, sizeof(*xp));
		goto bad;
	}
	mutex_enter(&fp->f_lock);
	fp->f_count++;
	mutex_exit(&fp->f_lock);
	so->so_rcv.sb_flags &= ~SB_NOINTR;
	so->so_rcv.sb_timeo = 0;
	so->so_snd.sb_flags &= ~SB_NOINTR;
	so->so_snd.sb_timeo = 0;
	so->so_upcallarg = xp;
	so->so_upcall = xprt_upcall;
	so->so_rcv.sb_flags |= SB_UPCALL;
	/* Data may have arrived before the upcall was there to see it. */
	mutex_enter(&svc->svc_lock);
	LIST_INSERT_HEAD(&svc->svc_xprts, xp, xp_list);
	svc->svc_nxprt++;
	xprt_queue(xp);
	mutex_exit(&svc->svc_lock);
	sounlock(so);
	return 0;

bad:
	m_freem(nam);
	return error;
}

/* Shut every socket added with tag.  Calls in progress finish. */
void
oncrpc_svc_closesocks(struct oncrpc_svc *svc, const void *tag)
{

	oncrpc_svc_closesocks_for(svc, tag, NULL);
}

/*
 * For a holder that is going while the others stay: with op, a connected
 * socket that has served any other program stays open, as a client of
 * that program is still on it.  Datagram sockets go whatever they have
 * served.  They are bound to the port, which the next one to start will
 * want, and a client of a stream transport is not on them.
 */
void
oncrpc_svc_closesocks_for(struct oncrpc_svc *svc, const void *tag,
    const struct oncrpc_program *op)
{
	struct oncrpc_xprt *xp;

	mutex_enter(&svc->svc_lock);
restart:
	LIST_FOREACH(xp, &svc->svc_xprts, xp_list) {
		if (xp->xp_tag != tag)
			continue;
		if (op != NULL && xp->xp_so->so_type == SOCK_STREAM &&
		    xp->xp_lastop != NULL &&
		    (xp->xp_mixed || xp->xp_lastop != op))
			continue;
		xp->xp_refs++;
		mutex_exit(&svc->svc_lock);
		xprt_zap(xp);
		xprt_rele(xp);
		mutex_enter(&svc->svc_lock);
		goto restart;
	}
	mutex_exit(&svc->svc_lock);
}

/*
 * Give the program the message and where the arguments start, for a
 * parser of its own.  rq_args is of no more use.  With no arguments the
 * cursor has run off the chain, and a parser needs a place to find that
 * there is nothing left.
 */
void
oncrpc_req_takemsg(struct oncrpc_req *rq, struct mbuf **mp, struct mbuf **mdp,
    char **posp)
{
	struct oncrpc_ireq *ir = (struct oncrpc_ireq *)rq;
	struct mbuf *m;

	oncrpc_xdrmbuf_getcursor(&ir->ir_args, mdp, posp);
	if (*mdp == NULL) {
		for (m = ir->ir_msg; m->m_next != NULL; m = m->m_next)
			continue;
		*mdp = m;
		*posp = mtod(m, char *) + m->m_len;
	}
	*mp = ir->ir_msg;
	ir->ir_msg = NULL;
}

/*
 * What the program keeps per socket, made by make on the first call
 * that asks and passed to dtor when the socket goes.  One slot, as only
 * NFS versions 2 and 3 have a use for it.
 */
void *
oncrpc_req_ctx(struct oncrpc_req *rq, void *(*make)(struct socket *),
    void (*dtor)(void *))
{
	struct oncrpc_xprt *xp = ((struct oncrpc_ireq *)rq)->ir_xprt;
	struct oncrpc_svc *svc = xp->xp_svc;
	void *ctx, *new;

	mutex_enter(&svc->svc_lock);
	ctx = xp->xp_ctx;
	mutex_exit(&svc->svc_lock);
	if (ctx != NULL)
		return ctx;

	new = (*make)(xp->xp_so);
	mutex_enter(&svc->svc_lock);
	if (xp->xp_ctx == NULL) {
		xp->xp_ctx = new;
		xp->xp_ctxdtor = dtor;
		new = NULL;
	}
	ctx = xp->xp_ctx;
	mutex_exit(&svc->svc_lock);
	if (new != NULL)
		(*dtor)(new);
	return ctx;
}

/* End a call left with ONCRPC_DEFERRED, with raw or with no reply. */
void
oncrpc_req_finish(struct oncrpc_req *rq, struct mbuf *raw)
{
	struct oncrpc_ireq *ir = (struct oncrpc_ireq *)rq;

	XDR_DESTROY(rq->rq_res);
	if (raw == NULL) {
		req_free(ir);
		return;
	}
	req_setraw(ir, raw);
	if (ir->ir_call.c_cred.oa_flavor == RPCSEC_GSS &&
	    !svc_gss_raw(ir, &ir->ir_reply)) {
		ir->ir_reply = NULL;
		req_free(ir);
		return;
	}
	xprt_send(ir);
}

u_int
oncrpc_svc_nxprt(struct oncrpc_svc *svc)
{

	return atomic_load_relaxed(&svc->svc_nxprt);
}

MODULE(MODULE_CLASS_MISC, oncrpc, "xdr,aes,des");

static int
oncrpc_modcmd(modcmd_t cmd, void *arg)
{

	switch (cmd) {
	case MODULE_CMD_INIT:
		if (gss_krb5_selftest() != 0)
			return EIO;
		oncrpc_gss_init();
		mutex_init(&oncrpc_named_lock, MUTEX_DEFAULT, IPL_NONE);
		return 0;
	case MODULE_CMD_FINI:
		if (atomic_load_relaxed(&oncrpc_nsvc) != 0)
			return EBUSY;
		oncrpc_gss_fini();
		mutex_destroy(&oncrpc_named_lock);
		return 0;
	default:
		return ENOTTY;
	}
}
