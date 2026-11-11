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
 * NFS versions 2 and 3 as a program of the RPC layer, under option
 * NFSSERVER_ONCRPC.  The layer owns the sockets and the dispatch by
 * (program, version), so that the port can be shared with version 4;
 * what is here stands where nfssvc_nfsd() and nfs_getreq() stood, in
 * front of nfsrv3_procs[], which do not change.
 *
 * The procedures take a struct nfssvc_sock, and each socket gets a
 * shadow of one with only these parts alive.
 *
 *	ns_so		page loan in nfsrv_read(), so_type in nfsrv_fsinfo()
 *	ns_tq		the queue of nfsrv_writegather()
 *	ns_wdelayhashtbl  likewise
 *
 * Its ns_flags has no SLP_VALID and it is not on nfssvc_sockhead, so
 * that nfsrv_timer() and nfsrv_init() never see it.  ns_uidhashtbl was
 * for AUTH_KERB only, which the layer rejects: nfs_rephead() does not
 * look at it unless ND_KERBFULL, and nothing here sets that.
 *
 * nfs_rephead() writes the RPC header into the reply, from inside the
 * procedures, so replies go back through ONCRPC_RAWREPLY as they are.
 *
 * Write gathering holds a call past its dispatch.  It belongs to no
 * thread of the layer, which can be lent by nfsd and gone, so a thread
 * here takes the place of nfsrv_timer() waking an nfsd.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#ifdef _KERNEL_OPT
#include "opt_nfs_oncrpc.h"
#endif

#include <sys/param.h>
#include <sys/condvar.h>
#include <sys/file.h>
#include <sys/kauth.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/kthread.h>
#include <sys/mbuf.h>
#include <sys/mount.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/vnode.h>

#include <nfs/nfsproto.h>
#include <nfs/rpcv2.h>
#include <nfs/nfs.h>
#include <nfs/nfsrvcache.h>
#include <nfs/nfs_var.h>

#include <oncrpc/oncrpc.h>
#include <oncrpc/oncrpc_gss.h>
#include <oncrpc/oncrpc_tls.h>

/* RFC 1094 s2.2.9, writeargs up to the data: the handle and four words. */
#define	NFSX_V2WRITEHDR	(NFSX_V2FH + 4 * NFSX_UNSIGNED)

/* A write held by nfsrv_writegather(), and the call it answers. */
struct nfs_oncrpc_call {
	LIST_ENTRY(nfs_oncrpc_call) nc_list;
	struct nfsrv_descript	*nc_nd;
	struct oncrpc_req	*nc_rq;
};

/* All under nfsd_lock but nx_slp, which has its own rules in nfs.h. */
struct nfs_oncrpc_xprt {
	struct nfssvc_sock	 nx_slp;
	LIST_ENTRY(nfs_oncrpc_xprt) nx_list;
	LIST_HEAD(, nfs_oncrpc_call) nx_calls;
	u_int			 nx_refs;	/* the socket, the gatherer */
};

extern int nfsrvw_procrastinate;
extern int (*nfsrv3_procs[NFS_NPROCS])(struct nfsrv_descript *,
    struct nfssvc_sock *, struct lwp *, struct mbuf **);

static struct oncrpc_svc *nfs_oncrpc_svc;
static LIST_HEAD(, nfs_oncrpc_xprt) nfs_oncrpc_xprts =
    LIST_HEAD_INITIALIZER(nfs_oncrpc_xprts);
static kcondvar_t nfs_oncrpc_gathercv;
static struct lwp *nfs_oncrpc_gatherlwp;
static bool nfs_oncrpc_dying;
static const char nfs_oncrpc_tag[] = "nfssvc";

static void *
nfs_oncrpc_xprt_make(struct socket *so)
{
	struct nfs_oncrpc_xprt *nx;

	nx = kmem_zalloc(sizeof(*nx), KM_SLEEP);
	nx->nx_slp.ns_so = so;
	LIST_INIT(&nx->nx_slp.ns_tq);
	LIST_INIT(&nx->nx_calls);
	nx->nx_refs = 1;
	mutex_enter(&nfsd_lock);
	LIST_INSERT_HEAD(&nfs_oncrpc_xprts, nx, nx_list);
	mutex_exit(&nfsd_lock);
	return nx;
}

static void
nfs_oncrpc_xprt_rele(struct nfs_oncrpc_xprt *nx)
{
	bool last;

	mutex_enter(&nfsd_lock);
	last = --nx->nx_refs == 0;
	mutex_exit(&nfsd_lock);
	if (last)
		kmem_free(nx, sizeof(*nx));
}

static void
nfs_oncrpc_xprt_dtor(void *arg)
{
	struct nfs_oncrpc_xprt *nx = arg;

	KASSERT(LIST_EMPTY(&nx->nx_calls));
	mutex_enter(&nfsd_lock);
	LIST_REMOVE(nx, nx_list);
	mutex_exit(&nfsd_lock);
	nfs_oncrpc_xprt_rele(nx);
}

/* A gathered write is done: nd goes, and the call it stood for ends. */
static void
nfs_oncrpc_gather_reply(struct nfs_oncrpc_xprt *nx, struct nfsrv_descript *nd,
    struct mbuf *mreq)
{
	struct nfs_oncrpc_call *nc;
	struct oncrpc_req *rq;

	nfsstats.srvrpccnt[nd->nd_procnum]++;
	nfsrv_updatecache(nd, true, mreq);
	nd->nd_mrep = NULL;

	mutex_enter(&nfsd_lock);
	LIST_FOREACH(nc, &nx->nx_calls, nc_list) {
		if (nc->nc_nd == nd)
			break;
	}
	KASSERT(nc != NULL);
	LIST_REMOVE(nc, nc_list);
	mutex_exit(&nfsd_lock);

	rq = nc->nc_rq;
	kmem_free(nc, sizeof(*nc));
	nfsdreq_free(nd);
	oncrpc_req_finish(rq, mreq);
}

static void
nfs_oncrpc_gather_flush(struct nfs_oncrpc_xprt *nx)
{
	struct nfsrv_descript *nd;
	struct mbuf *mreq;

	for (;;) {
		nd = NULL;
		mreq = NULL;
		netexport_rdlock();
		(void)nfsrv_writegather(&nd, &nx->nx_slp, curlwp, &mreq);
		netexport_rdunlock();
		if (mreq == NULL)
			return;
		nfs_oncrpc_gather_reply(nx, nd, mreq);
	}
}

static void
nfs_oncrpc_gatherer(void *arg)
{
	struct nfs_oncrpc_xprt *nx, *due;
	struct nfsrv_descript *nd;
	struct timeval tv;
	u_quad_t now, next;
	int ticks_;

	mutex_enter(&nfsd_lock);
	for (;;) {
		getmicrotime(&tv);
		now = (u_quad_t)tv.tv_sec * 1000000 + (u_quad_t)tv.tv_usec;
		next = UQUAD_MAX;
		due = NULL;
		LIST_FOREACH(nx, &nfs_oncrpc_xprts, nx_list) {
			nd = LIST_FIRST(&nx->nx_slp.ns_tq);
			if (nd == NULL)
				continue;
			if (nd->nd_time <= now) {
				due = nx;
				break;
			}
			if (nd->nd_time < next)
				next = nd->nd_time;
		}
		if (due != NULL) {
			due->nx_refs++;
			mutex_exit(&nfsd_lock);
			nfs_oncrpc_gather_flush(due);
			nfs_oncrpc_xprt_rele(due);
			mutex_enter(&nfsd_lock);
		} else if (next != UQUAD_MAX) {
			ticks_ = (next - now) * hz / 1000000 + 1;
			(void)cv_timedwait(&nfs_oncrpc_gathercv, &nfsd_lock,
			    ticks_);
		} else if (nfs_oncrpc_dying)
			break;
		else
			cv_wait(&nfs_oncrpc_gathercv, &nfsd_lock);
	}
	mutex_exit(&nfsd_lock);
	kthread_exit(0);
}

/*
 * Hand nd to write gathering.  The call may be over, in another thread,
 * as soon as nd is queued, so nothing of rq is touched after that.
 */
static enum oncrpc_dispatch
nfs_oncrpc_gather(struct nfs_oncrpc_xprt *nx, struct nfsrv_descript *nd,
    struct oncrpc_req *rq)
{
	struct nfs_oncrpc_call *nc;
	struct mbuf *mreq;

	nc = kmem_alloc(sizeof(*nc), KM_SLEEP);
	nc->nc_nd = nd;
	nc->nc_rq = rq;
	mutex_enter(&nfsd_lock);
	LIST_INSERT_HEAD(&nx->nx_calls, nc, nc_list);
	mutex_exit(&nfsd_lock);

	mreq = NULL;
	netexport_rdlock();
	(void)nfsrv_writegather(&nd, &nx->nx_slp, curlwp, &mreq);
	netexport_rdunlock();
	if (mreq != NULL)
		nfs_oncrpc_gather_reply(nx, nd, mreq);

	mutex_enter(&nfsd_lock);
	cv_broadcast(&nfs_oncrpc_gathercv);
	mutex_exit(&nfsd_lock);
	return ONCRPC_DEFERRED;
}

/* Bytes of the call from the parse position on. */
static u_int
nfs_oncrpc_avail(const struct nfsrv_descript *nd)
{
	const struct mbuf *m = nd->nd_md;
	u_int len;

	len = mtod(m, char *) + m->m_len - (char *)nd->nd_dpos;
	for (m = m->m_next; m != NULL; m = m->m_next)
		len += m->m_len;
	return len;
}

/*
 * The RC_ cases are those of nfssvc_nfsd(), with one difference: a reply
 * with an error from the procedure is freed, where the loop there drops
 * the pointer.  Nothing keeps it, nfsrv_updatecache() with false least
 * of all.  nfsrtton is not honoured; it can only be set from a debugger.
 */
static enum oncrpc_dispatch
nfs_oncrpc_dispatch(struct oncrpc_req *rq)
{
	struct nfs_oncrpc_xprt *nx;
	struct nfsrv_descript *nd;
	struct mbuf *mreq, *mrep, *md;
	char *dpos;
	int cacherep, error;
	bool v3 = rq->rq_vers == NFS_VER3;

	/* nfsrv_getcache() and the exports go by the peer's address. */
	if (rq->rq_nam == NULL)
		return ONCRPC_ERR_SYSTEM;
	if (rq->rq_proc > NFSPROC_COMMIT ||
	    (!v3 && rq->rq_proc > NFSV2PROC_STATFS))
		return ONCRPC_ERR_PROC;

	nx = oncrpc_req_ctx(rq, nfs_oncrpc_xprt_make, nfs_oncrpc_xprt_dtor);

	oncrpc_req_takemsg(rq, &mrep, &md, &dpos);
	m_claimm(mrep, &nfs_mowner);
	nd = nfsdreq_alloc();
	nd->nd_mrep = mrep;
	nd->nd_md = md;
	nd->nd_dpos = dpos;
	nd->nd_nam = rq->rq_nam;
	/*
	 * The layer keeps the address, so nothing here frees this.  It is
	 * set for a datagram because NFS_SRVMAXDATA() tells the transport
	 * by it: without it a READ asks for more than UDP can carry, and
	 * the reply is never sent.
	 */
	nd->nd_nam2 = nx->nx_slp.ns_so->so_type == SOCK_DGRAM ?
	    rq->rq_nam : NULL;
	nd->nd_retxid = rq->rq_xid;
	nd->nd_repstat = 0;
	nd->nd_flag = v3 ? ND_NFSV3 : 0;
	nd->nd_procnum = v3 ? rq->rq_proc : nfsv3_procid[rq->rq_proc];
	/*
	 * Taken, not shared: nfsrv_fhtovp() maps root by changing the
	 * credential, which wants the only reference.
	 */
	nd->nd_cr = rq->rq_cred;
	rq->rq_cred = NULL;
	if (rq->rq_flavor == RPCSEC_GSS) {
		nd->nd_flag |= (rq->rq_secflavor == RPCSEC_GSS_KRB5 ?
		    NFS_EXSEC_KRB5 : rq->rq_secflavor == RPCSEC_GSS_KRB5I ?
		    NFS_EXSEC_KRB5I : NFS_EXSEC_KRB5P) << ND_SECSHIFT;
	} else if (nd->nd_procnum != NFSPROC_NULL &&
	    rq->rq_flavor != RPCAUTH_UNIX) {
		/* AUTH_NONE passes the layer; as in nfs_getreq(). */
		nd->nd_repstat = (NFSERR_AUTHERR | AUTH_REJECTCRED);
		nd->nd_procnum = NFSPROC_NOOP;
	}
	getmicrotime(&nd->nd_starttime);

	cacherep = nfsrv_getcache(nd, &nx->nx_slp, &mreq);
	switch (cacherep) {
	case RC_DOIT:
		if (!v3 && nd->nd_procnum == NFSPROC_WRITE &&
		    nfsrvw_procrastinate > 0) {
			/* Too short to be a WRITE, as for nfsm_dissect(). */
			if (nfs_oncrpc_avail(nd) < NFSX_V2WRITEHDR) {
				m_freem(nd->nd_mrep);
				nfsrv_updatecache(nd, false, NULL);
				nfsdreq_free(nd);
				return ONCRPC_ERR_ARGS;
			}
			return nfs_oncrpc_gather(nx, nd, rq);
		}
		mreq = NULL;
		netexport_rdlock();
		error = (*nfsrv3_procs[nd->nd_procnum])(nd, &nx->nx_slp,
		    curlwp, &mreq);
		netexport_rdunlock();
		if (mreq == NULL) {
			/*
			 * nfsm_dissect() ran off the arguments and left with
			 * no reply; those nfsm_reply() sees are answered by
			 * nfs_rephead().  The cache entry would stay in
			 * progress and drop every retransmission.
			 */
			if (error != 0)
				nfsrv_updatecache(nd, false, NULL);
			nfsdreq_free(nd);
			if (error == 0)
				return ONCRPC_NOREPLY;
			return error == EBADRPC ? ONCRPC_ERR_ARGS :
			    ONCRPC_ERR_SYSTEM;
		}
		if (error != 0) {
			nfsstats.srv_errs++;
			nfsrv_updatecache(nd, false, mreq);
			m_freem(mreq);
			nfsdreq_free(nd);
			return ONCRPC_NOREPLY;
		}
		nfsstats.srvrpccnt[nd->nd_procnum]++;
		nfsrv_updatecache(nd, true, mreq);
		nd->nd_mrep = NULL;
		/* FALLTHROUGH */
	case RC_REPLY:
		m_freem(nd->nd_mrep);
		nfsdreq_free(nd);
		rq->rq_raw = mreq;
		return ONCRPC_RAWREPLY;
	default:	/* RC_DROPIT */
		m_freem(nd->nd_mrep);
		nfsdreq_free(nd);
		return ONCRPC_NOREPLY;
	}
}

static const struct oncrpc_program nfs_oncrpc_program = {
	.op_prog = NFS_PROG,
	.op_vers_low = NFS_VER2,
	.op_vers_high = NFS_VER3,
	.op_dispatch = nfs_oncrpc_dispatch,
};

int
nfs_oncrpc_init(void)
{
	int error;

	/* The threads are the nfsds', as many as nfsd -n says. */
	error = oncrpc_svc_hold("nfs", 0, &nfs_oncrpc_svc);
	if (error != 0)
		return error;
	error = oncrpc_svc_register(nfs_oncrpc_svc, &nfs_oncrpc_program);
	if (error != 0) {
		oncrpc_svc_rele(nfs_oncrpc_svc);
		return error;
	}
	cv_init(&nfs_oncrpc_gathercv, "nfsgathr");
	nfs_oncrpc_dying = false;
	error = kthread_create(PRI_NONE, KTHREAD_MPSAFE | KTHREAD_MUSTJOIN,
	    NULL, nfs_oncrpc_gatherer, NULL, &nfs_oncrpc_gatherlwp,
	    "nfsgather");
	if (error != 0) {
		cv_destroy(&nfs_oncrpc_gathercv);
		oncrpc_svc_unregister(nfs_oncrpc_svc, &nfs_oncrpc_program);
		oncrpc_svc_rele(nfs_oncrpc_svc);
	}
	return error;
}

void
nfs_oncrpc_fini(void)
{

	oncrpc_svc_unregister(nfs_oncrpc_svc, &nfs_oncrpc_program);
	oncrpc_svc_closesocks(nfs_oncrpc_svc, nfs_oncrpc_tag);

	/* What is queued runs out; each entry is due within the delay. */
	mutex_enter(&nfsd_lock);
	nfs_oncrpc_dying = true;
	cv_broadcast(&nfs_oncrpc_gathercv);
	mutex_exit(&nfsd_lock);
	kthread_join(nfs_oncrpc_gatherlwp);
	cv_destroy(&nfs_oncrpc_gathercv);

	oncrpc_svc_rele(nfs_oncrpc_svc);
}

int
nfs_oncrpc_addsock(file_t *fp, struct mbuf *nam)
{

	return oncrpc_svc_addsock_tag(nfs_oncrpc_svc, fp, nam, nfs_oncrpc_tag);
}

int
nfs_oncrpc_run(void)
{

	return oncrpc_svc_run(nfs_oncrpc_svc);
}

/* NFSSVC_TLSWAIT and NFSSVC_TLSDONE, for the TLS handshake daemon. */
int
nfs_oncrpc_tls(int flag, void *argp)
{
	struct nfsd_tlsarg nt;
	int error;

	struct oncrpc_tls_params tp;
	struct oncrpc_tls_event ev;
	struct oncrpc_tls_dgram dg;
	uint64_t cookie;
	int verdict;

	CTASSERT(sizeof(tp.tp_csecret) == sizeof(nt.nt_csecret));
	CTASSERT(sizeof(tp.tp_exporter) == sizeof(nt.nt_exporter));
	CTASSERT(sizeof(tp.tp_rcid) == sizeof(nt.nt_rcid));
	CTASSERT(sizeof(dg.td_peer) == sizeof(nt.nt_peer));

	error = copyin(argp, &nt, sizeof(nt));
	if (error != 0)
		return error;
	if ((flag & NFSSVC_TLSDONE) != 0) {
		memset(&tp, 0, sizeof(tp));
		tp.tp_suite = nt.nt_suite;
		tp.tp_flags = (nt.nt_flags & NFSD_TLS_PEERCERT) != 0 ?
		    ONCRPC_TLS_PEERCERT : 0;
		tp.tp_secretlen = MIN(nt.nt_secretlen, sizeof(tp.tp_csecret));
		memcpy(tp.tp_csecret, nt.nt_csecret, sizeof(tp.tp_csecret));
		memcpy(tp.tp_ssecret, nt.nt_ssecret, sizeof(tp.tp_ssecret));
		memcpy(tp.tp_exporter, nt.nt_exporter, sizeof(tp.tp_exporter));
		tp.tp_rcidlen = MIN(nt.nt_rcidlen, sizeof(tp.tp_rcid));
		tp.tp_tcidlen = MIN(nt.nt_tcidlen, sizeof(tp.tp_tcid));
		memcpy(tp.tp_rcid, nt.nt_rcid, sizeof(tp.tp_rcid));
		memcpy(tp.tp_tcid, nt.nt_tcid, sizeof(tp.tp_tcid));
		cookie = nt.nt_cookie;
		verdict = nt.nt_error;
		explicit_memset(&nt, 0, sizeof(nt));
		error = oncrpc_tls_done(cookie, verdict, &tp);
		explicit_memset(&tp, 0, sizeof(tp));
		return error;
	}
	memset(&dg, 0, sizeof(dg));
	dg.td_accept = (nt.nt_flags & NFSD_TLS_DGRAMOK) != 0;
	memset(&nt, 0, sizeof(nt));
	error = oncrpc_tls_wait(&nt.nt_cookie, &nt.nt_fd, &ev, &dg);
	if (error != 0)
		return error;
	if (dg.td_is) {
		nt.nt_flags = NFSD_TLS_DGRAM;
		nt.nt_pmtu = dg.td_pmtu;
		memcpy(&nt.nt_peer, &dg.td_peer, sizeof(nt.nt_peer));
	}
	if (nt.nt_fd == -1) {
		nt.nt_flags = NFSD_TLS_EVENT |
		    (ev.te_sent ? NFSD_TLS_ALERTSENT : 0);
		nt.nt_alertlevel = ev.te_level;
		nt.nt_alertdesc = ev.te_desc;
		return copyout(&nt, argp, sizeof(nt));
	}
	error = copyout(&nt, argp, sizeof(nt));
	if (error != 0)
		(void)oncrpc_tls_done(nt.nt_cookie, error, NULL);
	return error;
}

/* Connections that version 4 has used stay, served by its threads. */
void
nfs_oncrpc_closesocks(void)
{

	oncrpc_svc_closesocks_for(nfs_oncrpc_svc, nfs_oncrpc_tag,
	    &nfs_oncrpc_program);
}
