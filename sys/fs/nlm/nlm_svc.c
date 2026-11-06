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
 * The Network Lock Manager as a program of the RPC layer: versions 1, 3
 * and 4 for clients, and the private version 0 the NSM reports on.  It
 * has its own server and sockets, as the client finds it through the port
 * mapper, and rpc.lockd -k binds those and hands them over.  Version 2
 * does not exist: lib/librpcsvc/nlm_prot.x has none, and C702 ch. 10
 * describes 3 "backward compatible with versions 1 and 2" without saying
 * what 2 was.
 *
 * It needs NFS for two things only: file handles, which are the v2 or
 * v3 server's, and the exports they are checked against.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kauth.h>
#include <sys/kmem.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/vnode.h>

#include <netinet/in.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfs_var.h>

#include <fs/nlm/nlm_var.h>

#define	NLM_NTHREADS	4	/* not from any document */

static struct oncrpc_svc *nlm_svc;
static struct sysctllog *nlm_sysctllog;
static int nlm_grace = NLM_GRACE_DEFAULT;
static bool nlm_started;

/* A call that has passed its decoding. */
struct nlm_call {
	struct oncrpc_req	*c_rq;
	const struct sockaddr	*c_sa;
	struct sockaddr_storage	 c_ss;
	struct nlm_args		*c_args;
	struct nlm_xholder	 c_holder;
	uint8_t			*c_ohbuf;
};

/*
 * The vnode of a handle, unlocked and referenced.  Its form, 32 bytes for
 * NFS version 2 or a length of its own for version 3, is nothing to a
 * lock manager that goes by the vnode: RFC 1813 s6.1.4 worries about the
 * two forms of one file only for one that goes by the bytes.
 *
 * C702 asks for no permission here.  The file was opened on the client,
 * where it may have been opened by one who has lost the access since,
 * so the owner is let through, and the check is only that this one could
 * have opened it some way.
 */
static uint32_t
nlm_getvp(struct nlm_call *c, struct vnode **vpp)
{
	struct oncrpc_req *rq = c->c_rq;
	const struct nlm_xlock *l = &c->c_args->a_lock;
	struct vattr va;
	struct vnode *vp;
	nfsrvfh_t nsfh;
	int error, rdonly;

	/* C702 ch. 10: AUTH_UNIX.  Without it there is nothing to check. */
	if (rq->rq_cred == NULL)
		return NLM4_FAILED;
	if (l->xl_fhlen < FHANDLE_SIZE_MIN || l->xl_fhlen > NFSX_V3FHMAX)
		return NLM4_STALE_FH;
	nsfh.nsfh_size = l->xl_fhlen;
	memcpy(NFSRVFH_DATA(&nsfh), l->xl_fh, l->xl_fhlen);

	netexport_rdlock();
	error = nfsrv_fhtovp(&nsfh, 1, &vp, rq->rq_cred, NULL, rq->rq_nam,
	    &rdonly, 0, 0);
	netexport_rdunlock();
	if (error != 0)
		return NLM4_STALE_FH;

	if (VOP_ACCESS(vp, VREAD, rq->rq_cred) != 0 &&
	    VOP_ACCESS(vp, VWRITE, rq->rq_cred) != 0 &&
	    (VOP_GETATTR(vp, &va, rq->rq_cred) != 0 ||
	    va.va_uid != kauth_cred_geteuid(rq->rq_cred))) {
		vput(vp);
		return NLM4_FAILED;
	}
	VOP_UNLOCK(vp);
	*vpp = vp;
	return NLM4_GRANTED;
}

/*
 * C702 NLM_TEST ... NLM_UNSHARE: all of them answer
 * LCK_DENIED_GRACE_PERIOD in the grace period but a reclaim.
 */
static uint32_t
nlm_serve(struct nlm_call *c, uint32_t proc)
{
	struct nlm_args *a = c->c_args;
	struct vnode *vp = NULL;
	uint32_t stat, vers = c->c_rq->rq_vers;

	/* C702 NLM_UNSHARE: its reclaim is unused and ignored. */
	if (oncrpc_grace_active() && (!a->a_reclaim || proc == NLM_UNSHARE))
		return NLM4_DENIED_GRACE_PERIOD;
	stat = nlm_getvp(c, &vp);
	if (stat != NLM4_GRANTED)
		return stat;
	switch (proc) {
	case NLM_TEST:
		stat = nlm_do_test(a, c->c_sa, vp, &c->c_holder, c->c_ohbuf);
		break;
	case NLM_LOCK:
		stat = nlm_do_lock(a, c->c_sa, vp, vers, true);
		break;
	case NLM_NM_LOCK:
		stat = nlm_do_lock(a, c->c_sa, vp, vers, false);
		break;
	case NLM_CANCEL:
		stat = nlm_do_cancel(a, c->c_sa, vp);
		break;
	case NLM_UNLOCK:
		stat = nlm_do_unlock(a, c->c_sa, vp);
		break;
	case NLM_SHARE:
		stat = nlm_do_share(a, c->c_sa, vp);
		break;
	case NLM_UNSHARE:
		stat = nlm_do_unshare(a, c->c_sa, vp);
		break;
	default:
		panic("nlm_serve: %u", proc);
	}
	vrele(vp);
	return stat;
}

static bool
nlm_encode(XDR *x, struct nlm_call *c, uint32_t proc, uint32_t stat)
{
	const struct nlm_args *a = c->c_args;
	uint32_t vers = c->c_rq->rq_vers;

	switch (proc) {
	case NLM_TEST:
		return nlm_xdr_testres(x, vers, a->a_cookie, a->a_cookielen,
		    stat, &c->c_holder);
	case NLM_SHARE:
	case NLM_UNSHARE:
		return nlm_xdr_shareres(x, vers, a->a_cookie, a->a_cookielen,
		    stat);
	default:
		return nlm_xdr_res(x, vers, a->a_cookie, a->a_cookielen, stat);
	}
}

/* The largest result: two netobjs and a holder. */
#define	NLM_MAXRES	(2 * (MAXNETOBJ_SZ + 4) + 32)

/*
 * C702 ch. 10: a _MSG procedure is its synchronous one with the result
 * going back as a call of its own to NLM_x_RES, proc + 10, and no reply.
 */
static void
nlm_respond(struct nlm_call *c, uint32_t proc, uint32_t stat)
{
	void *buf;
	u_int len;
	XDR x;

	buf = kmem_alloc(NLM_MAXRES, KM_SLEEP);
	xdrmem_create(&x, buf, NLM_MAXRES, XDR_ENCODE);
	if (!nlm_encode(&x, c, proc, stat)) {
		kmem_free(buf, NLM_MAXRES);
		return;
	}
	len = xdr_getpos(&x);
	if (len != NLM_MAXRES) {
		void *nb = kmem_alloc(len, KM_SLEEP);

		memcpy(nb, buf, len);
		kmem_free(buf, NLM_MAXRES);
		buf = nb;
	}
	nlm_nsm_res(c->c_sa, c->c_rq->rq_vers, proc + 10, buf, len);
}

static bool
nlm_decode(struct oncrpc_req *rq, struct nlm_args *a, uint32_t proc)
{
	XDR *x = rq->rq_args;

	switch (proc) {
	case NLM_TEST:
	case NLM_GRANTED:
		return nlm_xdr_testargs(x, rq->rq_vers, a);
	case NLM_LOCK:
	case NLM_NM_LOCK:
		return nlm_xdr_lockargs(x, rq->rq_vers, a);
	case NLM_CANCEL:
		return nlm_xdr_cancargs(x, rq->rq_vers, a);
	case NLM_UNLOCK:
		return nlm_xdr_unlockargs(x, rq->rq_vers, a);
	case NLM_SHARE:
	case NLM_UNSHARE:
		return nlm_xdr_shareargs(x, a);
	case NLM_FREE_ALL:
		return nlm_xdr_notify(x, a);
	default:
		return false;
	}
}

/*
 * Only rpc.statd may say a host has rebooted, or anybody could have every
 * lock of a client dropped.  It is on this host, and a packet from outside
 * with a loopback source does not get past ip_input().  It should also be
 * asked for a reserved port, but rpc.statd does not bind one: until it
 * does, a local user can say this too.
 */
static bool
nlm_from_statd(const struct sockaddr *sa)
{
	const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
	const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;

	if (sa->sa_family == AF_INET)
		return sin->sin_addr.s_addr == INADDR_LOOPBACK;
	if (sa->sa_family == AF_INET6)
		return IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr);
	return false;
}

static enum oncrpc_dispatch
nlm_dispatch_sm(struct nlm_call *c)
{
	struct oncrpc_req *rq = c->c_rq;
	struct nlm_args *a = c->c_args;
	struct nlm_xlock *l = &a->a_lock;
	uint8_t priv[SM_PRIVLEN];

	if (rq->rq_proc == NLM_NULL)
		return ONCRPC_DONE;
	if (rq->rq_proc != NLM_SM_NOTIFY)
		return ONCRPC_ERR_PROC;
	if (!nlm_xdr_status(rq->rq_args, l->xl_name, &l->xl_namelen,
	    &a->a_state, priv))
		return ONCRPC_ERR_ARGS;
	if (!nlm_from_statd(c->c_sa))
		return ONCRPC_ERR_SYSTEM;
	nlm_do_notify(priv, a->a_state);
	nlm_client_notify(priv);
	return ONCRPC_DONE;
}

static enum oncrpc_dispatch
nlm_dispatch_call(struct nlm_call *c)
{
	struct oncrpc_req *rq = c->c_rq;
	uint32_t proc = rq->rq_proc, base, stat;
	bool async;

	if (rq->rq_vers == NLM_VERS_SM)
		return nlm_dispatch_sm(c);
	if (proc == NLM_NULL)
		return ONCRPC_DONE;

	/* C702 ch. 10: these came with version 3. */
	if (proc >= NLM_SHARE && rq->rq_vers < NLM_VERS3)
		return ONCRPC_ERR_PROC;
	if (proc > NLM_GRANTED_RES && proc < NLM_SHARE)
		return ONCRPC_ERR_PROC;
	/* A result we never asked for by this route; it needs no reply. */
	if (proc >= NLM_TEST_RES && proc <= NLM_GRANTED_RES)
		return ONCRPC_NOREPLY;

	async = proc >= NLM_TEST_MSG && proc <= NLM_GRANTED_MSG;
	base = async ? proc - (NLM_TEST_MSG - NLM_TEST) : proc;

	if (!nlm_decode(rq, c->c_args, base))
		return ONCRPC_ERR_ARGS;

	switch (base) {
	case NLM_FREE_ALL:
		nlm_do_free_all(c->c_args->a_lock.xl_name, c->c_sa);
		return ONCRPC_DONE;
	case NLM_GRANTED:
		stat = nlm_client_granted(c->c_args, c->c_sa);
		break;
	default:
		stat = nlm_serve(c, base);
		break;
	}
	if (async) {
		nlm_respond(c, base, stat);
		return ONCRPC_NOREPLY;
	}
	if (!nlm_encode(rq->rq_res, c, base, stat))
		return ONCRPC_ERR_SYSTEM;
	return ONCRPC_DONE;
}

static enum oncrpc_dispatch
nlm_dispatch(struct oncrpc_req *rq)
{
	struct nlm_call c;
	enum oncrpc_dispatch d;

	if (rq->rq_nam == NULL)
		return ONCRPC_ERR_SYSTEM;
	memset(&c, 0, sizeof(c));
	c.c_rq = rq;
	m_copydata(rq->rq_nam, 0, MIN(rq->rq_nam->m_len,
	    (int)sizeof(c.c_ss)), &c.c_ss);
	c.c_sa = (struct sockaddr *)&c.c_ss;
	c.c_args = kmem_zalloc(sizeof(*c.c_args), KM_SLEEP);
	c.c_ohbuf = kmem_alloc(MAXNETOBJ_SZ, KM_SLEEP);
	d = nlm_dispatch_call(&c);
	kmem_free(c.c_ohbuf, MAXNETOBJ_SZ);
	kmem_free(c.c_args, sizeof(*c.c_args));
	return d;
}

/* Two ranges, as PROG_MISMATCH should not offer a version 2. */
static const struct oncrpc_program nlm_program_low = {
	.op_prog = NLM_PROG,
	.op_vers_low = NLM_VERS_SM,
	.op_vers_high = NLM_VERS1,
	.op_nprocs = NLM_NPROCS,
	.op_dispatch = nlm_dispatch,
};

static const struct oncrpc_program nlm_program_high = {
	.op_prog = NLM_PROG,
	.op_vers_low = NLM_VERS3,
	.op_vers_high = NLM_VERS4,
	.op_nprocs = NLM_NPROCS,
	.op_dispatch = nlm_dispatch,
};

/*
 * Write a descriptor to vfs.nlm.addsock to have it served, as for
 * vfs.nfsv4.addsock.  The first starts the grace period, C702 ch. 9:
 * rpc.lockd coming back later finds the locks where they were.
 */
static int
nlm_sysctl_addsock(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct sockaddr_big sb;
	struct mbuf *nam;
	file_t *fp;
	int error, fd;

	fd = -1;
	node.sysctl_data = &fd;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error != 0 || newp == NULL)
		return error;

	if ((fp = fd_getfile(fd)) == NULL)
		return EBADF;
	nam = NULL;
	if (fp->f_type == DTYPE_SOCKET &&
	    fp->f_socket->so_type == SOCK_STREAM) {
		error = do_sys_getpeername(fd, (struct sockaddr *)&sb);
		if (error != 0) {
			fd_putfile(fd);
			return error;
		}
		nam = m_get(M_WAIT, MT_SONAME);
		m_copyback(nam, 0, sb.sb_len, &sb);
	}
	error = oncrpc_svc_addsock(nlm_svc, fp, nam);
	fd_putfile(fd);
	if (error == 0 && !nlm_started) {
		nlm_started = true;
		oncrpc_grace_start(nlm_grace);
		nlm_nsm_start();
	}
	return error;
}

/* vfs.nlm.client: lock through the server on NFS mounts, from now on. */
static int
nlm_sysctl_client(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	static int on;
	int error, v;

	v = on;
	node.sysctl_data = &v;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error != 0 || newp == NULL)
		return error;
	error = nlm_client_enable(v != 0);
	if (error == 0)
		on = v != 0;
	return error;
}

static void
nlm_sysctl_init(void)
{
	const struct sysctlnode *node = NULL;
	static struct { const char *n; u_int *p; const char *d; } ro[] = {
		{ "nhosts", &nlm_nhosts, "Hosts known" },
		{ "nowners", &nlm_nowners, "Lock owners known" },
		{ "nholds", &nlm_nholds, "Vnodes held for an owner" },
		{ "nwaiters", &nlm_nwaiters, "Locks queued" },
		{ "nshares", &nlm_nshares, "Share reservations" },
	};
	u_int i;

	sysctl_createv(&nlm_sysctllog, 0, NULL, &node,
	    CTLFLAG_PERMANENT, CTLTYPE_NODE, "nlm",
	    SYSCTL_DESCR("Network Lock Manager"),
	    NULL, 0, NULL, 0, CTL_VFS, CTL_CREATE, CTL_EOL);
	sysctl_createv(&nlm_sysctllog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE, CTLTYPE_INT, "addsock",
	    SYSCTL_DESCR("Serve this descriptor"),
	    nlm_sysctl_addsock, 0, NULL, 0,
	    CTL_VFS, node->sysctl_num, CTL_CREATE, CTL_EOL);
	sysctl_createv(&nlm_sysctllog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE, CTLTYPE_INT, "grace",
	    SYSCTL_DESCR("Seconds of grace period after the start"),
	    NULL, 0, &nlm_grace, 0,
	    CTL_VFS, node->sysctl_num, CTL_CREATE, CTL_EOL);
	sysctl_createv(&nlm_sysctllog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE, CTLTYPE_INT, "client",
	    SYSCTL_DESCR("Use the lock manager of the server on NFS mounts"),
	    nlm_sysctl_client, 0, NULL, 0,
	    CTL_VFS, node->sysctl_num, CTL_CREATE, CTL_EOL);
	sysctl_createv(&nlm_sysctllog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE, CTLTYPE_INT,
	    "monitor_required",
	    SYSCTL_DESCR("Refuse a lock when SM_MON fails"),
	    NULL, 0, &nlm_monitor_required, 0,
	    CTL_VFS, node->sysctl_num, CTL_CREATE, CTL_EOL);
	for (i = 0; i < __arraycount(ro); i++)
		sysctl_createv(&nlm_sysctllog, 0, NULL, NULL,
		    CTLFLAG_PERMANENT | CTLFLAG_READONLY, CTLTYPE_INT, ro[i].n,
		    SYSCTL_DESCR(ro[i].d), NULL, 0, (int *)ro[i].p, 0,
		    CTL_VFS, node->sysctl_num, CTL_CREATE, CTL_EOL);
}

MODULE(MODULE_CLASS_MISC, nlm, "oncrpc,nfsserver");

static int
nlm_modcmd(modcmd_t cmd, void *arg)
{
	int error;

	switch (cmd) {
	case MODULE_CMD_INIT:
		nlm_state_init();
		error = oncrpc_svc_create("nlm", NLM_NTHREADS, &nlm_svc);
		if (error == 0) {
			error = oncrpc_svc_register(nlm_svc, &nlm_program_low);
			if (error == 0) {
				error = oncrpc_svc_register(nlm_svc,
				    &nlm_program_high);
				if (error != 0)
					oncrpc_svc_unregister(nlm_svc,
					    &nlm_program_low);
			}
			if (error != 0)
				oncrpc_svc_destroy(nlm_svc);
		}
		if (error != 0) {
			nlm_state_fini();
			return error;
		}
		nlm_nsm_init();
		nlm_client_init();
		oncrpc_share_register(ONCRPC_SHARE_NLM, nlm_share_conflict);
		nlm_sysctl_init();
		return 0;
	case MODULE_CMD_FINI:
		error = nlm_client_enable(false);
		if (error != 0)
			return error;
		oncrpc_share_register(ONCRPC_SHARE_NLM, NULL);
		sysctl_teardown(&nlm_sysctllog);
		oncrpc_svc_unregister(nlm_svc, &nlm_program_low);
		oncrpc_svc_unregister(nlm_svc, &nlm_program_high);
		oncrpc_svc_destroy(nlm_svc);
		nlm_client_fini();
		nlm_nsm_fini();
		nlm_state_fini();
		nlm_started = false;
		return 0;
	default:
		return ENOTTY;
	}
}
