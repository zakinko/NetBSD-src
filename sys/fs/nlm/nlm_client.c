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
 * The client of the lock manager, for NFS versions 2 and 3: VOP_ADVLOCK
 * of an NFS vnode comes here when vfs.nlm.client is on.  NFS version 2
 * goes with NLM version 3 and NFS version 3 with NLM version 4, C702
 * ch. 14.
 *
 * The server is the authority on a lock.  The local lockf list then only
 * remembers what this host's owners hold, which is what F_UNLCK on close
 * and the local half of F_GETLK want, so an entry goes in after the
 * server has granted it and never waits.  Taking the local lock first
 * would be wrong where it replaces a lock of another type: to undo that
 * on a refusal is to lose the old one.
 *
 * What the server has granted is also kept in nlm_c_locks, for C702 ch. 9
 * Client Lock Recovery: the NSM is asked to watch the server, by address,
 * and on its word every lock there is sent again with reclaim set.  Calls
 * go over UDP whatever the mount uses.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/atomic.h>
#include <sys/condvar.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/kthread.h>
#include <sys/lockf.h>
#include <sys/mbuf.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/vnode.h>

#include <netinet/in.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfsmount.h>
#include <nfs/nfsnode.h>
#include <nfs/nfs_var.h>

#include <fs/nlm/nlm_var.h>

#define	NLM_C_POLL	30	/* s between LOCKs of a blocked waiter */
#define	NLM_C_GRACE	5	/* s between tries in the server's grace */
#define	NLM_C_TRIES	4	/* of a call, 3 s apart */

/* A LOCK the server has answered with LCK_BLOCKED. */
struct nlm_blocked {
	LIST_ENTRY(nlm_blocked)	 b_list;
	struct sockaddr_storage	 b_server;
	const void		*b_fh;
	uint32_t		 b_fhlen;
	int32_t			 b_svid;
	uint64_t		 b_offset;
	uint64_t		 b_len;
	bool			 b_granted;
};

/* A range granted to us, as it was asked for, one owner's. */
struct nlm_clock {
	LIST_ENTRY(nlm_clock)	 l_list;
	struct sockaddr_storage	 l_server;
	uint8_t			*l_fh;
	uint32_t		 l_fhlen;
	uint32_t		 l_vers;
	int32_t			 l_svid;
	uint64_t		 l_offset;
	uint64_t		 l_len;		/* 0 to the end */
	bool			 l_exclusive;
	bool			 l_todo;	/* for the reclaim going on */
	bool			 l_busy;	/* a reclaim is out */
	bool			 l_dead;	/* free it when not busy */
	kauth_cred_t		 l_cred;
};

/* A server the NSM has been asked to watch. */
struct nlm_cserver {
	LIST_ENTRY(nlm_cserver)	 s_list;
	uint8_t			 s_priv[SM_PRIVLEN];
};

static LIST_HEAD(, nlm_clock) nlm_c_locks = LIST_HEAD_INITIALIZER(nlm_c_locks);
static LIST_HEAD(, nlm_cserver) nlm_c_servers =
    LIST_HEAD_INITIALIZER(nlm_c_servers);
static volatile uint32_t nlm_c_state;	/* of the NSM here */
static volatile u_int nlm_c_reclaiming;

static kmutex_t nlm_c_lock;
static volatile u_int nlm_c_active;
static kcondvar_t nlm_c_cv;
static LIST_HEAD(, nlm_blocked) nlm_c_blocked =
    LIST_HEAD_INITIALIZER(nlm_c_blocked);

/*
 * C702 uppid: unique for the process on this host.  a_id is a process for
 * fcntl(2) and a file for flock(2), and the pid is the one an NFS version
 * 3 F_GETLK of another client can show to a user.  The second kind has
 * bit 30 set to stay out of the pids' way, and two files could meet in
 * the remaining bits, which would make them one owner.
 */
static int32_t
c_svid(const struct vop_advlock_args *ap)
{

	if ((ap->a_flags & F_POSIX) != 0)
		return ((struct proc *)ap->a_id)->p_pid;
	return (int32_t)(0x40000000U |
	    ((uint32_t)((uintptr_t)ap->a_id >> 4) & 0x3fffffffU));
}

/* Where the call goes, with the NLM's port. */
static int
c_server(struct nfsmount *nmp, uint32_t vers, struct sockaddr_storage *to)
{
	struct mbuf *nam = nmp->nm_nam;
	uint16_t port;
	int error;

	m_copydata(nam, 0, MIN(nam->m_len, (int)sizeof(*to)), to);
	error = oncrpc_clnt_getport((struct sockaddr *)to, NLM_PROG, vers,
	    IPPROTO_UDP, &port);
	if (error != 0)
		return error;
	((struct sockaddr_in *)to)->sin_port = htons(port);
	return 0;
}

static int
c_call(const struct sockaddr *to, uint32_t vers, uint32_t proc,
    xdrproc_t xargs, struct nlm_cargs *ca, xdrproc_t xres,
    struct nlm_cres *cr, kauth_cred_t cred)
{
	int error;

	cr->cr_vers = vers;
	error = oncrpc_clnt_call(to, NLM_PROG, vers, proc, xargs, ca, xres, cr,
	    NLM_C_TRIES, 3, cred);
	return error == ETIMEDOUT ? ENOLCK : error;
}

static int
c_errno(uint32_t stat)
{

	switch (stat) {
	case NLM4_GRANTED:
		return 0;
	case NLM4_DENIED:
		return EAGAIN;
	case NLM4_DEADLCK:
		return EDEADLK;
	case NLM4_ROFS:
		return EROFS;
	case NLM4_STALE_FH:
		return ESTALE;
	case NLM4_FBIG:
		return EFBIG;
	default:
		return ENOLCK;
	}
}

/*
 * The range as the protocol has it, from what lf_advlock() takes.  A
 * negative length counts back from the offset.  NLM version 3 has 32 bits
 * and C702 does not say what a server should make of more.
 */
static int
c_range(const struct flock *fl, off_t size, uint32_t vers,
    struct nlm_cargs *ca)
{
	off_t start;

	switch (fl->l_whence) {
	case SEEK_SET:
	case SEEK_CUR:
		start = fl->l_start;
		break;
	case SEEK_END:
		if (fl->l_start > __type_max(off_t) - size)
			return EINVAL;
		start = size + fl->l_start;
		break;
	default:
		return EINVAL;
	}
	if (fl->l_len < 0) {
		if (start + fl->l_len < 0)
			return EINVAL;
		ca->ca_offset = start + fl->l_len;
		ca->ca_len = -fl->l_len;
	} else {
		if (start < 0)
			return EINVAL;
		ca->ca_offset = start;
		ca->ca_len = fl->l_len;
	}
	if (vers != NLM_VERS4 && (ca->ca_offset > UINT32_MAX ||
	    ca->ca_len > UINT32_MAX))
		return EOVERFLOW;
	return 0;
}

/* NLM_GRANTED, in the server's thread: wake whoever is waiting for this. */
uint32_t
nlm_client_granted(const struct nlm_args *a, const struct sockaddr *sa)
{
	const struct nlm_xlock *l = &a->a_lock;
	struct nlm_blocked *b;
	uint32_t stat = NLM4_DENIED;

	mutex_enter(&nlm_c_lock);
	LIST_FOREACH(b, &nlm_c_blocked, b_list) {
		if (b->b_svid != l->xl_svid || b->b_offset != l->xl_offset ||
		    b->b_len != l->xl_len || b->b_fhlen != l->xl_fhlen ||
		    memcmp(b->b_fh, l->xl_fh, l->xl_fhlen) != 0)
			continue;
		/* Any port on the server's address will do. */
		if (((const struct sockaddr *)&b->b_server)->sa_family !=
		    sa->sa_family)
			continue;
		b->b_granted = true;
		cv_broadcast(&nlm_c_cv);
		stat = NLM4_GRANTED;
		break;
	}
	mutex_exit(&nlm_c_lock);
	return stat;
}

/*
 * Wait for a blocked lock.  It keeps asking, as NLM_GRANTED is one UDP
 * packet from a server that may have lost us; C702 does not require it
 * and a server takes the repeat as the same request.
 */
static int
c_lock_wait(const struct sockaddr *to, struct nlm_cargs *ca, kauth_cred_t cred)
{
	struct nlm_blocked b;
	struct nlm_cres cr;
	uint32_t vers = ca->ca_vers;
	int error;

	memset(&b, 0, sizeof(b));
	memcpy(&b.b_server, to, to->sa_len);
	b.b_fh = ca->ca_fh;
	b.b_fhlen = ca->ca_fhlen;
	b.b_svid = ca->ca_svid;
	b.b_offset = ca->ca_offset;
	b.b_len = ca->ca_len;
	mutex_enter(&nlm_c_lock);
	LIST_INSERT_HEAD(&nlm_c_blocked, &b, b_list);
	mutex_exit(&nlm_c_lock);

	for (;;) {
		error = c_call(to, vers, NLM_LOCK, nlm_xdr_c_lock, ca,
		    nlm_xdr_c_res, &cr, cred);
		if (error != 0)
			break;
		if (cr.cr_stat == NLM4_GRANTED)
			break;
		if (cr.cr_stat != NLM4_BLOCKED &&
		    cr.cr_stat != NLM4_DENIED_GRACE_PERIOD) {
			error = c_errno(cr.cr_stat);
			break;
		}
		mutex_enter(&nlm_c_lock);
		while (!b.b_granted && error == 0)
			error = cv_timedwait_sig(&nlm_c_cv, &nlm_c_lock,
			    (cr.cr_stat == NLM4_BLOCKED ? NLM_C_POLL :
			    NLM_C_GRACE) * hz);
		mutex_exit(&nlm_c_lock);
		if (b.b_granted) {
			error = 0;
			break;
		}
		if (error == EWOULDBLOCK) {
			error = 0;
			continue;
		}
		/* C702 NLM_CANCEL, whose arguments are those of the LOCK. */
		(void)c_call(to, vers, NLM_CANCEL, nlm_xdr_c_cancel, ca,
		    nlm_xdr_c_res, &cr, cred);
		break;
	}
	mutex_enter(&nlm_c_lock);
	LIST_REMOVE(&b, b_list);
	mutex_exit(&nlm_c_lock);
	return error;
}

static void
clock_free(struct nlm_clock *l)
{

	kmem_free(l->l_fh, l->l_fhlen);
	kauth_cred_free(l->l_cred);
	kmem_free(l, sizeof(*l));
}

static struct nlm_clock *
clock_alloc(const struct sockaddr *to, const struct nlm_cargs *ca,
    kauth_cred_t cred, uint64_t offset, uint64_t len)
{
	struct nlm_clock *l;

	l = kmem_zalloc(sizeof(*l), KM_SLEEP);
	memcpy(&l->l_server, to, to->sa_len);
	l->l_fhlen = ca->ca_fhlen;
	l->l_fh = kmem_alloc(l->l_fhlen, KM_SLEEP);
	memcpy(l->l_fh, ca->ca_fh, l->l_fhlen);
	l->l_vers = ca->ca_vers;
	l->l_svid = ca->ca_svid;
	l->l_offset = offset;
	l->l_len = len;
	l->l_exclusive = ca->ca_exclusive;
	kauth_cred_hold(cred);
	l->l_cred = cred;
	return l;
}

/*
 * Take a range out of what an owner has on a file, as a server splits a
 * lock.  The piece a split leaves on the right comes in as spare.
 */
static void
clock_clip(const struct nlm_cargs *ca, kauth_cred_t cred,
    const struct sockaddr *to)
{
	struct nlm_clock *l, *next, *spare;
	uint64_t cs = ca->ca_offset, ce, ls, le;

	ce = ca->ca_len == 0 ? UINT64_MAX : cs + ca->ca_len;
	spare = clock_alloc(to, ca, cred, 0, 0);
	mutex_enter(&nlm_c_lock);
	for (l = LIST_FIRST(&nlm_c_locks); l != NULL; l = next) {
		next = LIST_NEXT(l, l_list);
		if (l->l_dead || l->l_svid != ca->ca_svid ||
		    l->l_fhlen != ca->ca_fhlen ||
		    memcmp(l->l_fh, ca->ca_fh, l->l_fhlen) != 0)
			continue;
		ls = l->l_offset;
		le = l->l_len == 0 ? UINT64_MAX : ls + l->l_len;
		if (le <= cs || ce <= ls)
			continue;
		if (cs > ls && ce < le && spare != NULL) {
			spare->l_offset = ce;
			spare->l_len = le == UINT64_MAX ? 0 : le - ce;
			spare->l_exclusive = l->l_exclusive;
			LIST_INSERT_HEAD(&nlm_c_locks, spare, l_list);
			spare = NULL;
			l->l_len = cs - ls;
		} else if (cs > ls) {
			l->l_len = cs - ls;
		} else if (ce < le) {
			l->l_offset = ce;
			l->l_len = le == UINT64_MAX ? 0 : le - ce;
		} else if (l->l_busy) {
			l->l_dead = true;
		} else {
			LIST_REMOVE(l, l_list);
			mutex_exit(&nlm_c_lock);
			clock_free(l);
			mutex_enter(&nlm_c_lock);
			next = LIST_FIRST(&nlm_c_locks);
		}
	}
	mutex_exit(&nlm_c_lock);
	if (spare != NULL)
		clock_free(spare);
}

/* Remember a grant; what it replaces goes first. */
static void
clock_add(const struct sockaddr *to, const struct nlm_cargs *ca,
    kauth_cred_t cred)
{
	struct nlm_clock *l;

	clock_clip(ca, cred, to);
	l = clock_alloc(to, ca, cred, ca->ca_offset, ca->ca_len);
	mutex_enter(&nlm_c_lock);
	LIST_INSERT_HEAD(&nlm_c_locks, l, l_list);
	mutex_exit(&nlm_c_lock);
}

/* C702 ch. 9 Client Lock Request: the NSM watches the server. */
static void
c_monitor(const struct sockaddr *to)
{
	struct nlm_cserver *s, *ns;
	uint32_t state = 0;

	ns = kmem_zalloc(sizeof(*ns), KM_SLEEP);
	nlm_nsm_priv(to, ns->s_priv);
	mutex_enter(&nlm_c_lock);
	LIST_FOREACH(s, &nlm_c_servers, s_list)
		if (memcmp(s->s_priv, ns->s_priv, SM_PRIVLEN) == 0)
			break;
	if (s == NULL) {
		LIST_INSERT_HEAD(&nlm_c_servers, ns, s_list);
		ns = NULL;
	}
	mutex_exit(&nlm_c_lock);
	if (ns != NULL) {
		kmem_free(ns, sizeof(*ns));
		return;
	}
	if (nlm_nsm_mon(to, &state) == 0)
		nlm_c_state = state;
}

/* Send one lock again.  Waits out the server's grace, which is for this. */
static void
clock_reclaim(struct nlm_clock *l)
{
	struct sockaddr_storage to;
	struct nlm_cargs ca;
	struct nlm_cres cr;
	char oh[32 + MAXHOSTNAMELEN];
	uint16_t port;
	u_int tries;
	int error;

	memset(&ca, 0, sizeof(ca));
	ca.ca_vers = l->l_vers;
	ca.ca_name = hostname;
	ca.ca_fh = l->l_fh;
	ca.ca_fhlen = l->l_fhlen;
	ca.ca_svid = l->l_svid;
	ca.ca_offset = l->l_offset;
	ca.ca_len = l->l_len;
	ca.ca_exclusive = l->l_exclusive;
	ca.ca_reclaim = true;
	ca.ca_state = nlm_c_state;
	snprintf(oh, sizeof(oh), "%d@%s", ca.ca_svid, hostname);
	ca.ca_oh = oh;
	ca.ca_ohlen = strlen(oh);

	/* The server is rebooting and may not have its NLM up yet. */
	error = ENOENT;
	cr.cr_stat = NLM4_FAILED;
	for (tries = 0; tries < 12; tries++) {
		memcpy(&to, &l->l_server, l->l_server.ss_len);
		error = oncrpc_clnt_getport((struct sockaddr *)&to, NLM_PROG,
		    l->l_vers, IPPROTO_UDP, &port);
		if (error == 0) {
			((struct sockaddr_in *)&to)->sin_port = htons(port);
			error = c_call((struct sockaddr *)&to, l->l_vers,
			    NLM_LOCK, nlm_xdr_c_lock, &ca, nlm_xdr_c_res, &cr,
			    l->l_cred);
			if (error == 0 &&
			    cr.cr_stat != NLM4_DENIED_GRACE_PERIOD)
				break;
		}
		kpause("nlmrecl", false, NLM_C_GRACE * hz, NULL);
	}
	if (error != 0 || cr.cr_stat != NLM4_GRANTED)
		printf("nlm: lock of svid %d lost in the server's reboot "
		    "(error %d, status %u)\n", ca.ca_svid, error, cr.cr_stat);
}

static void
c_reclaim_thread(void *arg)
{
	uint8_t *priv = arg, p[SM_PRIVLEN];
	struct nlm_clock *l;
	bool again;

	mutex_enter(&nlm_c_lock);
	LIST_FOREACH(l, &nlm_c_locks, l_list)
		l->l_todo = true;
	do {
		again = false;
		LIST_FOREACH(l, &nlm_c_locks, l_list) {
			if (!l->l_todo || l->l_dead || l->l_busy)
				continue;
			l->l_todo = false;
			nlm_nsm_priv((struct sockaddr *)&l->l_server, p);
			if (memcmp(p, priv, SM_PRIVLEN) != 0)
				continue;
			l->l_busy = true;
			mutex_exit(&nlm_c_lock);
			clock_reclaim(l);
			mutex_enter(&nlm_c_lock);
			l->l_busy = false;
			if (l->l_dead) {
				LIST_REMOVE(l, l_list);
				mutex_exit(&nlm_c_lock);
				clock_free(l);
				mutex_enter(&nlm_c_lock);
			}
			again = true;
			break;
		}
	} while (again);
	mutex_exit(&nlm_c_lock);
	kmem_free(priv, SM_PRIVLEN);
	atomic_dec_uint(&nlm_c_reclaiming);
	kthread_exit(0);
}

/*
 * NLM_SM_NOTIFY: if that is a server we hold locks on, it has rebooted.
 * The thread is as C702 ch. 9 has it: reclaiming takes the grace period,
 * and the NSM is waiting for its reply here.
 */
void
nlm_client_notify(const uint8_t *priv)
{
	struct nlm_cserver *s;
	struct lwp *lwp;
	uint8_t *p;

	mutex_enter(&nlm_c_lock);
	LIST_FOREACH(s, &nlm_c_servers, s_list)
		if (memcmp(s->s_priv, priv, SM_PRIVLEN) == 0)
			break;
	mutex_exit(&nlm_c_lock);
	if (s == NULL)
		return;
	p = kmem_alloc(SM_PRIVLEN, KM_SLEEP);
	memcpy(p, priv, SM_PRIVLEN);
	atomic_inc_uint(&nlm_c_reclaiming);
	if (kthread_create(PRI_NONE, KTHREAD_MPSAFE, NULL, c_reclaim_thread, p,
	    &lwp, "nlmrecl") != 0) {
		atomic_dec_uint(&nlm_c_reclaiming);
		kmem_free(p, SM_PRIVLEN);
	}
}

/* The lf_advlock() that remembers it, which never waits. */
static int
c_local(struct vop_advlock_args *ap, struct lockf **head, off_t size)
{
	struct vop_advlock_args la = *ap;

	la.a_flags &= ~F_WAIT;
	return lf_advlock(&la, head, size);
}

static int
nlm_client_advlock(struct vop_advlock_args *ap, struct lockf **head, off_t size)
{
	struct vnode *vp = ap->a_vp;
	struct nfsmount *nmp = VFSTONFS(vp->v_mount);
	struct nfsnode *np = VTONFS(vp);
	struct sockaddr_storage to;
	struct nlm_cargs ca;
	struct nlm_cres cr;
	struct flock *fl = ap->a_fl, q;
	kauth_cred_t cred = kauth_cred_get();
	uint32_t vers = NFS_ISV3(vp) ? NLM_VERS4 : NLM_VERS3;
	char oh[32 + MAXHOSTNAMELEN];
	int error;

	/* Ops of the kernel's, for what a process of its own holds. */
	switch (ap->a_op) {
	case F_SETLK:
	case F_UNLCK:
	case F_GETLK:
		break;
	default:
		return lf_advlock(ap, head, size);
	}

	memset(&ca, 0, sizeof(ca));
	error = c_range(fl, size, vers, &ca);
	if (error != 0)
		return error;
	ca.ca_vers = vers;
	ca.ca_name = hostname;
	ca.ca_fh = np->n_fhp;
	ca.ca_fhlen = np->n_fhsize;
	ca.ca_svid = c_svid(ap);
	ca.ca_exclusive = fl->l_type == F_WRLCK;
	/* Only ever given back to us; C702 asks no more of it. */
	snprintf(oh, sizeof(oh), "%d@%s", ca.ca_svid, hostname);
	ca.ca_oh = oh;
	ca.ca_ohlen = strlen(oh);
	ca.ca_state = nlm_c_state;

	switch (ap->a_op) {
	case F_UNLCK:
		/* close(2) comes here for every file of a process. */
		q = *fl;
		q.l_type = F_WRLCK;
		if (lf_advlock(&(struct vop_advlock_args){ .a_vp = vp,
		    .a_id = ap->a_id, .a_op = F_HASLK, .a_fl = &q,
		    .a_flags = ap->a_flags }, head, size) == 0 &&
		    q.l_type == F_UNLCK)
			return 0;
		error = lf_advlock(ap, head, size);
		if (error != 0)
			return error;
		error = c_server(nmp, vers, &to);
		if (error == 0)
			clock_clip(&ca, cred, (struct sockaddr *)&to);
		if (error == 0)
			error = c_call((struct sockaddr *)&to, vers, NLM_UNLOCK,
			    nlm_xdr_c_unlock, &ca, nlm_xdr_c_res, &cr, cred);
		return error != 0 ? error : c_errno(cr.cr_stat);

	case F_GETLK:
		error = lf_advlock(ap, head, size);
		if (error != 0 || fl->l_type != F_UNLCK)
			return error;
		ca.ca_exclusive = true;
		q = *ap->a_fl;
		error = c_server(nmp, vers, &to);
		if (error == 0)
			error = c_call((struct sockaddr *)&to, vers, NLM_TEST,
			    nlm_xdr_c_test, &ca, nlm_xdr_c_testres, &cr, cred);
		if (error != 0)
			return error;
		if (cr.cr_stat == NLM4_GRANTED)
			return 0;
		if (cr.cr_stat != NLM4_DENIED)
			return c_errno(cr.cr_stat);
		fl->l_type = cr.cr_exclusive ? F_WRLCK : F_RDLCK;
		fl->l_whence = SEEK_SET;
		fl->l_start = cr.cr_offset;
		fl->l_len = cr.cr_len;
		fl->l_pid = cr.cr_svid;
		return 0;

	case F_SETLK:
		error = c_server(nmp, vers, &to);
		if (error != 0)
			return error == ETIMEDOUT ? ENOLCK : error;
		c_monitor((struct sockaddr *)&to);
		ca.ca_state = nlm_c_state;
		ca.ca_block = (ap->a_flags & F_WAIT) != 0;
		if (ca.ca_block) {
			error = c_lock_wait((struct sockaddr *)&to, &ca, cred);
		} else {
			do {
				error = c_call((struct sockaddr *)&to, vers,
				    NLM_LOCK, nlm_xdr_c_lock, &ca,
				    nlm_xdr_c_res, &cr, cred);
				if (error != 0)
					return error;
				if (cr.cr_stat != NLM4_DENIED_GRACE_PERIOD)
					break;
				error = kpause("nlmgrace", true,
				    NLM_C_GRACE * hz, NULL);
			} while (error == 0 || error == EWOULDBLOCK);
			if (error != 0 && error != EWOULDBLOCK)
				return error;
			error = c_errno(cr.cr_stat);
		}
		if (error != 0)
			return error;
		clock_add((struct sockaddr *)&to, &ca, cred);
		return c_local(ap, head, size);
	}
	return EINVAL;
}

static int
nlm_client_entry(struct vop_advlock_args *ap, struct lockf **head, off_t size)
{
	int error;

	atomic_inc_uint(&nlm_c_active);
	error = nlm_client_advlock(ap, head, size);
	atomic_dec_uint(&nlm_c_active);
	return error;
}

/*
 * Put or take back the hook of nfs_advlock().  EBUSY while a process is in
 * it, which is for the module to be able to go.  The moment between the
 * hook being read and the count going up is not covered.
 */
int
nlm_client_enable(bool on)
{

	atomic_store_release(&nfs_advlock_nlm, on ? nlm_client_entry : NULL);
	if (!on && (atomic_load_relaxed(&nlm_c_active) != 0 ||
	    atomic_load_relaxed(&nlm_c_reclaiming) != 0)) {
		atomic_store_release(&nfs_advlock_nlm, nlm_client_entry);
		return EBUSY;
	}
	return 0;
}

void
nlm_client_init(void)
{

	mutex_init(&nlm_c_lock, MUTEX_DEFAULT, IPL_NONE);
	cv_init(&nlm_c_cv, "nlmcwait");
}

void
nlm_client_fini(void)
{

	struct nlm_clock *l;
	struct nlm_cserver *s;

	while ((l = LIST_FIRST(&nlm_c_locks)) != NULL) {
		LIST_REMOVE(l, l_list);
		clock_free(l);
	}
	while ((s = LIST_FIRST(&nlm_c_servers)) != NULL) {
		LIST_REMOVE(s, s_list);
		kmem_free(s, sizeof(*s));
	}
	cv_destroy(&nlm_c_cv);
	mutex_destroy(&nlm_c_lock);
}
