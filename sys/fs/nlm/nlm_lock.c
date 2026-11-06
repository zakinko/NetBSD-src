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
 * The state of the lock manager.
 *
 * The locks are lockf's, reached by VOP_ADVLOCK with neither F_POSIX nor
 * F_FLOCK and a struct nlm_owner as the id, as the NFSv4 server does with
 * its own owners.  So a client's locks conflict with those of other
 * clients, of NFSv4 clients and of local processes, split and merge as
 * POSIX has it, and need no table here.
 *
 * An owner is (host, svid).  C702 ch. 10 has "uppid" uniquely describe
 * the process on the calling host; oh is not part of it, because a client
 * may give another one in the same process, Linux putting the pid of the
 * thread in it.  oh is only kept to be shown in NLM_TEST.  A host is
 * (caller_name, address): the name says which host it thinks it is and
 * the address stops one client unlocking for another by naming it.
 *
 * A hold says that an owner may have locks on a vnode, which needs to be
 * known twice: a vnode with locks must not be reclaimed, as the list is
 * in its inode, and FREE_ALL has to find them.
 *
 * nlm_lock covers all of it, is never held across a VOP or a sleep for
 * memory or the network, and comes after the vnode lock.  As in the NFSv4
 * server, that leaves a gap between looking and doing, and the owner's
 * busy flag closes it: a lock and its hold change together.
 *
 * A LOCK that has to wait gets a thread of its own, asleep in lockf as a
 * process would be: lockf has no way to call back, and who gets the lock
 * of those waiting is left to it, which wakes them all to try.  What this
 * costs is a thread per waiter, up to NLM_MAXWAITERS.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/condvar.h>
#include <sys/cprng.h>
#include <sys/hash.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/kthread.h>
#include <sys/lockf.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/vnode.h>

#include <netinet/in.h>

#include <fs/nlm/nlm_var.h>

#define	NLM_HASHSIZE	64
#define	NLM_IDLE	30	/* seconds an unused host is kept */
#define	NLM_MAXDEPTH	32	/* of a chain of waiters looked along */
#define	NLM_MAXTRIES	6	/* NLM_GRANTED, 1 + 2 + ... + 32 s apart */

struct nlm_owner;
struct nlm_hold;

struct nlm_host {
	LIST_ENTRY(nlm_host)	 h_list;
	char			*h_name;
	size_t			 h_namesz;
	struct sockaddr_storage	 h_addr;
	u_int			 h_refs;	/* owners, shares, calls */
	time_t			 h_used;
	bool			 h_mon;		/* the NSM has it */
	bool			 h_monbusy;	/* a call is out for that */
	LIST_HEAD(, nlm_owner)	 h_owners;
	LIST_HEAD(, nlm_share)	 h_shares;
};

struct nlm_owner {
	LIST_ENTRY(nlm_owner)	 ow_hlist;	/* h_owners */
	LIST_ENTRY(nlm_owner)	 ow_idlist;	/* nlm_owners, by pointer */
	struct nlm_host		*ow_host;
	int32_t			 ow_svid;
	u_int			 ow_refs;
	bool			 ow_busy;
	uint8_t			*ow_oh;
	uint32_t		 ow_ohlen;
	LIST_HEAD(, nlm_hold)	 ow_holds;
	LIST_HEAD(, nlm_waiter)	 ow_waiters;
};

struct nlm_hold {
	LIST_ENTRY(nlm_hold)	 hd_list;
	struct vnode		*hd_vp;		/* referenced */
	uint32_t		 hd_state;	/* client's NSM state */
	u_int			 hd_waiters;
};

enum nlm_wstate {
	NLM_W_WAITING,		/* its thread is in lockf */
	NLM_W_GRANTED,		/* has the lock, on nlm_grants */
	NLM_W_CALLING,		/* has the lock, NLM_GRANTED going out */
	NLM_W_FINISHED		/* its thread is out of lockf, with w_error */
};

struct nlm_waiter {
	LIST_ENTRY(nlm_waiter)	 w_list;	/* ow_waiters */
	TAILQ_ENTRY(nlm_waiter)	 w_grant;
	enum nlm_wstate		 w_wstate;
	bool			 w_cancel;	/* wanted no more */
	bool			 w_orphan;	/* its thread is to clean up */
	bool			 w_answered;	/* the client knows, by a LOCK */
	int			 w_error;
	u_int			 w_tries;
	time_t			 w_next;
	struct nlm_owner	*w_owner;
	struct nlm_hold		*w_hold;
	struct vnode		*w_vp;
	struct flock		 w_fl;
	/* As it asked; C702 NLM_GRANTED wants them back. */
	uint32_t		 w_vers;
	uint32_t		 w_state;
	bool			 w_exclusive;
	uint64_t		 w_offset;
	uint64_t		 w_len;
	uint8_t			*w_fh;
	uint32_t		 w_fhlen;
	uint8_t			*w_oh;
	uint32_t		 w_ohlen;
};

struct nlm_share {
	LIST_ENTRY(nlm_share)	 sh_vplist;	/* nlm_shares, by vnode */
	LIST_ENTRY(nlm_share)	 sh_hlist;	/* h_shares */
	struct nlm_host		*sh_host;
	struct vnode		*sh_vp;		/* referenced */
	uint8_t			*sh_oh;
	uint32_t		 sh_ohlen;
	uint32_t		 sh_mode;
	uint32_t		 sh_access;
};

kmutex_t nlm_lock;
int nlm_monitor_required = 1;
u_int nlm_nhosts, nlm_nowners, nlm_nholds, nlm_nwaiters, nlm_nshares;

static kcondvar_t nlm_cv;
static LIST_HEAD(, nlm_host) nlm_hosts[NLM_HASHSIZE];
static LIST_HEAD(, nlm_owner) nlm_owners[NLM_HASHSIZE];
static LIST_HEAD(, nlm_share) nlm_shares[NLM_HASHSIZE];
static TAILQ_HEAD(, nlm_waiter) nlm_grants =
    TAILQ_HEAD_INITIALIZER(nlm_grants);

#define	PTRHASH(p)	((((uintptr_t)(p)) >> 8) % NLM_HASHSIZE)

static bool
addr_eq(const struct sockaddr *a, const struct sockaddr *b)
{

	if (a->sa_family != b->sa_family)
		return false;
	if (a->sa_family == AF_INET)
		return ((const struct sockaddr_in *)a)->sin_addr.s_addr ==
		    ((const struct sockaddr_in *)b)->sin_addr.s_addr;
	if (a->sa_family == AF_INET6)
		return memcmp(&((const struct sockaddr_in6 *)a)->sin6_addr,
		    &((const struct sockaddr_in6 *)b)->sin6_addr,
		    sizeof(struct in6_addr)) == 0;
	return false;
}

static u_int
name_hash(const char *name)
{

	return hash32_str(name, HASH32_STR_INIT) % NLM_HASHSIZE;
}

static struct nlm_host *
host_find(const char *name, const struct sockaddr *sa)
{
	struct nlm_host *h;

	KASSERT(mutex_owned(&nlm_lock));

	LIST_FOREACH(h, &nlm_hosts[name_hash(name)], h_list)
		if (strcmp(h->h_name, name) == 0 &&
		    addr_eq((struct sockaddr *)&h->h_addr, sa))
			return h;
	return NULL;
}

/* With a reference, or NULL at the limit. */
static struct nlm_host *
host_get(const char *name, const struct sockaddr *sa)
{
	struct nlm_host *h, *nh;
	size_t sz = strlen(name) + 1;

	nh = kmem_zalloc(sizeof(*nh), KM_SLEEP);
	nh->h_name = kmem_alloc(sz, KM_SLEEP);
	nh->h_namesz = sz;
	memcpy(nh->h_name, name, sz);
	memcpy(&nh->h_addr, sa, sa->sa_len);
	LIST_INIT(&nh->h_owners);
	LIST_INIT(&nh->h_shares);

	mutex_enter(&nlm_lock);
	if ((h = host_find(name, sa)) == NULL &&
	    nlm_nhosts < NLM_MAXHOSTS) {
		h = nh;
		nh = NULL;
		LIST_INSERT_HEAD(&nlm_hosts[name_hash(name)], h, h_list);
		nlm_nhosts++;
	}
	if (h != NULL)
		h->h_refs++;
	mutex_exit(&nlm_lock);
	if (nh != NULL) {
		kmem_free(nh->h_name, sz);
		kmem_free(nh, sizeof(*nh));
	}
	return h;
}

static void
host_rele_locked(struct nlm_host *h)
{

	KASSERT(mutex_owned(&nlm_lock));
	KASSERT(h->h_refs > 0);
	h->h_refs--;
	h->h_used = time_uptime;
}

static void
host_rele(struct nlm_host *h)
{

	mutex_enter(&nlm_lock);
	host_rele_locked(h);
	mutex_exit(&nlm_lock);
}

/*
 * C702 ch. 9, Locking: "must" monitor the host.  A lock on a host nobody
 * watches stays after the host reboots, so failing here refuses the lock,
 * unless vfs.nlm.monitor_required says otherwise.  h_mon is set by success
 * alone, so the next lock of the host asks again and a statd that has come
 * back is found.  Another name on the address may have done it already.
 */
static bool
host_monitor(struct nlm_host *h)
{
	static struct timeval last;
	static const struct timeval every = { 10, 0 };
	const struct sockaddr *sa = (struct sockaddr *)&h->h_addr;
	struct nlm_host *o;
	char addr[INET6_ADDRSTRLEN + 8];
	bool ok;
	int error;
	u_int i;

	mutex_enter(&nlm_lock);
	while (h->h_monbusy)
		cv_wait(&nlm_cv, &nlm_lock);
	if (!h->h_mon) {
		for (i = 0; i < NLM_HASHSIZE; i++)
			LIST_FOREACH(o, &nlm_hosts[i], h_list)
				if (o->h_mon &&
				    addr_eq((struct sockaddr *)&o->h_addr, sa))
					h->h_mon = true;
	}
	if (h->h_mon) {
		mutex_exit(&nlm_lock);
		return true;
	}
	h->h_monbusy = true;
	mutex_exit(&nlm_lock);
	error = nlm_nsm_mon(sa, NULL);
	mutex_enter(&nlm_lock);
	ok = h->h_mon = error == 0;
	h->h_monbusy = false;
	cv_broadcast(&nlm_cv);
	if (!ok && ratecheck(&last, &every)) {
		mutex_exit(&nlm_lock);
		if (!nlm_addr_string(sa, addr, sizeof(addr)))
			addr[0] = '\0';
		printf("nlm: cannot monitor %s at %s (error %d): %s\n",
		    h->h_name, addr, error, nlm_monitor_required ?
		    "lock refused" : "lock let through");
		return false;
	}
	mutex_exit(&nlm_lock);
	return ok;
}

static void
owner_busy(struct nlm_owner *ow)
{

	KASSERT(mutex_owned(&nlm_lock));
	while (ow->ow_busy)
		cv_wait(&nlm_cv, &nlm_lock);
	ow->ow_busy = true;
}

static void
owner_unbusy(struct nlm_owner *ow)
{

	KASSERT(mutex_owned(&nlm_lock));
	ow->ow_busy = false;
	cv_broadcast(&nlm_cv);
}

static struct nlm_owner *
owner_find(struct nlm_host *h, int32_t svid)
{
	struct nlm_owner *ow;

	KASSERT(mutex_owned(&nlm_lock));
	LIST_FOREACH(ow, &h->h_owners, ow_hlist)
		if (ow->ow_svid == svid)
			return ow;
	return NULL;
}

/* With a reference, and busy; h gets a reference of its own for it. */
static struct nlm_owner *
owner_get(struct nlm_host *h, int32_t svid, const uint8_t *oh, uint32_t ohlen)
{
	struct nlm_owner *ow, *now;
	uint8_t *noh, *ooh = NULL;
	uint32_t ooh_len = 0;

	now = kmem_zalloc(sizeof(*now), KM_SLEEP);
	LIST_INIT(&now->ow_holds);
	LIST_INIT(&now->ow_waiters);
	noh = ohlen != 0 ? kmem_alloc(ohlen, KM_SLEEP) : NULL;
	if (ohlen != 0)
		memcpy(noh, oh, ohlen);

	mutex_enter(&nlm_lock);
	if ((ow = owner_find(h, svid)) == NULL) {
		ow = now;
		now = NULL;
		ow->ow_host = h;
		ow->ow_svid = svid;
		h->h_refs++;
		LIST_INSERT_HEAD(&h->h_owners, ow, ow_hlist);
		LIST_INSERT_HEAD(&nlm_owners[PTRHASH(ow)], ow, ow_idlist);
		nlm_nowners++;
	}
	ow->ow_refs++;
	owner_busy(ow);
	ooh = ow->ow_oh;
	ooh_len = ow->ow_ohlen;
	ow->ow_oh = noh;
	ow->ow_ohlen = ohlen;
	mutex_exit(&nlm_lock);
	if (ooh_len != 0)
		kmem_free(ooh, ooh_len);
	if (now != NULL)
		kmem_free(now, sizeof(*now));
	return ow;
}

/* Drop a reference; the owner goes when nothing is left to it. */
static void
owner_rele(struct nlm_owner *ow)
{
	struct nlm_host *h = ow->ow_host;
	uint8_t *oh = NULL;
	uint32_t ohlen = 0;

	mutex_enter(&nlm_lock);
	KASSERT(ow->ow_refs > 0);
	if (--ow->ow_refs > 0 || !LIST_EMPTY(&ow->ow_holds) ||
	    !LIST_EMPTY(&ow->ow_waiters)) {
		mutex_exit(&nlm_lock);
		return;
	}
	LIST_REMOVE(ow, ow_hlist);
	LIST_REMOVE(ow, ow_idlist);
	nlm_nowners--;
	oh = ow->ow_oh;
	ohlen = ow->ow_ohlen;
	host_rele_locked(h);
	mutex_exit(&nlm_lock);
	if (ohlen != 0)
		kmem_free(oh, ohlen);
	kmem_free(ow, sizeof(*ow));
}

/* The owner is busy, which is what keeps the list as it is. */
static struct nlm_hold *
hold_get(struct nlm_owner *ow, struct vnode *vp)
{
	struct nlm_hold *hd;

	mutex_enter(&nlm_lock);
	LIST_FOREACH(hd, &ow->ow_holds, hd_list)
		if (hd->hd_vp == vp)
			break;
	mutex_exit(&nlm_lock);
	if (hd != NULL)
		return hd;
	hd = kmem_zalloc(sizeof(*hd), KM_SLEEP);
	vref(vp);
	hd->hd_vp = vp;
	mutex_enter(&nlm_lock);
	LIST_INSERT_HEAD(&ow->ow_holds, hd, hd_list);
	nlm_nholds++;
	mutex_exit(&nlm_lock);
	return hd;
}

/* The owner has unlocked everything there.  Owner busy, no waiters. */
static void
hold_drop(struct nlm_hold *hd)
{

	mutex_enter(&nlm_lock);
	LIST_REMOVE(hd, hd_list);
	nlm_nholds--;
	mutex_exit(&nlm_lock);
	vrele(hd->hd_vp);
	kmem_free(hd, sizeof(*hd));
}

static void
fl_whole(struct flock *fl, short type)
{

	memset(fl, 0, sizeof(*fl));
	fl->l_whence = SEEK_SET;
	fl->l_type = type;
}

/* Let the hold go if the owner has nothing left there.  Owner busy. */
static void
hold_trim(struct nlm_owner *ow, struct nlm_hold *hd)
{
	struct flock fl;

	mutex_enter(&nlm_lock);
	if (hd->hd_waiters > 0) {
		mutex_exit(&nlm_lock);
		return;
	}
	mutex_exit(&nlm_lock);
	fl_whole(&fl, F_WRLCK);
	if (VOP_ADVLOCK(hd->hd_vp, ow, F_HASLK, &fl, 0) != 0 ||
	    fl.l_type != F_UNLCK)
		return;
	hold_drop(hd);
}

/*
 * RFC 1813 s6.1.4 has a length of 0 run to the end of the file.  What
 * off_t cannot hold is NLM4_FBIG, s6.3.1.  Versions 1 and 3 can reach
 * neither limit.
 */
static uint32_t
fl_range(const struct nlm_xlock *l, struct flock *fl)
{

	if (l->xl_offset > INT64_MAX)
		return NLM4_FBIG;
	if (l->xl_len != 0 && (l->xl_len - 1 > INT64_MAX ||
	    l->xl_offset + (l->xl_len - 1) > INT64_MAX))
		return NLM4_FBIG;
	memset(fl, 0, sizeof(*fl));
	fl->l_whence = SEEK_SET;
	fl->l_start = (off_t)l->xl_offset;
	fl->l_len = (off_t)l->xl_len;
	return NLM4_GRANTED;
}

static void
waiter_free(struct nlm_waiter *w)
{

	if (w->w_fhlen != 0)
		kmem_free(w->w_fh, w->w_fhlen);
	if (w->w_ohlen != 0)
		kmem_free(w->w_oh, w->w_ohlen);
	kmem_free(w, sizeof(*w));
}

/*
 * The end of a waiter, with its owner busy.  The owner has to have a
 * reference besides the waiter's.
 */
static void
waiter_done(struct nlm_waiter *w, bool unlock)
{
	struct nlm_owner *ow = w->w_owner;
	struct nlm_hold *hd = w->w_hold;
	struct flock fl;

	mutex_enter(&nlm_lock);
	LIST_REMOVE(w, w_list);
	hd->hd_waiters--;
	nlm_nwaiters--;
	KASSERT(ow->ow_refs > 1);
	ow->ow_refs--;
	cv_broadcast(&nlm_cv);
	mutex_exit(&nlm_lock);
	if (unlock) {
		fl = w->w_fl;
		fl.l_type = F_UNLCK;
		(void)VOP_ADVLOCK(w->w_vp, ow, F_UNLCK, &fl, 0);
	}
	hold_trim(ow, hd);
	waiter_free(w);
}

/* waiter_done() from outside: takes the owner by itself. */
static void
waiter_finish(struct nlm_waiter *w, bool unlock)
{
	struct nlm_owner *ow = w->w_owner;

	mutex_enter(&nlm_lock);
	ow->ow_refs++;
	owner_busy(ow);
	mutex_exit(&nlm_lock);
	waiter_done(w, unlock);
	mutex_enter(&nlm_lock);
	owner_unbusy(ow);
	mutex_exit(&nlm_lock);
	owner_rele(ow);
}

static void
waiter_thread(void *arg)
{
	struct nlm_waiter *w = arg;
	struct flock fl = w->w_fl;
	bool orphan;
	int error;

	error = VOP_ADVLOCK(w->w_vp, w->w_owner, F_SETLK, &fl, F_WAIT);

	mutex_enter(&nlm_lock);
	if (error == 0 && !w->w_cancel) {
		w->w_wstate = NLM_W_GRANTED;
		w->w_next = time_uptime;
		TAILQ_INSERT_TAIL(&nlm_grants, w, w_grant);
		nlm_nsm_kick();
		mutex_exit(&nlm_lock);
		kthread_exit(0);
	}
	w->w_error = error;
	w->w_wstate = NLM_W_FINISHED;
	/* If it failed by itself no one is waiting for this. */
	orphan = w->w_orphan || !w->w_cancel;
	cv_broadcast(&nlm_cv);
	mutex_exit(&nlm_lock);
	if (orphan)
		waiter_finish(w, error == 0);
	kthread_exit(0);
}

/*
 * Stop a waiter, with its owner busy and a reference to it besides the
 * waiter's.  A lock it has got goes with it.
 */
static void
waiter_cancel(struct nlm_waiter *w)
{
	struct flock fl;
	int error;

	mutex_enter(&nlm_lock);
	w->w_cancel = true;
	while (w->w_wstate == NLM_W_WAITING) {
		mutex_exit(&nlm_lock);
		fl = w->w_fl;
		error = VOP_ADVLOCK(w->w_vp, w->w_owner, F_CANCELWAIT, &fl, 0);
		mutex_enter(&nlm_lock);
		if (error != 0) {
			/* A file system of its own: leave it to finish. */
			if (w->w_wstate != NLM_W_WAITING)
				break;
			w->w_orphan = true;
			mutex_exit(&nlm_lock);
			return;
		}
		if (w->w_wstate == NLM_W_WAITING)
			(void)cv_timedwait(&nlm_cv, &nlm_lock, MAX(hz / 100, 1));
	}
	switch (w->w_wstate) {
	case NLM_W_GRANTED:
		TAILQ_REMOVE(&nlm_grants, w, w_grant);
		mutex_exit(&nlm_lock);
		waiter_done(w, true);
		return;
	case NLM_W_CALLING:
		/* grant_answer() will see w_cancel. */
		mutex_exit(&nlm_lock);
		return;
	default:
		mutex_exit(&nlm_lock);
		waiter_done(w, w->w_error == 0);
		return;
	}
}

static struct nlm_waiter *
waiter_find(struct nlm_owner *ow, struct vnode *vp, const struct flock *fl,
    bool exclusive)
{
	struct nlm_waiter *w;

	LIST_FOREACH(w, &ow->ow_waiters, w_list)
		if (w->w_vp == vp && w->w_fl.l_start == fl->l_start &&
		    w->w_fl.l_len == fl->l_len &&
		    w->w_exclusive == exclusive)
			return w;
	return NULL;
}

/*
 * Would waiting on this close a cycle of clients?  From what blocks the
 * request, follow the owner there to what it waits for, RFC 1813 s6.1.3
 * NLM4_DEADLCK.  A lock that many hold shows only one of them here, and
 * two requests at the same moment do not see each other, so this finds
 * deadlocks but not all of them; C702 does not ask for it at all.
 */
static bool
waiter_deadlock(struct nlm_owner *me, struct vnode *vp, const struct flock *fl)
{
	struct nlm_owner *ow;
	struct nlm_waiter *w;
	struct lf_query q;
	void *id;
	u_int depth;

	q.lfq_fl = *fl;
	q.lfq_id = NULL;
	if (VOP_ADVLOCK(vp, me, F_GETLKID, &q.lfq_fl, 0) != 0 ||
	    q.lfq_fl.l_type == F_UNLCK)
		return false;
	id = q.lfq_id;
	for (depth = 0; depth < NLM_MAXDEPTH; depth++) {
		mutex_enter(&nlm_lock);
		LIST_FOREACH(ow, &nlm_owners[PTRHASH(id)], ow_idlist)
			if (ow == id)
				break;
		w = NULL;
		if (ow != NULL)
			LIST_FOREACH(w, &ow->ow_waiters, w_list)
				if (w->w_wstate == NLM_W_WAITING)
					break;
		if (w == NULL) {
			mutex_exit(&nlm_lock);
			return false;
		}
		ow->ow_refs++;
		vref(w->w_vp);
		vp = w->w_vp;
		q.lfq_fl = w->w_fl;
		mutex_exit(&nlm_lock);
		q.lfq_id = NULL;
		if (VOP_ADVLOCK(vp, ow, F_GETLKID, &q.lfq_fl, 0) != 0)
			q.lfq_fl.l_type = F_UNLCK;
		vrele(vp);
		owner_rele(ow);
		if (q.lfq_fl.l_type == F_UNLCK)
			return false;
		if (q.lfq_id == me)
			return true;
		id = q.lfq_id;
	}
	return false;
}

/* Owner busy.  NLM4_BLOCKED, or why it could not be queued. */
static uint32_t
waiter_start(struct nlm_owner *ow, struct nlm_hold *hd,
    const struct nlm_args *a, const struct flock *fl, uint32_t vers)
{
	const struct nlm_xlock *l = &a->a_lock;
	struct nlm_waiter *w;
	struct lwp *lwp;
	int error;

	w = kmem_zalloc(sizeof(*w), KM_SLEEP);
	w->w_owner = ow;
	w->w_hold = hd;
	w->w_vp = hd->hd_vp;
	w->w_fl = *fl;
	w->w_vers = vers;
	w->w_state = a->a_state;
	w->w_exclusive = a->a_exclusive;
	w->w_offset = l->xl_offset;
	w->w_len = l->xl_len;
	w->w_fhlen = l->xl_fhlen;
	w->w_ohlen = l->xl_ohlen;
	if (w->w_fhlen != 0) {
		w->w_fh = kmem_alloc(w->w_fhlen, KM_SLEEP);
		memcpy(w->w_fh, l->xl_fh, w->w_fhlen);
	}
	if (w->w_ohlen != 0) {
		w->w_oh = kmem_alloc(w->w_ohlen, KM_SLEEP);
		memcpy(w->w_oh, l->xl_oh, w->w_ohlen);
	}

	mutex_enter(&nlm_lock);
	if (nlm_nwaiters >= NLM_MAXWAITERS) {
		mutex_exit(&nlm_lock);
		waiter_free(w);
		return NLM4_DENIED_NOLOCKS;
	}
	nlm_nwaiters++;
	hd->hd_waiters++;
	hd->hd_state = a->a_state;
	ow->ow_refs++;
	LIST_INSERT_HEAD(&ow->ow_waiters, w, w_list);
	mutex_exit(&nlm_lock);

	error = kthread_create(PRI_NONE, KTHREAD_MPSAFE, NULL, waiter_thread,
	    w, &lwp, "nlmwait");
	if (error != 0) {
		mutex_enter(&nlm_lock);
		LIST_REMOVE(w, w_list);
		nlm_nwaiters--;
		hd->hd_waiters--;
		ow->ow_refs--;
		mutex_exit(&nlm_lock);
		waiter_free(w);
		return NLM4_DENIED_NOLOCKS;
	}
	return NLM4_BLOCKED;
}

/*
 * NLM_LOCK, NLM_NM_LOCK.  C702 NLM_LOCK has no word for a call repeated,
 * which over UDP will be: a lock already held is granted again by lockf,
 * and one in the queue has this say so.
 */
uint32_t
nlm_do_lock(const struct nlm_args *a, const struct sockaddr *sa,
    struct vnode *vp, uint32_t vers, bool monitored)
{
	const struct nlm_xlock *l = &a->a_lock;
	struct nlm_host *h;
	struct nlm_owner *ow;
	struct nlm_hold *hd;
	struct nlm_waiter *w;
	struct flock fl, t;
	uint32_t stat;
	int error;

	stat = fl_range(l, &fl);
	if (stat != NLM4_GRANTED)
		return stat;
	fl.l_type = a->a_exclusive ? F_WRLCK : F_RDLCK;

	if ((h = host_get(l->xl_name, sa)) == NULL)
		return NLM4_DENIED_NOLOCKS;
	if (monitored && !host_monitor(h) && nlm_monitor_required) {
		host_rele(h);
		return NLM4_DENIED_NOLOCKS;
	}
	ow = owner_get(h, l->xl_svid, l->xl_oh, l->xl_ohlen);

	mutex_enter(&nlm_lock);
	w = monitored ? waiter_find(ow, vp, &fl, a->a_exclusive) : NULL;
	if (w != NULL) {
		switch (w->w_wstate) {
		case NLM_W_WAITING:
			mutex_exit(&nlm_lock);
			stat = NLM4_BLOCKED;
			goto out;
		case NLM_W_GRANTED:
			/* It has the lock and is about to hear so here. */
			TAILQ_REMOVE(&nlm_grants, w, w_grant);
			mutex_exit(&nlm_lock);
			waiter_done(w, false);
			stat = NLM4_GRANTED;
			goto out;
		case NLM_W_CALLING:
			w->w_answered = true;
			mutex_exit(&nlm_lock);
			stat = NLM4_GRANTED;
			goto out;
		case NLM_W_FINISHED:
			break;
		}
	}
	mutex_exit(&nlm_lock);

	hd = hold_get(ow, vp);
	t = fl;
	error = VOP_ADVLOCK(vp, ow, F_SETLK, &t, 0);
	switch (error) {
	case 0:
		hd->hd_state = a->a_state;
		stat = NLM4_GRANTED;
		break;
	case EAGAIN:
		stat = NLM4_DENIED;
		if (a->a_block && monitored)
			stat = waiter_deadlock(ow, vp, &fl) ? NLM4_DEADLCK :
			    waiter_start(ow, hd, a, &fl, vers);
		break;
	case ENOLCK:
	case ENOMEM:
		stat = NLM4_DENIED_NOLOCKS;
		break;
	default:
		stat = NLM4_FAILED;
		break;
	}
	if (stat != NLM4_GRANTED)
		hold_trim(ow, hd);
out:
	mutex_enter(&nlm_lock);
	owner_unbusy(ow);
	mutex_exit(&nlm_lock);
	owner_rele(ow);
	host_rele(h);
	return stat;
}

/*
 * NLM_CANCEL.  It stops what is queued and touches nothing held: a lock
 * already granted is for NLM_UNLOCK.  With nothing to stop C702 allows
 * either answer, and LCK_DENIED says what happened.
 */
uint32_t
nlm_do_cancel(const struct nlm_args *a, const struct sockaddr *sa,
    struct vnode *vp)
{
	const struct nlm_xlock *l = &a->a_lock;
	struct nlm_host *h;
	struct nlm_owner *ow;
	struct nlm_waiter *w;
	struct flock fl;
	uint32_t stat;

	stat = fl_range(l, &fl);
	if (stat != NLM4_GRANTED)
		return stat;

	mutex_enter(&nlm_lock);
	if ((h = host_find(l->xl_name, sa)) == NULL ||
	    (ow = owner_find(h, l->xl_svid)) == NULL) {
		mutex_exit(&nlm_lock);
		return NLM4_DENIED;
	}
	ow->ow_refs++;
	owner_busy(ow);
	w = waiter_find(ow, vp, &fl, a->a_exclusive);
	mutex_exit(&nlm_lock);
	if (w != NULL)
		waiter_cancel(w);
	else
		stat = NLM4_DENIED;
	mutex_enter(&nlm_lock);
	owner_unbusy(ow);
	mutex_exit(&nlm_lock);
	owner_rele(ow);
	return stat;
}

/*
 * NLM_UNLOCK.  The range is lockf's to split, and no match at all is
 * still LCK_GRANTED, C702 NLM_UNLOCK.
 */
uint32_t
nlm_do_unlock(const struct nlm_args *a, const struct sockaddr *sa,
    struct vnode *vp)
{
	const struct nlm_xlock *l = &a->a_lock;
	struct nlm_host *h;
	struct nlm_owner *ow;
	struct nlm_hold *hd;
	struct flock fl;
	uint32_t stat;

	stat = fl_range(l, &fl);
	if (stat != NLM4_GRANTED)
		return stat;
	fl.l_type = F_UNLCK;

	mutex_enter(&nlm_lock);
	if ((h = host_find(l->xl_name, sa)) == NULL ||
	    (ow = owner_find(h, l->xl_svid)) == NULL) {
		mutex_exit(&nlm_lock);
		return NLM4_GRANTED;
	}
	ow->ow_refs++;
	owner_busy(ow);
	LIST_FOREACH(hd, &ow->ow_holds, hd_list)
		if (hd->hd_vp == vp)
			break;
	mutex_exit(&nlm_lock);
	if (hd != NULL) {
		(void)VOP_ADVLOCK(vp, ow, F_UNLCK, &fl, 0);
		hold_trim(ow, hd);
	}
	mutex_enter(&nlm_lock);
	owner_unbusy(ow);
	mutex_exit(&nlm_lock);
	owner_rele(ow);
	return NLM4_GRANTED;
}

/*
 * Is id one of ours?  id is only compared, as F_GETLKID says, and the
 * owner's oh is copied to buf while it can still be looked at.
 */
bool
nlm_owner_byid(const void *id, struct nlm_xholder *xh, uint8_t *buf)
{
	struct nlm_owner *ow;

	KASSERT(mutex_owned(&nlm_lock));
	LIST_FOREACH(ow, &nlm_owners[PTRHASH(id)], ow_idlist) {
		if (ow != id)
			continue;
		xh->xh_svid = ow->ow_svid;
		xh->xh_ohlen = ow->ow_ohlen;
		if (ow->ow_ohlen != 0)
			memcpy(buf, ow->ow_oh, ow->ow_ohlen);
		xh->xh_oh = buf;
		return true;
	}
	return false;
}

/*
 * NLM_TEST.  The owner's own locks do not stand in its way.  An owner
 * not known has no locks, and any id that is no owner's will do for it;
 * this one is on the stack.  A holder that is not an NLM owner, a local
 * process or an NFSv4 client, has no svid or oh to show: C702 has
 * nothing for that case, and 0 and an empty oh are the server's choice.
 */
uint32_t
nlm_do_test(const struct nlm_args *a, const struct sockaddr *sa,
    struct vnode *vp, struct nlm_xholder *xh, uint8_t *ohbuf)
{
	const struct nlm_xlock *l = &a->a_lock;
	struct nlm_host *h;
	struct nlm_owner *ow = NULL;
	struct lf_query q;
	const void *id = &q;
	uint32_t stat;
	int error;

	stat = fl_range(l, &q.lfq_fl);
	if (stat != NLM4_GRANTED)
		return stat;
	q.lfq_fl.l_type = a->a_exclusive ? F_WRLCK : F_RDLCK;

	mutex_enter(&nlm_lock);
	if ((h = host_find(l->xl_name, sa)) != NULL &&
	    (ow = owner_find(h, l->xl_svid)) != NULL) {
		ow->ow_refs++;
		id = ow;
	}
	mutex_exit(&nlm_lock);
	q.lfq_id = NULL;
	error = VOP_ADVLOCK(vp, __UNCONST(id), F_GETLKID, &q.lfq_fl, 0);
	if (ow != NULL)
		owner_rele(ow);
	if (error != 0)
		return NLM4_FAILED;
	if (q.lfq_fl.l_type == F_UNLCK)
		return NLM4_GRANTED;

	memset(xh, 0, sizeof(*xh));
	mutex_enter(&nlm_lock);
	(void)nlm_owner_byid(q.lfq_id, xh, ohbuf);
	mutex_exit(&nlm_lock);
	xh->xh_exclusive = q.lfq_fl.l_type == F_WRLCK;
	xh->xh_offset = q.lfq_fl.l_start;
	xh->xh_len = q.lfq_fl.l_len;
	return NLM4_DENIED;
}

static void
share_free(struct nlm_share *sh)
{

	if (sh->sh_ohlen != 0)
		kmem_free(sh->sh_oh, sh->sh_ohlen);
	vrele(sh->sh_vp);
	kmem_free(sh, sizeof(*sh));
}

static void
share_unlink(struct nlm_share *sh)
{

	KASSERT(mutex_owned(&nlm_lock));
	LIST_REMOVE(sh, sh_vplist);
	LIST_REMOVE(sh, sh_hlist);
	nlm_nshares--;
	host_rele_locked(sh->sh_host);
}

/*
 * NLM_SHARE, DOS share modes (C702 ch. 10): a request meets each
 * reservation on the file from another owner both ways, the access of
 * the one against the deny mode of the other.  The bits of fsh_access
 * and fsh_mode line up for that.  One owner is (host, oh): the structure
 * has no svid.  Repeating a share changes it.
 */
uint32_t
nlm_do_share(const struct nlm_args *a, const struct sockaddr *sa,
    struct vnode *vp)
{
	const struct nlm_xlock *l = &a->a_lock;
	struct nlm_host *h;
	struct nlm_share *sh, *nsh, *mine = NULL, *added = NULL;
	uint32_t stat = NLM4_GRANTED, omode = 0, oaccess = 0;

	if ((h = host_get(l->xl_name, sa)) == NULL)
		return NLM4_DENIED_NOLOCKS;

	nsh = kmem_zalloc(sizeof(*nsh), KM_SLEEP);
	nsh->sh_host = h;
	nsh->sh_vp = vp;
	vref(vp);
	nsh->sh_ohlen = l->xl_ohlen;
	if (l->xl_ohlen != 0) {
		nsh->sh_oh = kmem_alloc(l->xl_ohlen, KM_SLEEP);
		memcpy(nsh->sh_oh, l->xl_oh, l->xl_ohlen);
	}
	nsh->sh_mode = l->xl_mode;
	nsh->sh_access = l->xl_access;

	mutex_enter(&nlm_lock);
	LIST_FOREACH(sh, &nlm_shares[PTRHASH(vp)], sh_vplist) {
		if (sh->sh_vp != vp)
			continue;
		if (sh->sh_host == h && sh->sh_ohlen == l->xl_ohlen &&
		    memcmp(sh->sh_oh, l->xl_oh, l->xl_ohlen) == 0) {
			mine = sh;
			continue;
		}
		if ((sh->sh_mode & l->xl_access) != 0 ||
		    (sh->sh_access & l->xl_mode) != 0) {
			stat = NLM4_DENIED;
			break;
		}
	}
	if (stat == NLM4_GRANTED) {
		if (mine != NULL) {
			omode = mine->sh_mode;
			oaccess = mine->sh_access;
			mine->sh_mode = l->xl_mode;
			mine->sh_access = l->xl_access;
		} else {
			LIST_INSERT_HEAD(&nlm_shares[PTRHASH(vp)], nsh,
			    sh_vplist);
			LIST_INSERT_HEAD(&h->h_shares, nsh, sh_hlist);
			nlm_nshares++;
			h->h_refs++;
			added = nsh;
			nsh = NULL;
		}
	}
	mutex_exit(&nlm_lock);

	/* NFSv4's OPEN, with this share already where it can see it. */
	if (stat == NLM4_GRANTED && oncrpc_share_conflict(ONCRPC_SHARE_NLM, vp,
	    l->xl_access, l->xl_mode)) {
		stat = NLM4_DENIED;
		mutex_enter(&nlm_lock);
		if (added != NULL) {
			share_unlink(added);
			nsh = added;
		} else {
			mine->sh_mode = omode;
			mine->sh_access = oaccess;
		}
		mutex_exit(&nlm_lock);
	}
	host_rele(h);
	if (nsh != NULL)
		share_free(nsh);
	return stat;
}

/* For an NFSv4 OPEN: oncrpc_share_register(). */
bool
nlm_share_conflict(struct vnode *vp, uint32_t access, uint32_t deny)
{
	struct nlm_share *sh;
	bool conflict = false;

	mutex_enter(&nlm_lock);
	LIST_FOREACH(sh, &nlm_shares[PTRHASH(vp)], sh_vplist)
		if (sh->sh_vp == vp && ((sh->sh_mode & access) != 0 ||
		    (sh->sh_access & deny) != 0))
			conflict = true;
	mutex_exit(&nlm_lock);
	return conflict;
}

uint32_t
nlm_do_unshare(const struct nlm_args *a, const struct sockaddr *sa,
    struct vnode *vp)
{
	const struct nlm_xlock *l = &a->a_lock;
	struct nlm_host *h;
	struct nlm_share *sh;

	mutex_enter(&nlm_lock);
	h = host_find(l->xl_name, sa);
	sh = NULL;
	if (h != NULL) {
		LIST_FOREACH(sh, &h->h_shares, sh_hlist)
			if (sh->sh_vp == vp && sh->sh_ohlen == l->xl_ohlen &&
			    memcmp(sh->sh_oh, l->xl_oh, l->xl_ohlen) == 0)
				break;
	}
	if (sh != NULL)
		share_unlink(sh);
	mutex_exit(&nlm_lock);
	if (sh != NULL)
		share_free(sh);
	return NLM4_GRANTED;
}

/*
 * Everything the host has that was had in NSM state below state; state 0
 * is all of it.  C702 NLM_LOCK says what the state is kept for: a
 * notification can arrive after the rebooted client has locked again.
 * The caller has a reference to h.
 */
static void
host_clear(struct nlm_host *h, uint32_t state)
{
	struct nlm_owner *ow, *next;
	struct nlm_waiter *w;
	struct nlm_hold *hd;
	struct nlm_share *sh;
	struct flock fl;

	mutex_enter(&nlm_lock);
	for (ow = LIST_FIRST(&h->h_owners); ow != NULL; ow = next) {
		ow->ow_refs++;
		owner_busy(ow);
		for (;;) {
			LIST_FOREACH(w, &ow->ow_waiters, w_list)
				if (!w->w_cancel &&
				    (state == 0 || w->w_state < state))
					break;
			if (w == NULL)
				break;
			mutex_exit(&nlm_lock);
			waiter_cancel(w);
			mutex_enter(&nlm_lock);
		}
		for (;;) {
			LIST_FOREACH(hd, &ow->ow_holds, hd_list)
				if (hd->hd_waiters == 0 &&
				    (state == 0 || hd->hd_state < state))
					break;
			if (hd == NULL)
				break;
			mutex_exit(&nlm_lock);
			fl_whole(&fl, F_UNLCK);
			(void)VOP_ADVLOCK(hd->hd_vp, ow, F_UNLCK, &fl, 0);
			hold_drop(hd);
			mutex_enter(&nlm_lock);
		}
		owner_unbusy(ow);
		mutex_exit(&nlm_lock);
		owner_rele(ow);
		mutex_enter(&nlm_lock);
		/* It may be gone; take the next that has anything to do. */
		next = NULL;
		LIST_FOREACH(ow, &h->h_owners, ow_hlist) {
			LIST_FOREACH(hd, &ow->ow_holds, hd_list)
				if (hd->hd_waiters == 0 &&
				    (state == 0 || hd->hd_state < state))
					break;
			LIST_FOREACH(w, &ow->ow_waiters, w_list)
				if (!w->w_cancel &&
				    (state == 0 || w->w_state < state))
					break;
			if (hd != NULL || w != NULL) {
				next = ow;
				break;
			}
		}
	}
	if (state == 0) {
		while ((sh = LIST_FIRST(&h->h_shares)) != NULL) {
			share_unlink(sh);
			mutex_exit(&nlm_lock);
			share_free(sh);
			mutex_enter(&nlm_lock);
		}
	}
	mutex_exit(&nlm_lock);
}

/*
 * NLM_FREE_ALL.  C702 gives only a name; a name from any other address
 * than the one holding the locks would be anybody's to free, so that
 * host must be the caller, as for the locks themselves.
 */
void
nlm_do_free_all(const char *name, const struct sockaddr *sa)
{
	struct nlm_host *h;

	mutex_enter(&nlm_lock);
	if ((h = host_find(name, sa)) == NULL) {
		mutex_exit(&nlm_lock);
		return;
	}
	h->h_refs++;
	mutex_exit(&nlm_lock);
	host_clear(h, 0);
	host_rele(h);
}

/*
 * NLM_SM_NOTIFY: that address has rebooted.  Shares are not monitored,
 * C702 NLM_SHARE, and are left to NLM_FREE_ALL: host_clear() only frees
 * them with state 0.
 */
void
nlm_do_notify(const uint8_t *priv, uint32_t state)
{
	struct nlm_host *h;
	uint8_t p[SM_PRIVLEN];
	u_int i;

	mutex_enter(&nlm_lock);
	for (i = 0; i < NLM_HASHSIZE; i++) {
		LIST_FOREACH(h, &nlm_hosts[i], h_list) {
			nlm_nsm_priv((struct sockaddr *)&h->h_addr, p);
			if (memcmp(p, priv, SM_PRIVLEN) != 0)
				continue;
			h->h_refs++;
			mutex_exit(&nlm_lock);
			host_clear(h, MAX(state, 1));
			mutex_enter(&nlm_lock);
			host_rele_locked(h);
		}
	}
	mutex_exit(&nlm_lock);
}

/* What the client said, or could not be got to say, to NLM_GRANTED. */
static void
grant_answer(struct nlm_waiter *w, int error, uint32_t stat)
{
	bool unlock;

	mutex_enter(&nlm_lock);
	if (w->w_cancel) {
		unlock = true;
	} else if (w->w_answered) {
		unlock = false;
	} else if (error == 0) {
		/* LCK_DENIED: it has given up on the lock. */
		unlock = stat != NLM4_GRANTED;
	} else if (++w->w_tries < NLM_MAXTRIES) {
		w->w_wstate = NLM_W_GRANTED;
		w->w_next = time_uptime + (1 << w->w_tries);
		TAILQ_INSERT_TAIL(&nlm_grants, w, w_grant);
		mutex_exit(&nlm_lock);
		return;
	} else {
		unlock = true;
		printf("nlm: %s does not take its lock, dropping it\n",
		    w->w_owner->ow_host->h_name);
	}
	mutex_exit(&nlm_lock);
	waiter_finish(w, unlock);
}

/* Make the calls that are due, from the thread in nlm_nsm.c. */
void
nlm_grants_run(void)
{
	struct nlm_waiter *w;
	uint64_t cookie;
	uint32_t stat;
	int error;

	mutex_enter(&nlm_lock);
	for (;;) {
		TAILQ_FOREACH(w, &nlm_grants, w_grant)
			if (w->w_next <= time_uptime)
				break;
		if (w == NULL)
			break;
		TAILQ_REMOVE(&nlm_grants, w, w_grant);
		w->w_wstate = NLM_W_CALLING;
		mutex_exit(&nlm_lock);
		cookie = cprng_fast64();
		stat = NLM4_FAILED;
		error = nlm_nsm_grant(
		    (struct sockaddr *)&w->w_owner->ow_host->h_addr, w->w_vers,
		    &cookie, sizeof(cookie), w->w_exclusive,
		    w->w_owner->ow_host->h_name, w->w_fh, w->w_fhlen, w->w_oh,
		    w->w_ohlen, w->w_owner->ow_svid, w->w_offset, w->w_len,
		    &stat);
		grant_answer(w, error, stat);
		mutex_enter(&nlm_lock);
	}
	mutex_exit(&nlm_lock);
}

/*
 * C702 ch. 9, Unlocking: the server can ask the NSM to stop monitoring.
 * A host is let go after it has been idle a while, not at its last
 * unlock, as most clients lock again.  The NSM keeps one list by address,
 * and SM_UNMON ends what any name on the address had.
 */
void
nlm_hosts_gc(void)
{
	struct nlm_host *h, *o;
	bool shared;
	u_int i, j;

	mutex_enter(&nlm_lock);
	for (i = 0; i < NLM_HASHSIZE; i++) {
again:
		LIST_FOREACH(h, &nlm_hosts[i], h_list) {
			if (h->h_refs != 0 || h->h_monbusy ||
			    time_uptime - h->h_used < NLM_IDLE)
				continue;
			shared = false;
			for (j = 0; j < NLM_HASHSIZE && !shared; j++)
				LIST_FOREACH(o, &nlm_hosts[j], h_list)
					if (o != h && o->h_mon && addr_eq(
					    (struct sockaddr *)&o->h_addr,
					    (struct sockaddr *)&h->h_addr))
						shared = true;
			if (h->h_mon && !shared) {
				h->h_monbusy = true;
				mutex_exit(&nlm_lock);
				nlm_nsm_unmon((struct sockaddr *)&h->h_addr);
				mutex_enter(&nlm_lock);
				h->h_mon = false;
				h->h_monbusy = false;
				cv_broadcast(&nlm_cv);
				goto again;
			}
			LIST_REMOVE(h, h_list);
			nlm_nhosts--;
			mutex_exit(&nlm_lock);
			kmem_free(h->h_name, h->h_namesz);
			kmem_free(h, sizeof(*h));
			mutex_enter(&nlm_lock);
			goto again;
		}
	}
	mutex_exit(&nlm_lock);
}

void
nlm_state_init(void)
{
	u_int i;

	mutex_init(&nlm_lock, MUTEX_DEFAULT, IPL_NONE);
	cv_init(&nlm_cv, "nlmlock");
	for (i = 0; i < NLM_HASHSIZE; i++) {
		LIST_INIT(&nlm_hosts[i]);
		LIST_INIT(&nlm_owners[i]);
		LIST_INIT(&nlm_shares[i]);
	}
}

/*
 * Nothing calls in any more.  Give back every lock, wake every waiter and
 * see the last of them out.  The NSM's list stays, for the next load.
 */
void
nlm_state_fini(void)
{
	struct nlm_host *h;
	u_int i;

	mutex_enter(&nlm_lock);
	for (i = 0; i < NLM_HASHSIZE; i++) {
		LIST_FOREACH(h, &nlm_hosts[i], h_list) {
			h->h_refs++;
			mutex_exit(&nlm_lock);
			host_clear(h, 0);
			mutex_enter(&nlm_lock);
			h->h_refs--;
		}
	}
	while (nlm_nwaiters != 0)
		(void)cv_timedwait(&nlm_cv, &nlm_lock, hz);
	for (i = 0; i < NLM_HASHSIZE; i++) {
		while ((h = LIST_FIRST(&nlm_hosts[i])) != NULL) {
			LIST_REMOVE(h, h_list);
			nlm_nhosts--;
			kmem_free(h->h_name, h->h_namesz);
			kmem_free(h, sizeof(*h));
		}
	}
	mutex_exit(&nlm_lock);
	cv_destroy(&nlm_cv);
	mutex_destroy(&nlm_lock);
}
