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
 * Clients, owners, stateids and leases, RFC 7530 s9.  See nfsv4_state.h
 * for the locking.
 *
 * A client finds out by NFS4ERR_STALE_CLIENTID that the server restarted
 * and it lost everything, s9.6.2.  nfsv4_stable.c has what remains.
 *
 * Under version 4.1 the same records serve, by RFC 8881 s8: seqids are
 * ignored and the owners are serialized only to hold state still.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/kauth.h>
#include <sys/kmem.h>
#include <sys/kthread.h>
#include <sys/lockf.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/vnode.h>

#include <fs/nfsv4/nfsv4_var.h>
#include <fs/nfsv4/nfsv4_state.h>

/*
 * Chosen, not from the RFC: how often leases are looked at, how long a
 * client that expired stays known, and the sizes of the hash tables.
 */
#define	NFSV4_LEASE_SCAN	10
#define	NFSV4_TOMB_TIME		(10 * NFSV4_LEASE)
#define	NFSV4_STATE_HASH	256
#define	NFSV4_FILE_HASH		64

kmutex_t nfsv4_state_lock;
kcondvar_t nfsv4_state_cv;		/* an owner went idle, or a scan */
uint32_t nfsv4_boot;

static LIST_HEAD(, nfsv4_client) nfsv4_clients;
static LIST_HEAD(, nfsv4_state) nfsv4_state_hash[NFSV4_STATE_HASH];
static LIST_HEAD(, nfsv4_file) nfsv4_file_hash[NFSV4_FILE_HASH];
static uint64_t nfsv4_counter;
static struct lwp *nfsv4_lease_lwp;
static bool nfsv4_dying;

static inline u_int
file_hash(const struct vnode *vp)
{

	return ((uintptr_t)vp >> 8) & (NFSV4_FILE_HASH - 1);
}

static inline u_int
state_hash(uint64_t other)
{

	return other & (NFSV4_STATE_HASH - 1);
}

/* Time in the lease, the wall clock not being trusted, s9.13. */
static inline time_t
lease_end(void)
{

	return time_uptime + NFSV4_LEASE;
}

uid_t
nfsv4_client_principal(const struct nfsv4_compound *c)
{
	kauth_cred_t cred = c->c_rq->rq_cred;

	return cred != NULL ? kauth_cred_geteuid(cred) : (uid_t)-1;
}

/*
 * A client ID, by s9.1.1: after a restart it is stale, because the top
 * half is the boot, and an unconfirmed one is not yet usable.  This is
 * what renews a lease, s9.5.
 */
uint32_t
nfsv4_client_get(uint64_t id, struct nfsv4_client **clp)
{
	struct nfsv4_client *cl;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if ((uint32_t)(id >> 32) != nfsv4_boot)
		return NFS4ERR_STALE_CLIENTID;
	LIST_FOREACH(cl, &nfsv4_clients, cl_list) {
		if (cl->cl_id == id && cl->cl_confirmed && cl->cl_minor == 0)
			break;
	}
	if (cl == NULL)
		return NFS4ERR_STALE_CLIENTID;
	if (cl->cl_expired || time_uptime > cl->cl_expire)
		return NFS4ERR_EXPIRED;
	cl->cl_expire = lease_end();
	if (nfsv4_lease_moved(cl))
		return NFS4ERR_LEASE_MOVED;
	*clp = cl;
	return NFS4_OK;
}

/*
 * The client of a request.  Under a session it is the session's, and
 * the id in the arguments means nothing, RFC 8881 s18.16.3 and s18.10.3.
 */
uint32_t
nfsv4_client_cur(struct nfsv4_compound *c, uint64_t id,
    struct nfsv4_client **clp)
{
	struct nfsv4_client *cl = c->c_client;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if (c->c_minor == 0)
		return nfsv4_client_get(id, clp);
	if (cl->cl_expired)
		return NFS4ERR_EXPIRED;
	cl->cl_expire = lease_end();
	*clp = cl;
	return NFS4_OK;
}

struct nfsv4_owner_s *
nfsv4_owner_find(struct nfsv4_client *cl, u_int type, const uint8_t *data,
    uint32_t len)
{
	struct nfsv4_owner_s *sw;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	LIST_FOREACH(sw, &cl->cl_owners, sw_list) {
		if (sw->sw_type == type && sw->sw_len == len &&
		    memcmp(sw->sw_data, data, len) == 0)
			return sw;
	}
	return NULL;
}

/* Add the owner in *spare, which the caller allocated, taking it. */
struct nfsv4_owner_s *
nfsv4_owner_add(struct nfsv4_client *cl, struct nfsv4_owner_s **spare,
    u_int type, const uint8_t *data, uint32_t len)
{
	struct nfsv4_owner_s *sw = *spare;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	*spare = NULL;
	sw->sw_client = cl;
	sw->sw_gen = ++nfsv4_counter;
	sw->sw_type = type;
	sw->sw_len = len;
	memcpy(sw->sw_data, data, len);
	LIST_INIT(&sw->sw_states);
	LIST_INSERT_HEAD(&cl->cl_owners, sw, sw_list);
	return sw;
}

/*
 * The lock owner that gave id to lockf, if it still is one.  A linear
 * search, for a denied lock; id is not to be trusted to point to one.
 */
struct nfsv4_owner_s *
nfsv4_owner_byid(const void *id)
{
	struct nfsv4_client *cl;
	struct nfsv4_owner_s *sw;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	LIST_FOREACH(cl, &nfsv4_clients, cl_list) {
		LIST_FOREACH(sw, &cl->cl_owners, sw_list) {
			if (sw == id && sw->sw_type == NFSV4_OWNER_LOCK)
				return sw;
		}
	}
	return NULL;
}

void
nfsv4_owner_busy(struct nfsv4_owner_s *sw)
{

	KASSERT(mutex_owned(&nfsv4_state_lock));

	sw->sw_waiters++;
	while (sw->sw_busy)
		cv_wait(&nfsv4_state_cv, &nfsv4_state_lock);
	sw->sw_waiters--;
	sw->sw_busy = true;
}

void
nfsv4_owner_idle(struct nfsv4_owner_s *sw)
{

	KASSERT(mutex_owned(&nfsv4_state_lock));
	KASSERT(sw->sw_busy);

	sw->sw_busy = false;
	cv_broadcast(&nfsv4_state_cv);
}

/*
 * s9.1.7, with the next value by s9.1.3: past the largest comes one, not
 * zero.  A replay of something else is no replay, s9.1.9.
 */
enum nfsv4_seq
nfsv4_seq_check(const struct nfsv4_owner_s *sw, uint32_t seqid, uint32_t op)
{
	uint32_t next;

	/* RFC 8881 s18.16.3 and the like: seqids are ignored. */
	if (sw->sw_client->cl_minor != 0)
		return NFSV4_SEQ_GO;
	next = sw->sw_seqid + 1;
	if (next == 0)
		next = 1;
	if (seqid == next)
		return NFSV4_SEQ_GO;
	if (seqid == sw->sw_seqid && sw->sw_lastop == op)
		return NFSV4_SEQ_REPLAY;
	return NFSV4_SEQ_BAD;
}

/* RELEASE_LOCKOWNER's end of an owner, which must be busy and alone. */
void
nfsv4_owner_free(struct nfsv4_owner_s *sw, struct nfsv4_reap *reap)
{
	struct nfsv4_state *st;

	KASSERT(mutex_owned(&nfsv4_state_lock));
	KASSERT(sw->sw_busy);

	while (sw->sw_waiters != 0)
		cv_wait(&nfsv4_state_cv, &nfsv4_state_lock);
	while ((st = LIST_FIRST(&sw->sw_states)) != NULL)
		nfsv4_state_unlink(st, reap, false);
	LIST_REMOVE(sw, sw_list);
	cv_broadcast(&nfsv4_state_cv);
	if (sw->sw_rbuf != NULL)
		kmem_free(sw->sw_rbuf, sw->sw_rlen);
	kmem_free(sw, sizeof(*sw));
}

/*
 * Keep the reply to a request that used up its seqid.  The client does
 * not advance past the errors listed in s9.1.7, so they keep the old
 * one.  Then the owner is idle again.
 */
void
nfsv4_owner_replay_save(struct nfsv4_owner_s *sw, uint32_t seqid, uint32_t op,
    uint32_t status, const char *body, u_int len)
{
	struct nfsv4_reap reap;
	char *buf = NULL, *old = NULL;
	u_int oldlen = 0;
	bool keep;

	/* RFC 8881 s2.10.6: the slot replays, the owner has nothing to. */
	if (sw->sw_client->cl_minor != 0) {
		mutex_enter(&nfsv4_state_lock);
		nfsv4_owner_idle(sw);
		mutex_exit(&nfsv4_state_lock);
		return;
	}

	switch (status) {
	case NFS4ERR_STALE_CLIENTID:
	case NFS4ERR_STALE_STATEID:
	case NFS4ERR_BAD_STATEID:
	case NFS4ERR_BAD_SEQID:
	case NFS4ERR_BADXDR:
	case NFS4ERR_RESOURCE:
	case NFS4ERR_NOFILEHANDLE:
	case NFS4ERR_MOVED:
		keep = false;
		break;
	default:
		keep = true;
		break;
	}
	if (keep && len > 0) {
		buf = kmem_alloc(len, KM_SLEEP);
		memcpy(buf, body, len);
	}

	SLIST_INIT(&reap);
	mutex_enter(&nfsv4_state_lock);
	if (keep) {
		/* s9.10.1: past a CLOSE, it can no longer be resent. */
		if (op != NFSV4_OP_CLOSE && sw->sw_closed != NULL) {
			nfsv4_state_unlink(sw->sw_closed, &reap, false);
			sw->sw_closed = NULL;
		}
		old = sw->sw_rbuf;
		oldlen = sw->sw_rlen;
		sw->sw_seqid = seqid;
		sw->sw_lastop = op;
		sw->sw_laststat = status;
		sw->sw_rbuf = buf;
		sw->sw_rlen = len;
	}
	nfsv4_owner_idle(sw);
	mutex_exit(&nfsv4_state_lock);
	nfsv4_reap_finish(&reap);
	if (old != NULL)
		kmem_free(old, oldlen);
}

/*
 * s9.14.3: does cl have state on a file system that has gone, and has
 * it not found out?  A linear search, and only with such a file system
 * around, for two leases.
 */
bool
nfsv4_lease_moved(const struct nfsv4_client *cl)
{
	const struct nfsv4_owner_s *sw;
	const struct nfsv4_state *st;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if (!nfsv4_moved_grace() || cl->cl_movedack == nfsv4_moved_gen())
		return false;
	LIST_FOREACH(sw, &cl->cl_owners, sw_list) {
		LIST_FOREACH(st, &sw->sw_states, st_olist) {
			if (st->st_file != NULL &&
			    nfsv4_moved_mount(st->st_file->f_vp->v_mount))
				return true;
		}
	}
	return false;
}

/* The client with this ID, confirmed, if it still exists. */
struct nfsv4_client *
nfsv4_client_byid(uint64_t id)
{
	struct nfsv4_client *cl;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	LIST_FOREACH(cl, &nfsv4_clients, cl_list) {
		if (cl->cl_id == id && cl->cl_confirmed)
			return cl;
	}
	return NULL;
}

void
nfsv4_client_renew(struct nfsv4_client *cl)
{

	KASSERT(mutex_owned(&nfsv4_state_lock));

	cl->cl_expire = lease_end();
}

struct nfsv4_state *
nfsv4_state_byother(uint64_t other)
{
	struct nfsv4_state *st;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	LIST_FOREACH(st, &nfsv4_state_hash[state_hash(other)], st_hash) {
		if (st->st_other == other)
			return st;
	}
	return NULL;
}

/* What is open on vp, or on its named attribute aname if not NULL. */
struct nfsv4_file *
nfsv4_file_find_attr(struct vnode *vp, const char *aname)
{
	struct nfsv4_file *f;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	LIST_FOREACH(f, &nfsv4_file_hash[file_hash(vp)], f_list) {
		if (f->f_vp == vp && f->f_isattr == (aname != NULL) &&
		    (aname == NULL || strcmp(f->f_aname, aname) == 0))
			return f;
	}
	return NULL;
}

/*
 * A reference to the vnode of an open file with this handle.  This is
 * for a file that has lost its last link, which a file system's
 * VFS_FHTOVP may no longer find: RFC 7530 s16.26.5 lets access go on until
 * the last CLOSE, and without it the CLOSE itself cannot name the file.
 * A linear search, as that is rare.
 */
struct vnode *
nfsv4_file_vp_byfh(const struct nfsv4_fh *fh)
{
	struct nfsv4_file *f;
	struct vnode *vp = NULL;
	u_int i;

	mutex_enter(&nfsv4_state_lock);
	for (i = 0; i < NFSV4_FILE_HASH && vp == NULL; i++) {
		LIST_FOREACH(f, &nfsv4_file_hash[i], f_list) {
			if (!f->f_isattr && f->f_fh.fh_len == fh->fh_len &&
			    memcmp(f->f_fh.fh_data, fh->fh_data,
			    fh->fh_len) == 0) {
				vp = f->f_vp;
				vref(vp);
				break;
			}
		}
	}
	mutex_exit(&nfsv4_state_lock);
	return vp;
}

struct nfsv4_file *
nfsv4_file_find(struct vnode *vp)
{

	return nfsv4_file_find_attr(vp, NULL);
}

/*
 * A new state for sw on vp, from what the caller allocated, taking from
 * *stp and, if vp has no file yet, *fp.  vp gets a reference for the
 * file then.
 */
struct nfsv4_state *
nfsv4_state_add(struct nfsv4_state **stp, struct nfsv4_owner_s *sw,
    struct nfsv4_file **fp, struct vnode *vp, u_int type)
{

	return nfsv4_state_add_attr(stp, sw, fp, vp, type, NULL);
}

struct nfsv4_state *
nfsv4_state_add_attr(struct nfsv4_state **stp, struct nfsv4_owner_s *sw,
    struct nfsv4_file **fp, struct vnode *vp, u_int type, const char *aname)
{
	struct nfsv4_state *st = *stp;
	struct nfsv4_file *f;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	f = nfsv4_file_find_attr(vp, aname);
	if (f == NULL) {
		f = *fp;
		*fp = NULL;
		f->f_vp = vp;
		if (aname != NULL) {
			f->f_isattr = true;
			strlcpy(f->f_aname, aname, sizeof(f->f_aname));
		}
		TAILQ_INIT(&f->f_waits);
		vref(vp);
		LIST_INIT(&f->f_states);
		LIST_INSERT_HEAD(&nfsv4_file_hash[file_hash(vp)], f, f_list);
	}
	*stp = NULL;
	st->st_other = ++nfsv4_counter;
	st->st_seqid = 1;		/* s9.1.4.2 */
	st->st_type = type;
	st->st_owner = sw;
	st->st_file = f;
	LIST_INIT(&st->st_locks);
	LIST_INSERT_HEAD(&sw->sw_states, st, st_olist);
	LIST_INSERT_HEAD(&f->f_states, st, st_flist);
	LIST_INSERT_HEAD(&nfsv4_state_hash[state_hash(st->st_other)], st,
	    st_hash);
	return st;
}

/*
 * Take a state off its file, with any locks under it, leaving the work
 * that cannot be done under the lock on *reap.  With keep, it stays
 * known as a stateid.
 */
void
nfsv4_state_unlink(struct nfsv4_state *st, struct nfsv4_reap *reap, bool keep)
{
	struct nfsv4_file *f = st->st_file;
	struct nfsv4_state *ls;
	struct nfsv4_lockwait *lw;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if (st->st_type == NFSV4_ST_DELEG && f != NULL)
		nfsv4_deleg_gone(st);
	while (!keep && (ls = LIST_FIRST(&st->st_locks)) != NULL) {
		LIST_REMOVE(ls, st_plist);
		ls->st_open = NULL;
		nfsv4_state_unlink(ls, reap, false);
	}

	if (f != NULL) {
		st->st_file = NULL;
		LIST_REMOVE(st, st_flist);
		if (LIST_EMPTY(&f->f_states)) {
			st->st_reapvp = f->f_vp;
			LIST_REMOVE(f, f_list);
			while ((lw = TAILQ_FIRST(&f->f_waits)) != NULL) {
				TAILQ_REMOVE(&f->f_waits, lw, lw_list);
				kmem_free(lw, sizeof(*lw));
			}
			kmem_free(f, sizeof(*f));
		} else {
			vref(f->f_vp);
			st->st_reapvp = f->f_vp;
		}
	}
	if (!keep) {
		if (st->st_open != NULL)
			LIST_REMOVE(st, st_plist);
		LIST_REMOVE(st, st_hash);
		LIST_REMOVE(st, st_olist);
		st->st_free = true;
	}
	SLIST_INSERT_HEAD(reap, st, st_reap);
}

/*
 * The second half of nfsv4_state_unlink().  The locks of an owner go
 * with its state, by id on the vnode: s9.8 for a lease, s9.10 for CLOSE.
 */
void
nfsv4_reap_finish(struct nfsv4_reap *reap)
{
	struct nfsv4_state *st;

	while ((st = SLIST_FIRST(reap)) != NULL) {
		SLIST_REMOVE_HEAD(reap, st_reap);
		if (st->st_reapvp != NULL) {
			if (st->st_type == NFSV4_ST_LOCK) {
				nfsv4_lock_drop(st, st->st_reapvp);
			}
			vrele(st->st_reapvp);
			st->st_reapvp = NULL;
		}
		if (st->st_free)
			kmem_free(st, sizeof(*st));
	}
}

/*
 * s9.1.4.3.  True if the stateid is one of the two special ones.  Those
 * that only look it are found not to exist by nfsv4_stateid_lookup().
 */
bool
nfsv4_stateid_special(const struct nfsv4_stateid *si)
{
	u_int i;
	bool zeros = true, ones = true;

	for (i = 0; i < sizeof(si->si_other); i++) {
		if (si->si_other[i] != 0)
			zeros = false;
		if (si->si_other[i] != 0xff)
			ones = false;
	}
	return (zeros && si->si_seqid == 0) ||
	    (ones && si->si_seqid == UINT32_MAX);
}

static inline void
other_encode(uint8_t *p, uint64_t other)
{

	be32enc(p, nfsv4_boot);
	be64enc(p + 4, other);
}

void
nfsv4_stateid_out(const struct nfsv4_state *st, struct nfsv4_stateid *si)
{

	si->si_seqid = st->st_seqid;
	other_encode(si->si_other, st->st_other);
}

/* The state a stateid names, with no regard to its seqid or its file. */
uint32_t
nfsv4_stateid_lookup(const struct nfsv4_compound *c,
    const struct nfsv4_stateid *si, struct nfsv4_state **stp)
{
	struct nfsv4_state *st;
	uint64_t other;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	/* s9.1.4.4: of those reserved, none can name state here. */
	if (nfsv4_stateid_special(si))
		return NFS4ERR_BAD_STATEID;
	other = be64dec(si->si_other + 4);
	if (be32dec(si->si_other) != nfsv4_boot) {
		/* All zeros or ones with the wrong seqid, s9.1.4.3. */
		if ((be32dec(si->si_other) == 0 && other == 0) ||
		    (be32dec(si->si_other) == UINT32_MAX &&
		    other == UINT64_MAX))
			return NFS4ERR_BAD_STATEID;
		/* RFC 8881 s15.1.16.5: the error is moot under a session. */
		return c->c_minor != 0 ? NFS4ERR_BAD_STATEID :
		    NFS4ERR_STALE_STATEID;
	}
	/* RFC 8881 s8.2.4: another client's is unknown. */
	if ((st = nfsv4_state_byother(other)) != NULL &&
	    (c->c_minor == 0 || st->st_owner->sw_client == c->c_client)) {
		*stp = st;
		return NFS4_OK;
	}
	return NFS4ERR_BAD_STATEID;
}

/*
 * The tests of s9.1.4.4, in its order, that st as found by
 * nfsv4_stateid_lookup() can be used on vp as type.  An unconfirmed open
 * is good only for OPEN_CONFIRM, s16.18.5, which does not come here.
 * This renews the lease, s9.5.
 */
uint32_t
nfsv4_stateid_check(const struct nfsv4_stateid *si,
    const struct nfsv4_state *st, struct vnode *vp, u_int type)
{
	struct nfsv4_client *cl = st->st_owner->sw_client;
	int32_t d;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if (st->st_closed)
		return NFS4ERR_BAD_STATEID;
	if (st->st_revoked)
		return NFS4ERR_DELEG_REVOKED;
	if (cl->cl_expired || st->st_file == NULL)
		return NFS4ERR_EXPIRED;
	if (st->st_file->f_vp != vp)
		return NFS4ERR_BAD_STATEID;
	/* RFC 8881 s15.1.16.2: superseded by the status of SEQUENCE. */
	if (cl->cl_minor == 0 && nfsv4_lease_moved(cl))
		return NFS4ERR_LEASE_MOVED;
	if (type != 0 && st->st_type != type)
		return NFS4ERR_BAD_STATEID;
	if (st->st_type == NFSV4_ST_OPEN && !st->st_owner->sw_confirmed)
		return NFS4ERR_BAD_STATEID;
	d = (int32_t)(si->si_seqid - st->st_seqid);	/* s9.1.3 */
	if (si->si_seqid != 0 && d > 0)
		return NFS4ERR_BAD_STATEID;
	if (si->si_seqid != 0 && d < 0)
		return NFS4ERR_OLD_STATEID;
	cl->cl_expire = lease_end();
	return NFS4_OK;
}

static bool
client_owners_idle(const struct nfsv4_client *cl)
{
	const struct nfsv4_owner_s *sw;

	LIST_FOREACH(sw, &cl->cl_owners, sw_list) {
		if (sw->sw_busy || sw->sw_waiters != 0)
			return false;
	}
	return true;
}

/*
 * Give up everything cl holds on files, but keep what lets its stateids
 * be told from unknown ones.
 */
static void
client_release(struct nfsv4_client *cl, struct nfsv4_reap *reap)
{
	struct nfsv4_owner_s *sw;
	struct nfsv4_state *st;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	LIST_FOREACH(sw, &cl->cl_owners, sw_list) {
		LIST_FOREACH(st, &sw->sw_states, st_olist) {
			if (st->st_file != NULL)
				nfsv4_state_unlink(st, reap, true);
		}
	}
}

/* Does cl hold anything, or have a stateid left to give back. */
bool
nfsv4_client_has_state(const struct nfsv4_client *cl)
{
	const struct nfsv4_owner_s *sw;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	LIST_FOREACH(sw, &cl->cl_owners, sw_list) {
		if (!LIST_EMPTY(&sw->sw_states))
			return true;
	}
	return false;
}

/* Forget cl.  Its owners must be idle. */
static void
client_free(struct nfsv4_client *cl)
{
	struct nfsv4_reap reap;
	struct nfsv4_owner_s *sw;
	struct nfsv4_state *st;

	KASSERT(mutex_owned(&nfsv4_state_lock));
	KASSERT(cl->cl_refs == 0);

	nfsv4_session_drop_all(cl);
	SLIST_INIT(&reap);
	while ((sw = LIST_FIRST(&cl->cl_owners)) != NULL) {
		while ((st = LIST_FIRST(&sw->sw_states)) != NULL) {
			if (st->st_open != NULL) {
				LIST_REMOVE(st, st_plist);
				st->st_open = NULL;
			}
			nfsv4_state_unlink(st, &reap, false);
		}
		LIST_REMOVE(sw, sw_list);
		if (sw->sw_rbuf != NULL)
			kmem_free(sw->sw_rbuf, sw->sw_rlen);
		kmem_free(sw, sizeof(*sw));
	}
	nfsv4_cb_forget_client(cl);
	LIST_REMOVE(cl, cl_list);
	kmem_free(cl, sizeof(*cl));

	mutex_exit(&nfsv4_state_lock);
	nfsv4_reap_finish(&reap);
	mutex_enter(&nfsv4_state_lock);
}

/* Wait for the owners of cl to finish what they are doing. */
static void
client_wait_idle(struct nfsv4_client *cl)
{

	while (!client_owners_idle(cl))
		cv_wait(&nfsv4_state_cv, &nfsv4_state_lock);
}

/*
 * RFC 7530 s9.8: an expired lease loses its locks.  The list may change
 * while the lock is dropped, so each pass starts over.
 */
static void
lease_thread(void *arg)
{
	struct nfsv4_client *cl;
	struct nfsv4_reap reap;
	bool again;
	static uint8_t idbuf[NFS4_OPAQUE_LIMIT];	/* one thread */

	mutex_enter(&nfsv4_state_lock);
	while (!nfsv4_dying) {
		(void)cv_timedwait(&nfsv4_state_cv, &nfsv4_state_lock,
		    NFSV4_LEASE_SCAN * hz);
		SLIST_INIT(&reap);
		nfsv4_deleg_scan(&reap);
		LIST_FOREACH(cl, &nfsv4_clients, cl_list) {
			if (cl->cl_prevend != 0 &&
			    time_uptime >= cl->cl_prevend)
				nfsv4_deleg_drop_prev(cl, &reap);
		}
		mutex_exit(&nfsv4_state_lock);
		nfsv4_reap_finish(&reap);
		nfsv4_grace_scan();
		mutex_enter(&nfsv4_state_lock);
		do {
			again = false;
			LIST_FOREACH(cl, &nfsv4_clients, cl_list) {
				/* s10.4.6: a path can come back. */
				if (cl->cl_confirmed &&
				    cl->cl_cbstate == NFSV4_CB_DOWN &&
				    time_uptime >= cl->cl_cbnext)
					nfsv4_cb_probe(cl);
				if (cl->cl_revoked) {
					uint32_t idlen = cl->cl_idlen;
					bool stable = cl->cl_stable;

					cl->cl_revoked = false;
					if (stable) {
						memcpy(idbuf, cl->cl_idstr,
						    idlen);
						mutex_exit(&nfsv4_state_lock);
						nfsv4_stable_gone(idbuf, idlen);
						mutex_enter(&nfsv4_state_lock);
						again = true;
						break;
					}
				}
				if (time_uptime <= cl->cl_expire)
					continue;
				if (cl->cl_refs != 0 || !client_owners_idle(cl))
					continue;
				if (!cl->cl_confirmed ||
				    time_uptime > cl->cl_expire +
				    NFSV4_TOMB_TIME) {
					client_free(cl);
					again = true;
					break;
				}
				if (!cl->cl_expired) {
					bool stable = cl->cl_stable;
					uint32_t idlen = cl->cl_idlen;

					/* Stays: it is only a name there. */
					if (stable) {
						KASSERT(idlen <=
						    sizeof(idbuf));
						memcpy(idbuf, cl->cl_idstr,
						    idlen);
					}
					cl->cl_expired = true;
					SLIST_INIT(&reap);
					client_release(cl, &reap);
					mutex_exit(&nfsv4_state_lock);
					nfsv4_reap_finish(&reap);
					/* s9.6.3.4.3 */
					if (stable)
						nfsv4_stable_gone(idbuf, idlen);
					mutex_enter(&nfsv4_state_lock);
					again = true;
					break;
				}
			}
		} while (again);
	}
	mutex_exit(&nfsv4_state_lock);
	kthread_exit(0);
}

void
nfsv4_state_init(void)
{
	u_int i;

	mutex_init(&nfsv4_state_lock, MUTEX_DEFAULT, IPL_NONE);
	cv_init(&nfsv4_state_cv, "nfsv4st");
	LIST_INIT(&nfsv4_clients);
	for (i = 0; i < NFSV4_STATE_HASH; i++)
		LIST_INIT(&nfsv4_state_hash[i]);
	for (i = 0; i < NFSV4_FILE_HASH; i++)
		LIST_INIT(&nfsv4_file_hash[i]);
	nfsv4_counter = 0;
	nfsv4_dying = false;
	nfsv4_deleg_init();
	nfsv4_session_init();
	/*
	 * Each load is a new instance of the server: stale stateids and
	 * client IDs must be seen as such, s9.1.1.  A second would do, as
	 * loading takes longer than that.
	 */
	nfsv4_boot = (uint32_t)time_second;
	if (kthread_create(PRI_NONE, KTHREAD_MPSAFE | KTHREAD_MUSTJOIN, NULL,
	    lease_thread, NULL, &nfsv4_lease_lwp, "nfsv4lease") != 0)
		panic("nfsv4_state_init: kthread_create");
}

void
nfsv4_state_fini(void)
{
	struct nfsv4_client *cl;

	mutex_enter(&nfsv4_state_lock);
	nfsv4_dying = true;
	cv_broadcast(&nfsv4_state_cv);
	mutex_exit(&nfsv4_state_lock);
	kthread_join(nfsv4_lease_lwp);

	mutex_enter(&nfsv4_state_lock);
	while ((cl = LIST_FIRST(&nfsv4_clients)) != NULL)
		client_free(cl);
	mutex_exit(&nfsv4_state_lock);
	nfsv4_session_fini();
	cv_destroy(&nfsv4_state_cv);
	mutex_destroy(&nfsv4_state_lock);
}

static void
client_newverf(struct nfsv4_client *cl)
{

	be64enc(cl->cl_confirm.v_data, ++nfsv4_counter);
}

struct nfsv4_client *
nfsv4_client_find(const uint8_t *id, uint32_t len, bool confirmed,
    uint32_t minor)
{
	struct nfsv4_client *cl;

	LIST_FOREACH(cl, &nfsv4_clients, cl_list) {
		if (cl->cl_confirmed == confirmed && cl->cl_idlen == len &&
		    (cl->cl_minor != 0) == (minor != 0) &&
		    memcmp(cl->cl_idstr, id, len) == 0)
			return cl;
	}
	return NULL;
}

/* By client ID, whether confirmed or not, for version 4.1. */
struct nfsv4_client *
nfsv4_client_byid41(uint64_t id)
{
	struct nfsv4_client *cl;

	LIST_FOREACH(cl, &nfsv4_clients, cl_list) {
		if (cl->cl_id == id && cl->cl_minor != 0 && !cl->cl_retired)
			return cl;
	}
	return NULL;
}

uint64_t
nfsv4_clientid_new(void)
{

	return ((uint64_t)nfsv4_boot << 32) | (uint32_t)++nfsv4_counter;
}

/* Enter a record the caller filled in, with a lease. */
struct nfsv4_client *
nfsv4_client_insert(struct nfsv4_client *n)
{

	n->cl_expire = lease_end();
	LIST_INIT(&n->cl_owners);
	LIST_INIT(&n->cl_sessions);
	LIST_INSERT_HEAD(&nfsv4_clients, n, cl_list);
	return n;
}

/*
 * RFC 8881 s18.35.4: end a record that something replaced.  Nothing finds
 * it from now on, its sessions go at once, and its locks once its owners
 * are idle.  The lease scan frees the rest.
 */
void
nfsv4_client_retire(struct nfsv4_client *cl)
{
	struct nfsv4_reap reap;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	cl->cl_retired = true;
	cl->cl_idlen = UINT32_MAX;
	cl->cl_expired = true;
	cl->cl_expire = time_uptime - NFSV4_TOMB_TIME - 1;
	cl->cl_refs++;
	nfsv4_session_drop_all(cl);
	client_wait_idle(cl);
	SLIST_INIT(&reap);
	client_release(cl, &reap);
	mutex_exit(&nfsv4_state_lock);
	nfsv4_reap_finish(&reap);
	mutex_enter(&nfsv4_state_lock);
	cl->cl_refs--;
}

/*
 * RFC 7530 s16.33.5, whose cases are marked.  The client ID is the boot
 * time above a counter, so one is not reused, and the counter is
 * shared with the confirm verifier: both are "extremely unlikely to ever
 * be regenerated", having been generated once.
 */
uint32_t
nfsv4_op_setclientid(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_setclientid *sa = &a->setclientid;
	struct nfsv4_client *conf, *unconf, *n, *dead = NULL;
	struct nfsv4_clientaddr ca;
	uid_t uid = nfsv4_client_principal(c);
	uint64_t id;
	struct nfsv4_verifier verf;

	n = kmem_zalloc(sizeof(*n), KM_SLEEP);

	mutex_enter(&nfsv4_state_lock);
	conf = nfsv4_client_find(sa->id, sa->idlen, true, 0);
	unconf = nfsv4_client_find(sa->id, sa->idlen, false, 0);

	/* What expired is of no use to compare with. */
	if (conf != NULL && (conf->cl_expired ||
	    time_uptime > conf->cl_expire))
		dead = conf;

	/*
	 * s16.33.5: the principal differs and the lease is in force, whether
	 * or not the client has state.  pynfs's CID2 wants NFS4_OK when it
	 * has none, which the RFC does not say.
	 */
	if (conf != NULL && dead == NULL && conf->cl_uid != uid) {
		ca = conf->cl_cb;
		mutex_exit(&nfsv4_state_lock);
		kmem_free(n, sizeof(*n));
		return nfsv4_xdr_clientaddr(c->c_rx, &ca) ?
		    NFS4ERR_CLID_INUSE : NFS4ERR_RESOURCE;
	}

	if (conf != NULL && dead == NULL &&
	    memcmp(&conf->cl_verf, &sa->verifier, sizeof(sa->verifier)) == 0) {
		/* Case { v, x, c, l, s }: update of k, same c. */
		id = conf->cl_id;
	} else {
		/* The cases with v != u, and with no confirmed record. */
		id = ((uint64_t)nfsv4_boot << 32) |
		    (uint32_t)++nfsv4_counter;
	}
	if (unconf != NULL)		/* every case replaces this */
		client_free(unconf);
	if (dead != NULL) {
		client_wait_idle(dead);
		/* client_free() drops the lock; it is still ours to free. */
		if (nfsv4_client_find(sa->id, sa->idlen, true, 0) == dead)
			client_free(dead);
	}

	n->cl_id = id;
	n->cl_verf = sa->verifier;
	n->cl_cb = sa->cb_location;
	n->cl_cbprog = sa->cb_program;
	n->cl_cbident = sa->cb_ident;
	n->cl_uid = uid;
	n->cl_gid = c->c_rq->rq_cred != NULL ?
	    kauth_cred_getegid(c->c_rq->rq_cred) : (gid_t)-1;
	n->cl_flavor = c->c_rq->rq_flavor;
	n->cl_connid = c->c_rq->rq_connid;
	n->cl_idlen = sa->idlen;
	memcpy(n->cl_idstr, sa->id, sa->idlen);
	client_newverf(n);
	verf = n->cl_confirm;
	(void)nfsv4_client_insert(n);
	mutex_exit(&nfsv4_state_lock);

	return xdr_u_int64_t(c->c_rx, &id) &&
	    nfsv4_xdr_verifier(c->c_rx, &verf) ? NFS4_OK : NFS4ERR_RESOURCE;
}

/* RFC 7530 s16.34.5, whose cases are marked. */
uint32_t
nfsv4_op_setclientid_confirm(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_setclientid_confirm *sa =
	    &a->setclientid_confirm;
	struct nfsv4_client *cl, *conf = NULL, *unconf = NULL, *old;
	struct nfsv4_owner_s *spare;
	uid_t uid = nfsv4_client_principal(c);
	uint32_t st;

	spare = kmem_zalloc(sizeof(*spare), KM_SLEEP);
	mutex_enter(&nfsv4_state_lock);
	if ((uint32_t)(sa->clientid >> 32) != nfsv4_boot) {
		st = NFS4ERR_STALE_CLIENTID;
		goto out;
	}
	LIST_FOREACH(cl, &nfsv4_clients, cl_list) {
		if (cl->cl_id != sa->clientid)
			continue;
		if (cl->cl_confirmed)
			conf = cl;
		else
			unconf = cl;
	}

	if (unconf != NULL && memcmp(&unconf->cl_confirm, &sa->verifier,
	    sizeof(sa->verifier)) == 0) {
		if (unconf->cl_uid != uid ||
		    (conf != NULL && conf->cl_uid != uid)) {
			st = NFS4ERR_CLID_INUSE;
			goto out;
		}
		st = NFS4_OK;
		if (conf != NULL) {
			/* { v, x, c, l, t }: only k changes. */
			conf->cl_cb = unconf->cl_cb;
			conf->cl_cbprog = unconf->cl_cbprog;
			conf->cl_cbident = unconf->cl_cbident;
			conf->cl_confirm = unconf->cl_confirm;
			client_free(unconf);
			nfsv4_cb_reset(conf);
			goto out;
		}
		/* { *, x, c, k, s }, and any { *, x, d, *, t } goes. */
		old = nfsv4_client_find(unconf->cl_idstr, unconf->cl_idlen, true, 0);
		if (old != NULL) {
			struct nfsv4_reap reap;

			/*
			 * Its stateids answer NFS4ERR_EXPIRED until the
			 * lease scan ends the record, which no name now
			 * finds.
			 */
			client_wait_idle(old);
			if (nfsv4_client_find(unconf->cl_idstr,
			    unconf->cl_idlen, true, 0) == old) {
				old->cl_idlen = UINT32_MAX;
				old->cl_expired = true;
				old->cl_expire = time_uptime;
				nfsv4_deleg_carry(old, unconf, &spare);
				SLIST_INIT(&reap);
				client_release(old, &reap);
				mutex_exit(&nfsv4_state_lock);
				nfsv4_reap_finish(&reap);
				mutex_enter(&nfsv4_state_lock);
			}
		}
		unconf->cl_confirmed = true;
		unconf->cl_expire = lease_end();
		nfsv4_cb_reset(unconf);
		goto out;
	}
	if (conf != NULL && memcmp(&conf->cl_confirm, &sa->verifier,
	    sizeof(sa->verifier)) == 0) {
		/* { v, x, c, *, s }: the reply went astray. */
		st = conf->cl_uid == uid ? NFS4_OK : NFS4ERR_CLID_INUSE;
		goto out;
	}
	st = NFS4ERR_STALE_CLIENTID;
out:
	mutex_exit(&nfsv4_state_lock);
	if (spare != NULL)
		kmem_free(spare, sizeof(*spare));
	return st;
}

uint32_t
nfsv4_op_renew(struct nfsv4_compound *c, union nfsv4_args *a)
{
	struct nfsv4_client *cl;
	uint32_t st;

	mutex_enter(&nfsv4_state_lock);
	/* s9.14.3: the convention for saying it has seen fs_locations. */
	if (c->c_probed &&
	    (cl = nfsv4_client_byid(a->clientid.clientid)) != NULL)
		cl->cl_movedack = nfsv4_moved_gen();
	st = nfsv4_client_get(a->clientid.clientid, &cl);
	/* s16.28.5: only the principal; open files are not looked for. */
	if (st == NFS4_OK && cl->cl_uid != nfsv4_client_principal(c))
		st = NFS4ERR_ACCESS;
	if (st == NFS4_OK) {
		cl->cl_connid = c->c_rq->rq_connid;
		if (nfsv4_deleg_path_down(cl))
			st = NFS4ERR_CB_PATH_DOWN;
	}
	mutex_exit(&nfsv4_state_lock);
	return st;
}
