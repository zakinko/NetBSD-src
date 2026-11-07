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
 * Open delegations, RFC 7530 s10.2 and s10.4.
 *
 * A delegation is a state like any other, of type NFSV4_ST_DELEG, so that
 * stateids, the file's list, a lease ending and the end of a client need
 * nothing new.  It belongs to the client as a whole, s10.2, and the state
 * model wants an owner, so each client that has any has one owner of type
 * NFSV4_OWNER_DELEG with no name, which is never busy.
 *
 * Whether to give one is decided by what is known of the file here;
 * nothing tries to guess future conflicts.  A conflict is answered with
 * NFS4ERR_DELAY while the recall runs, s10.2, rather than holding up a
 * worker.  A local process recalls through vn_lease_break() and waits.
 * What it has open already is seen only as v_writecount, below.
 *
 * Which client asks is not known for an operation with no stateid and
 * no client ID.  s10.4.4 cares for SETATTR, and s10.4.3 for GETATTR, so
 * those compare the connection with the one the client last used.  What
 * a wrong answer costs is a needless recall, or, if clients share a
 * connection, a delegation that a client on it does not recall; a real
 * client has connections of its own.  REMOVE, RENAME and LINK recall
 * whoever asks: s10.4.4 says "another client" of none of them.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/atomic.h>
#include <sys/fcntl.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/vnode.h>

#include <fs/nfsv4/nfsv4_var.h>
#include <fs/nfsv4/nfsv4_state.h>

/* A choice, to bound what clients can make this keep. */
#define	NFSV4_DELEG_MAX		65536

/* vfs.nfsv4.delegations: 0 for none, 1 for read, 2 for read and write. */
int nfsv4_deleg_mode = 2;

/*
 * vfs.nfsv4.dirdeleg.  Off to begin with, as a directory delegation
 * promises that the directory does not change, and all that recalls one
 * is an NFSv4 operation: a local process, or versions 2 and 3, can
 * change it without the holder hearing, against s10.9.
 */
int nfsv4_dirdeleg = 0;

/* Recalled and not yet back. */
static LIST_HEAD(, nfsv4_state) deleg_recalled;
static volatile u_int deleg_count;

/*
 * A local process wants to do what, see vn_lease_break().  It waits for
 * the end of the recall, which is bounded, s10.4.6.  Unlike a client it
 * has no NFS4ERR_DELAY to be told.
 */
static void
deleg_lease_hook(struct vnode *vp, u_int what)
{

	CTASSERT(VN_LEASE_READ == NFSV4_DC_READ);
	CTASSERT(VN_LEASE_WRITE == NFSV4_DC_WRITE);

	if (atomic_load_relaxed(&deleg_count) == 0)
		return;
	mutex_enter(&nfsv4_state_lock);
	while (nfsv4_deleg_conflict(vp, NULL, 0, what) != NFS4_OK)
		(void)cv_timedwait(&nfsv4_state_cv, &nfsv4_state_lock, hz);
	mutex_exit(&nfsv4_state_lock);
}

void
nfsv4_deleg_init(void)
{

	LIST_INIT(&deleg_recalled);
	deleg_count = 0;
	vn_lease_set(deleg_lease_hook);
}

void
nfsv4_deleg_fini(void)
{

	vn_lease_set(NULL);
}

/* The start of a recall.  Time for it to end is s10.4.6's. */
static void
deleg_recall(struct nfsv4_state *st)
{

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if (st->st_recalled)
		return;
	st->st_recalled = true;
	st->st_recall_end = time_uptime + NFSV4_LEASE;
	LIST_INSERT_HEAD(&deleg_recalled, st, st_rlist);
	nfsv4_cb_recall(st);
}

/*
 * Do delegations stand in the way of what is about to happen to the
 * file?  what is NFSV4_DC_READ for a reader, which only a write
 * delegation minds, and NFSV4_DC_WRITE for anything else.  The holders
 * self and those last seen on connection connid, if not 0, are let be.
 */
uint32_t
nfsv4_deleg_conflict(struct vnode *vp, const struct nfsv4_client *self,
    uint64_t connid, u_int what)
{
	struct nfsv4_file *f;
	struct nfsv4_state *st;
	struct nfsv4_client *cl;
	uint32_t status = NFS4_OK;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	f = nfsv4_file_find(vp);
	if (f == NULL)
		return NFS4_OK;
	LIST_FOREACH(st, &f->f_states, st_flist) {
		if (st->st_type != NFSV4_ST_DELEG)
			continue;
		cl = st->st_owner->sw_client;
		if (cl == self || (connid != 0 && cl->cl_connid == connid))
			continue;
		if (what == NFSV4_DC_READ && st->st_dtype != OPEN_DELEGATE_WRITE)
			continue;
		status = NFS4ERR_DELAY;
		/* Waiting to be reclaimed, s10.2.1: nobody to call. */
		if (!st->st_prev)
			deleg_recall(st);
	}
	return status;
}

/* As above, for those that do not hold the lock. */
uint32_t
nfsv4_deleg_break(struct vnode *vp, const struct nfsv4_client *self,
    uint64_t connid, u_int what)
{
	uint32_t st;

	if (atomic_load_relaxed(&deleg_count) == 0)
		return NFS4_OK;
	mutex_enter(&nfsv4_state_lock);
	st = nfsv4_deleg_conflict(vp, self, connid, what);
	mutex_exit(&nfsv4_state_lock);
	return st;
}

/*
 * The same for the file of a name in a directory, which is going to
 * change.  That the name may be taken over between here and the VOP
 * only means that a delegation is not recalled that a client got in
 * that moment; the lookup is not to be done under the directory's lock,
 * as nfsv4_state_lock stays outside the vnode locks.
 */
uint32_t
nfsv4_deleg_break_name(const struct nfsv4_cfh *dir, const char *name)
{
	struct vnode *vp;
	uint32_t st;

	if (atomic_load_relaxed(&deleg_count) == 0)
		return NFS4_OK;
	if (nfsv4_lookup_vp(dir->cf_vp, name, dir->cf_cred, &vp) != 0)
		return NFS4_OK;		/* the operation will say so */
	st = nfsv4_deleg_break(vp, NULL, 0, NFSV4_DC_WRITE);
	vrele(vp);
	return st;
}

/*
 * RFC 8881 s10.9: the directory dir is about to change.  No notification
 * is offered, so the delegations of others are recalled, and the holder
 * itself may do as it likes.  c_client is NULL under version 4.0.
 */
uint32_t
nfsv4_deleg_break_dir(const struct nfsv4_compound *c,
    const struct nfsv4_cfh *dir)
{

	return nfsv4_deleg_break(dir->cf_vp, c->c_client, 0, NFSV4_DC_WRITE);
}

/*
 * rfc8881bis-11 s36.25.4 (RFC 8881 s18.25.4 has a SHOULD NOT): an open
 * that denies writing keeps its name from being removed, by REMOVE or by
 * a RENAME over it.  Racing the VOP as above.
 */
uint32_t
nfsv4_open_denies_remove(const struct nfsv4_cfh *dir, const char *name)
{
	struct nfsv4_file *f;
	struct nfsv4_state *st;
	struct vnode *vp;
	uint32_t status = NFS4_OK;

	if (nfsv4_lookup_vp(dir->cf_vp, name, dir->cf_cred, &vp) != 0)
		return NFS4_OK;		/* the operation will say so */
	mutex_enter(&nfsv4_state_lock);
	f = nfsv4_file_find(vp);
	if (f != NULL) {
		LIST_FOREACH(st, &f->f_states, st_flist) {
			if (st->st_type == NFSV4_ST_OPEN &&
			    (st->st_deny & OPEN4_SHARE_DENY_WRITE) != 0)
				status = NFS4ERR_FILE_OPEN;
		}
	}
	mutex_exit(&nfsv4_state_lock);
	vrele(vp);
	return status;
}

/*
 * s10.4.3: a GETATTR of what the holder of a write delegation may have
 * changed.  Only for one whose holder is another client; c_ov gets what
 * the holder said, and if the holder cannot say, it is recalled and the
 * GETATTR waits like anything else.  Not done here, though a SHOULD: the
 * constructed times are not stored in the file's metadata, as there is
 * no way to set ctime through VOP_SETATTR.
 */
uint32_t
nfsv4_deleg_getattr(struct nfsv4_compound *c)
{
	const struct nfsv4_cfh *cf = &c->c_cur;
	struct vnode *vp = cf->cf_vp;
	struct nfsv4_file *f;
	struct nfsv4_state *st;
	struct nfsv4_client *cl;
	struct nfsv4_fh fh;
	struct vattr va;
	uint64_t other, size, cc;
	int error;

	if (atomic_load_relaxed(&deleg_count) == 0)
		return NFS4_OK;
	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = VOP_GETATTR(vp, &va, cf->cf_cred);
	VOP_UNLOCK(vp);
	if (error != 0)
		return nfsv4_errno(error);

	mutex_enter(&nfsv4_state_lock);
	f = nfsv4_file_find(vp);
	if (f != NULL) {
		LIST_FOREACH(st, &f->f_states, st_flist) {
			cl = st->st_owner->sw_client;
			if (st->st_type == NFSV4_ST_DELEG &&
			    st->st_dtype == OPEN_DELEGATE_WRITE &&
			    !st->st_recalled && !st->st_prev &&
			    cl->cl_cbstate == NFSV4_CB_UP &&
			    cl->cl_connid != c->c_rq->rq_connid)
				break;
		}
		if (st != NULL) {
			other = st->st_other;
			fh = f->f_fh;
			error = nfsv4_cb_getattr(cl, &fh, &size, &cc);
			st = error == 0 ? nfsv4_state_byother(other) : NULL;
			if (st != NULL && st->st_file != NULL) {
				if (!st->st_modified && (cc != st->st_sc ||
				    size != va.va_size))
					st->st_modified = true;
				if (st->st_modified) {
					st->st_sc++;
					c->c_ov.ao_valid = true;
					c->c_ov.ao_size = size;
					c->c_ov.ao_change = st->st_sc;
					getnanotime(&c->c_ov.ao_time);
				}
				mutex_exit(&nfsv4_state_lock);
				return NFS4_OK;
			}
		}
	}
	mutex_exit(&nfsv4_state_lock);
	return nfsv4_deleg_break(vp, NULL, c->c_rq->rq_connid, NFSV4_DC_READ);
}

/*
 * May cl have a delegation of vp?  0 if so, or a WND4_ with 1 added; with
 * one held already *heldp has it.
 */
static uint32_t
deleg_refused(struct nfsv4_client *cl, struct vnode *vp, bool write,
    const struct nfsv4_deleg_spare *ds, struct nfsv4_state **heldp)
{
	struct nfsv4_file *f;
	struct nfsv4_state *st;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	*heldp = NULL;
	if (cl->cl_cbstate != NFSV4_CB_UP || ds->ds_st == NULL ||
	    deleg_count >= NFSV4_DELEG_MAX || nfsv4_deleg_mode == 0 ||
	    (write && nfsv4_deleg_mode == 1))
		return WND4_RESOURCE + 1;
	if (ds->ds_locked || vp->v_writecount != 0)
		return WND4_CONTENTION + 1;
	f = nfsv4_file_find(vp);
	if (f == NULL)
		return 0;
	LIST_FOREACH(st, &f->f_states, st_flist) {
		if (st->st_owner->sw_client == cl) {
			/* One delegation of a file to a client is plenty. */
			if (st->st_type == NFSV4_ST_DELEG) {
				*heldp = st;
				return 0;
			}
			continue;
		}
		if (st->st_type == NFSV4_ST_DELEG &&
		    (write || st->st_dtype == OPEN_DELEGATE_WRITE))
			return WND4_CONTENTION + 1;
		if (st->st_type == NFSV4_ST_OPEN &&
		    (write || (st->st_access & OPEN4_SHARE_ACCESS_WRITE) != 0))
			return WND4_CONTENTION + 1;
	}
	return 0;
}

/*
 * Offer a delegation with an open of access just recorded by the owner
 * sw, s10.4, filling in *od.  From the spare states.
 *
 * Only an owner that is confirmed gets one: the open of one that is not
 * may turn out to have been a resend, s16.18.5, and be undone.
 */
void
nfsv4_deleg_offer(struct nfsv4_owner_s *sw, struct vnode *vp,
    const struct nfsv4_fh *fh, uint32_t access, struct nfsv4_deleg_spare *ds,
    struct nfsv4_open_deleg *od)
{
	struct nfsv4_client *cl = sw->sw_client;
	struct nfsv4_state *st;
	bool write = (access & OPEN4_SHARE_ACCESS_WRITE) != 0;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if (!sw->sw_confirmed || deleg_refused(cl, vp, write, ds, &st) != 0 ||
	    st != NULL)
		return;
	nfsv4_deleg_add(cl, vp, fh, write ? OPEN_DELEGATE_WRITE :
	    OPEN_DELEGATE_READ, ds, od);
}

/* What a delegation of vp from ds wants to know, away from the lock. */
void
nfsv4_deleg_look(struct vnode *vp, kauth_cred_t cred,
    struct nfsv4_deleg_spare *ds)
{
	struct flock fl;
	struct vattr va;

	/*
	 * s10.4.2 has the holder of a write delegation lock alone, and the
	 * client of Linux does so under a read delegation too, not sending
	 * LOCK: nobody may have any, or it would not see them.
	 */
	memset(&fl, 0, sizeof(fl));
	fl.l_whence = SEEK_SET;
	fl.l_type = F_WRLCK;
	if (VOP_ADVLOCK(vp, ds, F_GETLK, &fl, 0) != 0 ||
	    fl.l_type != F_UNLCK)
		ds->ds_locked = true;
	/* s10.4.3, sc */
	vn_lock(vp, LK_SHARED | LK_RETRY);
	if (VOP_GETATTR(vp, &va, cred) == 0)
		ds->ds_change = nfsv4_attr_change(vp, &va);
	VOP_UNLOCK(vp);
}

/* s2.10.6.3: what a recall of a delegation from ds is to refer to. */
void
nfsv4_deleg_refer(const struct nfsv4_compound *c, struct nfsv4_deleg_spare *ds)
{

	if (c->c_slot == NULL)
		return;
	ds->ds_refset = true;
	ds->ds_refsid = c->c_sess->se_id;
	ds->ds_refslot = c->c_slot - c->c_sess->se_slots;
	ds->ds_refseq = c->c_slot->sl_seq;
}

/* A delegation of type for cl, whatever else is going on, from ds. */
void
nfsv4_deleg_add(struct nfsv4_client *cl, struct vnode *vp,
    const struct nfsv4_fh *fh, uint32_t type, struct nfsv4_deleg_spare *ds,
    struct nfsv4_open_deleg *od)
{
	struct nfsv4_owner_s *dw;
	struct nfsv4_state *st;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	dw = nfsv4_owner_find(cl, NFSV4_OWNER_DELEG, (const uint8_t *)"", 0);
	if (dw == NULL) {
		dw = nfsv4_owner_add(cl, &ds->ds_sw, NFSV4_OWNER_DELEG,
		    (const uint8_t *)"", 0);
		dw->sw_confirmed = true;
	}
	st = nfsv4_state_add(&ds->ds_st, dw, &ds->ds_f, vp, NFSV4_ST_DELEG);
	st->st_dtype = type;
	st->st_sc = ds->ds_change;
	st->st_access = type == OPEN_DELEGATE_WRITE ?
	    OPEN4_SHARE_ACCESS_BOTH : OPEN4_SHARE_ACCESS_READ;
	st->st_file->f_fh = *fh;
	st->st_refset = ds->ds_refset;
	st->st_refsid = ds->ds_refsid;
	st->st_refslot = ds->ds_refslot;
	st->st_refseq = ds->ds_refseq;
	atomic_inc_uint(&deleg_count);
	od->od_type = type;
	nfsv4_stateid_out(st, &od->od_stateid);
}

/* A delegation leaves its file, by whatever road. */
void
nfsv4_deleg_gone(struct nfsv4_state *st)
{

	KASSERT(mutex_owned(&nfsv4_state_lock));
	KASSERT(st->st_type == NFSV4_ST_DELEG);

	nfsv4_cb_forget_state(st);
	if (st->st_recalled) {
		LIST_REMOVE(st, st_rlist);
		st->st_recalled = false;
	}
	atomic_dec_uint(&deleg_count);
}

/*
 * The time of recalls.  s10.4.6: revoke when the time is up, which is
 * not less than a lease, the path having been tried again meanwhile.
 * The client is in no trouble but with this delegation, s10.4.5.
 */
void
nfsv4_deleg_scan(struct nfsv4_reap *reap)
{
	struct nfsv4_state *st, *next;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	LIST_FOREACH_SAFE(st, &deleg_recalled, st_rlist, next) {
		if (time_uptime >= st->st_recall_end) {
			/* s10.2.1 and the boolean of s9.6.3.4.3 */
			st->st_owner->sw_client->cl_revoked = true;
			/* RFC 8881 s8.2.4: 4.1 keeps it for FREE_STATEID. */
			if (st->st_owner->sw_client->cl_minor != 0) {
				st->st_revoked = true;
				st->st_owner->sw_client->cl_nrevoked++;
				nfsv4_state_unlink(st, reap, true);
			} else
				nfsv4_state_unlink(st, reap, false);
		}
		else if (st->st_cbnext != 0 && time_uptime >= st->st_cbnext)
			nfsv4_cb_recall(st);
	}
}

/*
 * RENEW finds out whether it should say NFS4ERR_CB_PATH_DOWN, s16.28.5:
 * if cl holds delegations and cannot be reached.  Having said it, the
 * server gives the client time to return them, s10.4.6.
 */
bool
nfsv4_deleg_path_down(struct nfsv4_client *cl)
{
	struct nfsv4_owner_s *dw;
	struct nfsv4_state *st;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if (cl->cl_cbstate != NFSV4_CB_DOWN)
		return false;
	dw = nfsv4_owner_find(cl, NFSV4_OWNER_DELEG, (const uint8_t *)"", 0);
	if (dw == NULL)
		return false;
	LIST_FOREACH(st, &dw->sw_states, st_olist) {
		if (st->st_file != NULL)
			break;
	}
	if (st == NULL)
		return false;
	LIST_FOREACH(st, &dw->sw_states, st_olist) {
		if (st->st_recalled)
			st->st_recall_end = MAX(st->st_recall_end,
			    time_uptime + NFSV4_LEASE);
	}
	return true;
}

/*
 * CLAIM_DELEGATE_CUR, s16.16.5: the stateid must be a delegation that the
 * client holds of the file.
 */
uint32_t
nfsv4_deleg_claim_cur(const struct nfsv4_compound *c, struct nfsv4_client *cl,
    const struct nfsv4_stateid *si, struct vnode *vp)
{
	struct nfsv4_state *st;
	uint32_t status;

	mutex_enter(&nfsv4_state_lock);
	status = nfsv4_stateid_lookup(c, si, &st);
	if (status == NFS4_OK)
		status = nfsv4_stateid_check(si, st, vp, NFSV4_ST_DELEG);
	if (status == NFS4_OK && st->st_owner->sw_client != cl)
		status = NFS4ERR_BAD_STATEID;
	mutex_exit(&nfsv4_state_lock);
	return status;
}

/*
 * CLAIM_DELEGATE_PREV, s16.16.5, and the period goes on from here,
 * s10.2.1.  With a record, the delegation is the client's again, and the
 * reply carries it.
 */
uint32_t
nfsv4_deleg_claim_prev(struct nfsv4_client *cl, struct vnode *vp,
    struct nfsv4_open_deleg *od)
{
	struct nfsv4_file *f;
	struct nfsv4_state *st;
	uint32_t status = NFS4ERR_RECLAIM_BAD;

	mutex_enter(&nfsv4_state_lock);
	if (cl->cl_purged)
		status = NFS4ERR_INVAL;
	else if ((f = nfsv4_file_find(vp)) != NULL) {
		LIST_FOREACH(st, &f->f_states, st_flist) {
			if (st->st_type != NFSV4_ST_DELEG || !st->st_prev ||
			    st->st_owner->sw_client != cl)
				continue;
			st->st_prev = false;
			cl->cl_prevend = time_uptime + NFSV4_LEASE;
			od->od_type = st->st_dtype;
			nfsv4_stateid_out(st, &od->od_stateid);
			status = NFS4_OK;
			break;
		}
	}
	mutex_exit(&nfsv4_state_lock);
	return status;
}

/*
 * The client old has restarted and is replaced by new.  s10.2.1: having
 * CLAIM_DELEGATE_PREV, the server must not let its delegations go on
 * SETCLIENTID_CONFIRM.  They move to the new record to wait for a lease.
 * spare is used if the new one has no place for them yet.
 */
void
nfsv4_deleg_carry(struct nfsv4_client *old, struct nfsv4_client *new,
    struct nfsv4_owner_s **spare)
{
	struct nfsv4_owner_s *from, *to;
	struct nfsv4_state *st, *next;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	from = nfsv4_owner_find(old, NFSV4_OWNER_DELEG, (const uint8_t *)"", 0);
	if (from == NULL)
		return;
	to = NULL;
	LIST_FOREACH_SAFE(st, &from->sw_states, st_olist, next) {
		if (st->st_file == NULL)
			continue;
		if (to == NULL) {
			to = nfsv4_owner_add(new, spare, NFSV4_OWNER_DELEG,
			    (const uint8_t *)"", 0);
			to->sw_confirmed = true;
		}
		nfsv4_cb_forget_state(st);
		if (st->st_recalled) {
			LIST_REMOVE(st, st_rlist);
			st->st_recalled = false;
		}
		LIST_REMOVE(st, st_olist);
		LIST_INSERT_HEAD(&to->sw_states, st, st_olist);
		st->st_owner = to;
		st->st_prev = true;
	}
	if (to != NULL)
		new->cl_prevend = time_uptime + NFSV4_LEASE;
}

/* The end of the period, by DELEGPURGE or the clock. */
void
nfsv4_deleg_drop_prev(struct nfsv4_client *cl, struct nfsv4_reap *reap)
{
	struct nfsv4_owner_s *dw;
	struct nfsv4_state *st, *next;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	cl->cl_prevend = 0;
	dw = nfsv4_owner_find(cl, NFSV4_OWNER_DELEG, (const uint8_t *)"", 0);
	if (dw == NULL)
		return;
	LIST_FOREACH_SAFE(st, &dw->sw_states, st_olist, next) {
		if (st->st_prev)
			nfsv4_state_unlink(st, reap, false);
	}
}

/* RFC 7530 s16.5 */
uint32_t
nfsv4_op_delegpurge(struct nfsv4_compound *c, union nfsv4_args *a)
{
	struct nfsv4_client *cl;
	struct nfsv4_reap reap;
	uint32_t status;

	SLIST_INIT(&reap);
	mutex_enter(&nfsv4_state_lock);
	/* RFC 8881 s18.5.3: under a session the argument is ignored. */
	status = nfsv4_client_cur(c, a->clientid.clientid, &cl);
	if (status == NFS4_OK) {
		nfsv4_deleg_drop_prev(cl, &reap);
		cl->cl_purged = true;
	}
	mutex_exit(&nfsv4_state_lock);
	nfsv4_reap_finish(&reap);
	return status;
}

/* RFC 7530 s16.6 */
uint32_t
nfsv4_op_delegreturn(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_stateid *si = &a->stateid.stateid;
	struct nfsv4_state *st;
	struct nfsv4_reap reap;
	uint32_t status;

	if (c->c_cur.cf_vp == NULL)
		return NFS4ERR_INVAL;
	SLIST_INIT(&reap);
	mutex_enter(&nfsv4_state_lock);
	status = nfsv4_stateid_lookup(c, si, &st);
	if (status == NFS4_OK)
		status = nfsv4_stateid_check(si, st, c->c_cur.cf_vp,
		    NFSV4_ST_DELEG);
	if (status == NFS4_OK) {
		st->st_owner->sw_client->cl_connid = c->c_rq->rq_connid;
		nfsv4_state_unlink(st, &reap, false);
	}
	mutex_exit(&nfsv4_state_lock);
	nfsv4_reap_finish(&reap);
	return status;
}

/*
 * GDD4_UNAVAIL with no promise.  s18.39.3 has it for a delegation already
 * held and NFS4ERR_DIRDELEG_UNAVAIL for the other refusals, but the client
 * of Linux turns that error into EIO for the GETATTR it came with, as a
 * run of 2026-11-07 showed, and this says the same.
 */
static uint32_t
gdd_unavail(struct nfsv4_compound *c)
{

	return nfsv4_xdr_u32(c->c_rx, GDD4_UNAVAIL) &&
	    nfsv4_xdr_u32(c->c_rx, 0) ? NFS4_OK : NFS4ERR_RESOURCE;
}

/*
 * RFC 8881 s18.39.  gddr_notification is empty, which s18.39.3 allows: no
 * CB_NOTIFY is ever sent, and any change by another is a recall.  The
 * cookie verifier is that of READDIR here, which is zeros.  No "want" is
 * kept, so s18.39.3 has gdda_signal_deleg_avail go unheeded by the error.
 */
uint32_t
nfsv4_op_get_dir_delegation(struct nfsv4_compound *c, union nfsv4_args *a)
{
	struct nfsv4_cfh *cf = &c->c_cur;
	struct vnode *vp = cf->cf_vp;
	struct nfsv4_client *cl = c->c_client;
	struct nfsv4_deleg_spare ds;
	struct nfsv4_open_deleg od;
	struct nfsv4_verifier verf;
	struct nfsv4_file *f;
	struct nfsv4_state *st;
	bool held = false, ok;

	/* OPTIONAL, s17: off, there is no such operation. */
	if (!nfsv4_dirdeleg)
		return NFS4ERR_NOTSUPP;
	if (vp != NULL && vp->v_type != VDIR)
		return NFS4ERR_NOTDIR;
	if (vp == NULL || cf->cf_attr != 0)
		held = true;
	else if (nfsv4_grace_active() || !cl->cl_reclaimed)
		return NFS4ERR_GRACE;		/* s18.51.3 */
	if (held)
		return gdd_unavail(c);

	memset(&ds, 0, sizeof(ds));
	memset(&od, 0, sizeof(od));
	ds.ds_st = kmem_zalloc(sizeof(*ds.ds_st), KM_SLEEP);
	ds.ds_sw = kmem_zalloc(sizeof(*ds.ds_sw), KM_SLEEP);
	ds.ds_f = kmem_zalloc(sizeof(*ds.ds_f), KM_SLEEP);
	nfsv4_deleg_refer(c, &ds);
	nfsv4_client_stable(cl);

	mutex_enter(&nfsv4_state_lock);
	f = nfsv4_file_find(vp);
	if (f != NULL) {
		LIST_FOREACH(st, &f->f_states, st_flist) {
			if (st->st_type == NFSV4_ST_DELEG &&
			    st->st_owner->sw_client == cl)
				held = true;
		}
	}
	if (held)
		/* below */;
	else if (cl->cl_cbstate != NFSV4_CB_UP ||
	    deleg_count >= NFSV4_DELEG_MAX || nfsv4_deleg_mode == 0)
		held = true;
	else
		nfsv4_deleg_add(cl, vp, &cf->cf_fh, OPEN_DELEGATE_READ, &ds,
		    &od);
	mutex_exit(&nfsv4_state_lock);

	if (ds.ds_st != NULL)
		kmem_free(ds.ds_st, sizeof(*ds.ds_st));
	if (ds.ds_sw != NULL)
		kmem_free(ds.ds_sw, sizeof(*ds.ds_sw));
	if (ds.ds_f != NULL)
		kmem_free(ds.ds_f, sizeof(*ds.ds_f));
	if (held)
		return gdd_unavail(c);

	c->c_curst = od.od_stateid;
	memset(&verf, 0, sizeof(verf));
	ok = nfsv4_xdr_u32(c->c_rx, GDD4_OK) &&
	    nfsv4_xdr_verifier(c->c_rx, &verf) &&
	    nfsv4_xdr_stateid(c->c_rx, &od.od_stateid) &&
	    nfsv4_xdr_u32(c->c_rx, 0) &&	/* gddr_notification */
	    nfsv4_xdr_u32(c->c_rx, 0) &&	/* gddr_child_attributes */
	    nfsv4_xdr_u32(c->c_rx, 0);		/* gddr_dir_attributes */
	return ok ? NFS4_OK : NFS4ERR_RESOURCE;
}

/* The part of WANT_DELEGATION with the file known to be a good one. */
static void
deleg_want(struct nfsv4_compound *c, uint32_t type, bool any,
    struct nfsv4_open_deleg *od, uint32_t *whyp)
{
	struct nfsv4_cfh *cf = &c->c_cur;
	struct nfsv4_client *cl = c->c_client;
	struct nfsv4_deleg_spare ds;
	struct nfsv4_state *held;
	uint32_t why;
	bool write;

	memset(&ds, 0, sizeof(ds));
	ds.ds_st = kmem_zalloc(sizeof(*ds.ds_st), KM_SLEEP);
	ds.ds_sw = kmem_zalloc(sizeof(*ds.ds_sw), KM_SLEEP);
	ds.ds_f = kmem_zalloc(sizeof(*ds.ds_f), KM_SLEEP);
	nfsv4_deleg_refer(c, &ds);
	nfsv4_deleg_look(cf->cf_vp, cf->cf_cred, &ds);

	mutex_enter(&nfsv4_state_lock);
	write = type == OPEN_DELEGATE_WRITE;
	why = deleg_refused(cl, cf->cf_vp, write, &ds, &held);
	if (why != 0 && write && any) {
		write = false;
		type = OPEN_DELEGATE_READ;
		why = deleg_refused(cl, cf->cf_vp, write, &ds, &held);
	}
	if (why == 0 && held == NULL)
		nfsv4_deleg_add(cl, cf->cf_vp, &cf->cf_fh, type, &ds, od);
	else if (why == 0 && (held->st_dtype == type || any)) {
		od->od_type = held->st_dtype;
		nfsv4_stateid_out(held, &od->od_stateid);
	} else if (why == 0)
		why = (write ? WND4_NOT_SUPP_UPGRADE :
		    WND4_NOT_SUPP_DOWNGRADE) + 1;
	mutex_exit(&nfsv4_state_lock);
	*whyp = why;

	if (ds.ds_st != NULL)
		kmem_free(ds.ds_st, sizeof(*ds.ds_st));
	if (ds.ds_sw != NULL)
		kmem_free(ds.ds_sw, sizeof(*ds.ds_sw));
	if (ds.ds_f != NULL)
		kmem_free(ds.ds_f, sizeof(*ds.ds_f));
}

/*
 * RFC 8881 s18.49: a delegation with no open behind it.  Refused for the
 * same reasons as with one, and it is recalled the same way, s18.49.4.
 * ond_server_will_signal_avail stays false: no CB_PUSH_DELEG is promised.
 * Having s18.49.3 ignore WANT_NO_DELEG leaves nothing wanted, so INVAL.
 */
uint32_t
nfsv4_op_want_delegation(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_want_delegation *wa = &a->want_delegation;
	struct nfsv4_cfh *cf = &c->c_cur;
	struct vnode *vp = cf->cf_vp;
	struct nfsv4_open_deleg od;
	uint32_t want, why = 0, type = OPEN_DELEGATE_READ, st;
	bool any;

	want = wa->want & OPEN4_SHARE_ACCESS_WANT_DELEG_MASK;
	if (want == 0 || want == OPEN4_SHARE_ACCESS_WANT_NO_DELEG ||
	    want > OPEN4_SHARE_ACCESS_WANT_CANCEL)
		return NFS4ERR_INVAL;
	/* As for OPEN: nothing carries those over to a session. */
	if (wa->claim == CLAIM_DELEG_PREV_FH)
		return NFS4ERR_NOTSUPP;

	memset(&od, 0, sizeof(od));
	any = want == OPEN4_SHARE_ACCESS_WANT_ANY_DELEG;
	if (want == OPEN4_SHARE_ACCESS_WANT_CANCEL)
		why = WND4_CANCELLED + 1;
	else if (vp == NULL || vp->v_type == VDIR)
		why = WND4_IS_DIR + 1;
	else if (vp->v_type != VREG || cf->cf_attr != 0)
		why = (want == OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG ?
		    WND4_WRITE_DELEG_NOT_SUPP_FTYPE : WND4_NOT_SUPP_FTYPE) + 1;
	else if (wa->claim == CLAIM_PREVIOUS) {
		/* s18.49.3, as OPEN by the same claim */
		if (wa->delegate_type != OPEN_DELEGATE_READ &&
		    wa->delegate_type != OPEN_DELEGATE_WRITE)
			return NFS4ERR_INVAL;
		st = c->c_client->cl_reclaimed ? NFS4ERR_NO_GRACE :
		    nfsv4_reclaim_check(c->c_client);
		if (st != NFS4_OK)
			return st;
		type = wa->delegate_type;
		any = false;
	} else if (nfsv4_grace_active() || !c->c_client->cl_reclaimed)
		return NFS4ERR_GRACE;		/* s18.51.3 */
	else if (want != OPEN4_SHARE_ACCESS_WANT_READ_DELEG)
		type = OPEN_DELEGATE_WRITE;
	if (why == 0) {
		/* Nothing was opened, so nothing else has asked this. */
		if (nfsv4_access_vp(cf, VREAD) != 0)
			return NFS4ERR_ACCESS;
		if (type == OPEN_DELEGATE_WRITE &&
		    nfsv4_access_vp(cf, VWRITE) != 0) {
			if (!any)
				return NFS4ERR_ACCESS;
			type = OPEN_DELEGATE_READ;
		}
		nfsv4_client_stable(c->c_client);
		deleg_want(c, type, any, &od, &why);
	}
	/* s18.49.3: never OPEN_DELEGATE_NONE. */
	if (od.od_type == OPEN_DELEGATE_NONE) {
		od.od_type = OPEN_DELEGATE_NONE_EXT;
		od.od_why = why - 1;
	}
	return nfsv4_xdr_open_deleg(c->c_rx, &od) ? NFS4_OK : NFS4ERR_RESOURCE;
}
