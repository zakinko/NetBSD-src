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

/* s16.26.5: is the name a file opened to deny writing? */
bool
nfsv4_open_denies_remove(const struct nfsv4_cfh *dir, const char *name)
{
	struct nfsv4_file *f;
	struct nfsv4_state *st;
	struct vnode *vp;
	bool found = false;

	if (nfsv4_lookup_vp(dir->cf_vp, name, dir->cf_cred, &vp) != 0)
		return false;
	mutex_enter(&nfsv4_state_lock);
	if ((f = nfsv4_file_find(vp)) != NULL) {
		LIST_FOREACH(st, &f->f_states, st_flist) {
			if (st->st_type == NFSV4_ST_OPEN &&
			    (st->st_deny & OPEN4_SHARE_DENY_WRITE) != 0)
				found = true;
		}
	}
	mutex_exit(&nfsv4_state_lock);
	vrele(vp);
	return found;
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
	struct nfsv4_file *f;
	struct nfsv4_state *st;
	bool write = (access & OPEN4_SHARE_ACCESS_WRITE) != 0;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if (cl->cl_cbstate != NFSV4_CB_UP || !sw->sw_confirmed ||
	    ds->ds_st == NULL || deleg_count >= NFSV4_DELEG_MAX ||
	    nfsv4_deleg_mode == 0 || (write && nfsv4_deleg_mode == 1) ||
	    (write && ds->ds_nowrite) || vp->v_writecount != 0)
		return;
	f = nfsv4_file_find(vp);
	KASSERT(f != NULL);
	LIST_FOREACH(st, &f->f_states, st_flist) {
		if (st->st_owner->sw_client == cl) {
			/* One delegation of a file to a client is plenty. */
			if (st->st_type == NFSV4_ST_DELEG)
				return;
			continue;
		}
		if (st->st_type == NFSV4_ST_DELEG &&
		    (write || st->st_dtype == OPEN_DELEGATE_WRITE))
			return;
		if (st->st_type == NFSV4_ST_OPEN &&
		    (write || (st->st_access & OPEN4_SHARE_ACCESS_WRITE) != 0))
			return;
	}
	nfsv4_deleg_add(cl, vp, fh, write ? OPEN_DELEGATE_WRITE :
	    OPEN_DELEGATE_READ, ds, od);
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
nfsv4_deleg_claim_cur(struct nfsv4_client *cl, const struct nfsv4_stateid *si,
    struct vnode *vp)
{
	struct nfsv4_state *st;
	uint32_t status;

	mutex_enter(&nfsv4_state_lock);
	status = nfsv4_stateid_lookup(si, &st);
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
	status = nfsv4_client_get(a->clientid.clientid, &cl);
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
	status = nfsv4_stateid_lookup(si, &st);
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
