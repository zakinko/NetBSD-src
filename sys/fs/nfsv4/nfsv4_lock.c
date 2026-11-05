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
 * Byte-range locks, RFC 7530 s9 and s16.10 to s16.12.
 *
 * The locks themselves are lockf's, reached by VOP_ADVLOCK with neither
 * F_POSIX nor F_FLOCK and a lock owner as the id, which lockf is fine
 * with.  Such locks do conflict with those of local processes.  F_GETLKID
 * and F_HASLK say whose a lock is and whether an owner has one.  What
 * cannot be had from it is an offset from 2^63 up, which off_t cannot
 * say.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/kmem.h>
#include <sys/lockf.h>
#include <sys/systm.h>
#include <sys/vnode.h>

#include <fs/nfsv4/nfsv4_var.h>
#include <fs/nfsv4/nfsv4_state.h>

/*
 * s16.10.4.  The server's limit is 2^63 and the RFC only speaks of
 * 32-bit servers: it is a choice to read NFS4ERR_BAD_RANGE (s13.1.8.1)
 * as covering this limit in the same way.
 */
static uint32_t
lock_range(uint64_t offset, uint64_t length, struct flock *fl)
{

	if (length == 0)
		return NFS4ERR_INVAL;
	if (length != UINT64_MAX && offset + length < offset)
		return NFS4ERR_INVAL;
	if (offset > INT64_MAX)
		return NFS4ERR_BAD_RANGE;
	if (length != UINT64_MAX && offset + length - 1 > INT64_MAX)
		return NFS4ERR_BAD_RANGE;
	memset(fl, 0, sizeof(*fl));
	fl->l_whence = SEEK_SET;
	fl->l_start = (off_t)offset;
	fl->l_len = length == UINT64_MAX ? 0 : (off_t)length;
	return NFS4_OK;
}

static uint32_t
lock_type(uint32_t type, short *fltype)
{

	switch (type) {
	case READ_LT:
	case READW_LT:
		*fltype = F_RDLCK;
		return NFS4_OK;
	case WRITE_LT:
	case WRITEW_LT:
		*fltype = F_WRLCK;
		return NFS4_OK;
	default:
		return NFS4ERR_INVAL;
	}
}

/*
 * Encode LOCK4denied from what F_GETLKID says, s16.10.5.  The id is
 * looked for among the owners, not followed.  One that is not there is a
 * local process or an open file: the RFC has no owner for those, so
 * clientid 0 and an empty owner are the server's choice.
 */
static u_int
lock_denied(struct nfsv4_compound *c, const struct lf_query *q)
{
	const struct flock *fl = &q->lfq_fl;
	struct nfsv4_lock_denied ld;
	struct nfsv4_owner_s *sw;
	u_int len;
	XDR rb;

	memset(&ld, 0, sizeof(ld));
	ld.ld_offset = fl->l_start;
	ld.ld_length = fl->l_len == 0 ? UINT64_MAX : (uint64_t)fl->l_len;
	ld.ld_type = fl->l_type == F_WRLCK ? WRITE_LT : READ_LT;
	ld.ld_owner = (const uint8_t *)"";
	mutex_enter(&nfsv4_state_lock);
	if ((sw = nfsv4_owner_byid(q->lfq_id)) != NULL) {
		ld.ld_clientid = sw->sw_client->cl_id;
		ld.ld_ownerlen = sw->sw_len;
		ld.ld_owner = sw->sw_data;
	}
	xdrmem_create(&rb, c->c_rbuf, NFSV4_REPLAY_MAX, XDR_ENCODE);
	(void)nfsv4_xdr_lock_denied(&rb, &ld);
	len = xdr_getpos(&rb);
	mutex_exit(&nfsv4_state_lock);
	return len;
}

/*
 * Try the lock; the result for the reply goes in *rlen.  Waiting for it
 * is not done here even for READW_LT and WRITEW_LT: s9.4 has a client
 * poll, the blocking types being a hint.
 */
static uint32_t
lock_set(struct nfsv4_compound *c, struct nfsv4_owner_s *lo, struct flock *fl,
    u_int *rlen)
{
	struct vnode *vp = c->c_cur.cf_vp;
	struct lf_query q;
	struct flock t;
	int error;

	t = *fl;
	error = VOP_ADVLOCK(vp, lo, F_SETLK, &t, 0);
	if (error == 0)
		return NFS4_OK;
	if (error != EAGAIN)
		return error == ENOLCK ? NFS4ERR_RESOURCE :
		    nfsv4_errno(error);
	/* It may have gone since, or the file system not know the op. */
	q.lfq_fl = *fl;
	q.lfq_id = NULL;
	if (VOP_ADVLOCK(vp, lo, F_GETLKID, &q.lfq_fl, 0) != 0 ||
	    q.lfq_fl.l_type == F_UNLCK) {
		q.lfq_fl = *fl;
		q.lfq_id = NULL;
	}
	*rlen = lock_denied(c, &q);
	return NFS4ERR_DENIED;
}

uint32_t
nfsv4_op_lock(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_lock *la = &a->lock;
	struct vnode *vp = c->c_cur.cf_vp;
	struct nfsv4_owner_s *oo = NULL, *lo = NULL, *ssw;
	struct nfsv4_state *st = NULL, *ost = NULL, *sst, *t;
	struct nfsv4_stateid si;
	struct nfsv4_file *sf = NULL;
	struct flock fl;
	enum nfsv4_seq seq;
	uint32_t status, need;
	u_int rlen = 0;
	short type;
	XDR rb;

	status = nfsv4_file_check(&c->c_cur);
	if (status == NFS4_OK)
		status = lock_type(la->type, &type);
	if (status != NFS4_OK)
		return status;

	ssw = kmem_zalloc(sizeof(*ssw), KM_SLEEP);
	sst = kmem_zalloc(sizeof(*sst), KM_SLEEP);

	if (la->newowner) {
		status = nfsv4_seq_stateid(&la->open_stateid, la->open_seqid,
		    NFSV4_OP_LOCK, &ost, &seq);
		if (status != NFS4_OK)
			goto out;
		oo = ost->st_owner;
		if (seq == NFSV4_SEQ_BAD) {
			nfsv4_seq_cancel(oo);
			status = NFS4ERR_BAD_SEQID;
			goto out;
		}
		mutex_enter(&nfsv4_state_lock);
		status = nfsv4_stateid_check(&la->open_stateid, ost, vp,
		    NFSV4_ST_OPEN);
		if (status == NFS4_OK &&
		    oo->sw_client->cl_id != la->owner.ow_clientid)
			status = NFS4ERR_BAD_STATEID;
		if (status == NFS4_OK) {
			lo = nfsv4_owner_find(oo->sw_client, NFSV4_OWNER_LOCK,
			    la->owner.ow_data, la->owner.ow_len);
			if (lo == NULL) {
				lo = nfsv4_owner_add(oo->sw_client, &ssw,
				    NFSV4_OWNER_LOCK, la->owner.ow_data,
				    la->owner.ow_len);
				nfsv4_owner_busy(lo);
				/* It has nothing to replay. */
				if (seq == NFSV4_SEQ_REPLAY)
					seq = NFSV4_SEQ_BAD;
			} else {
				nfsv4_owner_busy(lo);
				/*
				 * With no state it is as good as unknown,
				 * s9.1.10, and s16.10.4 lets this set a new
				 * sequence: a client whose first LOCK was
				 * denied starts the owner again, and its
				 * seqid must not then look like a replay
				 * of the denial.
				 */
				if (LIST_EMPTY(&lo->sw_states)) {
					if (seq == NFSV4_SEQ_REPLAY)
						seq = NFSV4_SEQ_BAD;
					goto have_owner;
				}
				seq = nfsv4_seq_check(lo, la->lock_seqid,
				    NFSV4_OP_LOCK);
				/*
				 * s16.10.4: this owner has state here, and
				 * the boolean should not be set.  pynfs's
				 * LOCK24 does that after an OPEN upgrade and
				 * wants NFS4_OK; the RFC's BAD_SEQID stands.
				 */
				LIST_FOREACH(t, &lo->sw_states, st_olist) {
					if (t->st_open == ost)
						st = t;
				}
				if (st != NULL && seq != NFSV4_SEQ_REPLAY)
					seq = NFSV4_SEQ_BAD;
				else if (seq == NFSV4_SEQ_REPLAY && st == NULL)
					seq = NFSV4_SEQ_BAD;
			}
		}
have_owner:
		mutex_exit(&nfsv4_state_lock);
		if (status != NFS4_OK) {
			status = nfsv4_seq_reply(c, oo, la->open_seqid,
			    NFSV4_OP_LOCK, status, 0);
			goto out;
		}
	} else {
		status = nfsv4_seq_stateid(&la->lock_stateid, la->lock_seqid,
		    NFSV4_OP_LOCK, &st, &seq);
		if (status != NFS4_OK)
			goto out;
		lo = st->st_owner;
	}

	if (seq == NFSV4_SEQ_REPLAY) {
		status = nfsv4_seq_replay(c, lo, false);
		if (oo != NULL)
			nfsv4_seq_cancel(oo);
		goto out;
	}
	if (seq == NFSV4_SEQ_BAD) {
		nfsv4_seq_cancel(lo);
		if (oo != NULL)
			nfsv4_seq_cancel(oo);
		status = NFS4ERR_BAD_SEQID;
		goto out;
	}

	mutex_enter(&nfsv4_state_lock);
	if (!la->newowner) {
		status = nfsv4_stateid_check(&la->lock_stateid, st, vp,
		    NFSV4_ST_LOCK);
		ost = st->st_open;
		if (status == NFS4_OK && ost == NULL)
			status = NFS4ERR_BAD_STATEID;
	}
	if (status == NFS4_OK) {
		/* s16.10.5 leaves this to the file system's semantics. */
		need = type == F_WRLCK ? OPEN4_SHARE_ACCESS_WRITE :
		    OPEN4_SHARE_ACCESS_READ;
		if ((ost->st_access & need) == 0)
			status = NFS4ERR_OPENMODE;
	}
	mutex_exit(&nfsv4_state_lock);

	if (status == NFS4_OK && la->reclaim)
		status = NFS4ERR_NO_GRACE;
	if (status == NFS4_OK)
		status = lock_range(la->offset, la->length, &fl);
	if (status == NFS4_OK) {
		fl.l_type = type;
		status = lock_set(c, lo, &fl, &rlen);
	}
	if (status == NFS4_OK) {
		mutex_enter(&nfsv4_state_lock);
		if (st == NULL) {
			st = nfsv4_state_add(&sst, lo, &sf, vp, NFSV4_ST_LOCK);
			st->st_open = ost;
			LIST_INSERT_HEAD(&ost->st_locks, st, st_plist);
		} else
			st->st_seqid++;
		nfsv4_stateid_out(st, &si);
		mutex_exit(&nfsv4_state_lock);
		xdrmem_create(&rb, c->c_rbuf, NFSV4_REPLAY_MAX, XDR_ENCODE);
		(void)nfsv4_xdr_stateid(&rb, &si);
		rlen = xdr_getpos(&rb);
	}

	/* s9.1.9: both owners have used up their sequence numbers. */
	if (oo != NULL)
		nfsv4_owner_replay_save(oo, la->open_seqid, NFSV4_OP_LOCK,
		    status, c->c_rbuf, rlen);
	status = nfsv4_seq_reply(c, lo, la->lock_seqid, NFSV4_OP_LOCK, status,
	    rlen);
out:
	if (ssw != NULL)
		kmem_free(ssw, sizeof(*ssw));
	if (sst != NULL)
		kmem_free(sst, sizeof(*sst));
	return status;
}

uint32_t
nfsv4_op_lockt(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_lockt *la = &a->lockt;
	struct nfsv4_client *cl;
	struct nfsv4_owner_s *lo;
	struct lf_query q;
	const void *id;
	uint32_t status;
	short type;
	u_int rlen;
	int error;

	status = nfsv4_file_check(&c->c_cur);
	if (status == NFS4_OK)
		status = lock_type(la->type, &type);
	if (status == NFS4_OK)
		status = lock_range(la->offset, la->length, &q.lfq_fl);
	if (status != NFS4_OK)
		return status;

	mutex_enter(&nfsv4_state_lock);
	status = nfsv4_client_get(la->owner.ow_clientid, &cl);
	lo = NULL;
	if (status == NFS4_OK)
		lo = nfsv4_owner_find(cl, NFSV4_OWNER_LOCK, la->owner.ow_data,
		    la->owner.ow_len);
	mutex_exit(&nfsv4_state_lock);
	if (status != NFS4_OK)
		return status;

	/*
	 * s16.11.5: locks of this owner do not count.  An owner the server
	 * does not know has none, and any id that is no owner's will do.
	 * lo is only compared with.
	 */
	id = lo != NULL ? (const void *)lo : (const void *)c;
	q.lfq_fl.l_type = type;
	error = VOP_ADVLOCK(c->c_cur.cf_vp, __UNCONST(id), F_GETLKID,
	    &q.lfq_fl, 0);
	if (error != 0)
		return nfsv4_errno(error);
	if (q.lfq_fl.l_type == F_UNLCK)
		return NFS4_OK;
	rlen = lock_denied(c, &q);
	return XDR_PUTBYTES(c->c_rx, c->c_rbuf, rlen) ? NFS4ERR_DENIED :
	    NFS4ERR_RESOURCE;
}

/*
 * RFC 7530 s16.12.  Any range can be unlocked, as POSIX has it, so
 * NFS4ERR_LOCK_RANGE is not used.
 */
uint32_t
nfsv4_op_locku(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_locku *la = &a->locku;
	struct nfsv4_state *st;
	struct nfsv4_owner_s *lo;
	struct nfsv4_stateid si;
	struct flock fl;
	enum nfsv4_seq seq;
	uint32_t status;
	short type;
	u_int rlen = 0;
	int error;
	XDR rb;

	status = nfsv4_file_check(&c->c_cur);
	if (status == NFS4_OK)
		status = lock_type(la->type, &type);
	if (status != NFS4_OK)
		return status;

	status = nfsv4_seq_stateid(&la->stateid, la->seqid, NFSV4_OP_LOCKU,
	    &st, &seq);
	if (status != NFS4_OK)
		return status;
	lo = st->st_owner;
	if (seq == NFSV4_SEQ_REPLAY)
		return nfsv4_seq_replay(c, lo, false);
	if (seq == NFSV4_SEQ_BAD) {
		nfsv4_seq_cancel(lo);
		return NFS4ERR_BAD_SEQID;
	}

	mutex_enter(&nfsv4_state_lock);
	status = nfsv4_stateid_check(&la->stateid, st, c->c_cur.cf_vp,
	    NFSV4_ST_LOCK);
	mutex_exit(&nfsv4_state_lock);
	if (status == NFS4_OK)
		status = lock_range(la->offset, la->length, &fl);
	if (status == NFS4_OK) {
		fl.l_type = F_UNLCK;
		error = VOP_ADVLOCK(c->c_cur.cf_vp, lo, F_UNLCK, &fl, 0);
		status = nfsv4_errno(error);
	}
	if (status == NFS4_OK) {
		mutex_enter(&nfsv4_state_lock);
		st->st_seqid++;
		nfsv4_stateid_out(st, &si);
		mutex_exit(&nfsv4_state_lock);
		xdrmem_create(&rb, c->c_rbuf, NFSV4_REPLAY_MAX, XDR_ENCODE);
		(void)nfsv4_xdr_stateid(&rb, &si);
		rlen = xdr_getpos(&rb);
	}
	return nfsv4_seq_reply(c, lo, la->seqid, NFSV4_OP_LOCKU, status, rlen);
}

/*
 * Does lo hold a lock on any file.  It is busy, so it keeps its states
 * and gets no new ones, but one can lose its file with the open it came
 * under, so the list is gone over afresh after each VOP.
 */
static bool
lock_owner_held(struct nfsv4_owner_s *lo)
{
	struct nfsv4_state *st;
	struct vnode *vp;
	struct flock fl;
	bool held = false;

	KASSERT(mutex_owned(&nfsv4_state_lock));
	KASSERT(lo->sw_busy);

	LIST_FOREACH(st, &lo->sw_states, st_olist)
		st->st_asked = false;
	while (!held) {
		LIST_FOREACH(st, &lo->sw_states, st_olist) {
			if (!st->st_asked && st->st_file != NULL)
				break;
		}
		if (st == NULL)
			break;
		st->st_asked = true;
		vp = st->st_file->f_vp;
		vref(vp);
		mutex_exit(&nfsv4_state_lock);
		memset(&fl, 0, sizeof(fl));
		fl.l_whence = SEEK_SET;
		fl.l_type = F_WRLCK;
		if (VOP_ADVLOCK(vp, lo, F_HASLK, &fl, 0) != 0 ||
		    fl.l_type != F_UNLCK)
			held = true;
		vrele(vp);
		mutex_enter(&nfsv4_state_lock);
	}
	return held;
}

/* RFC 7530 s16.37 */
uint32_t
nfsv4_op_release_lockowner(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_owner *ow = &a->release_lockowner.owner;
	struct nfsv4_client *cl;
	struct nfsv4_owner_s *lo;
	struct nfsv4_reap reap;
	uint32_t status;

	SLIST_INIT(&reap);
	mutex_enter(&nfsv4_state_lock);
	status = nfsv4_client_get(ow->ow_clientid, &cl);
	if (status == NFS4_OK &&
	    (lo = nfsv4_owner_find(cl, NFSV4_OWNER_LOCK, ow->ow_data,
	    ow->ow_len)) != NULL) {
		nfsv4_owner_busy(lo);
		if (lock_owner_held(lo))
			status = NFS4ERR_LOCKS_HELD;
		if (status == NFS4_OK)
			nfsv4_owner_free(lo, &reap);
		else
			nfsv4_owner_idle(lo);
	}
	mutex_exit(&nfsv4_state_lock);
	nfsv4_reap_finish(&reap);
	return status;
}
