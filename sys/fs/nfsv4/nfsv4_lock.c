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
 * s9.4, for fairness: clients poll for a blocking lock, and the first of
 * them denied has a lease to come back in.  Is someone before lo in the
 * queue for a range that clashes with fl?
 */
#define	LOCKWAIT_MAX	64		/* of one file; a choice */

static off_t
fl_end(const struct flock *fl)
{

	return fl->l_len == 0 ? -1 : fl->l_start + fl->l_len - 1;
}

static bool
lw_overlaps(const struct nfsv4_lockwait *lw, const struct flock *fl)
{
	off_t e = fl_end(fl);

	return (e == -1 || lw->lw_start <= e) &&
	    (lw->lw_end == -1 || fl->l_start <= lw->lw_end);
}

bool
nfsv4_lock_fair(struct nfsv4_owner_s *lo, struct vnode *vp,
    const struct flock *fl)
{
	struct nfsv4_file *f;
	struct nfsv4_lockwait *lw, *next;
	bool write = fl->l_type == F_WRLCK, ok = true;

	mutex_enter(&nfsv4_state_lock);
	f = nfsv4_file_find(vp);
	if (f != NULL) {
		TAILQ_FOREACH_SAFE(lw, &f->f_waits, lw_list, next) {
			if (time_uptime >= lw->lw_expire) {
				TAILQ_REMOVE(&f->f_waits, lw, lw_list);
				f->f_nwaits--;
				kmem_free(lw, sizeof(*lw));
				continue;
			}
			if (lw->lw_gen == lo->sw_gen)
				break;
			if ((write || lw->lw_write) && lw_overlaps(lw, fl)) {
				ok = false;
				break;
			}
		}
	}
	mutex_exit(&nfsv4_state_lock);
	return ok;
}

/*
 * After the attempt: a blocking lock denied joins the queue or keeps its
 * place, and anything granted, or a last try by a non-blocking one,
 * leaves it, s9.4.
 */
void
nfsv4_lock_waited(struct nfsv4_owner_s *lo, struct vnode *vp,
    const struct flock *fl, bool blocking, bool denied)
{
	struct nfsv4_file *f;
	struct nfsv4_lockwait *lw;

	mutex_enter(&nfsv4_state_lock);
	f = nfsv4_file_find(vp);
	if (f != NULL) {
		TAILQ_FOREACH(lw, &f->f_waits, lw_list) {
			if (lw->lw_gen == lo->sw_gen)
				break;
		}
		if (blocking && denied) {
			if (lw == NULL && f->f_nwaits < LOCKWAIT_MAX &&
			    (lw = kmem_zalloc(sizeof(*lw), KM_NOSLEEP)) != NULL) {
				lw->lw_gen = lo->sw_gen;
				TAILQ_INSERT_TAIL(&f->f_waits, lw, lw_list);
				f->f_nwaits++;
			}
			if (lw != NULL) {
				lw->lw_start = fl->l_start;
				lw->lw_end = fl_end(fl);
				lw->lw_write = fl->l_type == F_WRLCK;
				lw->lw_expire = time_uptime + NFSV4_LEASE;
			}
		} else if (lw != NULL) {
			TAILQ_REMOVE(&f->f_waits, lw, lw_list);
			f->f_nwaits--;
			kmem_free(lw, sizeof(*lw));
		}
	}
	mutex_exit(&nfsv4_state_lock);
}

/*
 * RFC 8881 s9.5: of a lock-owner's states on a file, each byte belongs to
 * the one last used to lock it, for the CLOSE of the open behind one to
 * leave the others' locks alone.  The file system knows only the owner.
 * The count is a choice, to bound what one state can make this keep.
 */
#define	NFSV4_LRANGE_MAX	1024

static void
lrange_toall(struct nfsv4_state *st)
{
	struct nfsv4_lrange *lr;

	while ((lr = LIST_FIRST(&st->st_ranges)) != NULL) {
		LIST_REMOVE(lr, lr_list);
		kmem_free(lr, sizeof(*lr));
	}
	st->st_nranges = 0;
	st->st_allfile = true;
}

static struct nfsv4_lrange *
lrange_add(struct nfsv4_state *st, off_t start, off_t end)
{
	struct nfsv4_lrange *lr;

	if (st->st_allfile)
		return NULL;
	if (st->st_nranges >= NFSV4_LRANGE_MAX ||
	    (lr = kmem_alloc(sizeof(*lr), KM_NOSLEEP)) == NULL) {
		lrange_toall(st);
		return NULL;
	}
	lr->lr_start = start;
	lr->lr_end = end;
	LIST_INSERT_HEAD(&st->st_ranges, lr, lr_list);
	st->st_nranges++;
	return lr;
}

/* Take the bytes from start up to end out of what st has. */
static void
lrange_sub(struct nfsv4_state *st, off_t start, off_t end)
{
	struct nfsv4_lrange *lr, *next;
	off_t tail;

	LIST_FOREACH_SAFE(lr, &st->st_ranges, lr_list, next) {
		if (lr->lr_end <= start || lr->lr_start >= end)
			continue;
		tail = lr->lr_end;
		if (lr->lr_start < start) {
			lr->lr_end = start;
			if (tail > end)
				(void)lrange_add(st, end, tail);
		} else if (tail > end)
			lr->lr_start = end;
		else {
			LIST_REMOVE(lr, lr_list);
			st->st_nranges--;
			kmem_free(lr, sizeof(*lr));
		}
		if (st->st_allfile)
			return;
	}
}

/*
 * A LOCK through st, or with st NULL a LOCKU, has been done of fl.  The
 * states of the owner are few, and s9.5's case is the rare one.
 */
void
nfsv4_lock_assign(struct nfsv4_owner_s *lo, struct nfsv4_file *f,
    struct nfsv4_state *st, const struct flock *fl)
{
	struct nfsv4_state *t;
	off_t end;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	end = fl->l_len == 0 ? INT64_MAX : fl->l_start + fl->l_len;
	LIST_FOREACH(t, &lo->sw_states, st_olist) {
		if (t->st_file == f)
			lrange_sub(t, fl->l_start, end);
	}
	if (st != NULL)
		(void)lrange_add(st, fl->l_start, end);
}

/* The state is going, on the way out of nfsv4_state_unlink(). */
void
nfsv4_lock_drop(struct nfsv4_state *st, struct vnode *vp)
{
	struct nfsv4_lrange *lr;
	struct flock fl;

	memset(&fl, 0, sizeof(fl));
	fl.l_type = F_UNLCK;
	fl.l_whence = SEEK_SET;
	if (st->st_allfile) {
		(void)VOP_ADVLOCK(vp, st->st_owner, F_UNLCK, &fl, 0);
		return;
	}
	mutex_enter(&nfsv4_state_lock);
	while ((lr = LIST_FIRST(&st->st_ranges)) != NULL) {
		LIST_REMOVE(lr, lr_list);
		st->st_nranges--;
		mutex_exit(&nfsv4_state_lock);
		fl.l_start = lr->lr_start;
		fl.l_len = lr->lr_end == INT64_MAX ? 0 :
		    lr->lr_end - lr->lr_start;
		(void)VOP_ADVLOCK(vp, st->st_owner, F_UNLCK, &fl, 0);
		kmem_free(lr, sizeof(*lr));
		mutex_enter(&nfsv4_state_lock);
	}
	mutex_exit(&nfsv4_state_lock);
}

/*
 * RFC 8881 s8.4.3: a lock of an expired lease does not stand in the way.
 * The scan may not have come round to it; it is told to, and the caller
 * has the client ask again, the lock being gone by then.
 */
static bool
lock_holder_expired(const void *id)
{
	struct nfsv4_owner_s *sw;
	bool expired = false;

	if (id == NULL)
		return false;
	mutex_enter(&nfsv4_state_lock);
	sw = nfsv4_owner_byid(id);
	if (sw != NULL && time_uptime > sw->sw_client->cl_expire) {
		expired = true;
		cv_broadcast(&nfsv4_state_cv);
	}
	mutex_exit(&nfsv4_state_lock);
	return expired;
}

/*
 * Try the lock; the result for the reply goes in *rlen.  It is not
 * waited for even for READW_LT and WRITEW_LT: s9.4 has a client poll,
 * and a server may answer at once.
 */
static uint32_t
lock_set(struct nfsv4_compound *c, struct nfsv4_owner_s *lo, struct flock *fl,
    u_int *rlen)
{
	struct vnode *vp = c->c_cur.cf_vp;
	struct lf_query q;
	struct flock t;
	int error;

	if (!nfsv4_lock_fair(lo, vp, fl)) {
		q.lfq_fl = *fl;
		q.lfq_id = NULL;
		*rlen = lock_denied(c, &q);
		return NFS4ERR_DENIED;
	}
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
	if (lock_holder_expired(q.lfq_id))
		return NFS4ERR_DELAY;
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

	status = nfsv4_file_check(c, &c->c_cur);
	if (status == NFS4_OK)
		status = lock_type(la->type, &type);
	if (status != NFS4_OK)
		return status;

	ssw = kmem_zalloc(sizeof(*ssw), KM_SLEEP);
	sst = kmem_zalloc(sizeof(*sst), KM_SLEEP);

	if (la->newowner) {
		status = nfsv4_seq_stateid(c, &la->open_stateid, la->open_seqid,
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
		if (status == NFS4_OK && c->c_minor == 0 &&
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
				/*
				 * RFC 8881 s18.10.3 has this be for a client
				 * that lost the stateid: it is the same state.
				 */
				if (st != NULL && seq != NFSV4_SEQ_REPLAY &&
				    c->c_minor == 0)
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
		status = nfsv4_seq_stateid(c, &la->lock_stateid, la->lock_seqid,
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

	/* s9.6.2 */
	if (status == NFS4_OK && la->reclaim)
		status = c->c_minor != 0 && c->c_client->cl_reclaimed ?
		    NFS4ERR_NO_GRACE : nfsv4_reclaim_check(lo->sw_client);
	/* RFC 8881 s18.51.3 */
	else if (status == NFS4_OK && (nfsv4_grace_active() ||
	    (c->c_minor != 0 && !c->c_client->cl_reclaimed)))
		status = NFS4ERR_GRACE;
	if (status == NFS4_OK)
		status = lock_range(la->offset, la->length, &fl);
	if (status == NFS4_OK) {
		fl.l_type = type;
		status = lock_set(c, lo, &fl, &rlen);
		nfsv4_lock_waited(lo, vp, &fl, la->type == READW_LT ||
		    la->type == WRITEW_LT, status == NFS4ERR_DENIED);
	}
	if (status == NFS4_OK) {
		mutex_enter(&nfsv4_state_lock);
		if (st == NULL) {
			st = nfsv4_state_add(&sst, lo, &sf, vp, NFSV4_ST_LOCK);
			st->st_open = ost;
			LIST_INSERT_HEAD(&ost->st_locks, st, st_plist);
		} else
			st->st_seqid++;
		nfsv4_lock_assign(lo, st->st_file, st, &fl);
		nfsv4_stateid_out(st, &si);
		c->c_curst = si;
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

	status = nfsv4_file_check(c, &c->c_cur);
	if (status == NFS4_OK)
		status = lock_type(la->type, &type);
	if (status == NFS4_OK)
		status = lock_range(la->offset, la->length, &q.lfq_fl);
	if (status == NFS4_OK && nfsv4_grace_active())
		status = NFS4ERR_GRACE;		/* s13.2, s9.6.2 */
	if (status != NFS4_OK)
		return status;

	mutex_enter(&nfsv4_state_lock);
	status = nfsv4_client_cur(c, la->owner.ow_clientid, &cl);
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
	if (lock_holder_expired(q.lfq_id))
		return NFS4ERR_DELAY;
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

	status = nfsv4_file_check(c, &c->c_cur);
	if (status == NFS4_OK)
		status = lock_type(la->type, &type);
	if (status != NFS4_OK)
		return status;

	status = nfsv4_seq_stateid(c, &la->stateid, la->seqid, NFSV4_OP_LOCKU,
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
		nfsv4_lock_assign(lo, st->st_file, NULL, &fl);
		nfsv4_stateid_out(st, &si);
		c->c_curst = si;
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
