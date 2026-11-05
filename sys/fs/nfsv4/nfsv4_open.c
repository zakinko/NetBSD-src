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
 * OPEN and what goes with it, RFC 7530 s9 and s16: share reservations,
 * READ and WRITE under a stateid, COMMIT.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/kauth.h>
#include <sys/kmem.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/stat.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/vnode.h>

#include <fs/nfsv4/nfsv4_var.h>
#include <fs/nfsv4/nfsv4_state.h>

/*
 * The mode of a file created with no mode given is the server's choice;
 * the RFC names no default.
 */
#define	NFSV4_CREATE_MODE	0644

#define	OPEN4_ACCESS_OK(a)	((a) >= OPEN4_SHARE_ACCESS_READ && \
				 (a) <= OPEN4_SHARE_ACCESS_BOTH)
#define	OPEN4_DENY_OK(d)	((d) <= OPEN4_SHARE_DENY_BOTH)

/* s16.23.4 and s16.36: what READ, WRITE and COMMIT say of other types. */
uint32_t
nfsv4_file_check(const struct nfsv4_cfh *cf)
{

	if (cf->cf_vp == NULL || cf->cf_vp->v_type == VDIR)
		return NFS4ERR_ISDIR;
	return cf->cf_vp->v_type == VREG ? NFS4_OK : NFS4ERR_INVAL;
}

/* The change attribute of a locked directory, for change_info4. */
int
nfsv4_dir_change(struct vnode *dvp, kauth_cred_t cred, uint64_t *chp)
{
	struct vattr va;
	int error;

	error = VOP_GETATTR(dvp, &va, cred);
	if (error == 0)
		*chp = nfsv4_attr_change(dvp, &va);
	return error;
}

/*
 * s16.16.6: the verifier goes in atime, where version 3 keeps its own.
 * Not all 32 bits of a nanosecond field survive being stored, so the
 * top ones are left out of both the storing and the comparing.
 */
static void
verf_to_time(const struct nfsv4_verifier *v, struct timespec *ts)
{

	ts->tv_sec = be32dec(v->v_data);
	ts->tv_nsec = be32dec(v->v_data + 4) & 0x1fffffff;
	if (ts->tv_nsec >= 1000000000)
		ts->tv_nsec -= 1000000000;
}

/*
 * What OPEN does to the file system: find or create the file, and
 * give the referenced, unlocked vnode in *vpp.  Under OPEN4_CREATE with
 * the directory locked over it, so that change_info4 can be atomic.
 */
static uint32_t
open_vnode(struct nfsv4_compound *c, const struct nfsv4_args_open *oa,
    struct vnode **vpp, struct nfsv4_change_info *ci, uint64_t *setp,
    bool *createdp)
{
	const struct nfsv4_cfh *cf = &c->c_cur;
	struct vnode *dvp = cf->cf_vp, *vp;
	struct nameidata nd;
	struct vattr va, sva, cva;
	struct timespec ts;
	uint64_t set = 0;
	uint32_t st;
	int error;

	*createdp = false;
	vattr_null(&sva);
	if (oa->opentype == OPEN4_CREATE) {
		if (dvp == NULL)
			return NFS4ERR_ROFS;	/* s7.3 */
		if (oa->createmode != EXCLUSIVE4) {
			st = nfsv4_attr_parse(c, &oa->createattrs, &sva, &set);
			if (st != NFS4_OK)
				return st;
		}
	} else if (dvp == NULL)
		/*
		 * All that a pseudo file system holds is directories,
		 * and what it does not hold is not there.
		 */
		return nfsv4_cfh_lookup(c, __UNCONST(cf), oa->file.nm_str,
		    oa->file.nm_len, &c->c_scratch) == NFS4_OK ?
		    NFS4ERR_ISDIR : NFS4ERR_NOENT;

	if (oa->opentype == OPEN4_NOCREATE) {
		vn_lock(dvp, LK_SHARED | LK_RETRY);
		error = nfsv4_dir_change(dvp, cf->cf_cred, &ci->ci_before);
		VOP_UNLOCK(dvp);
		if (error == 0)
			error = nfsv4_lookup_vp(dvp, oa->file.nm_str,
			    cf->cf_cred, &vp);
		if (error != 0)
			return nfsv4_errno(error);
		ci->ci_after = ci->ci_before;
		ci->ci_atomic = 0;
		*vpp = vp;
		return NFS4_OK;
	}

	if ((cf->cf_exflags & MNT_EXRDONLY) != 0)
		return NFS4ERR_ROFS;
	error = nfsv4_namei(&nd, dvp, oa->file.nm_str, CREATE,
	    LOCKPARENT | LOCKLEAF, cf->cf_cred);
	if (error != 0)
		return nfsv4_errno(error);
	error = nfsv4_dir_change(nd.ni_dvp, cf->cf_cred, &ci->ci_before);

	if (nd.ni_vp != NULL) {
		vp = nd.ni_vp;
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		if (error == 0 && oa->createmode == GUARDED4)
			error = EEXIST;
		if (error == 0 && oa->createmode == EXCLUSIVE4) {
			verf_to_time(&oa->createverf, &ts);
			error = VOP_GETATTR(vp, &cva, cf->cf_cred);
			if (error == 0 && timespeccmp(&cva.va_atime, &ts, !=))
				error = EEXIST;
		}
		VOP_UNLOCK(vp);
		if (error == 0)
			ci->ci_after = ci->ci_before;
		vput(nd.ni_dvp);
		pathbuf_destroy(nd.ni_pathbuf);
		if (error != 0) {
			vrele(vp);
			return nfsv4_errno(error);
		}
		ci->ci_atomic = 1;
		*vpp = vp;
		/* s16.16.5: of the attributes, only a size of 0 is used. */
		if (oa->createmode == UNCHECKED4 &&
		    (set & (1ULL << FATTR4_SIZE)) != 0 && sva.va_size == 0)
			*setp = 1ULL << FATTR4_SIZE;
		return NFS4_OK;
	}

	if (error != 0) {
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		vput(nd.ni_dvp);
		pathbuf_destroy(nd.ni_pathbuf);
		return nfsv4_errno(error);
	}

	vattr_null(&va);
	va.va_type = VREG;
	va.va_mode = sva.va_mode != (mode_t)VNOVAL ? sva.va_mode :
	    NFSV4_CREATE_MODE;
	sva.va_mode = VNOVAL;
	error = VOP_CREATE(nd.ni_dvp, &vp, &nd.ni_cnd, &va);
	if (error == 0)
		error = nfsv4_dir_change(nd.ni_dvp, cf->cf_cred, &ci->ci_after);
	vput(nd.ni_dvp);
	pathbuf_destroy(nd.ni_pathbuf);
	if (error != 0)
		return nfsv4_errno(error);
	ci->ci_atomic = 1;
	*createdp = true;

	/* The rest of what was asked for, s16.16.5. */
	if (oa->createmode == EXCLUSIVE4) {
		vattr_null(&sva);
		verf_to_time(&oa->createverf, &sva.va_atime);
		set = 1ULL << FATTR4_TIME_ACCESS_SET;
	}
	if (sva.va_size != VNOVAL || sva.va_uid != VNOVAL ||
	    sva.va_gid != VNOVAL || sva.va_atime.tv_sec != VNOVAL ||
	    sva.va_mtime.tv_sec != VNOVAL ||
	    sva.va_birthtime.tv_sec != VNOVAL) {
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
		error = VOP_SETATTR(vp, &sva, cf->cf_cred);
		VOP_UNLOCK(vp);
		if (error != 0) {
			vrele(vp);
			return nfsv4_errno(error);
		}
	}
	if (*createdp) {
		st = nfsv4_acl_set(c, vp, cf->cf_cred);
		if (st != NFS4_OK) {
			vrele(vp);
			return st;
		}
	}
	*setp = set;
	*vpp = vp;
	return NFS4_OK;
}

/* s16.16.5, on a file that exists: what it is, and may it be opened. */
static uint32_t
open_access(const struct nfsv4_cfh *cf, struct vnode *vp, uint32_t access)
{
	struct nfsv4_cfh t;
	int error;

	if (vp->v_type == VDIR)
		return NFS4ERR_ISDIR;
	if (vp->v_type != VREG)
		return NFS4ERR_SYMLINK;
	t = *cf;
	t.cf_vp = vp;
	if ((access & OPEN4_SHARE_ACCESS_READ) != 0) {
		error = nfsv4_access_vp(&t, VREAD);
		if (error != 0)
			return nfsv4_errno(error);
	}
	if ((access & OPEN4_SHARE_ACCESS_WRITE) != 0) {
		error = nfsv4_access_vp(&t, VWRITE);
		if (error != 0)
			return nfsv4_errno(error);
	}
	return NFS4_OK;
}

/*
 * s9.9: the test against everything open on the file, with no exception
 * for this owner, then the state, s9.11: an owner has one open of a
 * file, and a second OPEN adds to it.
 */
static uint32_t
open_share(struct nfsv4_owner_s *sw, struct vnode *vp, uint32_t access,
    uint32_t deny, struct nfsv4_state **spare, struct nfsv4_file **sparef,
    struct nfsv4_stateid *si, const struct nfsv4_cfh *cf,
    struct nfsv4_deleg_spare *ds, struct nfsv4_open_deleg *od)
{
	struct nfsv4_file *f;
	struct nfsv4_state *st, *mine = NULL;
	uint32_t status;

	mutex_enter(&nfsv4_state_lock);
	/*
	 * s10.4: recalled before anything is decided, as only the holder
	 * knows what is open under a delegation.  A read delegation
	 * minds an open that may write, or that denies reading, which
	 * the holder would not send here; s10.4 again.
	 */
	status = nfsv4_deleg_conflict(vp, sw->sw_client, 0,
	    (access & OPEN4_SHARE_ACCESS_WRITE) != 0 ||
	    (deny & OPEN4_SHARE_DENY_READ) != 0 ?
	    NFSV4_DC_WRITE : NFSV4_DC_READ);
	if (status != NFS4_OK) {
		mutex_exit(&nfsv4_state_lock);
		return status;
	}
	f = nfsv4_file_find(vp);
	if (f != NULL) {
		LIST_FOREACH(st, &f->f_states, st_flist) {
			if (st->st_type != NFSV4_ST_OPEN)
				continue;
			if ((access & st->st_deny) != 0 ||
			    (deny & st->st_access) != 0) {
				mutex_exit(&nfsv4_state_lock);
				return NFS4ERR_SHARE_DENIED;
			}
			if (st->st_owner == sw)
				mine = st;
		}
	}
	if (mine != NULL)
		mine->st_seqid++;
	else {
		mine = nfsv4_state_add(spare, sw, sparef, vp, NFSV4_ST_OPEN);
		mine->st_seqid = 1;
	}
	mine->st_access |= access;
	mine->st_deny |= deny;
	mine->st_accbits |= 1U << access;
	mine->st_denybits |= 1U << deny;
	nfsv4_stateid_out(mine, si);
	if (ds != NULL)
		nfsv4_deleg_offer(sw, vp, &cf->cf_fh, access, ds, od);
	mutex_exit(&nfsv4_state_lock);
	return NFS4_OK;
}

static uint32_t
open_reply(struct nfsv4_compound *c, struct nfsv4_owner_s *sw,
    struct nfsv4_stateid *si, struct nfsv4_change_info *ci, uint64_t set,
    struct nfsv4_open_deleg *od, u_int *rlen)
{
	struct nfsv4_client *cl = sw->sw_client;
	uint32_t rflags;
	bool first;
	XDR rb;

	rflags = OPEN4_RESULT_LOCKTYPE_POSIX;
	if (!sw->sw_confirmed)
		rflags |= OPEN4_RESULT_CONFIRM;
	sw->sw_rfh = c->c_cur.cf_fh;

	/*
	 * s9.6.3.4.3.  The owner is busy, so the client stays.  Two owners
	 * at once may write it twice, which does no harm.
	 */
	mutex_enter(&nfsv4_state_lock);
	first = !cl->cl_stable;
	cl->cl_stable = true;
	mutex_exit(&nfsv4_state_lock);
	if (first)
		nfsv4_stable_good(cl->cl_idstr, cl->cl_idlen);

	xdrmem_create(&rb, c->c_rbuf, NFSV4_REPLAY_MAX, XDR_ENCODE);
	if (!nfsv4_xdr_stateid(&rb, si) ||
	    !nfsv4_xdr_change_info(&rb, ci) ||
	    !xdr_u_int32_t(&rb, &rflags) ||
	    !nfsv4_attr_put_mask(&rb, set) ||
	    !nfsv4_xdr_open_deleg(&rb, od))
		return NFS4ERR_SERVERFAULT;
	*rlen = xdr_getpos(&rb);
	return NFS4_OK;
}

/*
 * CLAIM_PREVIOUS, s9.6.2: the file is the current handle.  A delegation
 * claimed is granted whatever else, s10.2.1, and marked to be recalled
 * at once if the client has not shown it can be called: a server that
 * cannot recall has no business keeping it out.
 */
static uint32_t
open_previous(struct nfsv4_compound *c, const struct nfsv4_args_open *oa,
    struct nfsv4_owner_s *sw, struct nfsv4_state **spare,
    struct nfsv4_file **sparef, struct nfsv4_deleg_spare *ds, u_int *rlen)
{
	struct nfsv4_cfh *cf = &c->c_cur;
	struct nfsv4_change_info ci;
	struct nfsv4_stateid si;
	struct nfsv4_open_deleg od;
	struct vnode *vp = cf->cf_vp;
	uint32_t st;

	memset(&ci, 0, sizeof(ci));
	memset(&od, 0, sizeof(od));
	if (!OPEN4_ACCESS_OK(oa->share_access) ||
	    !OPEN4_DENY_OK(oa->share_deny) ||
	    oa->delegate_type > OPEN_DELEGATE_WRITE)
		return NFS4ERR_INVAL;
	st = nfsv4_reclaim_check(sw->sw_client);
	if (st != NFS4_OK)
		return st;
	if (vp == NULL || vp->v_type == VDIR)
		return NFS4ERR_ISDIR;
	if (vp->v_type != VREG)
		return NFS4ERR_SYMLINK;
	st = open_share(sw, vp, oa->share_access, oa->share_deny, spare,
	    sparef, &si, cf, NULL, NULL);
	if (st != NFS4_OK)
		return st;
	if (oa->delegate_type != OPEN_DELEGATE_NONE && ds->ds_st != NULL) {
		mutex_enter(&nfsv4_state_lock);
		nfsv4_deleg_add(sw->sw_client, vp, &cf->cf_fh,
		    oa->delegate_type, ds, &od);
		od.od_recall = sw->sw_client->cl_cbstate != NFSV4_CB_UP;
		mutex_exit(&nfsv4_state_lock);
	}
	return open_reply(c, sw, &si, &ci, 0, &od, rlen);
}

static uint32_t
open_do(struct nfsv4_compound *c, const struct nfsv4_args_open *oa,
    struct nfsv4_owner_s *sw, struct nfsv4_state **spare,
    struct nfsv4_file **sparef, struct nfsv4_deleg_spare *ds, u_int *rlen)
{
	struct nfsv4_cfh *cf = &c->c_cur;
	struct nfsv4_change_info ci;
	struct nfsv4_stateid si;
	struct vnode *vp = NULL;
	struct vattr va;
	uint64_t set = 0;
	struct nfsv4_open_deleg od;
	uint32_t st;
	bool created = false, trunc;
	int error;

	memset(&ci, 0, sizeof(ci));
	memset(&od, 0, sizeof(od));

	/*
	 * s16.16.5.  A delegation is the one claim to go by name in the
	 * grace period: of a reclaimed delegation, s10.2.1, or of a client
	 * restarted, and neither can conflict with a reclaim to come.
	 */
	switch (oa->claim) {
	case CLAIM_NULL:
		if (nfsv4_grace_active())
			return NFS4ERR_GRACE;
		break;
	case CLAIM_PREVIOUS:
		return open_previous(c, oa, sw, spare, sparef, ds, rlen);
	case CLAIM_DELEGATE_CUR:
	case CLAIM_DELEGATE_PREV:
		break;
	default:
		return NFS4ERR_NOTSUPP;
	}
	if (cf->cf_vp != NULL && cf->cf_vp->v_type != VDIR)
		return cf->cf_vp->v_type == VLNK ? NFS4ERR_SYMLINK :
		    NFS4ERR_NOTDIR;
	if (!OPEN4_ACCESS_OK(oa->share_access) ||
	    !OPEN4_DENY_OK(oa->share_deny))
		return NFS4ERR_INVAL;	/* s16.16.6 */
	st = nfsv4_name_check(&oa->file);
	if (st != NFS4_OK)
		return st;

	st = open_vnode(c, oa, &vp, &ci, &set, &created);
	if (st != NFS4_OK)
		return st;
	trunc = !created && set != 0;
	if (trunc)
		set = 0;

	if (!created) {
		st = open_access(cf, vp, oa->share_access);
		if (st != NFS4_OK)
			goto bad;
	}
	if (oa->claim == CLAIM_DELEGATE_CUR)
		st = nfsv4_deleg_claim_cur(sw->sw_client,
		    &oa->delegate_stateid, vp);
	else if (oa->claim == CLAIM_DELEGATE_PREV)
		st = nfsv4_deleg_claim_prev(sw->sw_client, vp, &od);
	if (st != NFS4_OK)
		goto bad;
	st = open_share(sw, vp, oa->share_access, oa->share_deny, spare,
	    sparef, &si, cf, ds, &od);
	if (st != NFS4_OK)
		goto bad;

	if (trunc) {
		vattr_null(&va);
		va.va_size = 0;
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
		error = VOP_SETATTR(vp, &va, cf->cf_cred);
		VOP_UNLOCK(vp);
		if (error != 0) {
			st = nfsv4_errno(error);
			goto bad;
		}
	}

	st = nfsv4_cfh_setvp(c, cf, vp);
	if (st != NFS4_OK)
		goto bad;
	vp = NULL;
	return open_reply(c, sw, &si, &ci, set, &od, rlen);
bad:
	if (vp != NULL)
		vrele(vp);
	return st;
}

/*
 * Write out the reply to a request under a seqid, which is the one to
 * keep: nfsv4_owner_replay_save() ends the request.
 */
uint32_t
nfsv4_seq_reply(struct nfsv4_compound *c, struct nfsv4_owner_s *sw, uint32_t seqid,
    uint32_t op, uint32_t st, u_int rlen)
{

	nfsv4_owner_replay_save(sw, seqid, op, st, c->c_rbuf, rlen);
	if (rlen != 0 && !XDR_PUTBYTES(c->c_rx, c->c_rbuf, rlen))
		return NFS4ERR_RESOURCE;
	return st;
}

/* The same, for a request that turned out to be a replay of the last. */
uint32_t
nfsv4_seq_replay(struct nfsv4_compound *c, struct nfsv4_owner_s *sw, bool fh)
{
	struct nfsv4_fh rfh;
	uint32_t st = sw->sw_laststat;
	u_int rlen = sw->sw_rlen;
	bool ok;

	ok = rlen == 0 || XDR_PUTBYTES(c->c_rx, sw->sw_rbuf, rlen);
	rfh = sw->sw_rfh;
	mutex_enter(&nfsv4_state_lock);
	nfsv4_owner_idle(sw);
	mutex_exit(&nfsv4_state_lock);
	if (!ok)
		return NFS4ERR_RESOURCE;
	if (fh && st == NFS4_OK)
		return nfsv4_cfh_put(c, &rfh);	/* s16.16.5, as it was */
	return st;
}

uint32_t
nfsv4_op_open(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_open *oa = &a->open;
	struct nfsv4_owner_s *sw, *ssw;
	struct nfsv4_client *cl;
	struct nfsv4_state *sst, *st;
	struct nfsv4_file *sf;
	struct nfsv4_reap reap;
	struct nfsv4_deleg_spare ds;
	enum nfsv4_seq seq;
	uint32_t status;
	u_int rlen = 0;
	bool want_deleg;

	ssw = kmem_zalloc(sizeof(*ssw), KM_SLEEP);
	sst = kmem_zalloc(sizeof(*sst), KM_SLEEP);
	sf = kmem_zalloc(sizeof(*sf), KM_SLEEP);
	memset(&ds, 0, sizeof(ds));
	SLIST_INIT(&reap);

	mutex_enter(&nfsv4_state_lock);
	status = nfsv4_client_get(oa->owner.ow_clientid, &cl);
	if (status != NFS4_OK) {
		mutex_exit(&nfsv4_state_lock);
		goto out;
	}
	cl->cl_connid = c->c_rq->rq_connid;
	want_deleg = cl->cl_cbstate == NFSV4_CB_UP;
	sw = nfsv4_owner_find(cl, NFSV4_OWNER_OPEN, oa->owner.ow_data,
	    oa->owner.ow_len);
	if (sw == NULL) {
		sw = nfsv4_owner_add(cl, &ssw, NFSV4_OWNER_OPEN,
		    oa->owner.ow_data, oa->owner.ow_len);
		nfsv4_owner_busy(sw);
		seq = NFSV4_SEQ_GO;
	} else {
		nfsv4_owner_busy(sw);
		seq = nfsv4_seq_check(sw, oa->seqid, NFSV4_OP_OPEN);
		if (!sw->sw_confirmed && seq != NFSV4_SEQ_REPLAY) {
			/*
			 * s16.18.5: the OPEN before this was not
			 * confirmed, so it was a replay, and this one is
			 * the one to believe.
			 */
			seq = NFSV4_SEQ_GO;
			while ((st = LIST_FIRST(&sw->sw_states)) != NULL)
				nfsv4_state_unlink(st, &reap, false);
			sw->sw_closed = NULL;
		}
	}
	mutex_exit(&nfsv4_state_lock);
	nfsv4_reap_finish(&reap);

	switch (seq) {
	case NFSV4_SEQ_REPLAY:
		status = nfsv4_seq_replay(c, sw, true);
		break;
	case NFSV4_SEQ_BAD:
		mutex_enter(&nfsv4_state_lock);
		nfsv4_owner_idle(sw);
		mutex_exit(&nfsv4_state_lock);
		status = NFS4ERR_BAD_SEQID;
		break;
	case NFSV4_SEQ_GO:
		if (want_deleg || oa->claim == CLAIM_PREVIOUS) {
			ds.ds_st = kmem_zalloc(sizeof(*ds.ds_st), KM_SLEEP);
			ds.ds_sw = kmem_zalloc(sizeof(*ds.ds_sw), KM_SLEEP);
			ds.ds_f = kmem_zalloc(sizeof(*ds.ds_f), KM_SLEEP);
		}
		status = open_do(c, oa, sw, &sst, &sf, &ds, &rlen);
		status = nfsv4_seq_reply(c, sw, oa->seqid, NFSV4_OP_OPEN, status,
		    status == NFS4_OK ? rlen : 0);
		break;
	}
out:
	if (ssw != NULL)
		kmem_free(ssw, sizeof(*ssw));
	if (sst != NULL)
		kmem_free(sst, sizeof(*sst));
	if (sf != NULL)
		kmem_free(sf, sizeof(*sf));
	if (ds.ds_st != NULL)
		kmem_free(ds.ds_st, sizeof(*ds.ds_st));
	if (ds.ds_sw != NULL)
		kmem_free(ds.ds_sw, sizeof(*ds.ds_sw));
	if (ds.ds_f != NULL)
		kmem_free(ds.ds_f, sizeof(*ds.ds_f));
	return status;
}

/*
 * Find what a stateid names and take up its owner under seqid: the
 * first half of everything that has both.  *replay is the case of
 * NFS4_OK with nothing more to do but send the old reply.
 */
uint32_t
nfsv4_seq_stateid(const struct nfsv4_stateid *si, uint32_t seqid, uint32_t op,
    struct nfsv4_state **stp, enum nfsv4_seq *seqp)
{
	struct nfsv4_state *st;
	uint32_t status;

	mutex_enter(&nfsv4_state_lock);
	status = nfsv4_stateid_lookup(si, &st);
	/* It has no seqid to take up, and is not good for any of these. */
	if (status == NFS4_OK && st->st_type == NFSV4_ST_DELEG)
		status = NFS4ERR_BAD_STATEID;
	if (status == NFS4_OK) {
		nfsv4_owner_busy(st->st_owner);
		*seqp = nfsv4_seq_check(st->st_owner, seqid, op);
		*stp = st;
	}
	mutex_exit(&nfsv4_state_lock);
	return status;
}

void
nfsv4_seq_cancel(struct nfsv4_owner_s *sw)
{

	mutex_enter(&nfsv4_state_lock);
	nfsv4_owner_idle(sw);
	mutex_exit(&nfsv4_state_lock);
}

/* RFC 7530 s16.18.  The seqid after that of the OPEN, and no other. */
uint32_t
nfsv4_op_open_confirm(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_open_confirm *oa = &a->open_confirm;
	struct nfsv4_reap reap;
	struct nfsv4_state *st;
	struct nfsv4_owner_s *sw;
	enum nfsv4_seq seq;
	struct nfsv4_stateid si;
	uint32_t status;
	XDR rb;

	status = nfsv4_seq_stateid(&oa->stateid, oa->seqid, NFSV4_OP_OPEN_CONFIRM,
	    &st, &seq);
	if (status != NFS4_OK)
		return status;
	sw = st->st_owner;
	if (seq == NFSV4_SEQ_REPLAY)
		return nfsv4_seq_replay(c, sw, false);

	SLIST_INIT(&reap);
	mutex_enter(&nfsv4_state_lock);
	if (st->st_type != NFSV4_ST_OPEN || sw->sw_confirmed ||
	    st->st_file == NULL || st->st_file->f_vp != c->c_cur.cf_vp)
		status = seq == NFSV4_SEQ_BAD ? NFS4ERR_BAD_SEQID :
		    NFS4ERR_BAD_STATEID;
	else if (seq == NFSV4_SEQ_BAD) {
		/*
		 * s16.18.4: then the client is taken not to want it.  The
		 * stateid stays, so that a resend gets the same answer.
		 */
		nfsv4_state_unlink(st, &reap, true);
		status = NFS4ERR_BAD_SEQID;
	} else if (oa->stateid.si_seqid != st->st_seqid &&
	    oa->stateid.si_seqid != 0)
		status = (int32_t)(oa->stateid.si_seqid - st->st_seqid) < 0 ?
		    NFS4ERR_OLD_STATEID : NFS4ERR_BAD_STATEID;
	else {
		sw->sw_confirmed = true;
		st->st_seqid++;
		nfsv4_stateid_out(st, &si);
		sw->sw_client->cl_expire = time_uptime + NFSV4_LEASE;
	}
	mutex_exit(&nfsv4_state_lock);
	nfsv4_reap_finish(&reap);

	if (status != NFS4_OK)
		return nfsv4_seq_reply(c, sw, oa->seqid, NFSV4_OP_OPEN_CONFIRM,
		    status, 0);
	xdrmem_create(&rb, c->c_rbuf, NFSV4_REPLAY_MAX, XDR_ENCODE);
	(void)nfsv4_xdr_stateid(&rb, &si);
	return nfsv4_seq_reply(c, sw, oa->seqid, NFSV4_OP_OPEN_CONFIRM, NFS4_OK,
	    xdr_getpos(&rb));
}

/*
 * bits has bit n set if some OPEN used the value n.  Is want the union
 * of some of them?  Those within it are the ones that can be in it.
 */
static bool
share_union(uint32_t bits, uint32_t want)
{
	uint32_t n, u = 0;

	if (want == 0)
		return (bits & 1) != 0;
	for (n = 1; n <= 3; n++) {
		if ((bits & (1U << n)) != 0 && (n & ~want) == 0)
			u |= n;
	}
	return u == want;
}

/* RFC 7530 s16.19. */
uint32_t
nfsv4_op_open_downgrade(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_open_downgrade *oa = &a->open_downgrade;
	struct nfsv4_state *st;
	struct nfsv4_owner_s *sw;
	struct nfsv4_stateid si;
	enum nfsv4_seq seq;
	uint32_t status, access = oa->share_access, deny = oa->share_deny;
	XDR rb;

	status = nfsv4_seq_stateid(&oa->stateid, oa->seqid,
	    NFSV4_OP_OPEN_DOWNGRADE, &st, &seq);
	if (status != NFS4_OK)
		return status;
	sw = st->st_owner;
	if (seq == NFSV4_SEQ_REPLAY)
		return nfsv4_seq_replay(c, sw, false);
	if (seq == NFSV4_SEQ_BAD) {
		nfsv4_seq_cancel(sw);
		return NFS4ERR_BAD_SEQID;
	}

	mutex_enter(&nfsv4_state_lock);
	status = nfsv4_stateid_check(&oa->stateid, st, c->c_cur.cf_vp,
	    NFSV4_ST_OPEN);
	if (status == NFS4_OK && (!OPEN4_ACCESS_OK(access) ||
	    !OPEN4_DENY_OK(deny) || !share_union(st->st_accbits, access) ||
	    !share_union(st->st_denybits, deny)))
		status = NFS4ERR_INVAL;
	if (status == NFS4_OK) {
		st->st_access = access;
		st->st_deny = deny;
		st->st_seqid++;
		nfsv4_stateid_out(st, &si);
	}
	mutex_exit(&nfsv4_state_lock);

	if (status != NFS4_OK)
		return nfsv4_seq_reply(c, sw, oa->seqid, NFSV4_OP_OPEN_DOWNGRADE,
		    status, 0);
	xdrmem_create(&rb, c->c_rbuf, NFSV4_REPLAY_MAX, XDR_ENCODE);
	(void)nfsv4_xdr_stateid(&rb, &si);
	return nfsv4_seq_reply(c, sw, oa->seqid, NFSV4_OP_OPEN_DOWNGRADE, NFS4_OK,
	    xdr_getpos(&rb));
}

/*
 * RFC 7530 s16.2.  Locks still held go too: s9.10 lets the server free
 * them, and then none exist after the CLOSE.
 */
uint32_t
nfsv4_op_close(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_close *ca = &a->close;
	struct nfsv4_state *st, *ls;
	struct nfsv4_owner_s *sw;
	struct nfsv4_stateid si;
	struct nfsv4_reap reap;
	enum nfsv4_seq seq;
	uint32_t status;
	XDR rb;

	status = nfsv4_seq_stateid(&ca->stateid, ca->seqid, NFSV4_OP_CLOSE, &st,
	    &seq);
	if (status != NFS4_OK)
		return status;
	sw = st->st_owner;
	if (seq == NFSV4_SEQ_REPLAY)
		return nfsv4_seq_replay(c, sw, false);
	if (seq == NFSV4_SEQ_BAD) {
		nfsv4_seq_cancel(sw);
		return NFS4ERR_BAD_SEQID;
	}

	SLIST_INIT(&reap);
	mutex_enter(&nfsv4_state_lock);
	status = nfsv4_stateid_check(&ca->stateid, st, c->c_cur.cf_vp,
	    NFSV4_ST_OPEN);
	if (status == NFS4_OK) {
		/*
		 * Nobody may be working with a lock state that goes with
		 * this.  The list can change during a wait.
		 */
again:
		LIST_FOREACH(ls, &st->st_locks, st_plist) {
			if (ls->st_owner->sw_busy) {
				cv_wait(&nfsv4_state_cv, &nfsv4_state_lock);
				goto again;
			}
		}
		while ((ls = LIST_FIRST(&st->st_locks)) != NULL)
			nfsv4_state_unlink(ls, &reap, false);
		if (sw->sw_closed != NULL)
			nfsv4_state_unlink(sw->sw_closed, &reap, false);
		st->st_seqid++;
		nfsv4_stateid_out(st, &si);
		nfsv4_state_unlink(st, &reap, true);
		st->st_closed = true;
		sw->sw_closed = st;
	}
	mutex_exit(&nfsv4_state_lock);
	nfsv4_reap_finish(&reap);

	if (status != NFS4_OK)
		return nfsv4_seq_reply(c, sw, ca->seqid, NFSV4_OP_CLOSE, status, 0);
	xdrmem_create(&rb, c->c_rbuf, NFSV4_REPLAY_MAX, XDR_ENCODE);
	(void)nfsv4_xdr_stateid(&rb, &si);
	return nfsv4_seq_reply(c, sw, ca->seqid, NFSV4_OP_CLOSE, NFS4_OK,
	    xdr_getpos(&rb));
}

/*
 * The stateid of a READ or a WRITE, s9.1.4 and s9.1.6.  A special one
 * must get past the deny bits of every open; a READ with the bypass may
 * skip that, s9.1.4.3.  A READ is allowed under an open for write
 * alone, which s9.1.6 leaves to the server, so a real stateid needs the
 * deny bits of other opens looked at as well.
 */
uint32_t
nfsv4_io_check(struct nfsv4_compound *c, const struct nfsv4_stateid *si,
    bool write)
{
	struct vnode *vp = c->c_cur.cf_vp;
	struct nfsv4_state *st = NULL, *o;
	struct nfsv4_state *open;
	struct nfsv4_file *f;
	struct nfsv4_client *self = NULL;
	uint32_t status = NFS4_OK, bit;

	bit = write ? OPEN4_SHARE_DENY_WRITE : OPEN4_SHARE_DENY_READ;
	/* s9.6.2: the simple way, whatever the stateid. */
	if (nfsv4_grace_active())
		return NFS4ERR_GRACE;
	mutex_enter(&nfsv4_state_lock);
	open = NULL;
	if (nfsv4_stateid_special(si)) {
		if (!write && si->si_seqid != 0)
			goto out;
	} else {
		status = nfsv4_stateid_lookup(si, &st);
		if (status != NFS4_OK)
			goto out;
		status = nfsv4_stateid_check(si, st, vp, 0);
		if (status != NFS4_OK)
			goto out;
		open = st->st_type == NFSV4_ST_LOCK ? st->st_open : st;
		if (open == NULL) {
			status = NFS4ERR_BAD_STATEID;
			goto out;
		}
		if (write && (open->st_access &
		    OPEN4_SHARE_ACCESS_WRITE) == 0) {
			status = NFS4ERR_OPENMODE;
			goto out;
		}
		self = st->st_owner->sw_client;
	}
	/* s10.4.1: without an open, these are the equivalent of one. */
	status = nfsv4_deleg_conflict(vp, self, 0,
	    write ? NFSV4_DC_WRITE : NFSV4_DC_READ);
	if (status != NFS4_OK)
		goto out;
	f = nfsv4_file_find(vp);
	if (f != NULL) {
		LIST_FOREACH(o, &f->f_states, st_flist) {
			if (o->st_type == NFSV4_ST_OPEN && o != open &&
			    (o->st_deny & bit) != 0) {
				status = NFS4ERR_LOCKED;
				break;
			}
		}
	}
out:
	mutex_exit(&nfsv4_state_lock);
	return status;
}

/* s16.16.6: access is checked on each READ and WRITE, not only at OPEN. */
uint32_t
nfsv4_op_read(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_read *ra = &a->read;
	const struct nfsv4_cfh *cf = &c->c_cur;
	struct vnode *vp = cf->cf_vp;
	struct iovec iov;
	struct uio uio;
	struct vattr va;
	char *buf = NULL;
	uint32_t st, count, n, eof;
	int error;

	st = nfsv4_file_check(cf);
	if (st != NFS4_OK)
		return st;
	st = nfsv4_io_check(c, &ra->stateid, false);
	if (st != NFS4_OK)
		return st;
	error = nfsv4_access_vp(cf, VREAD);
	if (error != 0)
		return nfsv4_errno(error);

	count = MIN(ra->count, NFSV4_MAXIO);
	if (ra->offset > INT64_MAX)
		count = 0;
	if (count != 0)
		buf = kmem_alloc(count, KM_SLEEP);

	iov.iov_base = buf;
	iov.iov_len = count;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = ra->offset > INT64_MAX ? 0 : (off_t)ra->offset;
	uio.uio_resid = count;
	uio.uio_rw = UIO_READ;
	UIO_SETUP_SYSSPACE(&uio);
	/*
	 * s16.23.4: at or past the end is no error, but FFS answers EFBIG
	 * past the largest file it can hold.
	 */
	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = VOP_GETATTR(vp, &va, cf->cf_cred);
	if (error == 0 && count != 0 && ra->offset < va.va_size) {
		error = VOP_READ(vp, &uio, IO_NODELOCKED, cf->cf_cred);
		if (error == 0)
			error = VOP_GETATTR(vp, &va, cf->cf_cred);
	}
	VOP_UNLOCK(vp);
	if (error != 0) {
		st = nfsv4_errno(error);
		goto out;
	}

	n = count - uio.uio_resid;
	eof = ra->offset + n >= va.va_size;	/* s16.23.4 */
	if (!xdr_u_int32_t(c->c_rx, &eof) || !xdr_u_int32_t(c->c_rx, &n) ||
	    (n != 0 && !xdr_opaque(c->c_rx, buf, n)))
		st = NFS4ERR_RESOURCE;
out:
	if (buf != NULL)
		kmem_free(buf, count);
	return st;
}

/*
 * The verifier of WRITE and COMMIT changes with each instance of the
 * server, s16.36.4.
 */
static void
write_verf(struct nfsv4_verifier *v)
{

	memset(v, 0, sizeof(*v));
	be32enc(v->v_data, nfsv4_boot);
}

uint32_t
nfsv4_op_write(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_write *wa = &a->write;
	const struct nfsv4_cfh *cf = &c->c_cur;
	struct vnode *vp = cf->cf_vp;
	struct nfsv4_verifier verf;
	struct iovec iov;
	struct uio uio;
	char *buf = NULL;
	uint32_t st, n, committed;
	u_int end;
	int error, ioflags;

	st = nfsv4_file_check(cf);
	if (st != NFS4_OK)
		return st;
	if (wa->stable > FILE_SYNC4)
		return NFS4ERR_INVAL;
	st = nfsv4_io_check(c, &wa->stateid, true);
	if (st != NFS4_OK)
		return st;
	error = nfsv4_access_vp(cf, VWRITE);
	if (error != 0)
		return nfsv4_errno(error);

	/* s16.36.4: the server may write less than asked. */
	n = MIN(wa->len, NFSV4_MAXIO);
	if (wa->offset > INT64_MAX ||
	    wa->offset + n > (uint64_t)INT64_MAX)
		return NFS4ERR_FBIG;
	if (n != 0) {
		buf = kmem_alloc(n, KM_SLEEP);
		end = XDR_GETPOS(c->c_ax);
		if (!XDR_SETPOS(c->c_ax, wa->pos) ||
		    !XDR_GETBYTES(c->c_ax, buf, n) ||
		    !XDR_SETPOS(c->c_ax, end)) {
			kmem_free(buf, n);
			return NFS4ERR_BADXDR;
		}
	}

	switch (wa->stable) {
	case UNSTABLE4:
		ioflags = IO_NODELOCKED;
		break;
	case DATA_SYNC4:
		ioflags = IO_DSYNC | IO_NODELOCKED;
		break;
	default:
		ioflags = IO_SYNC | IO_NODELOCKED;
		break;
	}
	iov.iov_base = buf;
	iov.iov_len = n;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = wa->offset;
	uio.uio_resid = n;
	uio.uio_rw = UIO_WRITE;
	UIO_SETUP_SYSSPACE(&uio);
	if (n != 0) {
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
		error = VOP_WRITE(vp, &uio, ioflags, cf->cf_cred);
		VOP_UNLOCK(vp);
	}
	if (buf != NULL)
		kmem_free(buf, n);
	if (error != 0)
		return nfsv4_errno(error);

	n -= uio.uio_resid;
	committed = wa->stable;
	write_verf(&verf);
	return xdr_u_int32_t(c->c_rx, &n) &&
	    xdr_u_int32_t(c->c_rx, &committed) &&
	    nfsv4_xdr_verifier(c->c_rx, &verf) ? NFS4_OK : NFS4ERR_RESOURCE;
}

uint32_t
nfsv4_op_commit(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_commit *ca = &a->commit;
	const struct nfsv4_cfh *cf = &c->c_cur;
	struct vnode *vp = cf->cf_vp;
	struct nfsv4_verifier verf;
	uint64_t end;
	uint32_t st;
	int error;

	st = nfsv4_file_check(cf);
	if (st != NFS4_OK)
		return st;
	/* s16.3.4: a count of 0 is to the end of the file. */
	if (ca->offset > (uint64_t)INT64_MAX ||
	    (uint64_t)INT64_MAX - ca->offset < ca->count)
		return NFS4ERR_INVAL;
	end = ca->count == 0 ? 0 : ca->offset + ca->count;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	error = VOP_FSYNC(vp, cf->cf_cred, FSYNC_WAIT, ca->offset, end);
	VOP_UNLOCK(vp);
	if (error != 0)
		return nfsv4_errno(error);
	write_verf(&verf);
	return nfsv4_xdr_verifier(c->c_rx, &verf) ? NFS4_OK : NFS4ERR_RESOURCE;
}
