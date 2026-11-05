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
 * Operations that change the name space or attributes and hold no
 * state: CREATE, REMOVE, RENAME, LINK, SETATTR, and with them VERIFY and
 * NVERIFY.  The VOP protocols are those of nfs_serv.c.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/kauth.h>
#include <sys/kmem.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/stat.h>
#include <sys/systm.h>
#include <sys/vnode.h>

#include <fs/nfsv4/nfsv4_var.h>
#include <fs/nfsv4/nfsv4_state.h>

/* The server's choice: the RFC gives no default for createattrs. */
#define	NFSV4_MKDIR_MODE	0755
#define	NFSV4_SYMLINK_MODE	0777
#define	NFSV4_MKNOD_MODE	0644

/* A directory that may be changed, for the operations here. */
static uint32_t
dir_check(const struct nfsv4_cfh *cf)
{

	if (cf->cf_vp == NULL)
		return NFS4ERR_ROFS;		/* s7.3 */
	if (cf->cf_vp->v_type != VDIR)
		return NFS4ERR_NOTDIR;
	if ((cf->cf_exflags & MNT_EXRDONLY) != 0)
		return NFS4ERR_ROFS;
	return NFS4_OK;
}

static enum vtype
create_vtype(uint32_t type)
{

	switch (type) {
	case NF4LNK:	return VLNK;
	case NF4BLK:	return VBLK;
	case NF4CHR:	return VCHR;
	case NF4SOCK:	return VSOCK;
	case NF4FIFO:	return VFIFO;
	case NF4DIR:	return VDIR;
	default:	return VNON;	/* s16.4.2: NFS4ERR_BADTYPE */
	}
}

/* RFC 7530 s16.4 */
uint32_t
nfsv4_op_create(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_create *ca = &a->create;
	struct nfsv4_cfh *cf = &c->c_cur;
	struct nfsv4_change_info ci;
	struct nameidata nd;
	struct vattr va, sva;
	struct vnode *vp;
	enum vtype vt;
	uint64_t set;
	uint32_t st;
	int error;

	vt = create_vtype(ca->type);
	if (cf->cf_vp != NULL && cf->cf_vp->v_type != VDIR)
		return NFS4ERR_NOTDIR;
	if (vt == VNON)
		return NFS4ERR_BADTYPE;
	st = nfsv4_name_check(&ca->name);
	if (st != NFS4_OK)
		return st;
	if (ca->type == NF4LNK) {
		if (ca->link.ln_toolong)
			return NFS4ERR_NAMETOOLONG;
		if (ca->link.ln_len == 0)
			return NFS4ERR_INVAL;
	}
	st = dir_check(cf);
	if (st != NFS4_OK)
		return st;
	st = nfsv4_attr_parse(c, &ca->attrs, &sva, &set);
	if (st != NFS4_OK)
		return st;
	if ((set & (1ULL << FATTR4_SIZE)) != 0)
		return NFS4ERR_INVAL;	/* of no use on these types */

	memset(&ci, 0, sizeof(ci));
	error = nfsv4_namei(&nd, cf->cf_vp, ca->name.nm_str, CREATE,
	    LOCKPARENT, cf->cf_cred);
	if (error != 0)
		return nfsv4_errno(error);
	if (nd.ni_vp != NULL) {
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		if (nd.ni_dvp == nd.ni_vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		vrele(nd.ni_vp);
		pathbuf_destroy(nd.ni_pathbuf);
		return NFS4ERR_EXIST;
	}

	vattr_null(&va);
	va.va_type = vt;
	va.va_mode = sva.va_mode;
	sva.va_mode = VNOVAL;
	error = nfsv4_dir_change(nd.ni_dvp, cf->cf_cred, &ci.ci_before);
	switch (error != 0 ? VNON : vt) {
	case VDIR:
		if (va.va_mode == (mode_t)VNOVAL)
			va.va_mode = NFSV4_MKDIR_MODE;
		error = VOP_MKDIR(nd.ni_dvp, &vp, &nd.ni_cnd, &va);
		break;
	case VLNK:
		if (va.va_mode == (mode_t)VNOVAL)
			va.va_mode = NFSV4_SYMLINK_MODE;
		error = VOP_SYMLINK(nd.ni_dvp, &vp, &nd.ni_cnd, &va,
		    __UNCONST(ca->link.ln_str));
		break;
	case VSOCK:
		if (va.va_mode == (mode_t)VNOVAL)
			va.va_mode = NFSV4_MKNOD_MODE;
		error = VOP_CREATE(nd.ni_dvp, &vp, &nd.ni_cnd, &va);
		break;
	case VBLK:
	case VCHR:
		error = kauth_authorize_system(cf->cf_cred,
		    KAUTH_SYSTEM_MKNOD, 0, NULL, NULL, NULL);
		if (error != 0) {
			VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
			break;
		}
		va.va_rdev = makedev(ca->spec1, ca->spec2);
		/* FALLTHROUGH */
	case VFIFO:
		if (va.va_mode == (mode_t)VNOVAL)
			va.va_mode = NFSV4_MKNOD_MODE;
		error = VOP_MKNOD(nd.ni_dvp, &vp, &nd.ni_cnd, &va);
		break;
	default:
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		break;
	}
	if (error == 0)
		error = nfsv4_dir_change(nd.ni_dvp, cf->cf_cred, &ci.ci_after);
	vput(nd.ni_dvp);
	pathbuf_destroy(nd.ni_pathbuf);
	if (error != 0)
		return nfsv4_errno(error);
	ci.ci_atomic = 1;

	/* What VOP_MKDIR and the rest do not take. */
	if (sva.va_uid != VNOVAL || sva.va_gid != VNOVAL ||
	    sva.va_atime.tv_sec != VNOVAL || sva.va_mtime.tv_sec != VNOVAL ||
	    sva.va_birthtime.tv_sec != VNOVAL) {
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
		error = VOP_SETATTR(vp, &sva, cf->cf_cred);
		VOP_UNLOCK(vp);
		if (error != 0) {
			vrele(vp);
			return nfsv4_errno(error);
		}
	}
	st = nfsv4_acl_set(c, vp, cf->cf_cred);
	if (st != NFS4_OK) {
		vrele(vp);
		return st;
	}

	st = nfsv4_cfh_setvp(c, cf, vp);
	if (st != NFS4_OK) {
		vrele(vp);
		return st;
	}
	return nfsv4_xdr_change_info(c->c_rx, &ci) &&
	    nfsv4_attr_put_mask(c->c_rx, set) ? NFS4_OK : NFS4ERR_RESOURCE;
}

/* RFC 7530 s16.26 */
uint32_t
nfsv4_op_remove(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_name *nm = &a->name.name;
	struct nfsv4_cfh *cf = &c->c_cur;
	struct nfsv4_change_info ci;
	struct nameidata nd;
	struct vnode *vp;
	uint32_t st;
	int error;

	st = dir_check(cf);
	if (st != NFS4_OK)
		return st;
	st = nfsv4_name_check(nm);
	/* A reclaim to come may name the file, s9.6.2. */
	if (st == NFS4_OK && nfsv4_grace_active())
		st = NFS4ERR_GRACE;
	if (st == NFS4_OK && nfsv4_open_denies_remove(cf, nm->nm_str))
		st = NFS4ERR_FILE_OPEN;
	if (st == NFS4_OK)
		st = nfsv4_deleg_break_name(cf, nm->nm_str);	/* s10.4.4 */
	if (st != NFS4_OK)
		return st;

	memset(&ci, 0, sizeof(ci));
	error = nfsv4_namei(&nd, cf->cf_vp, nm->nm_str, DELETE,
	    LOCKPARENT | LOCKLEAF, cf->cf_cred);
	if (error != 0)
		return nfsv4_errno(error);
	vp = nd.ni_vp;
	error = nfsv4_dir_change(nd.ni_dvp, cf->cf_cred, &ci.ci_before);
	if (error == 0 && (vp->v_vflag & VV_ROOT) != 0)
		error = EBUSY;
	if (error != 0) {
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		if (nd.ni_dvp == vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		vput(vp);
		pathbuf_destroy(nd.ni_pathbuf);
		return error == EBUSY ? NFS4ERR_FILE_OPEN :
		    nfsv4_errno(error);
	}
	if (vp->v_type == VDIR)
		error = VOP_RMDIR(nd.ni_dvp, vp, &nd.ni_cnd);
	else
		error = VOP_REMOVE(nd.ni_dvp, vp, &nd.ni_cnd);
	if (error == 0)
		error = nfsv4_dir_change(nd.ni_dvp, cf->cf_cred, &ci.ci_after);
	vput(nd.ni_dvp);
	pathbuf_destroy(nd.ni_pathbuf);
	if (error != 0)
		return nfsv4_errno(error);
	ci.ci_atomic = 1;
	return nfsv4_xdr_change_info(c->c_rx, &ci) ? NFS4_OK :
	    NFS4ERR_RESOURCE;
}

/* The change of an unlocked directory, for what is not atomic. */
static int
dir_change_u(const struct nfsv4_cfh *cf, uint64_t *chp)
{
	int error;

	vn_lock(cf->cf_vp, LK_SHARED | LK_RETRY);
	error = nfsv4_dir_change(cf->cf_vp, cf->cf_cred, chp);
	VOP_UNLOCK(cf->cf_vp);
	return error;
}

/*
 * RFC 7530 s16.27, in the steps of nfsrv_rename(): the source is looked
 * up, the rename lock taken, the source looked up again under it, and
 * only then the target.  change_info is not atomic: the directories
 * cannot be held still around VOP_RENAME here, which unlocks them.
 */
uint32_t
nfsv4_op_rename(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_rename *ra = &a->rename;
	struct nfsv4_cfh *sf = &c->c_saved, *tf = &c->c_cur;
	struct nfsv4_change_info sci, tci;
	struct nameidata fromnd, tond;
	struct vnode *fvp, *tvp, *tdvp;
	struct mount *mp;
	uint32_t st;
	int error;

	if (!sf->cf_set)
		return NFS4ERR_NOFILEHANDLE;
	if (sf->cf_attr != 0)
		return NFS4ERR_XDEV;		/* s5.3 */
	st = dir_check(sf);
	if (st == NFS4_OK)
		st = dir_check(tf);
	if (st == NFS4_OK)
		st = nfsv4_name_check(&ra->oldname);
	if (st == NFS4_OK)
		st = nfsv4_name_check(&ra->newname);
	if (st != NFS4_OK)
		return st;
	if (sf->cf_vp->v_mount != tf->cf_vp->v_mount)
		return NFS4ERR_XDEV;
	if (nfsv4_grace_active())
		return NFS4ERR_GRACE;		/* as for REMOVE */
	/* s10.4.4, as source and as target. */
	st = nfsv4_deleg_break_name(sf, ra->oldname.nm_str);
	if (st == NFS4_OK)
		st = nfsv4_deleg_break_name(tf, ra->newname.nm_str);
	if (st != NFS4_OK)
		return st;

	memset(&sci, 0, sizeof(sci));
	memset(&tci, 0, sizeof(tci));
	error = dir_change_u(sf, &sci.ci_before);
	if (error == 0)
		error = dir_change_u(tf, &tci.ci_before);
	if (error != 0)
		return nfsv4_errno(error);

	error = nfsv4_namei(&fromnd, sf->cf_vp, ra->oldname.nm_str, DELETE,
	    LOCKPARENT, sf->cf_cred);
	if (error != 0)
		return nfsv4_errno(error);
	mp = fromnd.ni_dvp->v_mount;
	if (fromnd.ni_dvp != fromnd.ni_vp)
		VOP_UNLOCK(fromnd.ni_dvp);
	fvp = fromnd.ni_vp;
	error = VFS_RENAMELOCK_ENTER(mp);
	if (error != 0) {
		VOP_ABORTOP(fromnd.ni_dvp, &fromnd.ni_cnd);
		vrele(fromnd.ni_dvp);
		vrele(fvp);
		goto fail;
	}
	vrele(fvp);
	vn_lock(fromnd.ni_dvp, LK_EXCLUSIVE | LK_RETRY);
	error = relookup(fromnd.ni_dvp, &fromnd.ni_vp, &fromnd.ni_cnd, 0);
	if (error != 0) {
		VOP_UNLOCK(fromnd.ni_dvp);
		VFS_RENAMELOCK_EXIT(mp);
		VOP_ABORTOP(fromnd.ni_dvp, &fromnd.ni_cnd);
		vrele(fromnd.ni_dvp);
		goto fail;
	}
	VOP_UNLOCK(fromnd.ni_vp);
	if (fromnd.ni_dvp != fromnd.ni_vp)
		VOP_UNLOCK(fromnd.ni_dvp);
	fvp = fromnd.ni_vp;

	error = nfsv4_namei(&tond, tf->cf_vp, ra->newname.nm_str, RENAME,
	    LOCKPARENT | LOCKLEAF | NOCACHE, tf->cf_cred);
	if (error != 0) {
		VFS_RENAMELOCK_EXIT(mp);
		VOP_ABORTOP(fromnd.ni_dvp, &fromnd.ni_cnd);
		vrele(fromnd.ni_dvp);
		vrele(fvp);
		goto fail;
	}
	tdvp = tond.ni_dvp;
	tvp = tond.ni_vp;

	/* s16.27.4: types that do not go together are NFS4ERR_EXIST. */
	if (tvp != NULL) {
		if ((fvp->v_type == VDIR) != (tvp->v_type == VDIR) ||
		    (tvp->v_type == VDIR && tvp->v_mountedhere != NULL))
			error = EEXIST;
	}
	if (error == 0 && fvp->v_type == VDIR &&
	    fvp->v_mountedhere != NULL)
		error = EXDEV;
	if (error == 0 && fvp == tdvp)
		error = EINVAL;		/* s16.27.5, an alias of the source */
	/* s16.27.4: the same file under both names is no work. */
	if (error == 0 && fvp == tvp)
		error = -1;

	if (error == 0) {
		error = VOP_RENAME(fromnd.ni_dvp, fromnd.ni_vp, &fromnd.ni_cnd,
		    tond.ni_dvp, tond.ni_vp, &tond.ni_cnd);
		VFS_RENAMELOCK_EXIT(mp);
		if (error == ENOTEMPTY)
			error = EEXIST;		/* s16.27.4 */
	} else {
		VOP_ABORTOP(tond.ni_dvp, &tond.ni_cnd);
		if (tdvp == tvp)
			vrele(tdvp);
		else
			vput(tdvp);
		if (tvp != NULL)
			vput(tvp);
		VFS_RENAMELOCK_EXIT(mp);
		VOP_ABORTOP(fromnd.ni_dvp, &fromnd.ni_cnd);
		vrele(fromnd.ni_dvp);
		vrele(fvp);
		if (error == -1)
			error = 0;
	}
	pathbuf_destroy(tond.ni_pathbuf);
fail:
	pathbuf_destroy(fromnd.ni_pathbuf);
	if (error != 0)
		return nfsv4_errno(error);

	if (dir_change_u(sf, &sci.ci_after) != 0 ||
	    dir_change_u(tf, &tci.ci_after) != 0)
		return NFS4ERR_SERVERFAULT;
	return nfsv4_xdr_change_info(c->c_rx, &sci) &&
	    nfsv4_xdr_change_info(c->c_rx, &tci) ? NFS4_OK : NFS4ERR_RESOURCE;
}

/* RFC 7530 s16.9: the saved handle gets a new name in the current one. */
uint32_t
nfsv4_op_link(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_name *nm = &a->name.name;
	struct nfsv4_cfh *sf = &c->c_saved, *cf = &c->c_cur;
	struct nfsv4_change_info ci;
	struct nameidata nd;
	struct vnode *vp;
	uint32_t st;
	int error;

	if (!sf->cf_set)
		return NFS4ERR_NOFILEHANDLE;
	if (sf->cf_vp == NULL || sf->cf_vp->v_type == VDIR)
		return NFS4ERR_ISDIR;
	if (sf->cf_attr != 0)
		return NFS4ERR_XDEV;		/* s5.3 */
	st = dir_check(cf);
	if (st == NFS4_OK)
		st = nfsv4_name_check(nm);
	if (st != NFS4_OK)
		return st;
	vp = sf->cf_vp;
	if (vp->v_mount != cf->cf_vp->v_mount)
		return NFS4ERR_XDEV;
	/* numlinks would change under the client; s10.4.4 lets it be asked. */
	st = nfsv4_deleg_break(vp, NULL, 0, NFSV4_DC_WRITE);
	if (st != NFS4_OK)
		return st;

	memset(&ci, 0, sizeof(ci));
	error = nfsv4_namei(&nd, cf->cf_vp, nm->nm_str, CREATE, LOCKPARENT,
	    cf->cf_cred);
	if (error != 0)
		return nfsv4_errno(error);
	if (nd.ni_vp != NULL)
		error = EEXIST;
	if (error == 0)
		error = nfsv4_dir_change(nd.ni_dvp, cf->cf_cred,
		    &ci.ci_before);
	if (error != 0) {
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		if (nd.ni_dvp == nd.ni_vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		if (nd.ni_vp != NULL)
			vrele(nd.ni_vp);
		pathbuf_destroy(nd.ni_pathbuf);
		return nfsv4_errno(error);
	}
	error = VOP_LINK(nd.ni_dvp, vp, &nd.ni_cnd);
	if (error == 0)
		error = nfsv4_dir_change(nd.ni_dvp, cf->cf_cred, &ci.ci_after);
	VOP_UNLOCK(nd.ni_dvp);
	vrele(nd.ni_dvp);
	pathbuf_destroy(nd.ni_pathbuf);
	if (error != 0)
		return nfsv4_errno(error);
	ci.ci_atomic = 1;
	return nfsv4_xdr_change_info(c->c_rx, &ci) ? NFS4_OK :
	    NFS4ERR_RESOURCE;
}

/*
 * RFC 7530 s16.32.  attrsset follows the status whatever it is.  The
 * attributes go to one VOP_SETATTR, so they are all set or none is, but
 * for the ACL, which comes after it and may fail alone.
 */
uint32_t
nfsv4_op_setattr(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_setattr *sa = &a->setattr;
	struct nfsv4_cfh *cf = &c->c_cur;
	struct vnode *vp = cf->cf_vp;
	struct vattr va;
	uint64_t set = 0;
	uint32_t st;
	int error;

	st = nfsv4_attr_parse(c, &sa->attrs, &va, &set);
	if (st == NFS4_OK && vp == NULL)
		st = NFS4ERR_ROFS;		/* s7.3 */
	if (st == NFS4_OK && (cf->cf_exflags & MNT_EXRDONLY) != 0)
		st = NFS4ERR_ROFS;
	if (st == NFS4_OK && (set & (1ULL << FATTR4_SIZE)) != 0) {
		if (vp->v_type == VDIR)
			st = NFS4ERR_ISDIR;
		else if (vp->v_type != VREG)
			st = NFS4ERR_INVAL;
		else
			st = nfsv4_io_check(c, &sa->stateid, true);
	}
	/* s10.4.4 */
	if (st == NFS4_OK)
		st = nfsv4_deleg_break(vp, NULL, c->c_rq->rq_connid,
		    NFSV4_DC_WRITE);
	if (st == NFS4_OK) {
		if ((set & ~(1ULL << FATTR4_ACL)) != 0) {
			vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
			error = VOP_SETATTR(vp, &va, cf->cf_cred);
			VOP_UNLOCK(vp);
			st = nfsv4_errno(error);
		}
		if (st != NFS4_OK)
			set = 0;
		else {
			st = nfsv4_acl_set(c, vp, cf->cf_cred);
			if (st != NFS4_OK)
				set &= ~(1ULL << FATTR4_ACL);
		}
	} else
		set = 0;
	if (!nfsv4_attr_put_mask(c->c_rx, set))
		return NFS4ERR_RESOURCE;
	return st;
}

/*
 * Compare the attributes given with those of the current handle, as
 * they would be encoded: same order, same form.  An object's attributes
 * are few enough for one buffer.
 */
static uint32_t
verify_same(struct nfsv4_compound *c, const struct nfsv4_fattr *fa, bool *same)
{
	struct nfsv4_bitmap got;
	char *mine, *theirs;
	u_int len, end, i;
	uint32_t st;

	/* s16.35.5 */
	if (fa->fa_mask.bm_more)
		return NFS4ERR_ATTRNOTSUPP;
	if (!nfsv4_attr_getonly_ok(&fa->fa_mask) ||
	    (fa->fa_mask.bm_n > 0 &&
	    (fa->fa_mask.bm_w[0] & (1U << FATTR4_RDATTR_ERROR)) != 0))
		return NFS4ERR_INVAL;
	if (!nfsv4_attr_supported(&fa->fa_mask, c->c_cur.cf_vp))
		return NFS4ERR_ATTRNOTSUPP;

	mine = kmem_alloc(NFSV4_ATTRBUF, KM_SLEEP);
	st = nfsv4_attr_fill(c, &c->c_cur, &fa->fa_mask, NFS4_OK, mine,
	    NFSV4_ATTRBUF, &got, &len);
	if (st != NFS4_OK)
		goto out;
	*same = false;
	if (len != fa->fa_len)
		goto out;
	theirs = kmem_alloc(NFSV4_ATTRBUF, KM_SLEEP);
	end = XDR_GETPOS(c->c_ax);
	if (!XDR_SETPOS(c->c_ax, fa->fa_pos) ||
	    !XDR_GETBYTES(c->c_ax, theirs, len) ||
	    !XDR_SETPOS(c->c_ax, end))
		st = NFS4ERR_BADXDR;
	else {
		*same = true;
		for (i = 0; i < len; i++) {
			if (mine[i] != theirs[i])
				*same = false;
		}
	}
	kmem_free(theirs, NFSV4_ATTRBUF);
out:
	kmem_free(mine, NFSV4_ATTRBUF);
	return st;
}

uint32_t
nfsv4_op_verify(struct nfsv4_compound *c, union nfsv4_args *a)
{
	uint32_t st;
	bool same;

	st = verify_same(c, &a->verify.attrs, &same);
	if (st != NFS4_OK)
		return st;
	return same ? NFS4_OK : NFS4ERR_NOT_SAME;
}

uint32_t
nfsv4_op_nverify(struct nfsv4_compound *c, union nfsv4_args *a)
{
	uint32_t st;
	bool same;

	st = verify_same(c, &a->verify.attrs, &same);
	if (st != NFS4_OK)
		return st;
	return same ? NFS4ERR_SAME : NFS4_OK;
}
