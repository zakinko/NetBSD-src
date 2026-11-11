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
 * Named attributes over NFS versions 2 and 3, under option
 * NFSSERVER_ONCRPC, as illumos serves them: GETXATTRDIR of NFSACL
 * (nfs_acl.c) gives a handle of the attribute directory of a file, and
 * the client walks it with the procedures of NFS itself.  The client is
 * illumos' (usr/src/uts/common/fs/nfs/nfs3_vnops.c:1945-1970 and
 * nfs_acl_vnops.c:618-680 at 586678ac1bc); the attributes are those of
 * version 4, through nfsxattr (nfs_xattr.c).
 *
 * The VFS has no vnode for them, so a handle here is the file's with a
 * mark after the file system's part, FHANDLE_SIZE() bytes, which is all
 * that VFS_FHTOVP() reads:
 *
 *	version 3	a byte, NFS_XATTR_DIR or NFS_XATTR_FILE, then for a
 *			file XA_KEY3 bytes of key, then zeros to a multiple
 *			of four: nfsm_srvmtofh() takes the handle without
 *			the padding of XDR, as nfsrv_composefh() makes no
 *			other kind
 *	version 2	the last four bytes of the 32, where the file's part
 *			is 28 bytes: 0 for none, as nfsrv_composefh() pads,
 *			0xffffffff for the directory, otherwise the key of
 *			four bytes, which nfs_xattr_key() keeps from both
 *
 * A file system whose part is longer has no room in version 2, and
 * GETXATTRDIR says so.  The name is found again among the file's by its
 * key, as version 4 does; two names of one key are refused by
 * nfs_xattr_byhash() and never made here.  With 32 bits, a file of 100
 * attributes has two of one key once in about a million.
 *
 * nfs_oncrpc_dispatch() sends a call whose first handle is marked to
 * nfsrv_xattr_procs[] in place of nfsrv3_procs[], and nfsrv_fhtovp()
 * refuses a marked handle, so that one that strays is never taken for
 * the file.  What is here takes the mark off before it.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#ifdef _KERNEL_OPT
#include "opt_nfs_oncrpc.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kauth.h>
#include <sys/kmem.h>
#include <sys/mbuf.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/unistd.h>
#include <sys/vnode.h>

#include <nfs/nfsproto.h>
#include <nfs/rpcv2.h>
#include <nfs/nfs.h>
#include <nfs/xdr_subs.h>
#include <nfs/nfsm_subs.h>
#include <nfs/nfs_var.h>
#include <nfs/nfs_xattr.h>

/* As version 4's, NFSV4_ANAME_HASH of fs/nfsv4/nfsv4_var.h. */
#define	XA_KEY3		16
#define	XA_KEY2		4
#define	XA_V2MARK	(NFSX_V2FH - XA_KEY2)
#define	XA_V2DIR	0xffffffffU

extern u_int32_t nfs_xdrneg1;
extern u_int32_t nfs_false, nfs_true;
extern struct nfsstats nfsstats;

/* The file system's part of a handle. */
static size_t
xa_base(const nfsrvfh_t *nsfh)
{

	return FHANDLE_SIZE(NFSRVFH_FHANDLE(nsfh));
}

/*
 * What a handle is marked: 0 for nothing, NFS_XATTR_DIR, NFS_XATTR_FILE
 * with its key, or -1 for a mark that is not one of these.
 */
int
nfsrv_xattr_marked(const nfsrvfh_t *nsfh, bool v3, uint8_t *key,
    size_t *keylenp)
{
	const uint8_t *d = NFSRVFH_DATA(nsfh);
	size_t size = NFSRVFH_SIZE(nsfh), base, need, i;
	uint32_t v;
	int kind;

	if (size < FHANDLE_SIZE_MIN)
		return 0;
	base = xa_base(nsfh);
	if (!v3) {
		if (base > XA_V2MARK)
			return 0;
		v = be32dec(d + XA_V2MARK);
		if (v == 0)
			return 0;
		if (v == XA_V2DIR)
			return NFS_XATTR_DIR;
		if (key != NULL) {
			memcpy(key, d + XA_V2MARK, XA_KEY2);
			*keylenp = XA_KEY2;
		}
		return NFS_XATTR_FILE;
	}
	if (size <= base)
		return 0;
	kind = d[base];
	if (kind == NFS_XATTR_DIR)
		need = roundup(base + 1, NFSX_UNSIGNED);
	else if (kind == NFS_XATTR_FILE)
		need = roundup(base + 1 + XA_KEY3, NFSX_UNSIGNED);
	else
		return -1;
	if (size != need)
		return -1;
	i = base + 1 + (kind == NFS_XATTR_FILE ? XA_KEY3 : 0);
	for (; i < size; i++)
		if (d[i] != 0)
			return -1;
	if (kind == NFS_XATTR_FILE && key != NULL) {
		memcpy(key, d + base + 1, XA_KEY3);
		*keylenp = XA_KEY3;
	}
	return kind;
}

/* The handle of the node kind (name) of the file of nsfh, unmarked. */
int
nfsrv_xattr_mkfh(const nfsrvfh_t *nsfh, bool v3, int kind, const char *name,
    nfsrvfh_t *out)
{
	uint8_t *d = NFSRVFH_DATA(out);
	uint8_t key[XA_KEY3];
	size_t base, need;

	nfsrv_copyfh(out, nsfh);
	base = xa_base(out);
	if (!v3) {
		if (base > XA_V2MARK)
			return EOPNOTSUPP;
		if (kind == NFS_XATTR_DIR)
			be32enc(d + XA_V2MARK, XA_V2DIR);
		else
			nfs_xattr_key(name, strlen(name), d + XA_V2MARK,
			    XA_KEY2);
		return 0;
	}
	if (kind == NFS_XATTR_FILE)
		nfs_xattr_key(name, strlen(name), key, XA_KEY3);
	need = roundup(base + 1 + (kind == NFS_XATTR_FILE ? XA_KEY3 : 0),
	    NFSX_UNSIGNED);
	if (need > NFSX_V3FHMAX)
		return EOPNOTSUPP;
	memset(d + base, 0, need - base);
	d[base] = kind;
	if (kind == NFS_XATTR_FILE)
		memcpy(d + base + 1, key, XA_KEY3);
	out->nsfh_size = need;
	return 0;
}

/* A node: the file it is of, and what of it. */
struct xa_node {
	struct vnode	*xn_vp;		/* referenced, unlocked */
	int		 xn_kind;
	int		 xn_rdonly;
	char		 xn_name[NFS_XATTR_NAMEMAX + 1];
	nfsrvfh_t	 xn_fh;		/* of the file, unmarked */
};

/*
 * The file of a marked handle, referenced and unlocked, with the checks
 * of nfsrv_fhtovp() on its own handle, which goes to filefh if not
 * NULL; *kindp and name[NFS_XATTR_NAMEMAX + 1] say which node.  An
 * attribute that is no longer there is ESTALE.  NFSACL comes here too.
 */
int
nfsrv_xattr_fhtovp(const nfsrvfh_t *nsfh, bool v3, kauth_cred_t cred,
    struct nfssvc_sock *slp, struct mbuf *nam, int kerbflag,
    struct vnode **vpp, int *kindp, char *name, int *rdonlyp,
    nfsrvfh_t *filefh)
{
	nfsrvfh_t fh;
	uint8_t key[XA_KEY3];
	size_t keylen = 0;
	int error;

	*vpp = NULL;
	name[0] = '\0';
	*kindp = nfsrv_xattr_marked(nsfh, v3, key, &keylen);
	if (*kindp <= 0)
		return ESTALE;
	nfsrv_copyfh(&fh, nsfh);
	if (v3)
		fh.nsfh_size = xa_base(nsfh);
	else
		memset(NFSRVFH_DATA(&fh) + XA_V2MARK, 0, XA_KEY2);
	error = nfsrv_fhtovp(&fh, 1, vpp, cred, slp, nam, rdonlyp, kerbflag,
	    false);
	if (error != 0)
		return error;
	VOP_UNLOCK(*vpp);
	if (*kindp == NFS_XATTR_FILE) {
		error = nfs_xattr_byhash(*vpp, cred, key, keylen, name);
		if (error != 0) {
			vrele(*vpp);
			*vpp = NULL;
			return error;
		}
	}
	if (filefh != NULL)
		nfsrv_copyfh(filefh, &fh);
	return 0;
}

static int
xa_get(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
    const nfsrvfh_t *nsfh, struct xa_node *xn)
{

	return nfsrv_xattr_fhtovp(nsfh, (nfsd->nd_flag & ND_NFSV3) != 0,
	    nfsd->nd_cr, slp, nfsd->nd_nam, nfsd->nd_flag & ND_KERBAUTH,
	    &xn->xn_vp, &xn->xn_kind, xn->xn_name, &xn->xn_rdonly,
	    &xn->xn_fh);
}

static void
xa_put(struct xa_node *xn)
{

	if (xn->xn_vp != NULL)
		vrele(xn->xn_vp);
	xn->xn_vp = NULL;
}

static int
xa_errno(int error)
{

	return error == ENOATTR ? ENOENT : error;
}

/* nfsrv_access() of the file, which says who may touch its attributes. */
static int
xa_access(struct xa_node *xn, int mode, kauth_cred_t cred, struct lwp *l)
{
	int error;

	vn_lock(xn->xn_vp, LK_SHARED | LK_RETRY);
	error = nfsrv_access(xn->xn_vp, mode, cred, xn->xn_rdonly, l, 0);
	VOP_UNLOCK(xn->xn_vp);
	return error;
}

/*
 * A name of the call, filename3 or filename, into
 * name[NFS_XATTR_NAMEMAX + 1].  One too long is skipped and
 * ENAMETOOLONG, so that what follows it is still read; one that
 * nfs_namei() refuses with EACCES, with a '/' or a NUL, is refused
 * alike.  EBADRPC is a call that ends early.
 */
static int
xa_name(struct mbuf **mdp, char **dposp, char *name)
{
	struct iovec iov;
	struct uio uio;
	uint32_t len;
	int error;

	iov.iov_base = &len;
	iov.iov_len = sizeof(len);
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = 0;
	uio.uio_resid = sizeof(len);
	uio.uio_rw = UIO_READ;
	UIO_SETUP_SYSSPACE(&uio);
	if (nfsm_mbuftouio(mdp, &uio, sizeof(len), dposp) != 0)
		return EBADRPC;
	len = fxdr_unsigned(uint32_t, len);
	if (len > NFS_XATTR_NAMEMAX) {
		if (len > NFS_MAXDATA || nfs_adv(mdp, dposp, nfsm_rndup(len),
		    mtod(*mdp, char *) + (*mdp)->m_len - *dposp) != 0)
			return EBADRPC;
		return ENAMETOOLONG;
	}
	iov.iov_base = name;
	iov.iov_len = len;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = 0;
	uio.uio_resid = len;
	UIO_SETUP_SYSSPACE(&uio);
	if (len != 0 && nfsm_mbuftouio(mdp, &uio, len, dposp) != 0)
		return EBADRPC;
	if (nfsm_padlen(len) != 0) {
		error = nfs_adv(mdp, dposp, nfsm_padlen(len),
		    mtod(*mdp, char *) + (*mdp)->m_len - *dposp);
		if (error != 0)
			return EBADRPC;
	}
	name[len] = '\0';
	if (len == 0 || strlen(name) != len || strchr(name, '/') != NULL)
		return EACCES;
	return 0;
}

/* The verifier of WRITE and COMMIT, the boot time as nfsrv_write(). */
static void
xa_verf(u_int32_t *tl)
{
	struct timeval btv;

	getmicroboottime(&btv);
	*tl++ = txdr_unsigned(btv.tv_sec);
	*tl = txdr_unsigned(btv.tv_usec);
}

/*
 * The locals of nfsm_subs.h, as each procedure of nfs_serv.c has them.
 */
#define	XA_LOCALS							\
	struct mbuf *mrep = nfsd->nd_mrep, *md = nfsd->nd_md;		\
	char *dpos = nfsd->nd_dpos;					\
	kauth_cred_t cred __unused = nfsd->nd_cr;			\
	u_int32_t *tl;							\
	int32_t t1;							\
	char *bpos, *cp2;						\
	int error = 0, cache = 0;					\
	struct mbuf *mb, *mreq __unused;				\
	u_quad_t frev;							\
	bool v3 __unused = (nfsd->nd_flag & ND_NFSV3) != 0

static int
xa_getattr(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
    struct lwp *lwp, struct mbuf **mrq)
{
	XA_LOCALS;
	struct nfs_fattr *fp;
	struct xa_node xn;
	struct vattr va;
	nfsrvfh_t nsfh;

	nfsm_srvmtofh(&nsfh);
	error = xa_get(nfsd, slp, &nsfh, &xn);
	if (error == 0)
		error = nfs_xattr_vattr(xn.xn_vp, cred, xn.xn_kind,
		    xn.xn_name, &va);
	xa_put(&xn);
	nfsm_reply(NFSX_FATTR(v3));
	if (error)
		return 0;
	nfsm_build(fp, struct nfs_fattr *, NFSX_FATTR(v3));
	nfsm_srvfillattr(&va, fp);
	nfsm_srvdone;
}

/*
 * Of an attribute only the size can be set, as version 4's
 * xa_op_setattr(); the rest has nowhere to be kept, and asking for it is
 * EINVAL.  The directory has nothing to set: EISDIR, as there.
 */
static int
xa_setattr(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
    struct lwp *lwp, struct mbuf **mrq)
{
	XA_LOCALS;
	struct nfsv2_sattr *sp;
	struct nfs_fattr *fp;
	struct xa_node xn;
	struct vattr va, sa, preat;
	struct timespec guard;
	nfsrvfh_t nsfh;
	int gcheck = 0, preat_ret = 1, postat_ret = 1;

	timespecclear(&guard);
	nfsm_srvmtofh(&nsfh);
	vattr_null(&sa);
	if (v3) {
		nfsm_srvsattr(&sa);
		nfsm_dissect(tl, u_int32_t *, NFSX_UNSIGNED);
		gcheck = fxdr_unsigned(int, *tl);
		if (gcheck) {
			nfsm_dissect(tl, u_int32_t *, 2 * NFSX_UNSIGNED);
			fxdr_nfsv3time(tl, &guard);
		}
	} else {
		nfsm_dissect(sp, struct nfsv2_sattr *, NFSX_V2SATTR);
		/* The Sun client's 0xffff, as nfsrv_setattr(). */
		if ((fxdr_unsigned(int, sp->sa_mode) & 0xffff) != 0xffff)
			sa.va_mode = nfstov_mode(sp->sa_mode);
		if (sp->sa_uid != nfs_xdrneg1)
			sa.va_uid = fxdr_unsigned(uid_t, sp->sa_uid);
		if (sp->sa_gid != nfs_xdrneg1)
			sa.va_gid = fxdr_unsigned(gid_t, sp->sa_gid);
		if (sp->sa_size != nfs_xdrneg1)
			sa.va_size = fxdr_unsigned(u_quad_t, sp->sa_size);
		if (sp->sa_atime.nfsv2_sec != nfs_xdrneg1)
			sa.va_atime.tv_sec = 0;
		if (sp->sa_mtime.nfsv2_sec != nfs_xdrneg1)
			sa.va_mtime.tv_sec = 0;
	}
	error = xa_get(nfsd, slp, &nsfh, &xn);
	if (error == 0)
		error = preat_ret = nfs_xattr_vattr(xn.xn_vp, cred,
		    xn.xn_kind, xn.xn_name, &preat);
	if (error == 0 && gcheck && timespeccmp(&preat.va_ctime, &guard, !=))
		error = NFSERR_NOT_SYNC;
	if (error == 0 && xn.xn_kind == NFS_XATTR_DIR)
		error = EISDIR;
	if (error == 0 && (sa.va_mode != (mode_t)VNOVAL ||
	    sa.va_uid != (uid_t)VNOVAL || sa.va_gid != (gid_t)VNOVAL ||
	    sa.va_atime.tv_sec != VNOVAL || sa.va_mtime.tv_sec != VNOVAL))
		error = EINVAL;
	if (error == 0 && sa.va_size != VNOVAL) {
		error = xa_access(&xn, VWRITE, cred, lwp);
		if (error == 0)
			error = xa_errno(nfs_xattr_write(xn.xn_vp, cred,
			    xn.xn_name, sa.va_size, NULL, 0, true));
	}
	if (xn.xn_vp != NULL)
		postat_ret = nfs_xattr_vattr(xn.xn_vp, cred, xn.xn_kind,
		    xn.xn_name, &va);
	xa_put(&xn);
	nfsm_reply(NFSX_WCCORFATTR(v3));
	if (v3) {
		nfsm_srvwcc_data(preat_ret, &preat, postat_ret, &va);
		return 0;
	}
	nfsm_build(fp, struct nfs_fattr *, NFSX_V2FATTR);
	nfsm_srvfillattr(&va, fp);
	nfsm_srvdone;
}

/* In the directory: an attribute, "." itself, ".." the file. */
static int
xa_lookup(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
    struct lwp *lwp, struct mbuf **mrq)
{
	XA_LOCALS;
	char name[NFS_XATTR_NAMEMAX + 1];
	struct nfs_fattr *fp;
	struct xa_node xn;
	struct vattr va, dirattr;
	nfsrvfh_t nsfh, fh;
	uint64_t size;
	char *cp;
	int kind = 0, dirattr_ret = 1;

	fh.nsfh_size = 0;
	nfsm_srvmtofh(&nsfh);
	error = xa_name(&md, &dpos, name);
	if (error == EBADRPC) {
		m_freem(mrep);
		return error;
	}
	if (error == 0)
		error = xa_get(nfsd, slp, &nsfh, &xn);
	else
		xn.xn_vp = NULL;
	if (error == 0) {
		dirattr_ret = nfs_xattr_vattr(xn.xn_vp, cred, NFS_XATTR_DIR,
		    "", &dirattr);
		if (xn.xn_kind != NFS_XATTR_DIR)
			error = ENOTDIR;
	}
	if (error == 0) {
		if (strcmp(name, ".") == 0)
			kind = NFS_XATTR_DIR;
		else if (strcmp(name, "..") == 0)
			kind = 0;
		else {
			kind = NFS_XATTR_FILE;
			error = xa_errno(nfs_xattr_size(xn.xn_vp, cred, name,
			    &size));
		}
	}
	if (error == 0) {
		if (kind == 0) {
			nfsrv_copyfh(&fh, &xn.xn_fh);
			vn_lock(xn.xn_vp, LK_SHARED | LK_RETRY);
			error = VOP_GETATTR(xn.xn_vp, &va, cred);
			VOP_UNLOCK(xn.xn_vp);
		} else {
			error = nfsrv_xattr_mkfh(&xn.xn_fh, v3, kind, name,
			    &fh);
			if (error == 0)
				error = nfs_xattr_vattr(xn.xn_vp, cred, kind,
				    name, &va);
		}
	}
	xa_put(&xn);
	nfsm_reply(NFSX_SRVFH(&fh, v3) + NFSX_POSTOPORFATTR(v3) +
	    NFSX_POSTOPATTR(v3));
	if (error) {
		nfsm_srvpostop_attr(dirattr_ret, &dirattr);
		return 0;
	}
	nfsm_srvfhtom(&fh, v3);
	if (v3) {
		nfsm_srvpostop_attr(0, &va);
		nfsm_srvpostop_attr(dirattr_ret, &dirattr);
	} else {
		nfsm_build(fp, struct nfs_fattr *, NFSX_V2FATTR);
		nfsm_srvfillattr(&va, fp);
	}
	nfsm_srvdone;
}

/*
 * Reading the list or an attribute is the file system's to allow, by
 * VREAD of the file; changing either, by VWRITE.  Nothing executes.
 */
static int
xa_access3(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
    struct lwp *lwp, struct mbuf **mrq)
{
	XA_LOCALS;
	struct xa_node xn;
	struct vattr va;
	nfsrvfh_t nsfh;
	uint32_t want, got = 0;
	int getret = 1;

	nfsm_srvmtofh(&nsfh);
	nfsm_dissect(tl, u_int32_t *, NFSX_UNSIGNED);
	want = fxdr_unsigned(uint32_t, *tl);
	error = xa_get(nfsd, slp, &nsfh, &xn);
	if (error == 0) {
		if ((want & (NFSV3ACCESS_READ | NFSV3ACCESS_LOOKUP)) &&
		    xa_access(&xn, VREAD, cred, lwp) == 0)
			got |= want & (xn.xn_kind == NFS_XATTR_DIR ?
			    NFSV3ACCESS_READ | NFSV3ACCESS_LOOKUP :
			    NFSV3ACCESS_READ);
		if ((want & (NFSV3ACCESS_MODIFY | NFSV3ACCESS_EXTEND |
		    NFSV3ACCESS_DELETE)) && xa_access(&xn, VWRITE, cred,
		    lwp) == 0)
			got |= want & (xn.xn_kind == NFS_XATTR_DIR ?
			    NFSV3ACCESS_MODIFY | NFSV3ACCESS_EXTEND |
			    NFSV3ACCESS_DELETE :
			    NFSV3ACCESS_MODIFY | NFSV3ACCESS_EXTEND);
		getret = nfs_xattr_vattr(xn.xn_vp, cred, xn.xn_kind,
		    xn.xn_name, &va);
	}
	xa_put(&xn);
	nfsm_reply(NFSX_POSTOPATTR(1) + NFSX_UNSIGNED);
	nfsm_srvpostop_attr(getret, &va);
	if (error)
		return 0;
	nfsm_build(tl, u_int32_t *, NFSX_UNSIGNED);
	*tl = txdr_unsigned(got);
	nfsm_srvdone;
}

/* The directory is EINVAL in version 3, EISDIR in 2, as nfsrv_read(). */
static int
xa_read(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
    struct lwp *lwp, struct mbuf **mrq)
{
	XA_LOCALS;
	struct nfs_fattr *fp;
	struct xa_node xn;
	struct vattr va;
	nfsrvfh_t nsfh;
	char *buf = NULL;
	uint64_t off, size = 0;
	size_t len = 0, got = 0;
	uint32_t reqlen;
	int32_t t2;
	int getret = 1;

	nfsm_srvmtofh(&nsfh);
	if (v3) {
		nfsm_dissect(tl, u_int32_t *, 2 * NFSX_UNSIGNED);
		off = fxdr_hyper(tl);
	} else {
		nfsm_dissect(tl, u_int32_t *, NFSX_UNSIGNED);
		off = fxdr_unsigned(u_int32_t, *tl);
	}
	nfsm_dissect(tl, uint32_t *, NFSX_UNSIGNED);
	reqlen = fxdr_unsigned(uint32_t, *tl);
	len = MIN(MIN(reqlen, NFS_SRVMAXDATA(nfsd)), NFS_XATTR_MAXSIZE);
	error = xa_get(nfsd, slp, &nsfh, &xn);
	if (error == 0 && xn.xn_kind == NFS_XATTR_DIR)
		error = v3 ? EINVAL : EISDIR;
	if (error == 0) {
		buf = kmem_alloc(MAX(len, 1), KM_SLEEP);
		error = xa_errno(nfs_xattr_read(xn.xn_vp, cred, xn.xn_name,
		    off, buf, len, &got, &size));
	}
	if (xn.xn_vp != NULL)
		getret = nfs_xattr_vattr(xn.xn_vp, cred, xn.xn_kind,
		    xn.xn_name, &va);
	xa_put(&xn);
	nfsm_reply(NFSX_POSTOPORFATTR(v3) + 3 * NFSX_UNSIGNED);
	if (error) {
		nfsm_srvpostop_attr(getret, &va);
		goto out;
	}
	if (v3) {
		nfsm_srvpostop_attr(getret, &va);
		nfsm_build(tl, u_int32_t *, 2 * NFSX_UNSIGNED);
		*tl++ = txdr_unsigned(got);
		*tl = off + got >= size ? nfs_true : nfs_false;
	} else {
		nfsm_build(fp, struct nfs_fattr *, NFSX_V2FATTR);
		nfsm_srvfillattr(&va, fp);
	}
	nfsm_strtom(buf, got, got);
out:
	error = 0;
nfsmout:
	if (buf != NULL)
		kmem_free(buf, MAX(len, 1));
	return error;
}

/* Written through to the file system: FILE_SYNC. */
static int
xa_write(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
    struct lwp *lwp, struct mbuf **mrq)
{
	XA_LOCALS;
	struct nfs_fattr *fp;
	struct xa_node xn;
	struct vattr va, forat;
	struct iovec iov;
	struct uio uio;
	nfsrvfh_t nsfh;
	char *buf = NULL;
	uint64_t off;
	int32_t len;
	int forat_ret = 1, aftat_ret = 1;

	xn.xn_vp = NULL;
	nfsm_srvmtofh(&nsfh);
	if (v3) {
		nfsm_dissect(tl, u_int32_t *, 5 * NFSX_UNSIGNED);
		off = fxdr_hyper(tl);
		tl += 4;
	} else {
		nfsm_dissect(tl, u_int32_t *, 4 * NFSX_UNSIGNED);
		off = fxdr_unsigned(u_int32_t, *++tl);
		tl += 2;
	}
	len = (int32_t)fxdr_unsigned(uint32_t, *tl);
	if (len < 0 || len > NFS_MAXDATA)
		error = EIO;
	else if (len > NFS_XATTR_MAXSIZE)
		error = EFBIG;
	else if (len > 0) {
		buf = kmem_alloc(len, KM_SLEEP);
		iov.iov_base = buf;
		iov.iov_len = len;
		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_offset = 0;
		uio.uio_resid = len;
		uio.uio_rw = UIO_READ;
		UIO_SETUP_SYSSPACE(&uio);
		error = nfsm_mbuftouio(&md, &uio, len, &dpos);
		if (error != 0)
			error = EIO;
	}
	if (error == 0)
		error = xa_get(nfsd, slp, &nsfh, &xn);
	if (error == 0 && xn.xn_kind == NFS_XATTR_DIR)
		error = v3 ? EINVAL : EISDIR;
	if (error == 0)
		error = forat_ret = nfs_xattr_vattr(xn.xn_vp, cred, xn.xn_kind,
		    xn.xn_name, &forat);
	if (error == 0)
		error = xa_access(&xn, VWRITE, cred, lwp);
	if (error == 0 && len > 0)
		error = xa_errno(nfs_xattr_write(xn.xn_vp, cred, xn.xn_name,
		    off, buf, len, false));
	if (xn.xn_vp != NULL)
		aftat_ret = nfs_xattr_vattr(xn.xn_vp, cred, xn.xn_kind,
		    xn.xn_name, &va);
	xa_put(&xn);
	if (buf != NULL)
		kmem_free(buf, len);
	nfsm_reply(NFSX_PREOPATTR(v3) + NFSX_POSTOPORFATTR(v3) +
	    2 * NFSX_UNSIGNED + NFSX_WRITEVERF(v3));
	if (v3) {
		nfsm_srvwcc_data(forat_ret, &forat, aftat_ret, &va);
		if (error)
			return 0;
		nfsm_build(tl, u_int32_t *, 4 * NFSX_UNSIGNED);
		*tl++ = txdr_unsigned(len);
		*tl++ = txdr_unsigned(NFSV3WRITE_FILESYNC);
		xa_verf(tl);
	} else {
		nfsm_build(fp, struct nfs_fattr *, NFSX_V2FATTR);
		nfsm_srvfillattr(&va, fp);
	}
	nfsm_srvdone;
}

/*
 * An empty attribute, or with a size asked for one of that size.
 * EXCLUSIVE has nowhere to keep its verifier, so it is GUARDED: a
 * retransmission after the reply is lost then finds EEXIST, where the
 * reply cache does not have the call.  The other attributes asked for
 * have nowhere to be kept either, and are left, as illumos'
 * xattr_dir_create() leaves them for a file system without a directory
 * of its own (usr/src/uts/common/fs/xattr.c:1201-1243).
 */
static int
xa_create(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
    struct lwp *lwp, struct mbuf **mrq)
{
	XA_LOCALS;
	char name[NFS_XATTR_NAMEMAX + 1];
	struct nfsv2_sattr *sp;
	struct nfs_fattr *fp;
	struct xa_node xn;
	struct vattr va, sa, dirfor, diraft;
	nfsrvfh_t nsfh, fh;
	char *cp;
	int how = NFSV3CREATE_UNCHECKED, dirfor_ret = 1, diraft_ret = 1;
	int32_t tsize;

	xn.xn_vp = NULL;
	fh.nsfh_size = 0;
	nfsm_srvmtofh(&nsfh);
	error = xa_name(&md, &dpos, name);
	if (error == EBADRPC) {
		m_freem(mrep);
		return error;
	}
	vattr_null(&sa);
	if (v3) {
		nfsm_dissect(tl, u_int32_t *, NFSX_UNSIGNED);
		how = fxdr_unsigned(int, *tl);
		switch (how) {
		case NFSV3CREATE_UNCHECKED:
		case NFSV3CREATE_GUARDED:
			nfsm_srvsattr(&sa);
			break;
		case NFSV3CREATE_EXCLUSIVE:
			nfsm_dissect(cp2, char *, NFSX_V3CREATEVERF);
			how = NFSV3CREATE_GUARDED;
			break;
		default:
			error = EBADRPC;
			m_freem(mrep);
			goto nfsmout;
		}
	} else {
		nfsm_dissect(sp, struct nfsv2_sattr *, NFSX_V2SATTR);
		tsize = fxdr_unsigned(int32_t, sp->sa_size);
		if (tsize != -1)
			sa.va_size = (u_quad_t)tsize;
	}
	if (error == 0)
		error = xa_get(nfsd, slp, &nsfh, &xn);
	if (error == 0 && xn.xn_kind != NFS_XATTR_DIR)
		error = ENOTDIR;
	if (error == 0)
		dirfor_ret = nfs_xattr_vattr(xn.xn_vp, cred, NFS_XATTR_DIR, "",
		    &dirfor);
	if (error == 0)
		error = xa_access(&xn, VWRITE, cred, lwp);
	if (error == 0)
		error = nfs_xattr_unique(xn.xn_vp, cred, name,
		    v3 ? XA_KEY3 : XA_KEY2);
	if (error == 0)
		error = xa_errno(nfs_xattr_create(xn.xn_vp, cred, name,
		    how == NFSV3CREATE_GUARDED, false));
	if (error == 0 && sa.va_size != VNOVAL)
		error = xa_errno(nfs_xattr_write(xn.xn_vp, cred, name,
		    sa.va_size, NULL, 0, true));
	if (error == 0)
		error = nfsrv_xattr_mkfh(&xn.xn_fh, v3, NFS_XATTR_FILE, name,
		    &fh);
	if (error == 0)
		error = nfs_xattr_vattr(xn.xn_vp, cred, NFS_XATTR_FILE, name,
		    &va);
	if (xn.xn_vp != NULL)
		diraft_ret = nfs_xattr_vattr(xn.xn_vp, cred, NFS_XATTR_DIR,
		    "", &diraft);
	xa_put(&xn);
	nfsm_reply(NFSX_SRVFH(&fh, v3) + NFSX_FATTR(v3) + NFSX_WCCDATA(v3));
	if (v3) {
		if (!error) {
			nfsm_srvpostop_fh(&fh);
			nfsm_srvpostop_attr(0, &va);
		}
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
	} else {
		nfsm_srvfhtom(&fh, v3);
		nfsm_build(fp, struct nfs_fattr *, NFSX_V2FATTR);
		nfsm_srvfillattr(&va, fp);
	}
	nfsm_srvdone;
}

static int
xa_remove(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
    struct lwp *lwp, struct mbuf **mrq)
{
	XA_LOCALS;
	char name[NFS_XATTR_NAMEMAX + 1];
	struct xa_node xn;
	struct vattr dirfor, diraft;
	nfsrvfh_t nsfh;
	int dirfor_ret = 1, diraft_ret = 1;

	xn.xn_vp = NULL;
	nfsm_srvmtofh(&nsfh);
	error = xa_name(&md, &dpos, name);
	if (error == EBADRPC) {
		m_freem(mrep);
		return error;
	}
	if (error == 0)
		error = xa_get(nfsd, slp, &nsfh, &xn);
	if (error == 0 && xn.xn_kind != NFS_XATTR_DIR)
		error = ENOTDIR;
	if (error == 0)
		dirfor_ret = nfs_xattr_vattr(xn.xn_vp, cred, NFS_XATTR_DIR, "",
		    &dirfor);
	if (error == 0)
		error = xa_access(&xn, VWRITE, cred, lwp);
	if (error == 0)
		error = xa_errno(nfs_xattr_remove(xn.xn_vp, cred, name));
	if (xn.xn_vp != NULL)
		diraft_ret = nfs_xattr_vattr(xn.xn_vp, cred, NFS_XATTR_DIR,
		    "", &diraft);
	xa_put(&xn);
	nfsm_reply(NFSX_WCCDATA(v3));
	if (v3)
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
	nfsm_srvdone;
}

/*
 * Within one directory.  Into a directory that is not one of attributes
 * is EINVAL, as illumos' zfs_rename() (usr/src/uts/common/fs/zfs/
 * zfs_vnops.c:3944-3951); into that of another file, EXDEV, where
 * illumos copies (xattr.c:1263-1320): the VOPs here move nothing between
 * files.
 */
static int
xa_rename(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
    struct lwp *lwp, struct mbuf **mrq)
{
	XA_LOCALS;
	char from[NFS_XATTR_NAMEMAX + 1], to[NFS_XATTR_NAMEMAX + 1];
	struct xa_node xn;
	struct vattr dirfor, diraft;
	nfsrvfh_t nsfh, tnsfh;
	int dirfor_ret = 1, diraft_ret = 1, tkind, terror;

	xn.xn_vp = NULL;
	nfsm_srvmtofh(&nsfh);
	error = xa_name(&md, &dpos, from);
	if (error == EBADRPC) {
		m_freem(mrep);
		return error;
	}
	nfsm_srvmtofh(&tnsfh);
	terror = xa_name(&md, &dpos, to);
	if (terror == EBADRPC) {
		m_freem(mrep);
		return terror;
	}
	if (error == 0)
		error = terror;
	if (error == 0)
		error = xa_get(nfsd, slp, &nsfh, &xn);
	if (error == 0 && xn.xn_kind != NFS_XATTR_DIR)
		error = ENOTDIR;
	if (error == 0) {
		tkind = nfsrv_xattr_marked(&tnsfh, v3, NULL, NULL);
		if (tkind != NFS_XATTR_DIR)
			error = EINVAL;
		else if (nfsrv_comparefh(&nsfh, &tnsfh) != 0)
			error = EXDEV;
	}
	if (error == 0)
		dirfor_ret = nfs_xattr_vattr(xn.xn_vp, cred, NFS_XATTR_DIR, "",
		    &dirfor);
	if (error == 0)
		error = xa_access(&xn, VWRITE, cred, lwp);
	if (error == 0)
		error = nfs_xattr_unique(xn.xn_vp, cred, to,
		    v3 ? XA_KEY3 : XA_KEY2);
	if (error == 0)
		error = xa_errno(nfs_xattr_rename(xn.xn_vp, cred, from, to));
	if (xn.xn_vp != NULL)
		diraft_ret = nfs_xattr_vattr(xn.xn_vp, cred, NFS_XATTR_DIR,
		    "", &diraft);
	xa_put(&xn);
	nfsm_reply(2 * NFSX_WCCDATA(v3));
	if (v3) {
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
		nfsm_srvwcc_data(dirfor_ret, &dirfor, diraft_ret, &diraft);
	}
	nfsm_srvdone;
}

/*
 * READDIR and READDIRPLUS: ".", "..", then the attributes in the order
 * the file system lists them.  Entry i has cookie i + 1; a cookie is
 * where to start.  The verifier is 0: the list has no generation, and a
 * cookie past its end is only the end.
 */
struct xa_rd {
	const char	*rd_name;
	size_t		 rd_len;
	int		 rd_kind;	/* 0 for "..", the file */
	uint64_t	 rd_fileid;
	uint64_t	 rd_cookie;
};

/* The names of the directory, as many as there are, in order. */
static int
xa_rdnext(char *buf, size_t blen, size_t *offp, uint64_t i, uint64_t fid,
    struct xa_rd *rd)
{
	u_int n;

	rd->rd_cookie = i + 1;
	if (i == 0) {
		rd->rd_name = ".";
		rd->rd_len = 1;
		rd->rd_kind = NFS_XATTR_DIR;
		rd->rd_fileid = nfs_xattr_fileid(fid, NFS_XATTR_DIR, "");
		return 1;
	}
	if (i == 1) {
		rd->rd_name = "..";
		rd->rd_len = 2;
		rd->rd_kind = 0;
		rd->rd_fileid = fid;
		return 1;
	}
	while (*offp < blen) {
		n = (uint8_t)buf[(*offp)++];
		if (n > blen - *offp)
			return 0;
		rd->rd_name = buf + *offp;
		rd->rd_len = n;
		*offp += n;
		if (n == 0)
			continue;
		rd->rd_kind = NFS_XATTR_FILE;
		return 1;
	}
	return 0;
}

static int
xa_readdir1(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
    struct lwp *lwp, struct mbuf **mrq, bool plus)
{
	XA_LOCALS;
	char name[NFS_XATTR_NAMEMAX + 1];
	struct xa_node xn;
	struct xa_rd rd;
	struct vattr at, va, fva;
	nfsrvfh_t nsfh, fh;
	char *buf = NULL;
	size_t blen = 0, alen = 0, boff = 0;
	uint64_t cookie, i, fid = 0;
	uint32_t cnt, used, esz, nent = 0;
	int32_t t2;
	int getret = 1, eof = 1, ret;

	xn.xn_vp = NULL;
	nfsm_srvmtofh(&nsfh);
	if (v3) {
		nfsm_dissect(tl, u_int32_t *, 5 * NFSX_UNSIGNED);
		cookie = fxdr_hyper(tl);
		tl += 4;
		if (plus) {
			nfsm_dissect(tl, u_int32_t *, NFSX_UNSIGNED);
		}
	} else {
		nfsm_dissect(tl, u_int32_t *, 2 * NFSX_UNSIGNED);
		cookie = fxdr_unsigned(u_int32_t, *tl++);
	}
	cnt = fxdr_unsigned(uint32_t, *tl);
	cnt = MIN(cnt, NFS_SRVMAXDATA(nfsd));
	error = xa_get(nfsd, slp, &nsfh, &xn);
	if (error == 0 && xn.xn_kind != NFS_XATTR_DIR)
		error = ENOTDIR;
	if (error == 0)
		error = getret = nfs_xattr_vattr(xn.xn_vp, cred, NFS_XATTR_DIR,
		    "", &at);
	if (error == 0) {
		vn_lock(xn.xn_vp, LK_SHARED | LK_RETRY);
		error = VOP_GETATTR(xn.xn_vp, &fva, cred);
		VOP_UNLOCK(xn.xn_vp);
		fid = fva.va_fileid;
	}
	if (error == 0)
		error = nfs_xattr_list(xn.xn_vp, cred, &buf, &blen, &alen);
	nfsm_reply(NFSX_POSTOPATTR(v3) + NFSX_COOKIEVERF(v3) +
	    2 * NFSX_UNSIGNED);
	if (error) {
		if (v3)
			nfsm_srvpostop_attr(getret, &at);
		goto out;
	}
	if (v3) {
		nfsm_srvpostop_attr(getret, &at);
		nfsm_build(tl, u_int32_t *, NFSX_V3COOKIEVERF);
		*tl++ = 0;
		*tl = 0;
	}
	/* What the reply has, and what an entry may make it. */
	used = NFSX_POSTOPATTR(v3) + NFSX_COOKIEVERF(v3) + 4 * NFSX_UNSIGNED;
	for (i = 0; ; i++) {
		ret = xa_rdnext(buf, blen, &boff, i, fid, &rd);
		if (ret == 0)
			break;
		if (i < cookie)
			continue;
		if (rd.rd_kind == NFS_XATTR_FILE) {
			memcpy(name, rd.rd_name, rd.rd_len);
			name[rd.rd_len] = '\0';
			rd.rd_fileid = nfs_xattr_fileid(fid, NFS_XATTR_FILE,
			    name);
		} else
			strlcpy(name, rd.rd_name, sizeof(name));
		esz = (v3 ? 6 : 4) * NFSX_UNSIGNED + nfsm_rndup(rd.rd_len);
		if (plus)
			esz += NFSX_V3POSTOPATTR + 2 * NFSX_UNSIGNED +
			    NFSX_V3FHMAX;
		/* One at least, or the client asks again for ever. */
		if (used + esz > cnt && nent != 0) {
			eof = 0;
			break;
		}
		used += esz;
		nent++;
		if (v3) {
			nfsm_build(tl, u_int32_t *, 3 * NFSX_UNSIGNED);
			*tl++ = nfs_true;
			txdr_hyper(rd.rd_fileid, tl);
		} else {
			nfsm_build(tl, u_int32_t *, 2 * NFSX_UNSIGNED);
			*tl++ = nfs_true;
			*tl = txdr_unsigned(rd.rd_fileid);
		}
		nfsm_strtom(name, rd.rd_len, NFS_XATTR_NAMEMAX);
		if (v3) {
			nfsm_build(tl, u_int32_t *, 2 * NFSX_UNSIGNED);
			txdr_hyper(rd.rd_cookie, tl);
		} else {
			nfsm_build(tl, u_int32_t *, NFSX_UNSIGNED);
			*tl = txdr_unsigned(rd.rd_cookie);
		}
		if (!plus)
			continue;
		if (rd.rd_kind == 0) {
			nfsrv_copyfh(&fh, &xn.xn_fh);
			ret = 0;
		} else
			ret = nfsrv_xattr_mkfh(&xn.xn_fh, v3, rd.rd_kind, name,
			    &fh);
		if (ret == 0 && rd.rd_kind != 0)
			ret = nfs_xattr_vattr(xn.xn_vp, cred, rd.rd_kind, name,
			    &va);
		nfsm_srvpostop_attr(ret, rd.rd_kind == 0 ? &fva : &va);
		if (ret == 0) {
			nfsm_srvpostop_fh(&fh);
		} else {
			nfsm_build(tl, u_int32_t *, NFSX_UNSIGNED);
			*tl = nfs_false;
		}
	}
	nfsm_build(tl, u_int32_t *, 2 * NFSX_UNSIGNED);
	*tl++ = nfs_false;
	*tl = eof ? nfs_true : nfs_false;
out:
	error = 0;
nfsmout:
	xa_put(&xn);
	if (alen != 0)
		kmem_free(buf, alen);
	return error;
}

static int
xa_readdir(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
    struct lwp *lwp, struct mbuf **mrq)
{

	return xa_readdir1(nfsd, slp, lwp, mrq, false);
}

static int
xa_readdirplus(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
    struct lwp *lwp, struct mbuf **mrq)
{

	return xa_readdir1(nfsd, slp, lwp, mrq, true);
}

/* The file system's, as nfsrv_statfs(), with the node's attributes. */
static int
xa_statfs(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
    struct lwp *lwp, struct mbuf **mrq)
{
	XA_LOCALS;
	struct statvfs *sf = NULL;
	struct nfs_statfs *sfp;
	struct xa_node xn;
	struct vattr at;
	nfsrvfh_t nsfh;
	u_quad_t tval;
	int getret = 1;

	nfsm_srvmtofh(&nsfh);
	sf = kmem_alloc(sizeof(*sf), KM_SLEEP);
	error = xa_get(nfsd, slp, &nsfh, &xn);
	if (error == 0) {
		error = VFS_STATVFS(xn.xn_vp->v_mount, sf);
		getret = nfs_xattr_vattr(xn.xn_vp, cred, xn.xn_kind,
		    xn.xn_name, &at);
	}
	xa_put(&xn);
	nfsm_reply(NFSX_POSTOPATTR(v3) + NFSX_STATFS(v3));
	if (v3)
		nfsm_srvpostop_attr(getret, &at);
	if (error) {
		error = 0;
		goto nfsmout;
	}
	nfsm_build(sfp, struct nfs_statfs *, NFSX_STATFS(v3));
	if (v3) {
		tval = (u_quad_t)sf->f_blocks * sf->f_frsize;
		txdr_hyper(tval, &sfp->sf_tbytes);
		tval = (u_quad_t)sf->f_bfree * sf->f_frsize;
		txdr_hyper(tval, &sfp->sf_fbytes);
		tval = (u_quad_t)sf->f_bavail * sf->f_frsize;
		txdr_hyper(tval, &sfp->sf_abytes);
		tval = (u_quad_t)sf->f_files;
		txdr_hyper(tval, &sfp->sf_tfiles);
		tval = (u_quad_t)sf->f_ffree;
		txdr_hyper(tval, &sfp->sf_ffiles);
		txdr_hyper(tval, &sfp->sf_afiles);
		sfp->sf_invarsec = 0;
	} else {
		sfp->sf_tsize = txdr_unsigned(NFS_MAXDGRAMDATA);
		sfp->sf_bsize = txdr_unsigned(NFS_V2CLAMP16(sf->f_frsize));
		sfp->sf_blocks = txdr_unsigned(NFS_V2CLAMP32(sf->f_blocks));
		sfp->sf_bfree = txdr_unsigned(NFS_V2CLAMP32(sf->f_bfree));
		sfp->sf_bavail = txdr_unsigned(NFS_V2CLAMP32(sf->f_bavail));
	}
nfsmout:
	if (sf != NULL)
		kmem_free(sf, sizeof(*sf));
	return error;
}

/*
 * As nfsrv_fsinfo(), but for the size of a file, which is
 * NFS_XATTR_MAXSIZE, and the properties: no links, and the times are
 * not set.
 */
static int
xa_fsinfo(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
    struct lwp *lwp, struct mbuf **mrq)
{
	XA_LOCALS;
	struct nfsv3_fsinfo *sip;
	struct xa_node xn;
	struct vattr at;
	nfsrvfh_t nsfh;
	uint32_t maxdata;
	int getret = 1;

	nfsm_srvmtofh(&nsfh);
	error = xa_get(nfsd, slp, &nsfh, &xn);
	if (error == 0)
		getret = nfs_xattr_vattr(xn.xn_vp, cred, xn.xn_kind,
		    xn.xn_name, &at);
	xa_put(&xn);
	nfsm_reply(NFSX_V3POSTOPATTR + NFSX_V3FSINFO);
	nfsm_srvpostop_attr(getret, &at);
	if (error)
		return 0;
	nfsm_build(sip, struct nfsv3_fsinfo *, NFSX_V3FSINFO);
	maxdata = slp->ns_so->so_type == SOCK_DGRAM ? NFS_MAXDGRAMDATA :
	    NFS_MAXDATA;
	sip->fs_rtmax = txdr_unsigned(maxdata);
	sip->fs_rtpref = txdr_unsigned(maxdata);
	sip->fs_rtmult = txdr_unsigned(NFS_FABLKSIZE);
	sip->fs_wtmax = txdr_unsigned(maxdata);
	sip->fs_wtpref = txdr_unsigned(maxdata);
	sip->fs_wtmult = txdr_unsigned(NFS_FABLKSIZE);
	sip->fs_dtpref = txdr_unsigned(maxdata);
	txdr_hyper((u_quad_t)NFS_XATTR_MAXSIZE, &sip->fs_maxfilesize);
	sip->fs_timedelta.nfsv3_sec = 0;
	sip->fs_timedelta.nfsv3_nsec = txdr_unsigned(1);
	sip->fs_properties = txdr_unsigned(NFSV3FSINFO_HOMOGENEOUS);
	nfsm_srvdone;
}

/* One link each; names as the length byte of the list allows. */
static int
xa_pathconf(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
    struct lwp *lwp, struct mbuf **mrq)
{
	XA_LOCALS;
	struct nfsv3_pathconf *pc;
	struct xa_node xn;
	struct vattr at;
	nfsrvfh_t nsfh;
	int getret = 1;

	nfsm_srvmtofh(&nsfh);
	error = xa_get(nfsd, slp, &nsfh, &xn);
	if (error == 0)
		getret = nfs_xattr_vattr(xn.xn_vp, cred, xn.xn_kind,
		    xn.xn_name, &at);
	xa_put(&xn);
	nfsm_reply(NFSX_V3POSTOPATTR + NFSX_V3PATHCONF);
	nfsm_srvpostop_attr(getret, &at);
	if (error)
		return 0;
	nfsm_build(pc, struct nfsv3_pathconf *, NFSX_V3PATHCONF);
	pc->pc_linkmax = txdr_unsigned(1);
	pc->pc_namemax = txdr_unsigned(NFS_XATTR_NAMEMAX);
	pc->pc_notrunc = nfs_true;
	pc->pc_chownrestricted = nfs_true;
	pc->pc_caseinsensitive = nfs_false;
	pc->pc_casepreserving = nfs_true;
	nfsm_srvdone;
}

/* What was written went to the file system whole. */
static int
xa_commit(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
    struct lwp *lwp, struct mbuf **mrq)
{
	XA_LOCALS;
	struct xa_node xn;
	struct vattr at;
	nfsrvfh_t nsfh;
	int getret = 1;

	nfsm_srvmtofh(&nsfh);
	nfsm_dissect(tl, u_int32_t *, 3 * NFSX_UNSIGNED);
	error = xa_get(nfsd, slp, &nsfh, &xn);
	if (error == 0 && xn.xn_kind == NFS_XATTR_DIR)
		error = EISDIR;
	if (xn.xn_vp != NULL)
		getret = nfs_xattr_vattr(xn.xn_vp, cred, xn.xn_kind,
		    xn.xn_name, &at);
	xa_put(&xn);
	nfsm_reply(NFSX_V3WCCDATA + NFSX_V3WRITEVERF);
	nfsm_srvwcc_data(getret, &at, getret, &at);
	if (error)
		return 0;
	nfsm_build(tl, u_int32_t *, NFSX_V3WRITEVERF);
	xa_verf(tl);
	nfsm_srvdone;
}

/*
 * READLINK, MKDIR, SYMLINK, MKNOD, RMDIR and LINK.  An attribute
 * directory holds regular files only, and illumos answers EINVAL
 * (usr/src/uts/common/fs/xattr.c:1517 for MKDIR, zfs_vnops.c:1676-1682
 * for a CREATE of any other type, 4552 for LINK); nfsrv_errmap() makes of
 * it what the procedure may return, as of an EINVAL of a file system.
 * The bodies are those of a failure: post_op_attr for READLINK,
 * wcc_data for the rest and post_op_attr before it for LINK.
 */
static int
xa_inval(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
    struct lwp *lwp, struct mbuf **mrq)
{
	XA_LOCALS;
	struct xa_node xn;
	nfsrvfh_t nsfh;

	nfsm_srvmtofh(&nsfh);
	error = xa_get(nfsd, slp, &nsfh, &xn);
	xa_put(&xn);
	if (error == 0)
		error = EINVAL;
	nfsm_reply(3 * NFSX_UNSIGNED);
	if (nfsd->nd_procnum == NFSPROC_READLINK ||
	    nfsd->nd_procnum == NFSPROC_LINK)
		nfsm_srvpostop_attr(1, NULL);
	if (nfsd->nd_procnum != NFSPROC_READLINK)
		nfsm_srvwcc_data(1, NULL, 1, NULL);
	nfsm_srvdone;
}

/* In place of nfsrv3_procs[] for a call on a marked handle. */
int (*const nfsrv_xattr_procs[NFS_NPROCS])(struct nfsrv_descript *,
    struct nfssvc_sock *, struct lwp *, struct mbuf **) = {
	[NFSPROC_NULL] =	nfsrv_null,
	[NFSPROC_GETATTR] =	xa_getattr,
	[NFSPROC_SETATTR] =	xa_setattr,
	[NFSPROC_LOOKUP] =	xa_lookup,
	[NFSPROC_ACCESS] =	xa_access3,
	[NFSPROC_READLINK] =	xa_inval,
	[NFSPROC_READ] =	xa_read,
	[NFSPROC_WRITE] =	xa_write,
	[NFSPROC_CREATE] =	xa_create,
	[NFSPROC_MKDIR] =	xa_inval,
	[NFSPROC_SYMLINK] =	xa_inval,
	[NFSPROC_MKNOD] =	xa_inval,
	[NFSPROC_REMOVE] =	xa_remove,
	[NFSPROC_RMDIR] =	xa_inval,
	[NFSPROC_RENAME] =	xa_rename,
	[NFSPROC_LINK] =	xa_inval,
	[NFSPROC_READDIR] =	xa_readdir,
	[NFSPROC_READDIRPLUS] =	xa_readdirplus,
	[NFSPROC_FSSTAT] =	xa_statfs,
	[NFSPROC_FSINFO] =	xa_fsinfo,
	[NFSPROC_PATHCONF] =	xa_pathconf,
	[NFSPROC_COMMIT] =	xa_commit,
	[NFSPROC_NOOP] =	nfsrv_noop,
};
