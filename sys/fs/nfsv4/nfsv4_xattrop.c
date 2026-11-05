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
 * Extended attributes, RFC 8276.  An xattr of the protocol is one in the
 * user namespace of the file system, s5, and a file system says whether
 * it has them by answering VOP_LISTEXTATTR.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/extattr.h>
#include <sys/kauth.h>
#include <sys/kmem.h>
#include <sys/mount.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/vnode.h>

#include <fs/nfsv4/nfsv4_var.h>

/*
 * Choices, none from the RFC, which s8.2.1 leaves to the file system.
 * NFSV4_XATTR_MAX is the most one value can be, and NFSV4_XATTR_LIST
 * the most the names of one file can be.
 */
#define	NFSV4_XATTR_MAX		NFSV4_MAXIO
#define	NFSV4_XATTR_LIST	(1024 * 1024)

/* The results of LISTXATTRS4resok around its names. */
#define	LISTXATTRS_OVERHEAD	(8 + 4 + 4)

#define	XATTR_PAD(n)		(((n) + 3) & ~3U)

/* The bit of fattr4_xattr_support, s8.2.1, and of ACCESS, s8.5. */
bool
nfsv4_xattr_supported(struct vnode *vp, kauth_cred_t cred)
{
	size_t size;
	int error;

	if (vp == NULL || (vp->v_type != VREG && vp->v_type != VDIR))
		return false;
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	error = VOP_LISTEXTATTR(vp, EXTATTR_NAMESPACE_USER, NULL, &size, 0,
	    cred);
	VOP_UNLOCK(vp);
	return error != EOPNOTSUPP;
}

/*
 * s8.4: what has no xattrs refuses them all.  s8.1 only has xattrs on
 * regular files and directories, though that does not refuse them on
 * the rest by name; NFS4ERR_WRONG_TYPE is in the table of s8.4.5.
 */
static uint32_t
xattr_check(const struct nfsv4_cfh *cf)
{
	struct vnode *vp = cf->cf_vp;

	if (vp == NULL)
		return NFS4ERR_NOTSUPP;
	if (vp->v_type != VREG && vp->v_type != VDIR)
		return NFS4ERR_WRONG_TYPE;
	return nfsv4_xattr_supported(vp, cf->cf_cred) ? NFS4_OK :
	    NFS4ERR_NOTSUPP;
}

/* s8.1: the same as a file name, except that it is no path. */
static uint32_t
xattr_key_check(const struct nfsv4_name *nm)
{

	if (nm->nm_toolong)
		return NFS4ERR_NAMETOOLONG;
	if (nm->nm_len == 0)
		return NFS4ERR_INVAL;
	if (memchr(nm->nm_str, '/', nm->nm_len) != NULL ||
	    memchr(nm->nm_str, '\0', nm->nm_len) != NULL)
		return NFS4ERR_BADCHAR;
	return NFS4_OK;
}

/* ENODATA as well: some file systems say that for no such attribute. */
static uint32_t
xattr_errno(int error)
{

	switch (error) {
	case ENOATTR:
	case ENODATA:
		return NFS4ERR_NOXATTR;
	case E2BIG:
		return NFS4ERR_XATTR2BIG;
	default:
		return nfsv4_errno(error);
	}
}

/* s8.4.1 */
uint32_t
nfsv4_op_getxattr(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_name *nm = &a->name.name;
	const struct nfsv4_cfh *cf = &c->c_cur;
	struct vnode *vp = cf->cf_vp;
	struct iovec iov;
	struct uio uio;
	size_t size;
	char *buf = NULL;
	uint32_t st, len;
	int error;

	st = xattr_check(cf);
	if (st == NFS4_OK)
		st = xattr_key_check(nm);
	if (st != NFS4_OK)
		return st;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	error = VOP_GETEXTATTR(vp, EXTATTR_NAMESPACE_USER, nm->nm_str, NULL,
	    &size, cf->cf_cred);
	if (error != 0) {
		VOP_UNLOCK(vp);
		return xattr_errno(error);
	}
	if (size > NFSV4_XATTR_MAX) {
		VOP_UNLOCK(vp);
		return NFS4ERR_REP_TOO_BIG;	/* s8.4.1.3 */
	}
	if (size != 0)
		buf = kmem_alloc(size, KM_SLEEP);
	iov.iov_base = buf;
	iov.iov_len = size;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = 0;
	uio.uio_resid = size;
	uio.uio_rw = UIO_READ;
	UIO_SETUP_SYSSPACE(&uio);
	if (size != 0)
		error = VOP_GETEXTATTR(vp, EXTATTR_NAMESPACE_USER, nm->nm_str,
		    &uio, NULL, cf->cf_cred);
	VOP_UNLOCK(vp);
	if (error != 0)
		st = xattr_errno(error);
	else {
		len = size - uio.uio_resid;
		if (!xdr_u_int32_t(c->c_rx, &len) ||
		    (len != 0 && !xdr_opaque(c->c_rx, buf, len)))
			st = NFS4ERR_RESOURCE;
	}
	if (buf != NULL)
		kmem_free(buf, size);
	return st;
}

/*
 * s8.4.2.  The vnode is locked for the whole of it so that change_info4
 * is atomic, and so that SETXATTR4_CREATE and SETXATTR4_REPLACE find
 * what they found when they set.
 */
uint32_t
nfsv4_op_setxattr(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_setxattr *sa = &a->setxattr;
	const struct nfsv4_cfh *cf = &c->c_cur;
	struct vnode *vp = cf->cf_vp;
	struct nfsv4_change_info ci;
	struct iovec iov;
	struct uio uio;
	size_t size;
	char *buf = NULL;
	uint32_t st;
	u_int end;
	int error;

	if (sa->option > SETXATTR4_REPLACE)
		return NFS4ERR_INVAL;
	st = xattr_check(cf);
	if (st == NFS4_OK)
		st = xattr_key_check(&sa->key);
	if (st == NFS4_OK)
		st = nfsv4_errno(nfsv4_access_vp(cf, VWRITE));
	if (st != NFS4_OK)
		return st;
	if (sa->len > NFSV4_XATTR_MAX)
		return NFS4ERR_XATTR2BIG;

	if (sa->len != 0) {
		buf = kmem_alloc(sa->len, KM_SLEEP);
		end = XDR_GETPOS(c->c_ax);
		if (!XDR_SETPOS(c->c_ax, sa->pos) ||
		    !XDR_GETBYTES(c->c_ax, buf, sa->len) ||
		    !XDR_SETPOS(c->c_ax, end)) {
			kmem_free(buf, sa->len);
			return NFS4ERR_BADXDR;
		}
	}

	iov.iov_base = buf;
	iov.iov_len = sa->len;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = 0;
	uio.uio_resid = sa->len;
	uio.uio_rw = UIO_WRITE;
	UIO_SETUP_SYSSPACE(&uio);

	memset(&ci, 0, sizeof(ci));
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	error = nfsv4_dir_change(vp, cf->cf_cred, &ci.ci_before);
	if (error == 0 && sa->option != SETXATTR4_EITHER) {
		error = VOP_GETEXTATTR(vp, EXTATTR_NAMESPACE_USER,
		    sa->key.nm_str, NULL, &size, cf->cf_cred);
		if (error == 0 && sa->option == SETXATTR4_CREATE)
			error = EEXIST;
		else if ((error == ENOATTR || error == ENODATA) &&
		    sa->option == SETXATTR4_CREATE)
			error = 0;
	}
	if (error == 0)
		error = VOP_SETEXTATTR(vp, EXTATTR_NAMESPACE_USER,
		    sa->key.nm_str, &uio, cf->cf_cred);
	if (error == 0)
		error = nfsv4_dir_change(vp, cf->cf_cred, &ci.ci_after);
	VOP_UNLOCK(vp);
	if (buf != NULL)
		kmem_free(buf, sa->len);
	if (error != 0)
		return xattr_errno(error);
	ci.ci_atomic = 1;
	return nfsv4_xdr_change_info(c->c_rx, &ci) ? NFS4_OK :
	    NFS4ERR_RESOURCE;
}

/* s8.4.4 */
uint32_t
nfsv4_op_removexattr(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_name *nm = &a->name.name;
	const struct nfsv4_cfh *cf = &c->c_cur;
	struct vnode *vp = cf->cf_vp;
	struct nfsv4_change_info ci;
	uint32_t st;
	int error;

	st = xattr_check(cf);
	if (st == NFS4_OK)
		st = xattr_key_check(nm);
	if (st == NFS4_OK)
		st = nfsv4_errno(nfsv4_access_vp(cf, VWRITE));
	if (st != NFS4_OK)
		return st;

	memset(&ci, 0, sizeof(ci));
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	error = nfsv4_dir_change(vp, cf->cf_cred, &ci.ci_before);
	if (error == 0) {
		error = VOP_DELETEEXTATTR(vp, EXTATTR_NAMESPACE_USER,
		    nm->nm_str, cf->cf_cred);
		/* As extattr_delete_vp(), for a file system with only set. */
		if (error == EOPNOTSUPP)
			error = VOP_SETEXTATTR(vp, EXTATTR_NAMESPACE_USER,
			    nm->nm_str, NULL, cf->cf_cred);
	}
	if (error == 0)
		error = nfsv4_dir_change(vp, cf->cf_cred, &ci.ci_after);
	VOP_UNLOCK(vp);
	if (error != 0)
		return xattr_errno(error);
	ci.ci_atomic = 1;
	return nfsv4_xdr_change_info(c->c_rx, &ci) ? NFS4_OK :
	    NFS4ERR_RESOURCE;
}

/*
 * s8.4.3.  The cookie counts names, so it is 0 at the start as it must
 * be, and a name set meanwhile can move what it stands for just as a
 * directory entry can.  One past the end is NFS4ERR_BAD_COOKIE, which
 * s8.4.5 does not list; an erratum to RFC 8276 reports that.
 */
uint32_t
nfsv4_op_listxattrs(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_listxattrs *la = &a->listxattrs;
	const struct nfsv4_cfh *cf = &c->c_cur;
	struct vnode *vp = cf->cf_vp;
	struct iovec iov;
	struct uio uio;
	XDR *rx = c->c_rx;
	char *buf = NULL;
	size_t size, have, p, first;
	uint64_t i, next;
	uint32_t st, room, used, n, len, eof, need;
	int error;

	st = xattr_check(cf);
	if (st != NFS4_OK)
		return st;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	size = 0;
	error = VOP_LISTEXTATTR(vp, EXTATTR_NAMESPACE_USER, NULL, &size,
	    EXTATTR_LIST_LENPREFIX, cf->cf_cred);
	if (error != 0 || size > NFSV4_XATTR_LIST) {
		VOP_UNLOCK(vp);
		return error != 0 ? xattr_errno(error) : NFS4ERR_SERVERFAULT;
	}
	have = 0;
	if (size != 0) {
		buf = kmem_alloc(size, KM_SLEEP);
		iov.iov_base = buf;
		iov.iov_len = size;
		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_offset = 0;
		uio.uio_resid = size;
		uio.uio_rw = UIO_READ;
		UIO_SETUP_SYSSPACE(&uio);
		error = VOP_LISTEXTATTR(vp, EXTATTR_NAMESPACE_USER, &uio, NULL,
		    EXTATTR_LIST_LENPREFIX, cf->cf_cred);
		have = size - uio.uio_resid;
	}
	VOP_UNLOCK(vp);
	if (error != 0) {
		st = xattr_errno(error);
		goto out;
	}

	/* Find where the cookie is. */
	for (p = 0, i = 0; i < la->cookie && p < have; i++)
		p += 1 + (uint8_t)buf[p];
	if (i != la->cookie) {
		st = NFS4ERR_BAD_COOKIE;
		goto out;
	}

	/* What fits, s8.4.3.3: maxcount counts the whole of the result. */
	room = MIN(la->maxcount, NFSV4_MAXIO);
	if (room < LISTXATTRS_OVERHEAD) {
		st = NFS4ERR_TOOSMALL;
		goto out;
	}
	used = LISTXATTRS_OVERHEAD;
	first = p;
	n = 0;
	while (p < have) {
		len = (uint8_t)buf[p];
		need = 4 + XATTR_PAD(len);
		if (need > room - used)
			break;
		used += need;
		p += 1 + len;
		n++;
	}
	if (n == 0 && p < have) {
		st = NFS4ERR_TOOSMALL;
		goto out;
	}

	next = la->cookie + n;
	eof = p >= have;
	if (!xdr_u_int64_t(rx, &next) || !xdr_u_int32_t(rx, &n)) {
		st = NFS4ERR_RESOURCE;
		goto out;
	}
	for (p = first; p < have && n > 0; n--) {
		len = (uint8_t)buf[p];
		if (!xdr_u_int32_t(rx, &len) ||
		    !xdr_opaque(rx, buf + p + 1, len)) {
			st = NFS4ERR_RESOURCE;
			goto out;
		}
		p += 1 + len;
	}
	if (!xdr_u_int32_t(rx, &eof))
		st = NFS4ERR_RESOURCE;
out:
	if (buf != NULL)
		kmem_free(buf, size);
	return st;
}
