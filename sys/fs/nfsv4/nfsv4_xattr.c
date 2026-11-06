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
 * Named attributes, RFC 7530 s5.3 and s16.17, on the extended attributes
 * of the file system: the namespace user, as the namespace system is
 * where FFS keeps ACLs and the file system's own things.  ZFS's own
 * extended attributes come the same way, through the VOPs.
 *
 * The VFS has no vnode for an attribute, so a node here is the vnode of
 * the file with a mark on the handle: cf_attr says what it is and cf_aname
 * names the attribute, and the handle carries both, see nfsv4_fh.c.  Such
 * a handle stays good as FH4_PERSISTENT says.  A name as long as s5.3
 * wants does not fit there, so the handle has its hash, and PUTFH finds
 * the name among the file's attributes.  There is no table to lose.
 *
 * Operations on those nodes come here first from nfsv4_one_op(), so
 * that the ones that do not know of them need not.  The VOPs have no
 * offset: an attribute is read and written whole, with the vnode locked
 * across the two for a partial WRITE, and NFSV4_ATTR_MAXSIZE keeps that
 * bounded.
 *
 * Not delegated, s5.3 leaving it to the server, and not locked: lockf is
 * per vnode, and would mix them up with the file's own locks.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/extattr.h>
#include <sys/kauth.h>
#include <sys/kmem.h>
#include <sys/sha2.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/vnode.h>

#include <fs/nfsv4/nfsv4_var.h>
#include <fs/nfsv4/nfsv4_state.h>

/* A choice: what is held in memory for one attribute. */
#define	NFSV4_ATTR_MAXSIZE	(64 * 1024)

#define	XA_NS			EXTATTR_NAMESPACE_USER

/* The first bytes of SHA-256: nobody finds a pair by chance, nor needs to. */
void
nfsv4_xattr_hash(const char *name, size_t len, uint8_t *out)
{
	SHA256_CTX ctx;
	uint8_t d[SHA256_DIGEST_LENGTH];

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, (const uint8_t *)name, len);
	SHA256_Final(d, &ctx);
	memcpy(out, d, NFSV4_ANAME_HASH);
}

/* cf is a file; make it the attribute with this hash, or NFS4ERR_STALE. */
uint32_t
nfsv4_xattr_byhash(struct nfsv4_cfh *cf, const uint8_t *hash)
{
	uint8_t h[NFSV4_ANAME_HASH];
	char *buf = NULL;
	size_t len, alen, off;
	uint32_t st = NFS4ERR_STALE;
	u_int n;
	int error;

	error = nfsv4_xattr_list(cf, &buf, &len, &alen);
	if (error != 0)
		return nfsv4_errno(error);
	for (off = 0; off < len; off += n) {
		n = (uint8_t)buf[off++];
		if (n > len - off)
			break;
		nfsv4_xattr_hash(buf + off, n, h);
		if (memcmp(h, hash, sizeof(h)) == 0) {
			st = nfsv4_cfh_setattr(cf, NFSV4_ATTR_FILE, buf + off,
			    n);
			break;
		}
	}
	if (alen != 0)
		kmem_free(buf, alen);
	return st;
}

static uint32_t
xa_errno(int error)
{

	return error == ENOATTR ? NFS4ERR_NOENT : nfsv4_errno(error);
}

static void
xa_uio(struct uio *uio, struct iovec *iov, void *buf, size_t len,
    enum uio_rw rw)
{

	iov->iov_base = buf;
	iov->iov_len = len;
	uio->uio_iov = iov;
	uio->uio_iovcnt = 1;
	uio->uio_offset = 0;
	uio->uio_resid = len;
	uio->uio_rw = rw;
	UIO_SETUP_SYSSPACE(uio);
}

/* The size of an attribute, with the vnode locked. */
static int
xa_size_l(struct vnode *vp, const char *name, kauth_cred_t cred, size_t *sizep)
{

	*sizep = 0;
	return VOP_GETEXTATTR(vp, XA_NS, name, NULL, sizep, cred);
}

int
nfsv4_xattr_size(const struct nfsv4_cfh *cf, uint64_t *sizep)
{
	size_t size;
	int error;

	vn_lock(cf->cf_vp, LK_SHARED | LK_RETRY);
	error = xa_size_l(cf->cf_vp, cf->cf_aname, cf->cf_cred, &size);
	VOP_UNLOCK(cf->cf_vp);
	if (error == 0)
		*sizep = size;
	return error;
}

/*
 * All the names, as the file system gives them with
 * EXTATTR_LIST_LENPREFIX: each a length byte and its bytes.  *bufp is to
 * be freed with kmem_free(*bufp, *alenp) if *alenp is not 0.
 */
int
nfsv4_xattr_list(const struct nfsv4_cfh *cf, char **bufp, size_t *lenp,
    size_t *alenp)
{
	struct vnode *vp = cf->cf_vp;
	struct iovec iov;
	struct uio uio;
	size_t size = 0;
	char *buf = NULL;
	int error;

	*alenp = 0;
	*lenp = 0;
	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = VOP_LISTEXTATTR(vp, XA_NS, NULL, &size, EXTATTR_LIST_LENPREFIX,
	    cf->cf_cred);
	if (error == 0 && size != 0) {
		buf = kmem_alloc(size, KM_SLEEP);
		xa_uio(&uio, &iov, buf, size, UIO_READ);
		error = VOP_LISTEXTATTR(vp, XA_NS, &uio, NULL,
		    EXTATTR_LIST_LENPREFIX, cf->cf_cred);
		if (error == 0) {
			*alenp = size;
			*lenp = size - uio.uio_resid;
			*bufp = buf;
		} else
			kmem_free(buf, size);
	}
	VOP_UNLOCK(vp);
	return error;
}

/*
 * archive, hidden, system, mimetype and time_backup, RFC 7530 s5.8.2:
 * NetBSD's file systems have nowhere of their own for these, so they
 * are extended attributes too, in the namespace system, where named
 * attributes do not go.  So they are there only where those are.  The
 * credential is NOCRED, the check being VWRITE on the file by whoever
 * sets them, and reading them being open to all as any attribute is.
 */
#define	XS_NS		EXTATTR_NAMESPACE_SYSTEM

bool
nfsv4_xstore_ok(struct vnode *vp)
{
	size_t size = 0;
	int error;

	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = VOP_LISTEXTATTR(vp, XS_NS, NULL, &size, 0, NOCRED);
	VOP_UNLOCK(vp);
	return error == 0;
}

static int
xs_get(struct vnode *vp, const char *name, void *buf, size_t len, size_t *gotp)
{
	struct iovec iov;
	struct uio uio;
	int error;

	xa_uio(&uio, &iov, buf, len, UIO_READ);
	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = VOP_GETEXTATTR(vp, XS_NS, name, &uio, NULL, NOCRED);
	VOP_UNLOCK(vp);
	*gotp = len - uio.uio_resid;
	return error;
}

static int
xs_set(struct vnode *vp, const char *name, const void *buf, size_t len)
{
	struct iovec iov;
	struct uio uio;
	int error;

	xa_uio(&uio, &iov, __UNCONST(buf), len, UIO_WRITE);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	error = VOP_SETEXTATTR(vp, XS_NS, name, &uio, NOCRED);
	VOP_UNLOCK(vp);
	return error;
}

bool
nfsv4_xstore_bool(struct vnode *vp, const char *name)
{
	uint8_t v = 0;
	size_t got;

	return xs_get(vp, name, &v, 1, &got) == 0 && got == 1 && v != 0;
}

u_int
nfsv4_xstore_mime(struct vnode *vp, char *buf)
{
	size_t got = 0;

	return xs_get(vp, "nfsv4.mimetype", buf, NFSV4_MIME_MAX, &got) == 0 ?
	    (u_int)got : 0;
}

void
nfsv4_xstore_time(struct vnode *vp, struct timespec *ts)
{
	int64_t v[2];
	size_t got;

	if (xs_get(vp, "nfsv4.time_backup", v, sizeof(v), &got) == 0 &&
	    got == sizeof(v)) {
		ts->tv_sec = v[0];
		ts->tv_nsec = (long)v[1];
	} else
		timespecclear(ts);
}

uint32_t
nfsv4_xstore_apply(struct nfsv4_compound *c, struct vnode *vp,
    kauth_cred_t cred)
{
	struct nfsv4_xstore *xs = &c->c_xs;
	uint64_t set = xs->xs_set;
	uint8_t v;
	int64_t t[2];
	int error = 0;

	xs->xs_set = 0;
	if (set == 0)
		return NFS4_OK;
	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = VOP_ACCESS(vp, VWRITE, cred);
	VOP_UNLOCK(vp);
	if (error == 0 && (set & (1ULL << FATTR4_ARCHIVE)) != 0) {
		v = xs->xs_archive != 0;
		error = xs_set(vp, "nfsv4.archive", &v, 1);
	}
	if (error == 0 && (set & (1ULL << FATTR4_HIDDEN)) != 0) {
		v = xs->xs_hidden != 0;
		error = xs_set(vp, "nfsv4.hidden", &v, 1);
	}
	if (error == 0 && (set & (1ULL << FATTR4_SYSTEM)) != 0) {
		v = xs->xs_system != 0;
		error = xs_set(vp, "nfsv4.system", &v, 1);
	}
	if (error == 0 && (set & (1ULL << FATTR4_MIMETYPE)) != 0)
		error = xs_set(vp, "nfsv4.mimetype", xs->xs_mime,
		    xs->xs_mimelen);
	if (error == 0 && (set & (1ULL << FATTR4_TIME_BACKUP)) != 0) {
		t[0] = xs->xs_backup.tv_sec;
		t[1] = xs->xs_backup.tv_nsec;
		error = xs_set(vp, "nfsv4.time_backup", t, sizeof(t));
	}
	if (error == EOPNOTSUPP)
		return NFS4ERR_ATTRNOTSUPP;
	return nfsv4_errno(error);
}

/* s5.8.1.8: does the object have any? */
bool
nfsv4_xattr_any(const struct nfsv4_cfh *cf)
{
	size_t size = 0;
	int error;

	vn_lock(cf->cf_vp, LK_SHARED | LK_RETRY);
	error = VOP_LISTEXTATTR(cf->cf_vp, XA_NS, NULL, &size,
	    EXTATTR_LIST_LENPREFIX, cf->cf_cred);
	VOP_UNLOCK(cf->cf_vp);
	return error == 0 && size != 0;
}

/* Make to the attribute name of the attribute directory dir. */
uint32_t
nfsv4_xattr_lookup(struct nfsv4_compound *c, struct nfsv4_cfh *dir,
    const char *name, struct nfsv4_cfh *to)
{
	size_t size, len = strlen(name);
	int error;

	if (len > NFSV4_ANAME_MAX)
		return NFS4ERR_NAMETOOLONG;
	vn_lock(dir->cf_vp, LK_SHARED | LK_RETRY);
	error = xa_size_l(dir->cf_vp, name, dir->cf_cred, &size);
	VOP_UNLOCK(dir->cf_vp);
	if (error != 0)
		return xa_errno(error);
	if (to != dir)
		nfsv4_cfh_copy(to, dir);
	return nfsv4_cfh_setattr(to, NFSV4_ATTR_FILE, name, len);
}

/*
 * Write n bytes at off, the vnode locked across reading and writing.
 * With truncate, the attribute then ends after them.
 */
static int
xa_modify(const struct nfsv4_cfh *cf, const char *name, uint64_t off,
    const char *data, size_t n, bool truncate)
{
	struct vnode *vp = cf->cf_vp;
	struct iovec iov;
	struct uio uio;
	char *buf = NULL;
	size_t old = 0, new;
	int error;

	if (off > NFSV4_ATTR_MAXSIZE || n > NFSV4_ATTR_MAXSIZE - off)
		return EFBIG;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	error = xa_size_l(vp, name, cf->cf_cred, &old);
	if (error == ENOATTR) {
		old = 0;
		error = 0;
	}
	if (error != 0 || old > NFSV4_ATTR_MAXSIZE) {
		VOP_UNLOCK(vp);
		return error != 0 ? error : EFBIG;
	}
	new = truncate ? off : MAX(old, off + n);
	if (new != 0) {
		buf = kmem_zalloc(new, KM_SLEEP);
		if (old != 0) {
			xa_uio(&uio, &iov, buf, MIN(old, new), UIO_READ);
			error = VOP_GETEXTATTR(vp, XA_NS, name, &uio, NULL,
			    cf->cf_cred);
		}
		if (error == 0 && n != 0)
			memcpy(buf + off, data, n);
	}
	if (error == 0) {
		xa_uio(&uio, &iov, buf, new, UIO_WRITE);
		error = VOP_SETEXTATTR(vp, XA_NS, name, &uio, cf->cf_cred);
	}
	VOP_UNLOCK(vp);
	if (buf != NULL)
		kmem_free(buf, new);
	return error;
}

/* OPEN of a name in the attribute directory cf, s16.16.5. */
uint32_t
nfsv4_xattr_prepare(struct nfsv4_cfh *cf, const char *name, bool create,
    bool guarded, bool truncate)
{
	size_t size;
	int error;

	if (strlen(name) > NFSV4_ANAME_MAX)
		return NFS4ERR_NAMETOOLONG;
	vn_lock(cf->cf_vp, LK_SHARED | LK_RETRY);
	error = xa_size_l(cf->cf_vp, name, cf->cf_cred, &size);
	VOP_UNLOCK(cf->cf_vp);
	if (error == 0 && create && guarded)
		return NFS4ERR_EXIST;
	if (error == ENOATTR && create)
		return xa_errno(xa_modify(cf, name, 0, NULL, 0, true));
	if (error == 0 && truncate)
		return xa_errno(xa_modify(cf, name, 0, NULL, 0, true));
	return xa_errno(error);
}

/* RFC 7530 s16.17 */
uint32_t
nfsv4_op_openattr(struct nfsv4_compound *c, union nfsv4_args *a)
{
	struct nfsv4_cfh *cf = &c->c_cur;
	size_t size = 0;
	int error;

	if (cf->cf_vp == NULL)
		return NFS4ERR_NOTSUPP;
	vn_lock(cf->cf_vp, LK_SHARED | LK_RETRY);
	error = VOP_LISTEXTATTR(cf->cf_vp, XA_NS, NULL, &size,
	    EXTATTR_LIST_LENPREFIX, cf->cf_cred);
	VOP_UNLOCK(cf->cf_vp);
	if (error != 0)
		return nfsv4_errno(error);	/* s16.17.5 for EOPNOTSUPP */
	if (size == 0 && !a->openattr.createdir)
		return NFS4ERR_NOENT;
	return nfsv4_cfh_setattr(cf, NFSV4_ATTR_DIR, "", 0);
}

static uint32_t
xa_op_read(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_read *ra = &a->read;
	const struct nfsv4_cfh *cf = &c->c_cur;
	struct vnode *vp = cf->cf_vp;
	struct iovec iov;
	struct uio uio;
	char *buf = NULL;
	size_t size;
	uint32_t st, n = 0, eof = 1;
	int error;

	st = nfsv4_io_check(c, &ra->stateid, false);
	if (st != NFS4_OK)
		return st;
	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = xa_size_l(vp, cf->cf_aname, cf->cf_cred, &size);
	if (error == 0 && size > NFSV4_ATTR_MAXSIZE)
		error = EFBIG;
	if (error == 0 && size != 0) {
		buf = kmem_alloc(size, KM_SLEEP);
		xa_uio(&uio, &iov, buf, size, UIO_READ);
		error = VOP_GETEXTATTR(vp, XA_NS, cf->cf_aname, &uio, NULL,
		    cf->cf_cred);
	}
	VOP_UNLOCK(vp);
	if (error == 0 && ra->offset < size) {
		n = (uint32_t)MIN(size - ra->offset, ra->count);
		eof = ra->offset + n >= size;
	}
	if (error != 0)
		st = xa_errno(error);
	else if (!xdr_u_int32_t(c->c_rx, &eof) ||
	    !xdr_u_int32_t(c->c_rx, &n) ||
	    (n != 0 && !xdr_opaque(c->c_rx, buf + ra->offset, n)))
		st = NFS4ERR_RESOURCE;
	if (buf != NULL)
		kmem_free(buf, size);
	return st;
}

static uint32_t
xa_op_write(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_write *wa = &a->write;
	const struct nfsv4_cfh *cf = &c->c_cur;
	struct nfsv4_verifier verf;
	char *buf = NULL;
	uint32_t st, n = wa->len, committed = FILE_SYNC4;
	u_int end;
	int error;

	if (wa->stable > FILE_SYNC4)
		return NFS4ERR_INVAL;
	st = nfsv4_io_check(c, &wa->stateid, true);
	if (st != NFS4_OK)
		return st;
	error = nfsv4_access_vp(cf, VWRITE);
	if (error != 0)
		return nfsv4_errno(error);
	if (n > NFSV4_ATTR_MAXSIZE)
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
		error = xa_modify(cf, cf->cf_aname, wa->offset, buf, n, false);
		kmem_free(buf, n);
		if (error != 0)
			return xa_errno(error);
	}
	nfsv4_write_verf(&verf);
	return xdr_u_int32_t(c->c_rx, &n) &&
	    xdr_u_int32_t(c->c_rx, &committed) &&
	    nfsv4_xdr_verifier(c->c_rx, &verf) ? NFS4_OK : NFS4ERR_RESOURCE;
}

static uint32_t
xa_op_commit(struct nfsv4_compound *c, union nfsv4_args *a)
{
	struct nfsv4_verifier verf;

	/* What was written went to the file system whole. */
	nfsv4_write_verf(&verf);
	return nfsv4_xdr_verifier(c->c_rx, &verf) ? NFS4_OK : NFS4ERR_RESOURCE;
}

/* Of a named attribute's own attributes only the size can be set. */
static uint32_t
xa_op_setattr(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_setattr *sa = &a->setattr;
	struct nfsv4_cfh *cf = &c->c_cur;
	struct vattr va;
	uint64_t set = 0;
	uint32_t st;
	int error;

	st = nfsv4_attr_parse(c, &sa->attrs, &va, &set);
	if (st == NFS4_OK && set != (1ULL << FATTR4_SIZE))
		st = NFS4ERR_ATTRNOTSUPP;
	if (st == NFS4_OK)
		st = nfsv4_io_check(c, &sa->stateid, true);
	if (st == NFS4_OK) {
		error = nfsv4_access_vp(cf, VWRITE);
		if (error == 0)
			error = xa_modify(cf, cf->cf_aname, va.va_size, NULL,
			    0, true);
		st = xa_errno(error);
	}
	if (st != NFS4_OK)
		set = 0;
	return nfsv4_attr_put_mask(c->c_rx, set) ? st : NFS4ERR_RESOURCE;
}

static uint32_t
xa_op_lookup(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_name *nm = &a->name.name;
	uint32_t st;

	st = nfsv4_name_check(c, nm);
	if (st != NFS4_OK)
		return st;
	return nfsv4_xattr_lookup(c, &c->c_cur, nm->nm_str, &c->c_cur);
}

static uint32_t
xa_op_lookupp(struct nfsv4_compound *c, union nfsv4_args *a)
{
	struct nfsv4_cfh *cf = &c->c_cur;

	return nfsv4_cfh_setattr(cf, cf->cf_attr == NFSV4_ATTR_FILE ?
	    NFSV4_ATTR_DIR : 0, "", 0);
}

static uint32_t
xa_change(const struct nfsv4_cfh *cf, struct nfsv4_change_info *ci, bool after)
{
	uint64_t *chp = after ? &ci->ci_after : &ci->ci_before;
	int error;

	vn_lock(cf->cf_vp, LK_SHARED | LK_RETRY);
	error = nfsv4_dir_change(cf->cf_vp, cf->cf_cred, chp);
	VOP_UNLOCK(cf->cf_vp);
	return nfsv4_errno(error);
}

static uint32_t
xa_op_remove(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_name *nm = &a->name.name;
	struct nfsv4_cfh *cf = &c->c_cur;
	struct nfsv4_change_info ci;
	uint32_t st;
	int error;

	st = nfsv4_name_check(c, nm);
	if (st != NFS4_OK)
		return st;
	memset(&ci, 0, sizeof(ci));
	st = xa_change(cf, &ci, false);
	if (st != NFS4_OK)
		return st;
	error = nfsv4_access_vp(cf, VWRITE);
	if (error != 0)
		return nfsv4_errno(error);
	vn_lock(cf->cf_vp, LK_EXCLUSIVE | LK_RETRY);
	error = VOP_DELETEEXTATTR(cf->cf_vp, XA_NS, nm->nm_str, cf->cf_cred);
	VOP_UNLOCK(cf->cf_vp);
	if (error != 0)
		return xa_errno(error);
	st = xa_change(cf, &ci, true);
	if (st != NFS4_OK)
		return st;
	return nfsv4_xdr_change_info(c->c_rx, &ci) ? NFS4_OK :
	    NFS4ERR_RESOURCE;
}

/* Within one attribute directory only, s5.3. */
static uint32_t
xa_op_rename(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_rename *ra = &a->rename;
	struct nfsv4_cfh *cf = &c->c_cur, *sf = &c->c_saved;
	struct nfsv4_change_info ci;
	struct vnode *vp = cf->cf_vp;
	struct iovec iov;
	struct uio uio;
	char *buf = NULL;
	size_t size = 0;
	uint32_t st;
	int error;

	if (!sf->cf_set)
		return NFS4ERR_NOFILEHANDLE;
	if (sf->cf_attr != NFSV4_ATTR_DIR || sf->cf_vp != vp)
		return NFS4ERR_XDEV;
	st = nfsv4_name_check(c, &ra->oldname);
	if (st == NFS4_OK)
		st = nfsv4_name_check(c, &ra->newname);
	if (st != NFS4_OK)
		return st;
	if (strlen(ra->newname.nm_str) > NFSV4_ANAME_MAX)
		return NFS4ERR_NAMETOOLONG;
	memset(&ci, 0, sizeof(ci));
	st = xa_change(cf, &ci, false);
	if (st != NFS4_OK)
		return st;
	error = nfsv4_access_vp(cf, VWRITE);
	if (error != 0)
		return nfsv4_errno(error);

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	error = xa_size_l(vp, ra->oldname.nm_str, cf->cf_cred, &size);
	if (error == 0 && size > NFSV4_ATTR_MAXSIZE)
		error = EFBIG;
	if (error == 0 && strcmp(ra->oldname.nm_str, ra->newname.nm_str) != 0) {
		if (size != 0) {
			buf = kmem_alloc(size, KM_SLEEP);
			xa_uio(&uio, &iov, buf, size, UIO_READ);
			error = VOP_GETEXTATTR(vp, XA_NS, ra->oldname.nm_str,
			    &uio, NULL, cf->cf_cred);
		}
		if (error == 0) {
			xa_uio(&uio, &iov, buf, size, UIO_WRITE);
			error = VOP_SETEXTATTR(vp, XA_NS, ra->newname.nm_str,
			    &uio, cf->cf_cred);
		}
		if (error == 0)
			error = VOP_DELETEEXTATTR(vp, XA_NS,
			    ra->oldname.nm_str, cf->cf_cred);
		if (buf != NULL)
			kmem_free(buf, size);
	}
	VOP_UNLOCK(vp);
	if (error != 0)
		return xa_errno(error);
	st = xa_change(cf, &ci, true);
	if (st != NFS4_OK)
		return st;
	return nfsv4_xdr_change_info(c->c_rx, &ci) &&
	    nfsv4_xdr_change_info(c->c_rx, &ci) ? NFS4_OK : NFS4ERR_RESOURCE;
}

/*
 * An operation with an attribute node as the current handle, s5.3 for
 * what is refused.  dflt is what would have run.
 */
uint32_t
nfsv4_xattr_op(struct nfsv4_compound *c, uint32_t op, union nfsv4_args *a,
    nfsv4_op_t dflt)
{
	bool dir = c->c_cur.cf_attr == NFSV4_ATTR_DIR;

	switch (op) {
	case NFSV4_OP_ACCESS:
	case NFSV4_OP_DELEGPURGE:
	case NFSV4_OP_GETATTR:
	case NFSV4_OP_GETFH:
	case NFSV4_OP_NVERIFY:
	case NFSV4_OP_PUTFH:
	case NFSV4_OP_PUTPUBFH:
	case NFSV4_OP_PUTROOTFH:
	case NFSV4_OP_RELEASE_LOCKOWNER:
	case NFSV4_OP_RENEW:
	case NFSV4_OP_RESTOREFH:
	case NFSV4_OP_SAVEFH:
	case NFSV4_OP_SETCLIENTID:
	case NFSV4_OP_SETCLIENTID_CONFIRM:
	case NFSV4_OP_VERIFY:
		return (*dflt)(c, a);
	case NFSV4_OP_LOOKUPP:
		return xa_op_lookupp(c, a);
	case NFSV4_OP_LOOKUP:
		return dir ? xa_op_lookup(c, a) : NFS4ERR_NOTDIR;
	case NFSV4_OP_OPEN:
	case NFSV4_OP_READDIR:
		return dir ? (*dflt)(c, a) : NFS4ERR_NOTDIR;
	case NFSV4_OP_REMOVE:
		return dir ? xa_op_remove(c, a) : NFS4ERR_NOTDIR;
	case NFSV4_OP_RENAME:
		return dir ? xa_op_rename(c, a) : NFS4ERR_NOTDIR;
	case NFSV4_OP_CLOSE:
	case NFSV4_OP_OPEN_CONFIRM:
	case NFSV4_OP_OPEN_DOWNGRADE:
		return dir ? NFS4ERR_ISDIR : (*dflt)(c, a);
	case NFSV4_OP_READ:
		return dir ? NFS4ERR_ISDIR : xa_op_read(c, a);
	case NFSV4_OP_WRITE:
		return dir ? NFS4ERR_ISDIR : xa_op_write(c, a);
	case NFSV4_OP_COMMIT:
		return dir ? NFS4ERR_ISDIR : xa_op_commit(c, a);
	case NFSV4_OP_LINK:
		return dir ? NFS4ERR_XDEV : NFS4ERR_NOTDIR;	/* s16.9.5 */
	case NFSV4_OP_SETATTR:
		if (!dir)
			return xa_op_setattr(c, a);
		return nfsv4_attr_put_mask(c->c_rx, 0) ? NFS4ERR_ISDIR :
		    NFS4ERR_RESOURCE;
	default:
		/* RFC 8881 s5.3 */
		return c->c_minor != 0 ? NFS4ERR_WRONG_TYPE : NFS4ERR_INVAL;
	}
}
