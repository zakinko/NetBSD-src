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
 * Named attributes as the NFS servers see them, on the extended
 * attributes of the file system in the namespace user: the namespace
 * system is where FFS keeps ACLs and the file system's own things.
 * Version 4 (fs/nfsv4/nfsv4_xattr.c, RFC 7530 s5.3) and versions 2 and 3
 * with illumos' GETXATTRDIR (nfs/nfs_srvxattr.c) speak to the same
 * attributes through what is here, which knows of no protocol: a vnode,
 * a credential, a name and an errno.
 *
 * The VFS has no vnode for an attribute, so the servers keep the vnode
 * of the file and mark their handles with what the node is and a key of
 * its name; the key is the first bytes of SHA-256 of the name, and the
 * name is found again among the file's own.  There is no table to lose,
 * and a handle stays good across a restart of the server.
 *
 * The VOPs have no offset: an attribute is read and written whole, with
 * the vnode locked across the two for a partial write, and
 * NFS_XATTR_MAXSIZE keeps that bounded.  The vnodes given here are
 * unlocked; each function locks as it needs.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/extattr.h>
#include <sys/kauth.h>
#include <sys/kmem.h>
#include <sys/module.h>
#include <sys/sha2.h>
#include <sys/stat.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/vnode.h>

#include <nfs/nfs_xattr.h>

MODULE(MODULE_CLASS_MISC, nfsxattr, NULL);

static int
nfsxattr_modcmd(modcmd_t cmd, void *arg)
{

	switch (cmd) {
	case MODULE_CMD_INIT:
	case MODULE_CMD_FINI:
		return 0;
	default:
		return ENOTTY;
	}
}

/*
 * The first n bytes of SHA-256 of the name: nobody finds a pair by
 * chance, nor needs to.  A key of four bytes, which is all a handle of
 * version 2 has room for, is never 0 nor 0xffffffff as a big endian
 * word, so that those can mean something else beside it; 0 and
 * 0xffffffff become 1 and 0xfffffffe.
 */
void
nfs_xattr_key(const char *name, size_t len, uint8_t *out, size_t n)
{
	SHA256_CTX ctx;
	uint8_t d[SHA256_DIGEST_LENGTH];
	uint32_t v;

	KASSERT(n <= NFS_XATTR_KEYMAX);
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, (const uint8_t *)name, len);
	SHA256_Final(d, &ctx);
	if (n == sizeof(v)) {
		v = be32dec(d);
		if (v == 0)
			v = 1;
		else if (v == 0xffffffff)
			v = 0xfffffffe;
		be32enc(d, v);
	}
	memcpy(out, d, n);
}

/*
 * A number of the node's own among the file system's: the file's mixed
 * with the name by FNV-1a's step, the top bit set.  The directory mixes
 * in "/", which no attribute is named, so that it differs from the file
 * even in the 32 bits of version 2.
 */
uint64_t
nfs_xattr_fileid(uint64_t id, int kind, const char *name)
{

	if (kind == NFS_XATTR_DIR)
		name = "/";
	for (; *name != '\0'; name++)
		id = (id ^ (uint8_t)*name) * 0x100000001b3ULL;
	return id | (1ULL << 63);
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
	return VOP_GETEXTATTR(vp, NFS_XATTR_NS, name, NULL, sizep, cred);
}

int
nfs_xattr_size(struct vnode *vp, kauth_cred_t cred, const char *name,
    uint64_t *sizep)
{
	size_t size;
	int error;

	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = xa_size_l(vp, name, cred, &size);
	VOP_UNLOCK(vp);
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
nfs_xattr_list(struct vnode *vp, kauth_cred_t cred, char **bufp, size_t *lenp,
    size_t *alenp)
{
	struct iovec iov;
	struct uio uio;
	size_t size = 0;
	char *buf = NULL;
	int error;

	*alenp = 0;
	*lenp = 0;
	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = VOP_LISTEXTATTR(vp, NFS_XATTR_NS, NULL, &size,
	    EXTATTR_LIST_LENPREFIX, cred);
	if (error == 0 && size != 0) {
		buf = kmem_alloc(size, KM_SLEEP);
		xa_uio(&uio, &iov, buf, size, UIO_READ);
		error = VOP_LISTEXTATTR(vp, NFS_XATTR_NS, &uio, NULL,
		    EXTATTR_LIST_LENPREFIX, cred);
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
 * Walk the names; f returns true to stop.  The names are not
 * terminated.
 */
static int
xa_walk(struct vnode *vp, kauth_cred_t cred,
    bool (*f)(const char *, size_t, void *), void *arg)
{
	char *buf = NULL;
	size_t len, alen, off;
	u_int n;
	int error;

	error = nfs_xattr_list(vp, cred, &buf, &len, &alen);
	if (error != 0)
		return error;
	for (off = 0; off < len; off += n) {
		n = (uint8_t)buf[off++];
		if (n > len - off)
			break;
		if (n != 0 && (*f)(buf + off, n, arg))
			break;
	}
	if (alen != 0)
		kmem_free(buf, alen);
	return 0;
}

struct xa_match {
	const uint8_t	*xm_key;
	size_t		 xm_keylen;
	const char	*xm_skip;	/* a name not to count */
	char		*xm_name;	/* the first found */
	u_int		 xm_count;
};

static bool
xa_match(const char *name, size_t n, void *arg)
{
	struct xa_match *xm = arg;
	uint8_t k[NFS_XATTR_KEYMAX];

	if (xm->xm_skip != NULL && strlen(xm->xm_skip) == n &&
	    memcmp(xm->xm_skip, name, n) == 0)
		return false;
	nfs_xattr_key(name, n, k, xm->xm_keylen);
	if (memcmp(k, xm->xm_key, xm->xm_keylen) != 0)
		return false;
	if (xm->xm_count++ == 0 && xm->xm_name != NULL) {
		memcpy(xm->xm_name, name, n);
		xm->xm_name[n] = '\0';
	}
	return false;
}

/*
 * The name with this key, into name[NFS_XATTR_NAMEMAX + 1]; ESTALE if
 * there is none.  Two names of one key are EIO: which of them a handle
 * meant cannot be told, and the other must not be given in its place.
 * nfs_xattr_unique() keeps the servers from making a second.
 */
int
nfs_xattr_byhash(struct vnode *vp, kauth_cred_t cred, const uint8_t *key,
    size_t keylen, char *name)
{
	struct xa_match xm = {
		.xm_key = key, .xm_keylen = keylen, .xm_name = name,
	};
	int error;

	error = xa_walk(vp, cred, xa_match, &xm);
	if (error != 0)
		return error;
	return xm.xm_count == 0 ? ESTALE : xm.xm_count > 1 ? EIO : 0;
}

/* EEXIST if a name other than this one has its key of keylen bytes. */
int
nfs_xattr_unique(struct vnode *vp, kauth_cred_t cred, const char *name,
    size_t keylen)
{
	uint8_t k[NFS_XATTR_KEYMAX];
	struct xa_match xm = {
		.xm_key = k, .xm_keylen = keylen, .xm_skip = name,
	};
	int error;

	nfs_xattr_key(name, strlen(name), k, keylen);
	error = xa_walk(vp, cred, xa_match, &xm);
	if (error != 0)
		return error;
	return xm.xm_count != 0 ? EEXIST : 0;
}

/* Does the file have any?  EOPNOTSUPP where it cannot. */
int
nfs_xattr_any(struct vnode *vp, kauth_cred_t cred, bool *anyp)
{
	size_t size = 0;
	int error;

	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = VOP_LISTEXTATTR(vp, NFS_XATTR_NS, NULL, &size,
	    EXTATTR_LIST_LENPREFIX, cred);
	VOP_UNLOCK(vp);
	*anyp = error == 0 && size != 0;
	return error;
}

/*
 * Up to len bytes at off into buf, *gotp of them; *sizep is the size of
 * the attribute.
 */
int
nfs_xattr_read(struct vnode *vp, kauth_cred_t cred, const char *name,
    uint64_t off, void *out, size_t len, size_t *gotp, uint64_t *sizep)
{
	struct iovec iov;
	struct uio uio;
	char *buf = NULL;
	size_t size, asize = 0;
	int error;

	*gotp = 0;
	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = xa_size_l(vp, name, cred, &size);
	if (error == 0 && size > NFS_XATTR_MAXSIZE)
		error = EFBIG;
	if (error == 0 && size != 0) {
		asize = size;
		buf = kmem_alloc(asize, KM_SLEEP);
		xa_uio(&uio, &iov, buf, size, UIO_READ);
		error = VOP_GETEXTATTR(vp, NFS_XATTR_NS, name, &uio, NULL,
		    cred);
		/* It may have shrunk between the two. */
		if (error == 0)
			size -= uio.uio_resid;
	}
	VOP_UNLOCK(vp);
	if (error == 0) {
		*sizep = size;
		if (off < size) {
			*gotp = MIN(size - off, len);
			memcpy(out, buf + off, *gotp);
		}
	}
	if (buf != NULL)
		kmem_free(buf, asize);
	return error;
}

/*
 * Write n bytes at off, the vnode locked across reading and writing.
 * With truncate, the attribute then ends after them.  One that is not
 * there is made.
 */
int
nfs_xattr_write(struct vnode *vp, kauth_cred_t cred, const char *name,
    uint64_t off, const void *data, size_t n, bool truncate)
{
	struct iovec iov;
	struct uio uio;
	char *buf = NULL;
	size_t old = 0, new;
	int error;

	if (off > NFS_XATTR_MAXSIZE || n > NFS_XATTR_MAXSIZE - off)
		return EFBIG;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	error = xa_size_l(vp, name, cred, &old);
	if (error == ENOATTR) {
		old = 0;
		error = 0;
	}
	if (error != 0 || old > NFS_XATTR_MAXSIZE) {
		VOP_UNLOCK(vp);
		return error != 0 ? error : EFBIG;
	}
	new = truncate ? off + n : MAX(old, off + n);
	if (new != 0) {
		buf = kmem_zalloc(new, KM_SLEEP);
		if (old != 0) {
			xa_uio(&uio, &iov, buf, MIN(old, new), UIO_READ);
			error = VOP_GETEXTATTR(vp, NFS_XATTR_NS, name, &uio,
			    NULL, cred);
		}
		if (error == 0 && n != 0)
			memcpy(buf + off, data, n);
	}
	if (error == 0) {
		xa_uio(&uio, &iov, buf, new, UIO_WRITE);
		error = VOP_SETEXTATTR(vp, NFS_XATTR_NS, name, &uio, cred);
	}
	VOP_UNLOCK(vp);
	if (buf != NULL)
		kmem_free(buf, new);
	return error;
}

/*
 * Make an empty attribute if it is not there.  If it is: EEXIST with
 * excl, else emptied with truncate.
 */
int
nfs_xattr_create(struct vnode *vp, kauth_cred_t cred, const char *name,
    bool excl, bool truncate)
{
	uint64_t size;
	int error;

	if (strlen(name) > NFS_XATTR_NAMEMAX)
		return ENAMETOOLONG;
	error = nfs_xattr_size(vp, cred, name, &size);
	if (error == 0 && excl)
		return EEXIST;
	if (error == ENOATTR || (error == 0 && truncate))
		return nfs_xattr_write(vp, cred, name, 0, NULL, 0, true);
	return error;
}

int
nfs_xattr_remove(struct vnode *vp, kauth_cred_t cred, const char *name)
{
	int error;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	error = VOP_DELETEEXTATTR(vp, NFS_XATTR_NS, name, cred);
	VOP_UNLOCK(vp);
	return error;
}

/* Within one file only: the VOPs have no rename. */
int
nfs_xattr_rename(struct vnode *vp, kauth_cred_t cred, const char *from,
    const char *to)
{
	struct iovec iov;
	struct uio uio;
	char *buf = NULL;
	size_t size = 0;
	int error;

	if (strlen(to) > NFS_XATTR_NAMEMAX)
		return ENAMETOOLONG;
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	error = xa_size_l(vp, from, cred, &size);
	if (error == 0 && size > NFS_XATTR_MAXSIZE)
		error = EFBIG;
	if (error == 0 && strcmp(from, to) != 0) {
		if (size != 0) {
			buf = kmem_alloc(size, KM_SLEEP);
			xa_uio(&uio, &iov, buf, size, UIO_READ);
			error = VOP_GETEXTATTR(vp, NFS_XATTR_NS, from, &uio,
			    NULL, cred);
		}
		if (error == 0) {
			xa_uio(&uio, &iov, buf, size, UIO_WRITE);
			error = VOP_SETEXTATTR(vp, NFS_XATTR_NS, to, &uio,
			    cred);
		}
		if (error == 0)
			error = VOP_DELETEEXTATTR(vp, NFS_XATTR_NS, from, cred);
		if (buf != NULL)
			kmem_free(buf, size);
	}
	VOP_UNLOCK(vp);
	return error;
}

/*
 * The attributes of a node, made from the file's.  The directory is as
 * illumos makes one for a file system with no directory of its own,
 * xattr_dir_getattr() in usr/src/uts/common/fs/xattr.c:1079-1131 at
 * 586678ac1bc: the owner, the group and the times but the access time
 * from the file (PARENT_ATTRMASK, 1075), a directory of mode 01777
 * (1124), two links and a size of two, there being none of the entries
 * of illumos' own system attributes (1126-1127), accessed now.  Who may
 * read or write the attributes is the file system's to say, by the
 * file's mode.  An attribute is a regular file of the file's mode, one
 * link, its own size.
 */
int
nfs_xattr_vattr(struct vnode *vp, kauth_cred_t cred, int kind,
    const char *name, struct vattr *va)
{
	uint64_t size = 0;
	int error;

	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = VOP_GETATTR(vp, va, cred);
	VOP_UNLOCK(vp);
	if (error == 0 && kind == NFS_XATTR_FILE)
		error = nfs_xattr_size(vp, cred, name, &size);
	if (error != 0)
		return error;
	va->va_fileid = nfs_xattr_fileid(va->va_fileid, kind, name);
	va->va_rdev = 0;
	switch (kind) {
	case NFS_XATTR_DIR:
		va->va_type = VDIR;
		va->va_mode = S_ISVTX | ACCESSPERMS;
		va->va_nlink = 2;
		va->va_size = 2;
		va->va_bytes = 0;
		getnanotime(&va->va_atime);
		break;
	case NFS_XATTR_FILE:
		va->va_type = VREG;
		va->va_mode &= ALLPERMS;
		va->va_nlink = 1;
		va->va_size = size;
		va->va_bytes = size;
		break;
	}
	return 0;
}
