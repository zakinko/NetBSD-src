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
 * sec_label, RFC 7862 s12.2.4, in the Limited Server Mode of s9.5.2: a
 * label is stored and given back, and takes no part in access decisions,
 * the kernel having no MAC model for one to mean anything to.  A label
 * lives beside the ACLs of a file system in its system namespace, which
 * no user can reach, so that only SETATTR's access check guards it.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/extattr.h>
#include <sys/kmem.h>
#include <sys/mount.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/vnode.h>

#include <fs/nfsv4/nfsv4_var.h>

#define	NFSV4_LABEL_ATTR	"nfs4.sec_label"
#define	LABEL_HDR		8	/* lfs_lfs, lfs_pi */

static void
label_uio(struct uio *uio, struct iovec *iov, void *buf, size_t len,
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

/* A pseudo node has no label but must answer, s9.4. */
bool
nfsv4_label_supported(struct vnode *vp)
{

	return vp == NULL || nfsv4_xattr_supported(vp, NOCRED);
}

/* The sec_label4 of vp to x; a file never labelled has an empty one. */
bool
nfsv4_label_put(XDR *x, struct vnode *vp)
{
	struct iovec iov;
	struct uio uio;
	uint32_t lfs = 0, pi = 0, len = 0;
	size_t size = 0;
	char *buf;
	bool ok;
	int error;

	buf = kmem_alloc(LABEL_HDR + NFSV4_LABEL_MAX, KM_SLEEP);
	if (vp != NULL) {
		label_uio(&uio, &iov, buf, LABEL_HDR + NFSV4_LABEL_MAX,
		    UIO_READ);
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
		error = VOP_GETEXTATTR(vp, EXTATTR_NAMESPACE_SYSTEM,
		    NFSV4_LABEL_ATTR, &uio, NULL, NOCRED);
		VOP_UNLOCK(vp);
		if (error == 0)
			size = LABEL_HDR + NFSV4_LABEL_MAX - uio.uio_resid;
	}
	if (size >= LABEL_HDR) {
		lfs = be32dec(buf);
		pi = be32dec(buf + 4);
		len = size - LABEL_HDR;
	}
	ok = xdr_u_int32_t(x, &lfs) && xdr_u_int32_t(x, &pi) &&
	    xdr_u_int32_t(x, &len) &&
	    (len == 0 || xdr_opaque(x, buf + LABEL_HDR, len));
	kmem_free(buf, LABEL_HDR + NFSV4_LABEL_MAX);
	return ok;
}

/* Read a sec_label4 from x, to be stored by nfsv4_label_set(). */
uint32_t
nfsv4_label_parse(struct nfsv4_compound *c, XDR *x)
{
	uint32_t lfs, pi, len;

	if (!xdr_u_int32_t(x, &lfs) || !xdr_u_int32_t(x, &pi) ||
	    !xdr_u_int32_t(x, &len))
		return NFS4ERR_BADXDR;
	if (len > NFSV4_LABEL_MAX)
		return NFS4ERR_BADLABEL;
	if (c->c_setlabel == NULL)
		c->c_setlabel = kmem_alloc(LABEL_HDR + NFSV4_LABEL_MAX,
		    KM_SLEEP);
	be32enc(c->c_setlabel, lfs);
	be32enc(c->c_setlabel + 4, pi);
	c->c_setlabellen = LABEL_HDR + len;
	if (len != 0 && !xdr_opaque(x, c->c_setlabel + LABEL_HDR, len))
		return NFS4ERR_BADXDR;
	return NFS4_OK;
}

void
nfsv4_label_free(struct nfsv4_compound *c)
{

	if (c->c_setlabel != NULL)
		kmem_free(c->c_setlabel, LABEL_HDR + NFSV4_LABEL_MAX);
	c->c_setlabel = NULL;
	c->c_setlabellen = 0;
}

uint32_t
nfsv4_label_set(struct nfsv4_compound *c, struct vnode *vp, kauth_cred_t cred)
{
	struct iovec iov;
	struct uio uio;
	int error;

	if (c->c_setlabellen == 0)
		return NFS4_OK;
	label_uio(&uio, &iov, c->c_setlabel, c->c_setlabellen, UIO_WRITE);
	c->c_setlabellen = 0;
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	error = VOP_ACCESS(vp, VWRITE, cred);
	if (error == 0)
		error = VOP_SETEXTATTR(vp, EXTATTR_NAMESPACE_SYSTEM,
		    NFSV4_LABEL_ATTR, &uio, NOCRED);
	VOP_UNLOCK(vp);
	return error == EOPNOTSUPP ? NFS4ERR_ATTRNOTSUPP : nfsv4_errno(error);
}
