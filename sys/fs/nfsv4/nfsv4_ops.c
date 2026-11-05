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
 * Operations that read a file system and hold no state: ACCESS,
 * READLINK, READDIR and SECINFO.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/dirent.h>
#include <sys/kauth.h>
#include <sys/kmem.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/vnode.h>

#include <fs/nfsv4/nfsv4_var.h>

/*
 * Cookies 0, 1 and 2 may not be returned (RFC 7530 s16.24.4), and a file
 * system's own numbering starts low: tmpfs counts entries from 2.  So
 * the wire has the directory offset plus this.
 */
#define	NFSV4_COOKIE_BASE	3

#define	NFSV4_DIRBUF		8192
#define	NFSV4_READDIR_MAX	(64 * 1024)	/* of the result; a choice */
#define	NFSV4_PSEUDO_MAXNAMES	64		/* of one directory; a choice */

/*
 * nfsrv_access(), with the export and the lock taken here: may the
 * credential of cf do mode to its vnode.
 */
int
nfsv4_access_vp(const struct nfsv4_cfh *cf, int mode)
{
	struct vnode *vp = cf->cf_vp;
	int error;

	if ((mode & VWRITE) != 0) {
		if (((cf->cf_exflags & MNT_EXRDONLY) != 0 ||
		    (vp->v_mount->mnt_flag & MNT_RDONLY) != 0) &&
		    (vp->v_type == VREG || vp->v_type == VDIR ||
		    vp->v_type == VLNK))
			return EROFS;
		if ((vp->v_iflag & VI_TEXT) != 0)
			return ETXTBSY;
	}
	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = VOP_ACCESS(vp, mode, cf->cf_cred);
	VOP_UNLOCK(vp);
	return error;
}

/* RFC 7530 s16.1.2 */
#define	ACCESS4_ALL	(ACCESS4_READ | ACCESS4_LOOKUP | ACCESS4_MODIFY | \
			 ACCESS4_EXTEND | ACCESS4_DELETE | ACCESS4_EXECUTE)
#define	ACCESS4_XATTRS	(ACCESS4_XAREAD | ACCESS4_XAWRITE | ACCESS4_XALIST)

uint32_t
nfsv4_op_access(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_cfh *cf = &c->c_cur;
	struct vnode *vp = cf->cf_vp;
	uint32_t want = a->access.access, sup, got = 0, known;
	bool isdir;

	known = ACCESS4_ALL | (c->c_minor >= 2 ? ACCESS4_XATTRS : 0);
	if ((want & ~known) != 0)
		return NFS4ERR_INVAL;

	isdir = vp == NULL || vp->v_type == VDIR;
	sup = want;
	/*
	 * RFC 7530 s16.1.4: LOOKUP means nothing for a non-directory and
	 * EXECUTE nothing for a directory, and s16.1.5 has DELETE of a
	 * file be something this kind of file system cannot tell.
	 */
	if (!isdir)
		sup &= ~(ACCESS4_DELETE | ACCESS4_LOOKUP);
	else
		sup &= ~ACCESS4_EXECUTE;
	if ((want & ACCESS4_XATTRS) != 0 &&
	    !nfsv4_xattr_supported(vp, cf->cf_cred))
		sup &= ~ACCESS4_XATTRS;

	if (vp == NULL)
		/* s7.3: the pseudo file system is read-only. */
		got = sup & (ACCESS4_READ | ACCESS4_LOOKUP);
	else {
		if ((sup & ACCESS4_READ) != 0 &&
		    nfsv4_access_vp(cf, VREAD) == 0)
			got |= ACCESS4_READ;
		if ((sup & (ACCESS4_LOOKUP | ACCESS4_EXECUTE)) != 0 &&
		    nfsv4_access_vp(cf, VEXEC) == 0)
			got |= sup & (ACCESS4_LOOKUP | ACCESS4_EXECUTE);
		if ((sup & (ACCESS4_MODIFY | ACCESS4_EXTEND |
		    ACCESS4_DELETE)) != 0 && nfsv4_access_vp(cf, VWRITE) == 0)
			got |= sup & (ACCESS4_MODIFY | ACCESS4_EXTEND |
			    ACCESS4_DELETE);
		/* RFC 8276 s8.5, as extattr_check_cred() does the user's. */
		if ((sup & (ACCESS4_XAREAD | ACCESS4_XALIST)) != 0 &&
		    nfsv4_access_vp(cf, VREAD) == 0)
			got |= sup & (ACCESS4_XAREAD | ACCESS4_XALIST);
		if ((sup & ACCESS4_XAWRITE) != 0 &&
		    nfsv4_access_vp(cf, VWRITE) == 0)
			got |= ACCESS4_XAWRITE;
	}
	return xdr_u_int32_t(c->c_rx, &sup) && xdr_u_int32_t(c->c_rx, &got) ?
	    NFS4_OK : NFS4ERR_RESOURCE;
}

uint32_t
nfsv4_op_readlink(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_cfh *cf = &c->c_cur;
	struct vnode *vp = cf->cf_vp;
	struct iovec iov;
	struct uio uio;
	char *buf;
	uint32_t len;
	uint32_t st;
	int error;

	/* RFC 7530 s16.25.5 */
	if (vp == NULL || vp->v_type != VLNK)
		/* RFC 8881 s18.24.3 */
		return c->c_minor != 0 ? NFS4ERR_WRONG_TYPE : NFS4ERR_INVAL;

	buf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	iov.iov_base = buf;
	iov.iov_len = MAXPATHLEN;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = 0;
	uio.uio_resid = MAXPATHLEN;
	uio.uio_rw = UIO_READ;
	UIO_SETUP_SYSSPACE(&uio);
	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = VOP_READLINK(vp, &uio, cf->cf_cred);
	VOP_UNLOCK(vp);
	st = nfsv4_errno(error);
	if (st == NFS4_OK) {
		len = MAXPATHLEN - uio.uio_resid;
		if (!xdr_u_int32_t(c->c_rx, &len) ||
		    !xdr_opaque(c->c_rx, buf, len))
			st = NFS4ERR_RESOURCE;
	}
	kmem_free(buf, MAXPATHLEN);
	return st;
}

/* A READDIR in progress; the result is built in rd_out. */
struct readdir_state {
	struct nfsv4_compound	*rd_c;
	struct nfsv4_cfh	*rd_dir;
	const struct nfsv4_bitmap *rd_mask;
	XDR		rd_x;
	char		*rd_out;
	u_int		rd_limit;	/* of rd_out */
	char		*rd_attrs;	/* NFSV4_ATTRBUF */
	u_int		rd_nent;
	bool		rd_full;
};

/*
 * Add one entry, RFC 7530 s16.24.3.  An error from reaching the object
 * goes in the entry as rdattr_error if that was asked for, and otherwise
 * fails the READDIR, s16.24.4.  An entry that has gone since the
 * directory was read is left out.
 */
static uint32_t
readdir_entry(struct readdir_state *rd, const char *name, size_t namelen,
    uint64_t cookie)
{
	struct nfsv4_cfh cf;
	struct nfsv4_bitmap got;
	const struct nfsv4_bitmap *m = rd->rd_mask;
	uint32_t follows = 1, len32 = (uint32_t)namelen, alen32, st, rderr;
	u_int alen = 0, need;
	char lname[NFSV4_NAME_MAX + 1];

	memset(&cf, 0, sizeof(cf));
	memset(&got, 0, sizeof(got));
	if (namelen > NFSV4_NAME_MAX)
		return NFS4_OK;		/* cannot be asked for by name */
	memcpy(lname, name, namelen);
	lname[namelen] = '\0';

	st = NFS4_OK;
	rderr = NFS4_OK;
	if (m->bm_n != 0) {
		rderr = nfsv4_cfh_lookup(rd->rd_c, rd->rd_dir, lname, namelen,
		    &cf);
		if (rderr == NFS4ERR_NOENT)
			return NFS4_OK;
		/* RFC 8881 s18.29.4, the only way READDIR can say this. */
		if (rderr == NFS4_OK && cf.cf_wrongsec)
			rderr = NFS4ERR_WRONGSEC;
		/* s8.3.2 */
		if (rderr == NFS4_OK && cf.cf_ref != NULL &&
		    (m->bm_w[0] & (1U << FATTR4_FS_LOCATIONS)) == 0) {
			rderr = NFS4ERR_MOVED;
			if ((m->bm_w[0] & (1U << FATTR4_RDATTR_ERROR)) == 0) {
				nfsv4_cfh_clear(&cf);
				return rderr;
			}
		}
		if (rderr != NFS4_OK) {
			if ((m->bm_w[0] & (1U << FATTR4_RDATTR_ERROR)) == 0)
				return rderr;
		}
		st = nfsv4_attr_fill(rd->rd_c, &cf, m, rderr, rd->rd_attrs,
		    NFSV4_ATTRBUF, &got, &alen);
		nfsv4_cfh_clear(&cf);
		if (st != NFS4_OK)
			return st;
	}

	/*
	 * Space for this entry: follows, cookie, name, bitmap, length,
	 * values; and after it the last follows and eof.
	 */
	need = 4 + 8 + 4 + roundup2(namelen, 4) + 4 + 4 * got.bm_n + 4 +
	    alen + 8;
	if (xdr_getpos(&rd->rd_x) + need > rd->rd_limit) {
		rd->rd_full = true;
		return rd->rd_nent == 0 ? NFS4ERR_TOOSMALL : NFS4_OK;
	}
	alen32 = alen;
	if (!xdr_u_int32_t(&rd->rd_x, &follows) ||
	    !xdr_u_int64_t(&rd->rd_x, &cookie) ||
	    !xdr_u_int32_t(&rd->rd_x, &len32) ||
	    !xdr_opaque(&rd->rd_x, lname, len32) ||
	    !nfsv4_xdr_bitmap(&rd->rd_x, &got) ||
	    !xdr_u_int32_t(&rd->rd_x, &alen32) ||
	    !XDR_PUTBYTES(&rd->rd_x, rd->rd_attrs, alen))
		return NFS4ERR_SERVERFAULT;
	rd->rd_nent++;
	return NFS4_OK;
}

struct pseudo_names {
	u_int	pn_n;
	char	(*pn_names)[NFSV4_NAME_MAX + 1];
};

static int
pseudo_names_fn(struct mount *mp, const char *rest, size_t len, void *arg)
{
	struct pseudo_names *pn = arg;
	const char *end;
	size_t n;
	u_int i;

	if (len == 0)
		return 0;
	rest++;			/* the '/' */
	len--;
	end = memchr(rest, '/', len);
	n = end != NULL ? (size_t)(end - rest) : len;
	if (n > NFSV4_NAME_MAX)
		return 0;
	for (i = 0; i < pn->pn_n; i++) {
		if (strlen(pn->pn_names[i]) == n &&
		    memcmp(pn->pn_names[i], rest, n) == 0)
			return 0;
	}
	if (pn->pn_n == NFSV4_PSEUDO_MAXNAMES)
		return 1;
	memcpy(pn->pn_names[pn->pn_n], rest, n);
	pn->pn_names[pn->pn_n][n] = '\0';
	pn->pn_n++;
	return 0;
}

/*
 * A pseudo directory.  Its cookies are positions in the list of names,
 * in the order of the mount list.
 */
static uint32_t
readdir_pseudo(struct readdir_state *rd, uint64_t cookie, bool *eofp)
{
	struct pseudo_names pn;
	const char *path;
	size_t len;
	uint64_t i;
	uint32_t st;

	path = nfsv4_cfh_path(rd->rd_dir, &len);
	pn.pn_n = 0;
	pn.pn_names = kmem_alloc(NFSV4_PSEUDO_MAXNAMES * sizeof(*pn.pn_names),
	    KM_SLEEP);
	(void)nfsv4_pseudo_walk(rd->rd_c, path, len, pseudo_names_fn, &pn);

	st = NFS4_OK;
	i = cookie == 0 ? 0 : cookie - NFSV4_COOKIE_BASE + 1;
	for (; i < pn.pn_n && st == NFS4_OK && !rd->rd_full; i++)
		st = readdir_entry(rd, pn.pn_names[i], strlen(pn.pn_names[i]),
		    i + NFSV4_COOKIE_BASE);
	*eofp = !rd->rd_full;
	kmem_free(pn.pn_names, NFSV4_PSEUDO_MAXNAMES * sizeof(*pn.pn_names));
	return st;
}

/*
 * A real directory.  The vnode is not locked while entries are looked
 * up, as that takes the directory's lock.  VOP_READDIR's cookies are
 * the offset following each entry, which is what a client should come
 * back with to go on after that entry.
 */
static uint32_t
readdir_real(struct readdir_state *rd, uint64_t cookie, bool *eofp)
{
	struct vnode *vp = rd->rd_dir->cf_vp;
	kauth_cred_t cred = rd->rd_dir->cf_cred;
	struct iovec iov;
	struct uio uio;
	struct dirent *dp;
	off_t off, *cookies;
	char *dbuf, *cp, *end;
	int eof, ncookies, i, error;
	uint32_t st;

	dbuf = kmem_alloc(NFSV4_DIRBUF, KM_SLEEP);
	off = cookie == 0 ? 0 : (off_t)(cookie - NFSV4_COOKIE_BASE);
	st = NFS4_OK;
	*eofp = false;

	while (st == NFS4_OK && !rd->rd_full) {
		iov.iov_base = dbuf;
		iov.iov_len = NFSV4_DIRBUF;
		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_offset = off;
		uio.uio_resid = NFSV4_DIRBUF;
		uio.uio_rw = UIO_READ;
		UIO_SETUP_SYSSPACE(&uio);
		eof = 0;
		cookies = NULL;
		ncookies = 0;
		vn_lock(vp, LK_SHARED | LK_RETRY);
		error = VOP_READDIR(vp, &uio, cred, &eof, &cookies, &ncookies);
		VOP_UNLOCK(vp);
		/*
		 * Past the end, ZFS gives nothing at all, and FFS and tmpfs
		 * refuse an offset they cannot use: a cookie that was never
		 * given out, s13.1.1.2.
		 */
		if (error == 0 && cookies == NULL) {
			if (uio.uio_resid == NFSV4_DIRBUF) {
				*eofp = true;
				break;
			}
			error = EOPNOTSUPP;
		}
		if (cookie != 0 && (error == EINVAL || error == EFBIG))
			st = NFS4ERR_BAD_COOKIE;
		if (error != 0) {
			if (cookies != NULL)
				free(cookies, M_TEMP);
			if (st == NFS4_OK)
				st = nfsv4_errno(error);
			break;
		}
		off = uio.uio_offset;

		cp = dbuf;
		end = dbuf + NFSV4_DIRBUF - uio.uio_resid;
		for (i = 0; i < ncookies && cp < end && st == NFS4_OK &&
		    !rd->rd_full; i++) {
			dp = (struct dirent *)cp;
			cp += dp->d_reclen;
			if (dp->d_fileno == 0 ||
			    (dp->d_name[0] == '.' && (dp->d_namlen == 1 ||
			    (dp->d_namlen == 2 && dp->d_name[1] == '.'))))
				continue;
			st = readdir_entry(rd, dp->d_name, dp->d_namlen,
			    (uint64_t)cookies[i] + NFSV4_COOKIE_BASE);
		}
		free(cookies, M_TEMP);
		if (eof != 0 || end == dbuf) {
			*eofp = !rd->rd_full;
			break;
		}
	}
	kmem_free(dbuf, NFSV4_DIRBUF);
	return st;
}

/* Named attributes.  Cookies are positions in the file system's list. */
static uint32_t
readdir_xattr(struct readdir_state *rd, uint64_t cookie, bool *eofp)
{
	char *buf = NULL;
	size_t len, alen, off;
	uint64_t i, first;
	uint32_t st = NFS4_OK;
	u_int n;
	int error;

	error = nfsv4_xattr_list(rd->rd_dir, &buf, &len, &alen);
	if (error != 0)
		return nfsv4_errno(error);
	first = cookie == 0 ? 0 : cookie - NFSV4_COOKIE_BASE + 1;
	for (i = 0, off = 0; off < len && st == NFS4_OK && !rd->rd_full; i++) {
		n = (uint8_t)buf[off++];
		if (n > len - off)
			break;
		if (i >= first && n <= NFSV4_ANAME_MAX && n != 0)
			st = readdir_entry(rd, buf + off, n,
			    i + NFSV4_COOKIE_BASE);
		off += n;
	}
	*eofp = !rd->rd_full;
	if (alen != 0)
		kmem_free(buf, alen);
	return st;
}

uint32_t
nfsv4_op_readdir(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_readdir *ra = &a->readdir;
	struct nfsv4_cfh *cf = &c->c_cur;
	struct readdir_state rd;
	struct nfsv4_verifier verf;
	uint32_t st, zero = 0, eofw;
	u_int i;
	bool eof = false;

	if (cf->cf_vp != NULL && cf->cf_attr == 0 &&
	    cf->cf_vp->v_type != VDIR)
		return NFS4ERR_NOTDIR;
	if (!nfsv4_attr_getonly_ok(&ra->mask))
		return NFS4ERR_INVAL;
	/* RFC 7530 s16.24.4 */
	if (ra->cookie == 1 || ra->cookie == 2)
		return NFS4ERR_BAD_COOKIE;
	/*
	 * No cookie given out is this large, and readdir_real() would make
	 * a negative offset of it for the file system; s13.1.1.2.
	 */
	if (ra->cookie != 0 &&
	    ra->cookie - NFSV4_COOKIE_BASE >= (uint64_t)INT64_MAX)
		return NFS4ERR_BAD_COOKIE;

	/*
	 * The cookies are offsets, valid for as long as the directory is
	 * the same directory, so the verifier is always zero.  One that
	 * is not was never given out.
	 */
	memset(&verf, 0, sizeof(verf));
	if (ra->cookie != 0) {
		for (i = 0; i < sizeof(verf.v_data); i++) {
			if (ra->cookieverf.v_data[i] != 0)
				return NFS4ERR_NOT_SAME;
		}
	}

	if (cf->cf_vp != NULL) {
		int error = nfsv4_access_vp(cf, VREAD);

		if (error != 0)
			return nfsv4_errno(error);
	}

	memset(&rd, 0, sizeof(rd));
	rd.rd_c = c;
	rd.rd_dir = cf;
	rd.rd_mask = &ra->mask;
	rd.rd_limit = MIN(ra->maxcount, NFSV4_READDIR_MAX);
	if (rd.rd_limit < sizeof(verf) + 8)
		return NFS4ERR_TOOSMALL;
	rd.rd_out = kmem_alloc(rd.rd_limit, KM_SLEEP);
	rd.rd_attrs = kmem_alloc(NFSV4_ATTRBUF, KM_SLEEP);
	xdrmem_create(&rd.rd_x, rd.rd_out, rd.rd_limit, XDR_ENCODE);

	if (!nfsv4_xdr_verifier(&rd.rd_x, &verf))
		panic("nfsv4_op_readdir: limit");
	if (cf->cf_attr != 0)
		st = readdir_xattr(&rd, ra->cookie, &eof);
	else if (cf->cf_vp == NULL)
		st = readdir_pseudo(&rd, ra->cookie, &eof);
	else
		st = readdir_real(&rd, ra->cookie, &eof);

	if (st == NFS4_OK) {
		eofw = eof;
		if (!xdr_u_int32_t(&rd.rd_x, &zero) ||
		    !xdr_u_int32_t(&rd.rd_x, &eofw) ||
		    !XDR_PUTBYTES(c->c_rx, rd.rd_out,
		    xdr_getpos(&rd.rd_x)))
			st = NFS4ERR_RESOURCE;
	}
	kmem_free(rd.rd_attrs, NFSV4_ATTRBUF);
	kmem_free(rd.rd_out, rd.rd_limit);
	return st;
}

/*
 * RFC 7530 s16.31.  Every object has the same flavors, as the exports
 * say nothing about them yet (decisions.md, sec=).  Lookup is done for
 * the errors it gives.
 */
uint32_t
nfsv4_op_secinfo(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_name *nm = &a->name.name;
	struct nfsv4_cfh *cf = &c->c_cur, to;
	uint32_t st, n = 2, sys = ONCRPC_AUTH_SYS, none = ONCRPC_AUTH_NONE;

	if (cf->cf_vp != NULL && cf->cf_vp->v_type != VDIR)
		return NFS4ERR_NOTDIR;
	st = nfsv4_name_check(c, nm);
	if (st != NFS4_OK)
		return st;
	memset(&to, 0, sizeof(to));
	st = nfsv4_cfh_lookup(c, cf, nm->nm_str, nm->nm_len, &to);
	nfsv4_cfh_clear(&to);
	if (st != NFS4_OK)
		return st;
	/* RFC 8881 s18.29.3 */
	if (c->c_minor != 0)
		nfsv4_cfh_clear(cf);
	return xdr_u_int32_t(c->c_rx, &n) && xdr_u_int32_t(c->c_rx, &sys) &&
	    xdr_u_int32_t(c->c_rx, &none) ? NFS4_OK : NFS4ERR_RESOURCE;
}

/* RFC 8881 s18.45.  The flavors are those of everything, as above. */
uint32_t
nfsv4_op_secinfo_no_name(struct nfsv4_compound *c, union nfsv4_args *a)
{
	uint32_t st, n = 2, sys = ONCRPC_AUTH_SYS, none = ONCRPC_AUTH_NONE;

	if (a->u32.value == SECINFO_STYLE4_PARENT) {
		st = nfsv4_lookupp(c);
		if (st != NFS4_OK)
			return st;
	}
	nfsv4_cfh_clear(&c->c_cur);
	return xdr_u_int32_t(c->c_rx, &n) && xdr_u_int32_t(c->c_rx, &sys) &&
	    xdr_u_int32_t(c->c_rx, &none) ? NFS4_OK : NFS4ERR_RESOURCE;
}
