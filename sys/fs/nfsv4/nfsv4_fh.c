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
 * File handles and the name space, RFC 7530 s4 and s7.
 *
 * The form of a handle is the server's own, opaque to clients (RFC 7530
 * s4.2.1).  The first byte says what the rest is, and three more keep
 * what follows aligned:
 *
 *	NFSV4_FHT_REAL		fhandle_t, from vfs_composefh()
 *	NFSV4_FHT_PSEUDO	path of a node of the pseudo file system
 *	NFSV4_FHT_ATTRDIR	as REAL: the named attributes of that file
 *	NFSV4_FHT_ATTR		as REAL, then a hash of the name
 *
 * The pseudo file system is computed, with no table behind it.  Its
 * nodes are the proper ancestors of the mount points exported to this
 * client (RFC 7530 s7.3), a path being a node exactly when that is true
 * of it, and exports are of mounts.  So a handle holding the path is
 * good across restarts, as FH4_PERSISTENT says it is.  A mount point
 * with a path too long to fit a handle cannot be reached; there is no
 * way to store a longer one without a table.
 *
 * Mounts are walked with mountlist_iterator_trynext(): this runs with
 * the exports read locked and dounmount() wants them write locked with
 * the mount busy, so to wait for a mount here could deadlock.  A mount
 * going away is simply not seen.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/kauth.h>
#include <sys/mbuf.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/systm.h>
#include <sys/vnode.h>

#include <netinet/in.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfs_var.h>

#include <oncrpc/oncrpc_gss.h>

#include <fs/nfsv4/nfsv4_var.h>
#include <fs/nfsv4/nfsv4_state.h>

#define	NFSV4_FHT_PSEUDO	1
#define	NFSV4_FHT_REAL		2
#define	NFSV4_FHT_ATTRDIR	3
#define	NFSV4_FHT_ATTR		4
#define	NFSV4_FH_HDR		4
#define	NFSV4_FH_PATHMAX	(NFS4_FHSIZE - NFSV4_FH_HDR)

/* Errors of the VFS, RFC 7530 s13.1.  Anything else has no equivalent. */
uint32_t
nfsv4_errno(int error)
{

	switch (error) {
	case 0:			return NFS4_OK;
	case EPERM:		return NFS4ERR_PERM;
	case ENOENT:		return NFS4ERR_NOENT;
	case EIO:		return NFS4ERR_IO;
	case ENXIO:		return NFS4ERR_NXIO;
	case EACCES:		return NFS4ERR_ACCESS;
	case EEXIST:		return NFS4ERR_EXIST;
	case EXDEV:		return NFS4ERR_XDEV;
	case ENOTDIR:		return NFS4ERR_NOTDIR;
	case EISDIR:		return NFS4ERR_ISDIR;
	case EINVAL:		return NFS4ERR_INVAL;
	case EILSEQ:		return NFS4ERR_INVAL;	/* s12.7, utf8only */
	case EFBIG:		return NFS4ERR_FBIG;
	case ENOSPC:		return NFS4ERR_NOSPC;
	case EROFS:		return NFS4ERR_ROFS;
	case EMLINK:		return NFS4ERR_MLINK;
	case ENAMETOOLONG:	return NFS4ERR_NAMETOOLONG;
	case ENOTEMPTY:		return NFS4ERR_NOTEMPTY;
	case EDQUOT:		return NFS4ERR_DQUOT;
	case ESTALE:		return NFS4ERR_STALE;
	case EOPNOTSUPP:	return NFS4ERR_NOTSUPP;
	case ETXTBSY:		return NFS4ERR_ACCESS;
	case EAGAIN:		return NFS4ERR_DELAY;
	default:		return NFS4ERR_SERVERFAULT;
	}
}

/*
 * vfs.nfsv4.utf8only.  With 0, names in the bytes that local programs
 * left stay reachable at the price of RFC 8881 s18.4.3.
 */
int nfsv4_utf8_only = 1;

/* RFC 3629 s4: no overlong form, no surrogate, nothing past U+10FFFF. */
static bool
utf8_valid(const uint8_t *p, size_t len)
{
	const uint8_t *end = p + len;
	uint8_t lo, hi;
	u_int n;

	while (p < end) {
		lo = 0x80;
		hi = 0xbf;
		if (*p < 0x80) {
			p++;
			continue;
		} else if (*p >= 0xc2 && *p <= 0xdf)
			n = 1;
		else if (*p >= 0xe0 && *p <= 0xef) {
			n = 2;
			if (*p == 0xe0)
				lo = 0xa0;
			else if (*p == 0xed)
				hi = 0x9f;
		} else if (*p >= 0xf0 && *p <= 0xf4) {
			n = 3;
			if (*p == 0xf0)
				lo = 0x90;
			else if (*p == 0xf4)
				hi = 0x8f;
		} else
			return false;
		if ((size_t)(end - p) <= n)
			return false;
		p++;
		if (*p < lo || *p > hi)
			return false;
		while (--n > 0) {
			p++;
			if (*p < 0x80 || *p > 0xbf)
				return false;
		}
		p++;
	}
	return true;
}

/*
 * A component of a name, by RFC 7530 s12.7 and s13.1.7.  Version 4.0 does
 * not check it to be UTF-8: FFS keeps uninterpreted bytes, and s12.8 lets
 * a server accept such names.  What it says of them, not changing them
 * and comparing them by octets, is what happens here anyway.  RFC 8881
 * s14.5 and s18.4.3 have version 4.1 say NFS4ERR_INVAL.  "." and ".."
 * have no meaning in NFSv4 (s16.13.5), and passing them down would give
 * them the meaning they have here.
 */
uint32_t
nfsv4_name_check(const struct nfsv4_compound *c, const struct nfsv4_name *nm)
{

	if (nm->nm_toolong)
		return NFS4ERR_NAMETOOLONG;
	if (nm->nm_len == 0)
		return NFS4ERR_INVAL;
	if (c->c_minor != 0 && nfsv4_utf8_only &&
	    !utf8_valid((const uint8_t *)nm->nm_str, nm->nm_len))
		return NFS4ERR_INVAL;
	if (memchr(nm->nm_str, '/', nm->nm_len) != NULL ||
	    memchr(nm->nm_str, '\0', nm->nm_len) != NULL)
		return NFS4ERR_BADCHAR;
	if (nm->nm_str[0] == '.' && (nm->nm_len == 1 ||
	    (nm->nm_len == 2 && nm->nm_str[1] == '.')))
		return NFS4ERR_BADNAME;
	return NFS4_OK;
}

void
nfsv4_cfh_clear(struct nfsv4_cfh *cf)
{

	if (cf->cf_vp != NULL)
		vrele(cf->cf_vp);
	if (cf->cf_cred != NULL)
		kauth_cred_free(cf->cf_cred);
	cf->cf_vp = NULL;
	cf->cf_cred = NULL;
	cf->cf_set = false;
	cf->cf_attr = 0;
	cf->cf_ref = NULL;
}

void
nfsv4_cfh_copy(struct nfsv4_cfh *to, const struct nfsv4_cfh *from)
{

	nfsv4_cfh_clear(to);
	*to = *from;
	if (to->cf_vp != NULL)
		vref(to->cf_vp);
	if (to->cf_cred != NULL)
		kauth_cred_hold(to->cf_cred);
}

/*
 * What versions 2 and 3 do in nfsrv_fhtovp(), for one client on one
 * mount: the anonymous credential for root and for MNT_EXPORTANON, and
 * here also for AUTH_NONE, which has no identity to use otherwise.  The
 * port test has no such counterpart in the RFC, but an export that asks
 * for it should get it; a client told NFS4ERR_WRONGSEC at least knows
 * this is about how it connected.  Which operation says so depends on
 * those around it, RFC 8881 s2.6.3.1.1, so here it is only noted.
 */
/*
 * May this flavor, or pseudo flavor, use an export with these flags?
 * The test is for the flavor exactly, RFC 2623 s3.2: a triple is
 * exported or it is not, and krb5p does not stand in for krb5.
 */
bool
nfsv4_sec_allowed(int exflags, uint32_t flavor)
{
	int sec = exflags & NFS_EXSEC_MASK;

	switch (flavor) {
	case ONCRPC_AUTH_NONE:
		return sec == 0 || (sec & NFS_EXSEC_NONE) != 0;
	case ONCRPC_AUTH_SYS:
		return sec == 0 || (sec & NFS_EXSEC_SYS) != 0;
	case RPCSEC_GSS_KRB5:
		return (sec & NFS_EXSEC_KRB5) != 0;
	case RPCSEC_GSS_KRB5I:
		return (sec & NFS_EXSEC_KRB5I) != 0;
	case RPCSEC_GSS_KRB5P:
		return (sec & NFS_EXSEC_KRB5P) != 0;
	default:
		return false;
	}
}

static uint32_t
cfh_export(struct nfsv4_compound *c, struct mount *mp, struct nfsv4_cfh *cf)
{
	struct oncrpc_req *rq = c->c_rq;
	const struct sockaddr_in *sin;
	struct mount *emp;
	kauth_cred_t anon, cred;
	int exflags;

	if (netexport_check(&mp->mnt_stat.f_fsidx, rq->rq_nam, &emp, &exflags,
	    &anon) != 0)
		return NFS4ERR_ACCESS;

	if ((exflags & (MNT_EXNORESPORT | MNT_EXPUBLIC)) == 0) {
		sin = mtod(rq->rq_nam, const struct sockaddr_in *);
		if ((sin->sin_family == AF_INET ||
		    sin->sin_family == AF_INET6) &&
		    ntohs(sin->sin_port) >= IPPORT_RESERVED)
			cf->cf_wrongsec = true;
	}

	/*
	 * RFC 7530 s3.3.2 and RFC 8881 s2.6.3.1: a flavor the export does
	 * not have.  As the port above, it is noted for the COMPOUND to
	 * answer, as the minor version says, s16.20.4 for PUTFH in 4.0.
	 */
	if (!nfsv4_sec_allowed(exflags, rq->rq_secflavor))
		cf->cf_wrongsec = true;

	if (rq->rq_cred == NULL) {
		kauth_cred_hold(anon);
		cred = anon;
	} else if (kauth_cred_geteuid(rq->rq_cred) == 0 ||
	    (exflags & MNT_EXPORTANON) != 0) {
		cred = kauth_cred_alloc();
		kauth_cred_clone(anon, cred);
	} else {
		kauth_cred_hold(rq->rq_cred);
		cred = rq->rq_cred;
	}
	cf->cf_cred = cred;
	cf->cf_exflags = exflags;
	return NFS4_OK;
}

/*
 * Make the file cf is of the node kind of its named attributes, or 0
 * for the file again: see nfsv4_xattr.c.
 */
uint32_t
nfsv4_cfh_setattr(struct nfsv4_cfh *cf, u_int kind, const char *name,
    size_t len)
{
	struct nfsv4_fh *fh = &cf->cf_fh;

	if (cf->cf_attr == NFSV4_ATTR_FILE)
		fh->fh_len -= NFSV4_ANAME_HASH;
	if (len > NFSV4_ANAME_MAX ||
	    fh->fh_len + NFSV4_ANAME_HASH > NFS4_FHSIZE)
		return NFS4ERR_NAMETOOLONG;
	cf->cf_attr = kind;
	switch (kind) {
	case NFSV4_ATTR_DIR:
		fh->fh_data[0] = NFSV4_FHT_ATTRDIR;
		break;
	case NFSV4_ATTR_FILE:
		fh->fh_data[0] = NFSV4_FHT_ATTR;
		nfsv4_xattr_hash(name, len, fh->fh_data + fh->fh_len);
		fh->fh_len += NFSV4_ANAME_HASH;
		memcpy(cf->cf_aname, name, len);
		cf->cf_aname[len] = '\0';
		break;
	default:
		fh->fh_data[0] = NFSV4_FHT_REAL;
		break;
	}
	return NFS4_OK;
}

/*
 * Make cf the handle of vp, an unlocked reference which it takes over
 * on success.
 */
uint32_t
nfsv4_cfh_setvp(struct nfsv4_compound *c, struct nfsv4_cfh *cf,
    struct vnode *vp)
{
	struct nfsv4_cfh n;
	size_t size;
	uint32_t st;

	memset(&n, 0, sizeof(n));
	st = cfh_export(c, vp->v_mount, &n);
	if (st != NFS4_OK)
		return st;

	size = sizeof(n.cf_fh.fh_data) - NFSV4_FH_HDR;
	if (vfs_composefh(vp, (fhandle_t *)(n.cf_fh.fh_data + NFSV4_FH_HDR),
	    &size) != 0) {
		kauth_cred_free(n.cf_cred);
		return NFS4ERR_SERVERFAULT;
	}
	n.cf_fh.fh_data[0] = NFSV4_FHT_REAL;
	n.cf_fh.fh_len = NFSV4_FH_HDR + size;
	n.cf_vp = vp;
	n.cf_set = true;
	n.cf_ref = nfsv4_referral_find(vp);
	nfsv4_cfh_clear(cf);
	*cf = n;
	return NFS4_OK;
}

static void
cfh_setpseudo(struct nfsv4_cfh *cf, const char *path, size_t len)
{

	KASSERT(len <= NFSV4_FH_PATHMAX);

	nfsv4_cfh_clear(cf);
	memset(cf, 0, sizeof(*cf));
	cf->cf_fh.fh_data[0] = NFSV4_FHT_PSEUDO;
	memcpy(cf->cf_fh.fh_data + NFSV4_FH_HDR, path, len);
	cf->cf_fh.fh_len = NFSV4_FH_HDR + len;
	cf->cf_set = true;
}

/* The path of a pseudo handle, of *lenp bytes with no NUL. */
const char *
nfsv4_cfh_path(const struct nfsv4_cfh *cf, size_t *lenp)
{

	KASSERT(cf->cf_vp == NULL);

	*lenp = cf->cf_fh.fh_len - NFSV4_FH_HDR;
	return (const char *)cf->cf_fh.fh_data + NFSV4_FH_HDR;
}

/*
 * Call fn for each mount exported to this client that lies strictly
 * below the path, or at it, until fn returns nonzero, with what of the
 * mount point is below the path.  That is empty at the path itself.
 * The mount stays good for as long as the exports are read locked.
 */
int
nfsv4_pseudo_walk(struct nfsv4_compound *c, const char *path, size_t len,
    int (*fn)(struct mount *, const char *, size_t, void *), void *arg)
{
	mount_iterator_t *mi;
	struct mount *mp, *emp;
	const char *on;
	size_t onlen;
	kauth_cred_t anon;
	int exflags, r;

	/* "/" is the empty prefix here, as every mount point follows it. */
	if (len == 1 && path[0] == '/')
		len = 0;

	r = 0;
	mountlist_iterator_init(&mi);
	while (r == 0 && (mp = mountlist_iterator_trynext(mi)) != NULL) {
		if ((mp->mnt_flag & MNT_EXPORTED) == 0)
			continue;
		on = mp->mnt_stat.f_mntonname;
		onlen = strlen(on);
		if (onlen == 1)		/* the root is "/" */
			onlen = 0;
		if (onlen > NFSV4_FH_PATHMAX || onlen < len ||
		    memcmp(on, path, len) != 0 ||
		    (onlen > len && on[len] != '/'))
			continue;
		if (netexport_check(&mp->mnt_stat.f_fsidx, c->c_rq->rq_nam,
		    &emp, &exflags, &anon) != 0)
			continue;
		r = (*fn)(mp, on + len, onlen - len, arg);
	}
	mountlist_iterator_destroy(mi);
	return r;
}

struct pseudo_find {
	struct mount	*pf_exact;
	bool		pf_below;
};

static int
pseudo_find_fn(struct mount *mp, const char *rest, size_t len, void *arg)
{
	struct pseudo_find *pf = arg;

	if (len == 0)
		pf->pf_exact = mp;
	else
		pf->pf_below = true;
	return 0;
}

/*
 * Make cf the handle at path in the name space: the root of an exported
 * file system if one is mounted there, and otherwise a pseudo node if
 * one lies below.  The root of the server always exists, RFC 7530 s4.1.1.
 */
static uint32_t
cfh_setpath(struct nfsv4_compound *c, struct nfsv4_cfh *cf, const char *path,
    size_t len)
{
	struct pseudo_find pf;
	struct vnode *vp;
	uint32_t st;
	int error;

	memset(&pf, 0, sizeof(pf));
	(void)nfsv4_pseudo_walk(c, path, len, pseudo_find_fn, &pf);

	if (pf.pf_exact != NULL) {
		error = VFS_ROOT(pf.pf_exact, LK_SHARED, &vp);
		if (error != 0)
			return nfsv4_errno(error);
		VOP_UNLOCK(vp);
		st = nfsv4_cfh_setvp(c, cf, vp);
		if (st != NFS4_OK)
			vrele(vp);
		return st;
	}
	if (!pf.pf_below && !(len == 1 && path[0] == '/'))
		return NFS4ERR_NOENT;
	cfh_setpseudo(cf, path, len);
	return NFS4_OK;
}

uint32_t
nfsv4_op_putrootfh(struct nfsv4_compound *c, union nfsv4_args *a)
{

	return cfh_setpath(c, &c->c_cur, "/", 1);
}

/* RFC 7530 s16.21.4: they should be the same, so they are. */
uint32_t
nfsv4_op_putpubfh(struct nfsv4_compound *c, union nfsv4_args *a)
{

	return cfh_setpath(c, &c->c_cur, "/", 1);
}

/* Make the handle fh from a client the current one. */
uint32_t
nfsv4_cfh_put(struct nfsv4_compound *c, const struct nfsv4_fh *fh)
{
	const fhandle_t *fhp;
	struct mount *mp;
	struct vnode *vp;
	kauth_cred_t anon;
	union {
		fhandle_t	fh;
		char		buf[NFS4_FHSIZE];
	} u;
	uint8_t ahash[NFSV4_ANAME_HASH];
	size_t len;
	uint32_t st;
	int error, exflags;

	if (fh->fh_len < NFSV4_FH_HDR)
		return NFS4ERR_BADHANDLE;
	len = fh->fh_len - NFSV4_FH_HDR;

	switch (fh->fh_data[0]) {
	case NFSV4_FHT_PSEUDO:
		if (len == 0 || fh->fh_data[NFSV4_FH_HDR] != '/')
			return NFS4ERR_BADHANDLE;
		st = cfh_setpath(c, &c->c_cur,
		    (const char *)fh->fh_data + NFSV4_FH_HDR, len);
		return st == NFS4ERR_NOENT ? NFS4ERR_STALE : st;
	case NFSV4_FHT_ATTR:
		if (len <= NFSV4_ANAME_HASH)
			return NFS4ERR_BADHANDLE;
		len -= NFSV4_ANAME_HASH;
		memcpy(ahash, fh->fh_data + NFSV4_FH_HDR + len,
		    NFSV4_ANAME_HASH);
		break;
	case NFSV4_FHT_REAL:
	case NFSV4_FHT_ATTRDIR:
		break;
	default:
		return NFS4ERR_BADHANDLE;
	}

	/*
	 * The length inside must be the one that was composed, or the file
	 * system would read past what came with the request.
	 */
	if (len < FHANDLE_SIZE_MIN)
		return NFS4ERR_BADHANDLE;
	memset(&u, 0, sizeof(u));
	memcpy(&u, fh->fh_data + NFSV4_FH_HDR, len);
	fhp = &u.fh;
	if (fhp->fh_fid.fid_len < offsetof(struct fid, fid_data) ||
	    FHANDLE_SIZE(fhp) != len)
		return NFS4ERR_BADHANDLE;

	/* No longer exported, as far as a client can tell, is gone. */
	if (netexport_check(&fhp->fh_fsid, c->c_rq->rq_nam, &mp, &exflags,
	    &anon) != 0)
		return NFS4ERR_STALE;
	error = VFS_FHTOVP(mp, __UNCONST(&fhp->fh_fid), LK_SHARED, &vp);
	if (error == ESTALE || error == ENOENT) {
		if (fh->fh_data[0] != NFSV4_FHT_REAL ||
		    (vp = nfsv4_file_vp_byfh(fh)) == NULL)
			return NFS4ERR_STALE;	/* s4.2.2 */
	} else if (error != 0)
		return nfsv4_errno(error);
	else
		VOP_UNLOCK(vp);
	st = nfsv4_cfh_setvp(c, &c->c_cur, vp);
	if (st != NFS4_OK) {
		vrele(vp);
		return st;
	}
	if (fh->fh_data[0] == NFSV4_FHT_ATTRDIR)
		return nfsv4_cfh_setattr(&c->c_cur, NFSV4_ATTR_DIR, "", 0);
	if (fh->fh_data[0] == NFSV4_FHT_ATTR)
		return nfsv4_xattr_byhash(&c->c_cur, ahash);
	return NFS4_OK;
}

uint32_t
nfsv4_op_putfh(struct nfsv4_compound *c, union nfsv4_args *a)
{

	return nfsv4_cfh_put(c, &a->putfh.fh);
}

uint32_t
nfsv4_op_getfh(struct nfsv4_compound *c, union nfsv4_args *a)
{

	return nfsv4_xdr_fh(c->c_rx, &c->c_cur.cf_fh) ? NFS4_OK :
	    NFS4ERR_RESOURCE;
}

uint32_t
nfsv4_op_savefh(struct nfsv4_compound *c, union nfsv4_args *a)
{

	nfsv4_cfh_copy(&c->c_saved, &c->c_cur);
	return NFS4_OK;
}

uint32_t
nfsv4_op_restorefh(struct nfsv4_compound *c, union nfsv4_args *a)
{

	if (!c->c_saved.cf_set)
		return NFS4ERR_RESTOREFH;
	nfsv4_cfh_copy(&c->c_cur, &c->c_saved);
	return NFS4_OK;
}

/*
 * One component in the directory dvp.  This does not follow a symbolic
 * link (RFC 7530 s16.13.5) and stays on the file system, with the
 * crossing left to the caller, who knows about exports.
 */
int
nfsv4_lookup_vp(struct vnode *dvp, const char *name, kauth_cred_t cred,
    struct vnode **vpp)
{
	struct nameidata nd;
	int error;

	memset(&nd, 0, sizeof(nd));
	nd.ni_pathbuf = pathbuf_create(name);
	if (nd.ni_pathbuf == NULL)
		return ENOMEM;
	nd.ni_rootdir = rootvnode;
	nd.ni_erootdir = NULL;
	nd.ni_cnd.cn_nameiop = LOOKUP;
	nd.ni_cnd.cn_flags = NOCROSSMOUNT;
	nd.ni_cnd.cn_cred = cred;
	error = lookup_for_nfsd_index(&nd, dvp);
	pathbuf_destroy(nd.ni_pathbuf);
	if (error == 0)
		*vpp = nd.ni_vp;
	return error;
}

/*
 * For an operation that changes the directory dvp: nd is set up as
 * nfs_namei() does, and the caller gets what lookup_for_nfsd() leaves,
 * with ni_dvp locked if LOCKPARENT was asked for.  The pathbuf is the
 * caller's to destroy.
 */
int
nfsv4_namei(struct nameidata *nd, struct vnode *dvp, const char *name,
    uint32_t op, uint32_t flags, kauth_cred_t cred)
{
	int error;

	memset(nd, 0, sizeof(*nd));
	nd->ni_pathbuf = pathbuf_create(name);
	if (nd->ni_pathbuf == NULL)
		return ENOMEM;
	nd->ni_cnd.cn_nameiop = op;
	nd->ni_cnd.cn_flags = flags | NOCROSSMOUNT;
	nd->ni_cnd.cn_cred = cred;
	error = lookup_for_nfsd(nd, dvp, 1);
	if (error != 0) {
		pathbuf_destroy(nd->ni_pathbuf);
		nd->ni_pathbuf = NULL;
	}
	return error;
}

/*
 * vp was found by a lookup, and may have a file system on it.  If that
 * one is exported, RFC 7530 s7.7 says the client gets its root.  If it
 * is not, it is left covered: s7.6 would have a pseudo file system
 * bridge it to any exports further down, and that is not done here.
 */
static int
lookup_cross(struct nfsv4_compound *c, struct vnode **vpp)
{
	struct vnode *vp = *vpp, *rvp;
	struct mount *mp, *emp;
	kauth_cred_t anon;
	int error, exflags;

	if (vp->v_type != VDIR || (mp = vp->v_mountedhere) == NULL)
		return 0;
	if (netexport_check(&mp->mnt_stat.f_fsidx, c->c_rq->rq_nam, &emp,
	    &exflags, &anon) != 0)
		return 0;
	error = VFS_ROOT(emp, LK_SHARED, &rvp);
	if (error != 0)
		return error;
	VOP_UNLOCK(rvp);
	vrele(vp);
	*vpp = rvp;
	return 0;
}

/*
 * Set to the object called name in the directory dir, with the rules of
 * LOOKUP but for the name having been checked.  to may be dir.
 */
uint32_t
nfsv4_cfh_lookup(struct nfsv4_compound *c, struct nfsv4_cfh *dir,
    const char *name, size_t namelen, struct nfsv4_cfh *to)
{
	struct vnode *vp;
	char path[NFSV4_FH_PATHMAX + 1];
	const char *cur;
	size_t curlen;
	uint32_t st;
	int error;

	if (dir->cf_attr != 0)
		return nfsv4_xattr_lookup(c, dir, name, to);
	if (dir->cf_vp == NULL) {
		cur = nfsv4_cfh_path(dir, &curlen);
		if (curlen == 1)	/* "/" */
			curlen = 0;
		if (curlen + 1 + namelen > NFSV4_FH_PATHMAX)
			return NFS4ERR_NOENT;
		memcpy(path, cur, curlen);
		path[curlen] = '/';
		memcpy(path + curlen + 1, name, namelen);
		return cfh_setpath(c, to, path, curlen + 1 + namelen);
	}

	error = nfsv4_lookup_vp(dir->cf_vp, name, dir->cf_cred, &vp);
	if (error != 0)
		return nfsv4_errno(error);
	error = lookup_cross(c, &vp);
	if (error != 0) {
		vrele(vp);
		return nfsv4_errno(error);
	}
	st = nfsv4_cfh_setvp(c, to, vp);
	if (st != NFS4_OK)
		vrele(vp);
	return st;
}

uint32_t
nfsv4_op_lookup(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_name *nm = &a->name.name;
	struct nfsv4_cfh *cf = &c->c_cur;
	uint32_t st;

	/* RFC 7530 s16.13.5 */
	if (cf->cf_vp != NULL && cf->cf_vp->v_type != VDIR)
		return cf->cf_vp->v_type == VLNK ? NFS4ERR_SYMLINK :
		    NFS4ERR_NOTDIR;
	st = nfsv4_name_check(c, nm);
	if (st != NFS4_OK)
		return st;
	st = nfsv4_cfh_lookup(c, cf, nm->nm_str, nm->nm_len, cf);
	/* RFC 8881 s2.6.3.1.1.3: the policy of what was found. */
	return st == NFS4_OK && cf->cf_wrongsec ? NFS4ERR_WRONGSEC : st;
}

/*
 * Up from the root of a file system is into what it is mounted on, if
 * that is exported, and otherwise the pseudo file system.  At the root
 * of the server there is nothing, RFC 7530 s16.14.4.
 */
static uint32_t
lookupp_fsroot(struct nfsv4_compound *c, struct vnode *fsvp)
{
	struct nfsv4_cfh *cf = &c->c_cur;
	struct mount *mp = fsvp->v_mount, *emp;
	struct vnode *cvp = mp->mnt_vnodecovered, *vp;
	const char *on = mp->mnt_stat.f_mntonname;
	const char *slash;
	kauth_cred_t anon;
	uint32_t st;
	int error, exflags;

	if (on[1] == '\0')
		return NFS4ERR_NOENT;
	if (cvp != NULL && netexport_check(&cvp->v_mount->mnt_stat.f_fsidx,
	    c->c_rq->rq_nam, &emp, &exflags, &anon) == 0) {
		error = nfsv4_lookup_vp(cvp, "..", cf->cf_cred, &vp);
		if (error != 0)
			return nfsv4_errno(error);
		st = nfsv4_cfh_setvp(c, cf, vp);
		if (st != NFS4_OK)
			vrele(vp);
		return st;
	}
	slash = strrchr(on, '/');
	KASSERT(slash != NULL);
	return cfh_setpath(c, cf, on, slash == on ? 1 : (size_t)(slash - on));
}

uint32_t
nfsv4_lookupp(struct nfsv4_compound *c)
{
	struct nfsv4_cfh *cf = &c->c_cur;
	struct vnode *vp;
	const char *cur, *p;
	char path[NFS4_FHSIZE];
	size_t len;
	uint32_t st;
	int error;

	if (cf->cf_vp == NULL) {
		cur = nfsv4_cfh_path(cf, &len);
		if (len == 1)
			return NFS4ERR_NOENT;
		for (p = cur + len - 1; *p != '/'; p--)
			continue;
		/*
		 * Setting the handle clears cf, which cur points into: the
		 * root came out as a NUL in place of its slash.
		 */
		len = p == cur ? 1 : (size_t)(p - cur);
		memcpy(path, cur, len);
		return cfh_setpath(c, cf, path, len);
	}

	if (cf->cf_vp->v_type != VDIR)
		return cf->cf_vp->v_type == VLNK ? NFS4ERR_SYMLINK :
		    NFS4ERR_NOTDIR;
	if ((cf->cf_vp->v_vflag & VV_ROOT) != 0)
		return lookupp_fsroot(c, cf->cf_vp);

	error = nfsv4_lookup_vp(cf->cf_vp, "..", cf->cf_cred, &vp);
	if (error != 0)
		return nfsv4_errno(error);
	st = nfsv4_cfh_setvp(c, cf, vp);
	if (st != NFS4_OK)
		vrele(vp);
	return st;
}

/* RFC 8881 s2.6.3.1.1.4: SECINFO_NO_NAME goes up without this answer. */
uint32_t
nfsv4_op_lookupp(struct nfsv4_compound *c, union nfsv4_args *a)
{
	uint32_t st;

	st = nfsv4_lookupp(c);
	return st == NFS4_OK && c->c_cur.cf_wrongsec ? NFS4ERR_WRONGSEC : st;
}
