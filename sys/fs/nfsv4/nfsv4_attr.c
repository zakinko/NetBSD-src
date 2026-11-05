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
 * Attributes, RFC 7530 s5.
 *
 * Those that can be had from the file system or are fixed are given;
 * of the RECOMMENDED ones, archive, fs_locations, hidden, mimetype,
 * quota_*, system and time_backup are not, and so are left out of
 * supported_attrs as s16.7.4 allows.  acl and aclsupport are in it only
 * where the file system has ACLs.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/acl.h>
#include <sys/kauth.h>
#include <sys/kmem.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/unistd.h>
#include <sys/vnode.h>

#include <fs/nfsv4/nfsv4_var.h>

#define	BIT(n)		(1ULL << (n))
#define	W0(a)		((uint32_t)(a))
#define	W1(a)		((uint32_t)((a) >> 32))

/* Table 3 and those of Table 4 given here, by number in a 64-bit word. */
static const uint64_t attr_supported =
    BIT(FATTR4_SUPPORTED_ATTRS) | BIT(FATTR4_TYPE) |
    BIT(FATTR4_FH_EXPIRE_TYPE) | BIT(FATTR4_CHANGE) | BIT(FATTR4_SIZE) |
    BIT(FATTR4_LINK_SUPPORT) | BIT(FATTR4_SYMLINK_SUPPORT) |
    BIT(FATTR4_NAMED_ATTR) | BIT(FATTR4_FSID) | BIT(FATTR4_UNIQUE_HANDLES) |
    BIT(FATTR4_LEASE_TIME) | BIT(FATTR4_RDATTR_ERROR) | BIT(FATTR4_ACL) |
    BIT(FATTR4_ACLSUPPORT) | BIT(FATTR4_FILEHANDLE) | BIT(FATTR4_CANSETTIME) |
    BIT(FATTR4_CASE_INSENSITIVE) | BIT(FATTR4_CASE_PRESERVING) |
    BIT(FATTR4_CHOWN_RESTRICTED) | BIT(FATTR4_FILEID) |
    BIT(FATTR4_FILES_AVAIL) | BIT(FATTR4_FILES_FREE) |
    BIT(FATTR4_FILES_TOTAL) | BIT(FATTR4_HOMOGENEOUS) |
    BIT(FATTR4_MAXFILESIZE) | BIT(FATTR4_MAXLINK) | BIT(FATTR4_MAXNAME) |
    BIT(FATTR4_MAXREAD) | BIT(FATTR4_MAXWRITE) | BIT(FATTR4_MODE) |
    BIT(FATTR4_NO_TRUNC) | BIT(FATTR4_NUMLINKS) | BIT(FATTR4_OWNER) |
    BIT(FATTR4_OWNER_GROUP) | BIT(FATTR4_RAWDEV) |
    BIT(FATTR4_SPACE_AVAIL) | BIT(FATTR4_SPACE_FREE) |
    BIT(FATTR4_SPACE_TOTAL) | BIT(FATTR4_SPACE_USED) |
    BIT(FATTR4_TIME_ACCESS) | BIT(FATTR4_TIME_ACCESS_SET) |
    BIT(FATTR4_TIME_CREATE) | BIT(FATTR4_TIME_DELTA) |
    BIT(FATTR4_TIME_METADATA) | BIT(FATTR4_TIME_MODIFY) |
    BIT(FATTR4_TIME_MODIFY_SET) | BIT(FATTR4_MOUNTED_ON_FILEID);

/* RFC 7530 s5.7, those with access W */
static const uint64_t attr_setonly =
    BIT(FATTR4_TIME_ACCESS_SET) | BIT(FATTR4_TIME_MODIFY_SET);

/* Those needing VOP_GETATTR, and those needing VFS_STATVFS. */
static const uint64_t attr_vattr =
    BIT(FATTR4_TYPE) | BIT(FATTR4_CHANGE) | BIT(FATTR4_SIZE) |
    BIT(FATTR4_FILEID) | BIT(FATTR4_MODE) | BIT(FATTR4_NUMLINKS) |
    BIT(FATTR4_OWNER) | BIT(FATTR4_OWNER_GROUP) | BIT(FATTR4_RAWDEV) |
    BIT(FATTR4_SPACE_USED) | BIT(FATTR4_TIME_ACCESS) |
    BIT(FATTR4_TIME_CREATE) | BIT(FATTR4_TIME_METADATA) |
    BIT(FATTR4_TIME_MODIFY) | BIT(FATTR4_MOUNTED_ON_FILEID);
static const uint64_t attr_statvfs =
    BIT(FATTR4_FILES_AVAIL) | BIT(FATTR4_FILES_FREE) |
    BIT(FATTR4_FILES_TOTAL) | BIT(FATTR4_SPACE_AVAIL) |
    BIT(FATTR4_SPACE_FREE) | BIT(FATTR4_SPACE_TOTAL);

/*
 * fsid of the pseudo file system: RFC 7530 s7.3 gives it one of its own,
 * and the real ones have nothing above 32 bits in major.
 */
#define	NFSV4_PSEUDO_FSID_MAJOR	(1ULL << 32)

/* Attributes of a pseudo node; it is a read-only directory, s7.3. */
#define	NFSV4_PSEUDO_MODE	0555

/* acl and aclsupport go with the file system; vp is NULL on a pseudo node. */
static uint64_t
attr_supported_by(struct vnode *vp)
{

	if (nfsv4_acl_supported(vp))
		return attr_supported;
	return attr_supported & ~(BIT(FATTR4_ACL) | BIT(FATTR4_ACLSUPPORT));
}

static inline uint64_t
attr_mask(const struct nfsv4_bitmap *bm)
{
	uint64_t m;

	m = bm->bm_n > 0 ? bm->bm_w[0] : 0;
	if (bm->bm_n > 1)
		m |= (uint64_t)bm->bm_w[1] << 32;
	return m;
}

/* RFC 7530 s5.5: asking for a set-only attribute is NFS4ERR_INVAL. */
bool
nfsv4_attr_getonly_ok(const struct nfsv4_bitmap *bm)
{

	return (attr_mask(bm) & attr_setonly) == 0;
}

bool
nfsv4_attr_supported(const struct nfsv4_bitmap *bm, struct vnode *vp)
{

	return (attr_mask(bm) & ~attr_supported_by(vp)) == 0;
}

static uint32_t
attr_ftype(enum vtype t)
{

	switch (t) {
	case VREG:	return NF4REG;
	case VDIR:	return NF4DIR;
	case VBLK:	return NF4BLK;
	case VCHR:	return NF4CHR;
	case VLNK:	return NF4LNK;
	case VSOCK:	return NF4SOCK;
	case VFIFO:	return NF4FIFO;
	default:	return 0;	/* nothing can have this */
	}
}

/*
 * The change attribute: va_ctime folded into 64 bits, RFC 7530 s5.8.1.4
 * allowing time_metadata for objects that cannot change faster than its
 * resolution.  ffs_itimes() and tmpfs_update_locked() see to that by
 * moving ctime on by at least a nanosecond each time, whatever the clock
 * does, so a file system whose ctime is not kept that way must not be
 * trusted here.  ZFS keeps no such ctime, but has a sequence number in
 * va_filerev; adding it means that either moving moves the attribute.
 */
uint64_t
nfsv4_attr_change(const struct vnode *vp, const struct vattr *va)
{
	uint64_t ch;

	ch = (uint64_t)va->va_ctime.tv_sec * 1000000000ULL +
	    va->va_ctime.tv_nsec;
	if (strcmp(vp->v_mount->mnt_stat.f_fstypename, MOUNT_ZFS) == 0)
		ch += va->va_filerev;
	return ch;
}

static bool
attr_time(XDR *x, const struct timespec *ts)
{
	uint64_t s = (uint64_t)(int64_t)ts->tv_sec;
	uint32_t ns = (uint32_t)ts->tv_nsec;

	return xdr_u_int64_t(x, &s) && xdr_u_int32_t(x, &ns);
}

static bool
attr_u32(XDR *x, uint32_t v)
{

	return xdr_u_int32_t(x, &v);
}

static bool
attr_u64(XDR *x, uint64_t v)
{

	return xdr_u_int64_t(x, &v);
}

/* Numbers, as RFC 7530 s5.9 allows outside Kerberos. */
static bool
attr_id(XDR *x, uint32_t id)
{
	char buf[12];
	uint32_t len;

	len = snprintf(buf, sizeof(buf), "%u", id);
	return xdr_u_int32_t(x, &len) && xdr_opaque(x, buf, len);
}

/* Fileid of a pseudo node: FNV-1a of the path.  Any stable value will do. */
static uint64_t
attr_pseudo_fileid(const struct nfsv4_cfh *cf)
{
	const char *p;
	size_t len, i;
	uint64_t h = 0xcbf29ce484222325ULL;

	p = nfsv4_cfh_path(cf, &len);
	for (i = 0; i < len; i++)
		h = (h ^ (uint8_t)p[i]) * 0x100000001b3ULL;
	return h;
}

/*
 * RFC 7530 s5.8.2.19: at the root of a file system, the file id of the
 * directory at the bottom of whatever is mounted there.
 */
static int
attr_mounted_on(struct vnode *vp, kauth_cred_t cred, const struct vattr *va,
    uint64_t *idp)
{
	struct vnode *cvp;
	struct vattr cva;
	int error;

	*idp = va->va_fileid;
	if ((vp->v_vflag & VV_ROOT) == 0)
		return 0;
	cvp = NULL;
	while ((vp->v_vflag & VV_ROOT) != 0 &&
	    vp->v_mount->mnt_vnodecovered != NULL)
		vp = cvp = vp->v_mount->mnt_vnodecovered;
	if (cvp == NULL)
		return 0;
	vn_lock(cvp, LK_SHARED | LK_RETRY);
	error = VOP_GETATTR(cvp, &cva, cred);
	VOP_UNLOCK(cvp);
	if (error == 0)
		*idp = cva.va_fileid;
	return error;
}

static uint64_t
attr_pathconf(struct vnode *vp, int name, uint64_t dflt)
{
	register_t v;

	if (vp == NULL || VOP_PATHCONF(vp, name, &v) != 0 || v < 0)
		return dflt;
	return (uint64_t)v;
}

/*
 * Encode the attributes of cf asked for by want, lowest number first
 * (RFC 7530 s16.7.4), to buf, and say in *got which they were and in
 * *lenp how long they are.  A nonzero rderr is what happened trying to
 * reach the object in a READDIR; then all that there is to say is that.
 */
uint32_t
nfsv4_attr_fill(struct nfsv4_compound *c, const struct nfsv4_cfh *cf,
    const struct nfsv4_bitmap *want, uint32_t rderr, char *buf, size_t max,
    struct nfsv4_bitmap *got, u_int *lenp)
{
	struct vnode *vp = cf->cf_vp;
	struct statvfs *sb = NULL;
	struct acl *acl = NULL;
	struct vattr va;
	struct timespec boot;
	uint64_t m, out, id, maxsize, sup;
	uint32_t st;
	u_int n;
	bool ok;
	XDR x;
	int error;

	sup = attr_supported_by(vp);
	m = attr_mask(want) & sup & ~attr_setonly;
	if (rderr != NFS4_OK)
		m &= BIT(FATTR4_RDATTR_ERROR);

	id = 0;
	if (vp != NULL && (m & attr_vattr) != 0) {
		vn_lock(vp, LK_SHARED | LK_RETRY);
		error = VOP_GETATTR(vp, &va, cf->cf_cred);
		VOP_UNLOCK(vp);
		if (error != 0)
			return nfsv4_errno(error);
		if ((m & BIT(FATTR4_MOUNTED_ON_FILEID)) != 0) {
			error = attr_mounted_on(vp, cf->cf_cred, &va, &id);
			if (error != 0)
				return nfsv4_errno(error);
		}
	} else if (vp == NULL && rderr == NFS4_OK) {
		id = attr_pseudo_fileid(cf);
		getnanoboottime(&boot);
	}
	if (vp != NULL && (m & attr_statvfs) != 0) {
		sb = kmem_alloc(sizeof(*sb), KM_SLEEP);
		error = VFS_STATVFS(vp->v_mount, sb);
		if (error != 0) {
			kmem_free(sb, sizeof(*sb));
			return nfsv4_errno(error);
		}
	}

	if ((m & BIT(FATTR4_ACL)) != 0) {
		st = nfsv4_acl_get(vp, cf->cf_cred, &acl);
		if (st != NFS4_OK) {
			if (sb != NULL)
				kmem_free(sb, sizeof(*sb));
			return st;
		}
	}

	xdrmem_create(&x, buf, max, XDR_ENCODE);
	ok = true;
	out = 0;
	for (n = 0; n < 64 && ok; n++) {
		if ((m & BIT(n)) == 0)
			continue;
		out |= BIT(n);
		switch (n) {
		case FATTR4_SUPPORTED_ATTRS:
			ok = attr_u32(&x, 2) && attr_u32(&x, W0(sup)) &&
			    attr_u32(&x, W1(sup));
			break;
		case FATTR4_ACL:
			ok = nfsv4_acl_put(&x, acl);
			break;
		case FATTR4_ACLSUPPORT:
			/* s6.2.1.2 */
			ok = attr_u32(&x, ACL4_SUPPORT_ALLOW_ACL |
			    ACL4_SUPPORT_DENY_ACL);
			break;
		case FATTR4_TYPE:
			ok = attr_u32(&x, vp ? attr_ftype(va.va_type) : NF4DIR);
			break;
		case FATTR4_FH_EXPIRE_TYPE:
			ok = attr_u32(&x, FH4_PERSISTENT);
			break;
		case FATTR4_CHANGE:
			/* A pseudo node only changes at a reboot, as far
			   as a client can tell; see nfsv4_fh.c. */
			ok = attr_u64(&x, vp ? nfsv4_attr_change(vp, &va) :
			    (uint64_t)boot.tv_sec);
			break;
		case FATTR4_SIZE:
			ok = attr_u64(&x, vp ? va.va_size : 512);
			break;
		case FATTR4_LINK_SUPPORT:
		case FATTR4_SYMLINK_SUPPORT:
		case FATTR4_UNIQUE_HANDLES:
		case FATTR4_CANSETTIME:
		case FATTR4_CASE_PRESERVING:
		case FATTR4_HOMOGENEOUS:
		case FATTR4_NO_TRUNC:
			ok = attr_u32(&x, 1);
			break;
		case FATTR4_NAMED_ATTR:
		case FATTR4_CASE_INSENSITIVE:
			ok = attr_u32(&x, 0);
			break;
		case FATTR4_FSID:
			if (vp != NULL) {
				const fsid_t *fs =
				    &vp->v_mount->mnt_stat.f_fsidx;
				ok = attr_u64(&x, (uint32_t)fs->__fsid_val[0]) &&
				    attr_u64(&x, (uint32_t)fs->__fsid_val[1]);
			} else
				ok = attr_u64(&x, NFSV4_PSEUDO_FSID_MAJOR) &&
				    attr_u64(&x, 0);
			break;
		case FATTR4_LEASE_TIME:
			ok = attr_u32(&x, NFSV4_LEASE);
			break;
		case FATTR4_RDATTR_ERROR:
			ok = attr_u32(&x, rderr);
			break;
		case FATTR4_FILEHANDLE:
			ok = nfsv4_xdr_fh(&x, __UNCONST(&cf->cf_fh));
			break;
		case FATTR4_CHOWN_RESTRICTED:
			ok = attr_u32(&x, attr_pathconf(vp,
			    _PC_CHOWN_RESTRICTED, 1) != 0);
			break;
		case FATTR4_FILEID:
			ok = attr_u64(&x, vp ? va.va_fileid : id);
			break;
		case FATTR4_MOUNTED_ON_FILEID:
			ok = attr_u64(&x, id);
			break;
		case FATTR4_FILES_AVAIL:
			ok = attr_u64(&x, sb ? sb->f_favail : 0);
			break;
		case FATTR4_FILES_FREE:
			ok = attr_u64(&x, sb ? sb->f_ffree : 0);
			break;
		case FATTR4_FILES_TOTAL:
			ok = attr_u64(&x, sb ? sb->f_files : 0);
			break;
		case FATTR4_SPACE_AVAIL:
			ok = attr_u64(&x, sb ? sb->f_bavail * sb->f_frsize : 0);
			break;
		case FATTR4_SPACE_FREE:
			ok = attr_u64(&x, sb ? sb->f_bfree * sb->f_frsize : 0);
			break;
		case FATTR4_SPACE_TOTAL:
			ok = attr_u64(&x, sb ? sb->f_blocks * sb->f_frsize : 0);
			break;
		case FATTR4_MAXFILESIZE:
			maxsize = attr_pathconf(vp, _PC_FILESIZEBITS, 64);
			ok = attr_u64(&x, maxsize >= 64 ? (uint64_t)INT64_MAX :
			    (1ULL << maxsize) - 1);
			break;
		case FATTR4_MAXLINK:
			ok = attr_u32(&x, attr_pathconf(vp, _PC_LINK_MAX,
			    LINK_MAX));
			break;
		case FATTR4_MAXNAME:
			ok = attr_u32(&x, NFSV4_NAME_MAX);
			break;
		case FATTR4_MAXREAD:
		case FATTR4_MAXWRITE:
			ok = attr_u64(&x, NFSV4_MAXIO);
			break;
		case FATTR4_MODE:
			ok = attr_u32(&x, vp ? va.va_mode & ALLPERMS :
			    NFSV4_PSEUDO_MODE);
			break;
		case FATTR4_NUMLINKS:
			ok = attr_u32(&x, vp ? va.va_nlink : 2);
			break;
		case FATTR4_OWNER:
			ok = attr_id(&x, vp ? va.va_uid : 0);
			break;
		case FATTR4_OWNER_GROUP:
			ok = attr_id(&x, vp ? va.va_gid : 0);
			break;
		case FATTR4_RAWDEV:
			if (vp != NULL && (va.va_type == VBLK ||
			    va.va_type == VCHR))
				ok = attr_u32(&x, major(va.va_rdev)) &&
				    attr_u32(&x, minor(va.va_rdev));
			else
				ok = attr_u32(&x, 0) && attr_u32(&x, 0);
			break;
		case FATTR4_SPACE_USED:
			ok = attr_u64(&x, vp ? va.va_bytes : 0);
			break;
		case FATTR4_TIME_ACCESS:
			ok = attr_time(&x, vp ? &va.va_atime : &boot);
			break;
		case FATTR4_TIME_CREATE:
			ok = attr_time(&x, vp ? &va.va_birthtime : &boot);
			break;
		case FATTR4_TIME_METADATA:
			ok = attr_time(&x, vp ? &va.va_ctime : &boot);
			break;
		case FATTR4_TIME_MODIFY:
			ok = attr_time(&x, vp ? &va.va_mtime : &boot);
			break;
		case FATTR4_TIME_DELTA:
			ok = attr_u64(&x, 0) && attr_u32(&x, 1);
			break;
		default:
			panic("nfsv4_attr_fill: attribute %u", n);
		}
	}

	if (sb != NULL)
		kmem_free(sb, sizeof(*sb));
	if (acl != NULL)
		acl_free(acl);
	if (!ok)
		return NFS4ERR_TOOSMALL;
	got->bm_n = 2;
	got->bm_w[0] = W0(out);
	got->bm_w[1] = W1(out);
	got->bm_more = false;
	*lenp = xdr_getpos(&x);
	return NFS4_OK;
}

uint32_t
nfsv4_op_getattr(struct nfsv4_compound *c, union nfsv4_args *a)
{
	struct nfsv4_bitmap got;
	char *buf;
	u_int len;
	uint32_t st;

	if (!nfsv4_attr_getonly_ok(&a->getattr.mask))
		return NFS4ERR_INVAL;

	buf = kmem_alloc(NFSV4_ATTRBUF, KM_SLEEP);
	st = nfsv4_attr_fill(c, &c->c_cur, &a->getattr.mask, NFS4_OK, buf,
	    NFSV4_ATTRBUF, &got, &len);
	if (st == NFS4_OK && (!nfsv4_xdr_bitmap(c->c_rx, &got) ||
	    !xdr_u_int32_t(c->c_rx, &len) ||
	    !XDR_PUTBYTES(c->c_rx, buf, len)))
		st = NFS4ERR_RESOURCE;
	kmem_free(buf, NFSV4_ATTRBUF);
	return st;
}

/*
 * Owners on the way in.  Numbers are the only form understood, s5.9, and
 * a string that is not one has no translation here.
 */
static uint32_t
attr_parse_id(XDR *x, uint32_t *idp)
{
	char buf[12];
	uint32_t len;

	if (!xdr_u_int32_t(x, &len))
		return NFS4ERR_BADXDR;
	if (len == 0)
		return NFS4ERR_INVAL;
	if (len >= sizeof(buf)) {
		return nfsv4_xdr_skip(x, len) ? NFS4ERR_BADOWNER :
		    NFS4ERR_BADXDR;
	}
	if (!xdr_opaque(x, buf, len))
		return NFS4ERR_BADXDR;
	return nfsv4_attr_strid(buf, len, idp);
}

uint32_t
nfsv4_attr_strid(const char *buf, u_int len, uint32_t *idp)
{
	uint64_t v;
	u_int i;

	if (buf[0] == '0' && len > 1)		/* "no leading zeros" */
		return NFS4ERR_BADOWNER;
	v = 0;
	for (i = 0; i < len; i++) {
		if (buf[i] < '0' || buf[i] > '9')
			return NFS4ERR_BADOWNER;
		v = v * 10 + (buf[i] - '0');
	}
	if (v > UINT32_MAX)
		return NFS4ERR_BADOWNER;
	*idp = (uint32_t)v;
	return NFS4_OK;
}

static uint32_t
attr_parse_nfstime(XDR *x, struct timespec *ts)
{
	uint64_t s;
	uint32_t ns;

	if (!xdr_u_int64_t(x, &s) || !xdr_u_int32_t(x, &ns))
		return NFS4ERR_BADXDR;
	if (ns >= 1000000000)
		return NFS4ERR_INVAL;
	ts->tv_sec = (time_t)(int64_t)s;
	ts->tv_nsec = ns;
	return NFS4_OK;
}

/* settime4; RFC 7531 s2 */
static uint32_t
attr_parse_settime(XDR *x, struct timespec *ts, u_int *flags)
{
	uint32_t how;

	if (!xdr_u_int32_t(x, &how))
		return NFS4ERR_BADXDR;
	switch (how) {
	case SET_TO_SERVER_TIME4:
		vfs_timestamp(ts);
		*flags |= VA_UTIMES_NULL;
		return NFS4_OK;
	case SET_TO_CLIENT_TIME4:
		return attr_parse_nfstime(x, ts);
	default:
		return NFS4ERR_BADXDR;
	}
}

/* RFC 7530 s5.7, those of access W or R W that are supported */
static const uint64_t attr_settable =
    BIT(FATTR4_SIZE) | BIT(FATTR4_ACL) | BIT(FATTR4_MODE) |
    BIT(FATTR4_OWNER) | BIT(FATTR4_OWNER_GROUP) |
    BIT(FATTR4_TIME_ACCESS_SET) | BIT(FATTR4_TIME_CREATE) |
    BIT(FATTR4_TIME_MODIFY_SET);

/*
 * Read the fattr4 in the arguments into va, and the mask of what was
 * in it into *setp.  Unknown attributes are NFS4ERR_ATTRNOTSUPP and
 * those that cannot be set NFS4ERR_INVAL, s5.5.  attr_vals must hold
 * exactly the values of the bitmap (RFC 7530 s2.2).  The arguments are
 * left positioned after it, whatever happens.
 */
uint32_t
nfsv4_attr_parse(struct nfsv4_compound *c, const struct nfsv4_fattr *fa,
    struct vattr *va, uint64_t *setp)
{
	XDR *x = c->c_ax;
	uint64_t m = attr_mask(&fa->fa_mask);
	uint32_t st, v, id;
	u_int n, end;

	vattr_null(va);
	*setp = 0;
	if (c->c_setacl != NULL) {
		acl_free(c->c_setacl);
		c->c_setacl = NULL;
	}
	if (fa->fa_mask.bm_more || (m & ~attr_supported) != 0)
		return NFS4ERR_ATTRNOTSUPP;
	if ((m & ~attr_settable) != 0)
		return NFS4ERR_INVAL;

	end = XDR_GETPOS(x);
	if (!XDR_SETPOS(x, fa->fa_pos))
		return NFS4ERR_BADXDR;

	st = NFS4_OK;
	for (n = 0; n < 64 && st == NFS4_OK; n++) {
		if ((m & BIT(n)) == 0)
			continue;
		switch (n) {
		case FATTR4_SIZE:
			/*
			 * More than off_t can say would also come out as
			 * VNOVAL, or "leave the size alone".
			 */
			if (!xdr_u_int64_t(x, &va->va_size))
				st = NFS4ERR_BADXDR;
			else if (va->va_size > (uint64_t)INT64_MAX)
				st = NFS4ERR_FBIG;
			break;
		case FATTR4_ACL:
			st = nfsv4_acl_parse(x, &c->c_setacl);
			break;
		case FATTR4_MODE:
			if (!xdr_u_int32_t(x, &v))
				st = NFS4ERR_BADXDR;
			else if ((v & ~07777U) != 0)	/* s6.2.2 */
				st = NFS4ERR_INVAL;
			else
				va->va_mode = v;
			break;
		case FATTR4_OWNER:
			st = attr_parse_id(x, &id);
			if (st == NFS4_OK)
				va->va_uid = id;
			break;
		case FATTR4_OWNER_GROUP:
			st = attr_parse_id(x, &id);
			if (st == NFS4_OK)
				va->va_gid = id;
			break;
		case FATTR4_TIME_ACCESS_SET:
			st = attr_parse_settime(x, &va->va_atime,
			    &va->va_vaflags);
			break;
		case FATTR4_TIME_CREATE:
			st = attr_parse_nfstime(x, &va->va_birthtime);
			break;
		case FATTR4_TIME_MODIFY_SET:
			st = attr_parse_settime(x, &va->va_mtime,
			    &va->va_vaflags);
			break;
		}
	}
	if (st == NFS4_OK && XDR_GETPOS(x) != fa->fa_pos + fa->fa_len)
		st = NFS4ERR_BADXDR;
	if (!XDR_SETPOS(x, end))
		st = NFS4ERR_BADXDR;
	if (st == NFS4_OK)
		*setp = m;
	return st;
}

/* The bitmap of what was set, for attrset and attrsset. */
bool
nfsv4_attr_put_mask(XDR *x, uint64_t set)
{
	struct nfsv4_bitmap bm;

	bm.bm_n = 2;
	bm.bm_w[0] = W0(set);
	bm.bm_w[1] = W1(set);
	bm.bm_more = false;
	return nfsv4_xdr_bitmap(x, &bm);
}
