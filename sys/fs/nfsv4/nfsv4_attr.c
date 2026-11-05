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
 * archive, hidden, mimetype, system and time_backup go where nfsv4_xattr.c
 * keeps them, and quota_* to the file system's quota; a file system with
 * neither has them left out of supported_attrs as s16.7.4 allows.  acl and aclsupport are in it only
 * where the file system has ACLs.
 *
 * Of those of version 4.2, sec_label is not given either: labels need a
 * MAC model and the kernel has none to enforce one, and RFC 7862 s13
 * has Labeled NFS OPTIONAL.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/acl.h>
#include <sys/kauth.h>
#include <sys/kmem.h>
#include <sys/mount.h>
#include <sys/quota.h>
#include <sys/quotactl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/unistd.h>
#include <sys/vnode.h>

#include <fs/nfsv4/nfsv4_var.h>
#include <fs/nfsv4/nfsv4_state.h>

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
    BIT(FATTR4_FILES_TOTAL) | BIT(FATTR4_FS_LOCATIONS) |
    BIT(FATTR4_HOMOGENEOUS) |
    BIT(FATTR4_MAXFILESIZE) | BIT(FATTR4_MAXLINK) | BIT(FATTR4_MAXNAME) |
    BIT(FATTR4_MAXREAD) | BIT(FATTR4_MAXWRITE) | BIT(FATTR4_MODE) |
    BIT(FATTR4_NO_TRUNC) | BIT(FATTR4_NUMLINKS) | BIT(FATTR4_OWNER) |
    BIT(FATTR4_OWNER_GROUP) | BIT(FATTR4_RAWDEV) |
    BIT(FATTR4_SPACE_AVAIL) | BIT(FATTR4_SPACE_FREE) |
    BIT(FATTR4_SPACE_TOTAL) | BIT(FATTR4_SPACE_USED) |
    BIT(FATTR4_TIME_ACCESS) | BIT(FATTR4_TIME_ACCESS_SET) |
    BIT(FATTR4_TIME_CREATE) | BIT(FATTR4_TIME_DELTA) |
    BIT(FATTR4_TIME_METADATA) | BIT(FATTR4_TIME_MODIFY) |
    BIT(FATTR4_TIME_MODIFY_SET) | BIT(FATTR4_MOUNTED_ON_FILEID) |
    BIT(FATTR4_CHANGE_POLICY) | BIT(FATTR4_FS_STATUS);

/* Of those, the ones that version 4.0 has no number for. */
static const uint64_t attr_v41 =
    BIT(FATTR4_CHANGE_POLICY) | BIT(FATTR4_FS_STATUS);

/* RFC 7530 s5.7, those with access W */
static const uint64_t attr_setonly =
    BIT(FATTR4_TIME_ACCESS_SET) | BIT(FATTR4_TIME_MODIFY_SET);

/* Where they are kept is optional, so they are not always supported. */
static const uint64_t attr_stored =
    BIT(FATTR4_ARCHIVE) | BIT(FATTR4_HIDDEN) | BIT(FATTR4_MIMETYPE) |
    BIT(FATTR4_SYSTEM) | BIT(FATTR4_TIME_BACKUP);
static const uint64_t attr_quota =
    BIT(FATTR4_QUOTA_AVAIL_HARD) | BIT(FATTR4_QUOTA_AVAIL_SOFT) |
    BIT(FATTR4_QUOTA_USED);

/* Those that a write delegation may change at the client, s10.4. */
static const uint64_t attr_delegated =
    BIT(FATTR4_CHANGE) | BIT(FATTR4_SIZE) | BIT(FATTR4_TIME_MODIFY);

/* What an absent file system has, s8.3.1. */
static const uint64_t attr_absent =
    BIT(FATTR4_FS_LOCATIONS) | BIT(FATTR4_FSID) | BIT(FATTR4_RDATTR_ERROR) |
    BIT(FATTR4_MOUNTED_ON_FILEID) | BIT(FATTR4_CHANGE_POLICY) |
    BIT(FATTR4_FS_STATUS);

/* Those needing VOP_GETATTR, and those needing VFS_STATVFS. */
static const uint64_t attr_vattr =
    BIT(FATTR4_QUOTA_AVAIL_HARD) | BIT(FATTR4_QUOTA_AVAIL_SOFT) |
    BIT(FATTR4_QUOTA_USED) | BIT(FATTR4_TYPE) | BIT(FATTR4_CHANGE) | BIT(FATTR4_SIZE) |
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

/* The same with the ones that cost a VOP to find out about. */
static uint64_t
attr_supported_full(struct vnode *vp)
{
	struct quotastat qs;
	uint64_t m = attr_supported_by(vp);

	if (vp == NULL)
		return m;
	if (nfsv4_xstore_ok(vp))
		m |= attr_stored;
	if (vfs_quotactl_stat(vp->v_mount, &qs) == 0)
		m |= attr_quota;
	return m;
}

/*
 * s5.8.2.24 to 26, of the owner of the file.  The file system counts in
 * blocks of DEV_BSIZE.  With no entry or no limit, the answer that is
 * true is as much as can be said.
 */
static bool
attr_quota_put(XDR *x, struct vnode *vp, uid_t uid, u_int n)
{
	struct quotakey key;
	struct quotaval qv;
	uint64_t v;

	key.qk_idtype = QUOTA_IDTYPE_USER;
	key.qk_id = uid;
	key.qk_objtype = QUOTA_OBJTYPE_BLOCKS;
	if (vfs_quotactl_get(vp->v_mount, &key, &qv) != 0) {
		qv.qv_hardlimit = qv.qv_softlimit = QUOTA_NOLIMIT;
		qv.qv_usage = 0;
	}
	switch (n) {
	case FATTR4_QUOTA_USED:
		v = qv.qv_usage;
		break;
	case FATTR4_QUOTA_AVAIL_HARD:
		v = qv.qv_hardlimit == QUOTA_NOLIMIT ? UINT64_MAX / DEV_BSIZE :
		    qv.qv_hardlimit > qv.qv_usage ?
		    qv.qv_hardlimit - qv.qv_usage : 0;
		break;
	default:
		v = qv.qv_softlimit == QUOTA_NOLIMIT ? UINT64_MAX / DEV_BSIZE :
		    qv.qv_softlimit > qv.qv_usage ?
		    qv.qv_softlimit - qv.qv_usage : 0;
		break;
	}
	return xdr_u_int64_t(x, &(uint64_t){ v * DEV_BSIZE });
}

/*
 * RFC 8881 s5.8.1.14: what EXCLUSIVE4_1 can set.  Not time_access_set,
 * which holds the verifier, s18.16.3, and size would mean nothing.
 */
const uint64_t nfsv4_attr_exclcreat =
    BIT(FATTR4_ACL) | BIT(FATTR4_MODE) | BIT(FATTR4_OWNER) |
    BIT(FATTR4_OWNER_GROUP) | BIT(FATTR4_TIME_MODIFY_SET);

/* The bits of the third word, all of version 4.1. */
#define	W2_EXCLCREAT	(1U << (FATTR4_SUPPATTR_EXCLCREAT - 64))
#define	W2_CHARSET	(1U << (FATTR4_FS_CHARSET_CAP - 64))
#define	W2_ALL		(W2_EXCLCREAT | W2_CHARSET)

#define	W2(n)		(1U << ((n) - 64))

/*
 * What the third word has for this object in this minor version, RFC
 * 7862 s12.1.  CLONE goes with clone_blksize, s4.1.2.
 * space_freed is left out on ZFS, as what deleting a file would free
 * depends on the blocks and snapshots that share it, which nothing here
 * can find out.
 */
static uint32_t
attr_w2_by(struct vnode *vp, uint32_t minor)
{
	uint32_t w2 = 0;
	bool zfs;

	if (minor != 0)
		w2 |= W2_ALL;
	if (minor >= 2) {
		w2 |= W2(FATTR4_CHANGE_ATTR_TYPE);
		zfs = vp != NULL && strcmp(vp->v_mount->mnt_stat.f_fstypename,
		    MOUNT_ZFS) == 0;
		w2 |= zfs ? W2(FATTR4_CLONE_BLKSIZE) :
		    vp != NULL ? W2(FATTR4_SPACE_FREED) : 0;
	}
	return w2;
}

/* Words past two that this minor version has nothing to say of. */
static inline bool
attr_more(const struct nfsv4_bitmap *bm, struct vnode *vp, uint32_t minor)
{
	uint32_t w2;

	w2 = bm->bm_n > 2 ? bm->bm_w[2] : 0;
	return bm->bm_more || (w2 & ~attr_w2_by(vp, minor)) != 0;
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

/* s8.3.1: VERIFY in an absent file system. */
bool
nfsv4_attr_absent_ok(const struct nfsv4_bitmap *bm)
{

	return (attr_mask(bm) & BIT(FATTR4_FS_LOCATIONS)) != 0 &&
	    (attr_mask(bm) & ~attr_absent) == 0;
}

bool
nfsv4_attr_supported(const struct nfsv4_compound *c,
    const struct nfsv4_bitmap *bm, struct vnode *vp)
{

	uint64_t m = attr_supported_full(vp);

	if (c->c_minor == 0)
		m &= ~attr_v41;
	return !attr_more(bm, vp, c->c_minor) && (attr_mask(bm) & ~m) == 0;
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

/*
 * RFC 7862 s12.2.3, a per file system attribute.  FFS and tmpfs do what
 * nfsv4_attr_change() relies on, and the value is time_metadata folded,
 * so NFS4_CHANGE_TYPE_IS_TIME_METADATA.  ZFS adds a sequence number to a
 * ctime that can go backwards, and the others are not known to move
 * ctime for each change.
 */
static uint32_t
attr_change_type(const struct vnode *vp)
{

	if (vp != NULL &&
	    (strcmp(vp->v_mount->mnt_stat.f_fstypename, MOUNT_FFS) == 0 ||
	    strcmp(vp->v_mount->mnt_stat.f_fstypename, MOUNT_TMPFS) == 0))
		return NFS4_CHANGE_TYPE_IS_TIME_METADATA;
	return NFS4_CHANGE_TYPE_IS_UNDEFINED;
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

/* A pathname4, s2.2.8, from the text of a path. */
static bool
attr_pathname(XDR *x, const char *p, const char *end)
{
	const char *e;
	uint32_t n = 0, l;

	for (e = p; e < end; e++) {
		if (*e != '/' && (e == p || e[-1] == '/'))
			n++;
	}
	if (!xdr_u_int32_t(x, &n))
		return false;
	while (p < end) {
		if (*p == '/') {
			p++;
			continue;
		}
		e = memchr(p, '/', end - p);
		if (e == NULL)
			e = end;
		l = (uint32_t)(e - p);
		if (!xdr_u_int32_t(x, &l) ||
		    !xdr_opaque(x, __UNCONST(p), l))
			return false;
		p = e;
	}
	return true;
}

static u_int
attr_count(const char *p, const char *end, char c)
{
	u_int n = 1;

	for (; p < end; p++)
		n += *p == c;
	return n;
}

/* The fs_location4 of "s1,s2:/root". */
static bool
attr_fs_location(XDR *x, const char *p, const char *end)
{
	const char *colon, *e;
	uint32_t n, l;

	colon = memchr(p, ':', end - p);
	if (colon == NULL)
		return false;
	n = attr_count(p, colon, ',');
	if (!xdr_u_int32_t(x, &n))
		return false;
	while (p < colon) {
		e = memchr(p, ',', colon - p);
		if (e == NULL)
			e = colon;
		l = (uint32_t)(e - p);
		if (!xdr_u_int32_t(x, &l) ||
		    !xdr_opaque(x, __UNCONST(p), l))
			return false;
		p = e < colon ? e + 1 : e;
	}
	return attr_pathname(x, colon + 1, end);
}

/*
 * fs_locations, s8.8.  Other than for a referral no file system is known
 * to live anywhere else, so there are no locations, as s8.8 has it, and
 * only fs_root says anything: the mount point, which is the path a client
 * reaches it by through the pseudo file system.
 */
static bool
attr_fs_locations(XDR *x, const struct nfsv4_cfh *cf)
{
	const char *p, *end, *e;
	size_t len;
	uint32_t n;

	if (cf->cf_ref != NULL) {
		p = cf->cf_ref->rf_path;
		len = strlen(p);
	} else if (cf->cf_vp != NULL) {
		p = cf->cf_vp->v_mount->mnt_stat.f_mntonname;
		len = strlen(p);
	} else
		p = nfsv4_cfh_path(cf, &len);
	if (!attr_pathname(x, p, p + len))
		return false;
	if (cf->cf_ref == NULL) {
		n = 0;
		return xdr_u_int32_t(x, &n);	/* locations<> */
	}
	p = cf->cf_ref->rf_locs;
	end = p + strlen(p);
	n = attr_count(p, end, ';');
	if (!xdr_u_int32_t(x, &n))
		return false;
	while (p < end) {
		e = memchr(p, ';', end - p);
		if (e == NULL)
			e = end;
		if (!attr_fs_location(x, p, e))
			return false;
		p = e < end ? e + 1 : e;
	}
	return true;
}

/* s5.9, by nfsv4_idmap.c. */
static bool
attr_id(XDR *x, bool group, uint32_t id)
{
	char buf[NFSV4_IDSTR_MAX];
	uint32_t len;

	len = nfsv4_idmap_out(group, id, buf);
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

/* The high bit keeps it from the numbers that files have. */
static uint64_t
attr_named_fileid(uint64_t id, const char *name)
{

	for (; *name != '\0'; name++)
		id = (id ^ (uint8_t)*name) * 0x100000001b3ULL;
	return id | (1ULL << 63);
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
	uint32_t st, w2, w2low, w2out, w2sup;
	u_int n;
	bool ok;
	XDR x;
	int error;

	sup = attr_supported_by(vp);
	if ((attr_mask(want) & (BIT(FATTR4_SUPPORTED_ATTRS) | attr_stored |
	    attr_quota)) != 0 && cf->cf_attr == 0)
		sup = attr_supported_full(vp);
	if (c->c_minor == 0)
		sup &= ~attr_v41;
	m = attr_mask(want) & sup & ~attr_setonly;
	if (cf->cf_ref != NULL)
		m &= attr_absent;
	if (rderr == NFS4ERR_MOVED)	/* s8.3.2 */
		m &= attr_absent;
	else if (rderr != NFS4_OK)
		m &= BIT(FATTR4_RDATTR_ERROR);
	w2sup = attr_w2_by(vp, c->c_minor);
	w2 = (want->bm_n > 2 ? want->bm_w[2] : 0) & w2sup & ~W2_ALL;
	if (rderr != NFS4_OK)
		w2 = 0;

	id = 0;
	if (vp != NULL && ((m & attr_vattr) != 0 ||
	    (w2 & (W2(FATTR4_CLONE_BLKSIZE) | W2(FATTR4_SPACE_FREED))) != 0)) {
		vn_lock(vp, LK_SHARED | LK_RETRY);
		error = VOP_GETATTR(vp, &va, cf->cf_cred);
		VOP_UNLOCK(vp);
		if (error != 0)
			return nfsv4_errno(error);
		if (cf->cf_attr == NFSV4_ATTR_FILE) {
			/* Its own number among the file system's. */
			va.va_fileid = attr_named_fileid(va.va_fileid,
			    cf->cf_aname);
			va.va_size = 0;
			if ((m & BIT(FATTR4_SIZE)) != 0) {
				error = nfsv4_xattr_size(cf, &va.va_size);
				if (error != 0)
					return nfsv4_errno(error);
			}
		}
		/* s10.4.3 */
		if (c->c_ov.ao_valid) {
			va.va_size = c->c_ov.ao_size;
			va.va_mtime = c->c_ov.ao_time;
			va.va_ctime = c->c_ov.ao_time;
		}
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
			ok = attr_u32(&x, c->c_minor != 0 ? 3 : 2) &&
			    attr_u32(&x, W0(sup)) && attr_u32(&x, W1(sup));
			if (ok && c->c_minor != 0)
				ok = attr_u32(&x, w2sup);
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
			ok = attr_u32(&x, cf->cf_attr == NFSV4_ATTR_DIR ?
			    NF4ATTRDIR : cf->cf_attr == NFSV4_ATTR_FILE ?
			    NF4NAMEDATTR : vp ? attr_ftype(va.va_type) : NF4DIR);
			break;
		case FATTR4_FH_EXPIRE_TYPE:
			ok = attr_u32(&x, FH4_PERSISTENT);
			break;
		case FATTR4_CHANGE:
			/* A pseudo node only changes at a reboot, as far
			   as a client can tell; see nfsv4_fh.c. */
			ok = attr_u64(&x, c->c_ov.ao_valid ? c->c_ov.ao_change :
			    vp ? nfsv4_attr_change(vp, &va) :
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
		case FATTR4_FS_LOCATIONS:
			ok = attr_fs_locations(&x, cf);
			if (cf->cf_ref != NULL)
				c->c_probed = true;	/* s9.14.3 */
			break;
		case FATTR4_CHANGE_POLICY:
			/* s5.8.2.5: fs_locations moves with the generation. */
			ok = attr_u64(&x, nfsv4_moved_gen()) &&
			    attr_u64(&x, (cf->cf_exflags & MNT_EXRDONLY) != 0);
			break;
		case FATTR4_FS_STATUS:
			/* s11.18: no image history to tell, so no strings. */
			ok = attr_u32(&x, cf->cf_ref != NULL) &&
			    attr_u32(&x, cf->cf_ref != NULL ?
			    STATUS4_REFERRAL : STATUS4_WRITABLE) &&
			    attr_u32(&x, 0) && attr_u32(&x, 0) &&
			    attr_u32(&x, 0) && attr_u64(&x, 0) &&
			    attr_u32(&x, 0);
			break;
		case FATTR4_ARCHIVE:
			ok = attr_u32(&x, nfsv4_xstore_bool(vp, "nfsv4.archive"));
			break;
		case FATTR4_HIDDEN:
			ok = attr_u32(&x, nfsv4_xstore_bool(vp, "nfsv4.hidden"));
			break;
		case FATTR4_SYSTEM:
			ok = attr_u32(&x, nfsv4_xstore_bool(vp, "nfsv4.system"));
			break;
		case FATTR4_MIMETYPE: {
			char mime[NFSV4_MIME_MAX];
			uint32_t l = nfsv4_xstore_mime(vp, mime);

			ok = xdr_u_int32_t(&x, &l) && xdr_opaque(&x, mime, l);
			break;
		}
		case FATTR4_TIME_BACKUP: {
			struct timespec ts;

			nfsv4_xstore_time(vp, &ts);
			ok = attr_time(&x, &ts);
			break;
		}
		case FATTR4_QUOTA_AVAIL_HARD:
		case FATTR4_QUOTA_AVAIL_SOFT:
		case FATTR4_QUOTA_USED:
			ok = attr_quota_put(&x, vp, va.va_uid, n);
			break;
		case FATTR4_NAMED_ATTR:
			ok = attr_u32(&x, vp != NULL && cf->cf_attr == 0 &&
			    nfsv4_xattr_any(cf));
			break;
		case FATTR4_CASE_INSENSITIVE:
			ok = attr_u32(&x, 0);
			break;
		case FATTR4_FSID:
			if (cf->cf_ref != NULL) {
				/* s8.3.1: unlike any other here */
				ok = attr_u64(&x, NFSV4_PSEUDO_FSID_MAJOR +
				    cf->cf_ref->rf_index) && attr_u64(&x, 0);
			} else if (vp != NULL) {
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
			ok = attr_id(&x, false, vp ? va.va_uid : 0);
			break;
		case FATTR4_OWNER_GROUP:
			ok = attr_id(&x, true, vp ? va.va_gid : 0);
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

	/* The third word comes after all the others, s5.8.1.14. */
	w2low = 0;
	if (ok && rderr == NFS4_OK && c->c_minor != 0 && want->bm_n > 2 &&
	    cf->cf_ref == NULL)
		w2low = want->bm_w[2] & W2_ALL;
	if ((w2low & W2_EXCLCREAT) != 0) {
		sup = nfsv4_attr_exclcreat & attr_supported_by(vp);
		ok = attr_u32(&x, 2) && attr_u32(&x, W0(sup)) &&
		    attr_u32(&x, W1(sup));
	}
	/* s14.4; what local programs left in a directory is not looked at. */
	if (ok && (w2low & W2_CHARSET) != 0)
		ok = attr_u32(&x, nfsv4_utf8_only ?
		    FSCHARSET_CAP4_ALLOWS_ONLY_UTF8 :
		    FSCHARSET_CAP4_CONTAINS_NON_UTF8);

	/* RFC 7530 s16.7.4, lowest number first. */
	w2out = 0;
	if (ok && rderr == NFS4_OK && (w2 & W2(FATTR4_CLONE_BLKSIZE)) != 0) {
		/*
		 * In bytes, and per file on ZFS: RFC 7862 s12.2.1 says
		 * neither, draft-cel-nfsv4-copy-implementation-experience-03
		 * s10.1 asks for both.
		 */
		ok = attr_u32(&x, (uint32_t)va.va_blocksize);
		w2out |= W2(FATTR4_CLONE_BLKSIZE);
	}
	if (ok && (w2 & W2(FATTR4_SPACE_FREED)) != 0) {
		/* s12.2.2; another link keeps the blocks. */
		ok = attr_u64(&x, va.va_nlink > 1 ? 0 : va.va_bytes);
		w2out |= W2(FATTR4_SPACE_FREED);
	}
	if (ok && (w2 & W2(FATTR4_CHANGE_ATTR_TYPE)) != 0) {
		ok = attr_u32(&x, attr_change_type(vp));
		w2out |= W2(FATTR4_CHANGE_ATTR_TYPE);
	}

	if (sb != NULL)
		kmem_free(sb, sizeof(*sb));
	if (acl != NULL)
		acl_free(acl);
	if (!ok)
		return NFS4ERR_TOOSMALL;
	got->bm_n = (w2low | w2out) != 0 ? 3 : 2;
	got->bm_w[0] = W0(out);
	got->bm_w[1] = W1(out);
	got->bm_w[2] = w2low | w2out;
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
	/*
	 * s10.4.3: a client with a write delegation may have what these
	 * say in its cache.
	 */
	if (c->c_cur.cf_vp != NULL &&
	    (attr_mask(&a->getattr.mask) & attr_delegated) != 0) {
		st = nfsv4_deleg_getattr(c);
		if (st != NFS4_OK)
			return st;
	}

	buf = kmem_alloc(NFSV4_ATTRBUF, KM_SLEEP);
	st = nfsv4_attr_fill(c, &c->c_cur, &a->getattr.mask, NFS4_OK, buf,
	    NFSV4_ATTRBUF, &got, &len);
	c->c_ov.ao_valid = false;
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
attr_parse_id(XDR *x, bool group, uint32_t *idp)
{
	char buf[NFSV4_IDSTR_MAX];
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
	return nfsv4_attr_strid(group, buf, len, idp);
}

uint32_t
nfsv4_attr_strid(bool group, const char *buf, u_int len, uint32_t *idp)
{
	const char *at;
	uint64_t v;
	u_int i;

	if ((at = memchr(buf, '@', len)) != NULL)
		return nfsv4_idmap_in(group, buf, len, (u_int)(at - buf), idp);
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
    BIT(FATTR4_TIME_MODIFY_SET) | attr_stored;

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
	c->c_xs.xs_set = 0;
	/* Everything of version 4.2 that is given here is read-only. */
	if (c->c_minor >= 2 && fa->fa_mask.bm_n > 2 &&
	    (fa->fa_mask.bm_w[2] & attr_w2_by(c->c_cur.cf_vp, c->c_minor) &
	    ~W2_ALL) != 0)
		return NFS4ERR_INVAL;
	/* RFC 8881 s5.5: it is known, and get-only. */
	if (c->c_minor != 0 && !attr_more(&fa->fa_mask, NULL, 1) &&
	    fa->fa_mask.bm_n > 2 && fa->fa_mask.bm_w[2] != 0)
		return NFS4ERR_INVAL;
	if (attr_more(&fa->fa_mask, NULL, 0) ||
	    (m & ~(attr_supported | attr_stored | attr_quota)) != 0)
		return NFS4ERR_ATTRNOTSUPP;
	/* Whether these can be set depends on the file system. */
	if ((m & attr_stored) != 0 && (c->c_cur.cf_vp == NULL ||
	    !nfsv4_xstore_ok(c->c_cur.cf_vp)))
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
		case FATTR4_ARCHIVE:
		case FATTR4_HIDDEN:
		case FATTR4_SYSTEM:
			if (!xdr_u_int32_t(x, &v) || v > 1)
				st = NFS4ERR_BADXDR;
			else {
				if (n == FATTR4_ARCHIVE)
					c->c_xs.xs_archive = v;
				else if (n == FATTR4_HIDDEN)
					c->c_xs.xs_hidden = v;
				else
					c->c_xs.xs_system = v;
				c->c_xs.xs_set |= BIT(n);
			}
			break;
		case FATTR4_MIMETYPE:
			if (!xdr_u_int32_t(x, &v))
				st = NFS4ERR_BADXDR;
			else if (v > NFSV4_MIME_MAX)
				st = NFS4ERR_INVAL;
			else if (!xdr_opaque(x, c->c_xs.xs_mime, v))
				st = NFS4ERR_BADXDR;
			else {
				c->c_xs.xs_mimelen = v;
				c->c_xs.xs_set |= BIT(n);
			}
			break;
		case FATTR4_TIME_BACKUP:
			st = attr_parse_nfstime(x, &c->c_xs.xs_backup);
			if (st == NFS4_OK)
				c->c_xs.xs_set |= BIT(n);
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
			st = attr_parse_id(x, false, &id);
			if (st == NFS4_OK)
				va->va_uid = id;
			break;
		case FATTR4_OWNER_GROUP:
			st = attr_parse_id(x, true, &id);
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

	memset(&bm, 0, sizeof(bm));
	bm.bm_n = 2;
	bm.bm_w[0] = W0(set);
	bm.bm_w[1] = W1(set);
	return nfsv4_xdr_bitmap(x, &bm);
}
