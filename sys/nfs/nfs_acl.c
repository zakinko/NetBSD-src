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
 * The NFSACL side protocol, version 3, for the POSIX.1e ACLs of the
 * file systems exported by version 3.  There is no RFC.  What is here
 * follows two sources, cited by file and line at each place:
 *
 *	[X]	illumos usr/src/head/rpcsvc/nfs_acl.x, the published XDR
 *	[IS]	illumos usr/src/uts/common/fs/nfs/nfs_acl_srv.c
 *	[IF]	illumos usr/src/uts/common/fs/fs_subr.c
 *	[IN]	illumos usr/src/uts/common/fs/nfs/nfs_subr.c
 *	[L3]	Linux fs/nfsd/nfs3acl.c
 *	[LC]	Linux fs/nfs_common/nfsacl.c
 *	[LP]	Linux fs/posix_acl.c
 *	[LV]	Linux fs/nfsd/vfs.c
 *	[L2]	Linux fs/nfsd/nfs2acl.c
 *
 * illumos at 586678ac1bc, Linux at ef33735edec (v6.18 based).
 *
 * Versions 2 and 3.  Version 2 has GETATTR and ACCESS besides, as
 * illumos [IS 248-375] and Linux (fs/nfsd/nfs2acl.c [L2]) have them;
 * Linux clients speak only version 3 (fs/nfs/nfs3client.c:13-14).
 * GETXATTRDIR, version 2 procedure 5 and version 3 procedure 3, is
 * illumos' own [X 358-369], which Linux does not have [L3 259-295]: the
 * handle of the directory of a file's named attributes, which the
 * client then walks with NFS itself (nfs_srvxattr.c).
 *
 * A file system answers _PC_ACL_EXTENDED if it keeps POSIX.1e ACLs.
 * For one that does not -- tmpfs, ZFS and FFS with NFSv4 ACLs -- GETACL
 * makes the ACL from the mode, as both sources do (Linux through
 * __get_acl() returning NULL when !IS_POSIXACL [LP 139-140] and
 * posix_acl_from_mode() [L3 64-68]; illumos through fs_fab_acl() [IS
 * 470-487]), and SETACL is NFS3ERR_NOTSUPP, as both do (set_posix_acl()
 * [LP 945-946] and ZFS's ENOSYS [IN 3748-3750]).  The client then
 * keeps asking for the ACLs of the other files of the mount, which may
 * be on a file system that has them.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#ifdef _KERNEL_OPT
#include "opt_nfs_oncrpc.h"
#endif

#include <sys/param.h>
#include <sys/acl.h>
#include <sys/kauth.h>
#include <sys/kmem.h>
#include <sys/mbuf.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/unistd.h>
#include <sys/vnode.h>

#include <nfs/nfsproto.h>
#include <nfs/rpcv2.h>
#include <nfs/nfs.h>
#include <nfs/nfs_var.h>
#include <nfs/nfs_xattr.h>

#include <oncrpc/oncrpc.h>
#include <oncrpc/oncrpc_gss.h>

/* [X 346], IANA. */
#define	NFS_ACL_PROGRAM		100227
/* [X 347, 361]. */
#define	NFS_ACL_V2		2
#define	NFS_ACL_V3		3
/* [X 348-359]. */
#define	ACLPROC2_NULL		0
#define	ACLPROC2_GETACL		1
#define	ACLPROC2_SETACL		2
#define	ACLPROC2_GETATTR	3
#define	ACLPROC2_ACCESS		4
#define	ACLPROC2_GETXATTRDIR	5
/* [X 362-369]. */
#define	ACLPROC3_NULL		0
#define	ACLPROC3_GETACL		1
#define	ACLPROC3_SETACL		2
#define	ACLPROC3_GETXATTRDIR	3

/* ACCESS2args.access, [X 164-170]. */
#define	ACCESS2_READ		0x1
#define	ACCESS2_LOOKUP		0x2
#define	ACCESS2_MODIFY		0x4
#define	ACCESS2_EXTEND		0x8
#define	ACCESS2_DELETE		0x10
#define	ACCESS2_EXECUTE		0x20

/*
 * NFSERR_OPNOTSUPP of illumos' nfs.h, a version 2 status that RFC 1094
 * does not have.  illumos' puterrno() gives it for EOPNOTSUPP and ENOSYS
 * [IN 3629-3646], which is how SETACL on ZFS answers there; Linux sends
 * NFS3ERR_NOTSUPP, 10004, in version 2 as well (nfserrno() [LV 99] and
 * nfsacld_map_status() in fs/nfsd/nfs2acl.c leave it).  A client of
 * version 2 of this program is Solaris' or illumos', whose geterrno()
 * reads 45 as EOPNOTSUPP [IN 3656-3661]; 10004 it would take as an errno of
 * that number.  So this is illumos'.
 */
#define	NFSERR_V2_OPNOTSUPP	45

/* [X 28]. */
#define	NFS_ACL_MAX_ENTRIES	1024

/* aclent.type, [X 45-51]. */
#define	NA_USER_OBJ		0x1
#define	NA_USER			0x2
#define	NA_GROUP_OBJ		0x4
#define	NA_GROUP		0x8
#define	NA_CLASS_OBJ		0x10
#define	NA_OTHER_OBJ		0x20
#define	NA_ACL_DEFAULT		0x1000

/* aclent.perm, [X 58-60]. */
#define	NA_READ			0x4
#define	NA_WRITE		0x2
#define	NA_EXEC			0x1
#define	NA_PERMS		(NA_READ | NA_WRITE | NA_EXEC)

/* secattr.mask, [X 83-86]; Linux checks against the four [L3 57]. */
#define	NA_ACL			0x1
#define	NA_ACLCNT		0x2
#define	NA_DFACL		0x4
#define	NA_DFACLCNT		0x8
#define	NA_MASK			(NA_ACL | NA_ACLCNT | NA_DFACL | NA_DFACLCNT)

/*
 * aclent [X 36-40]: type, id and perm, each a word on the wire.  perm
 * is an o_mode, unsigned short [X 31], which XDR carries in four bytes;
 * Linux has elem_size 12 [LC 99].
 */
struct nfsacl_ent {
	uint32_t	ne_type;
	uint32_t	ne_id;
	uint32_t	ne_perm;
};

struct nfsacl_list {
	uint32_t	nl_cnt;		/* aclcnt or dfaclcnt */
	uint32_t	nl_len;		/* entries in nl_ent */
	struct nfsacl_ent *nl_ent;
};

/* The tags of <sys/acl.h> and of [X 45-50], by name, not by value. */
static const struct {
	acl_tag_t	nt_tag;
	uint32_t	nt_na;
} nfsacl_tags[] = {
	{ ACL_USER_OBJ,		NA_USER_OBJ },
	{ ACL_USER,		NA_USER },
	{ ACL_GROUP_OBJ,	NA_GROUP_OBJ },
	{ ACL_GROUP,		NA_GROUP },
	{ ACL_MASK,		NA_CLASS_OBJ },
	{ ACL_OTHER,		NA_OTHER_OBJ },
};

static uint32_t
nfsacl_tag_to_na(acl_tag_t tag)
{
	size_t i;

	for (i = 0; i < __arraycount(nfsacl_tags); i++)
		if (nfsacl_tags[i].nt_tag == tag)
			return nfsacl_tags[i].nt_na;
	return 0;
}

static acl_tag_t
nfsacl_na_to_tag(uint32_t na)
{
	size_t i;

	for (i = 0; i < __arraycount(nfsacl_tags); i++)
		if (nfsacl_tags[i].nt_na == na)
			return nfsacl_tags[i].nt_tag;
	return ACL_UNDEFINED_TAG;
}

static acl_perm_t
nfsacl_na_to_perm(uint32_t na)
{
	acl_perm_t perm = 0;

	if (na & NA_READ)
		perm |= ACL_READ;
	if (na & NA_WRITE)
		perm |= ACL_WRITE;
	if (na & NA_EXEC)
		perm |= ACL_EXECUTE;
	return perm;
}

static uint32_t
nfsacl_perm_to_na(acl_perm_t perm)
{
	uint32_t na = 0;

	if (perm & ACL_READ)
		na |= NA_READ;
	if (perm & ACL_WRITE)
		na |= NA_WRITE;
	if (perm & ACL_EXECUTE)
		na |= NA_EXEC;
	return na;
}

/* As [LV 65-120], for what the calls here can return. */
static uint32_t
nfsacl_errno(int error)
{

	if (error & NFSERR_AUTHERR) {
		/*
		 * A flavor the export does not take.  Linux answers
		 * NFS3ERR_ACCES [L3 23-24]; illumos rejects the call with
		 * AUTH_TOOWEAK in common_dispatch().  An RPC layer reply is
		 * not open to a procedure here, so this is Linux's.
		 */
		return NFSERR_ACCES;
	}
	switch (error) {
	case 0:			return NFS_OK;
	case EPERM:		return NFSERR_PERM;
	case ENOENT:		return NFSERR_NOENT;
	case EIO:		return NFSERR_IO;
	case ENXIO:		return NFSERR_NXIO;
	case EACCES:		return NFSERR_ACCES;
	case EEXIST:		return NFSERR_EXIST;
	case EXDEV:		return NFSERR_XDEV;
	case ENODEV:		return NFSERR_NODEV;
	case ENOTDIR:		return NFSERR_NOTDIR;
	case EISDIR:		return NFSERR_ISDIR;
	case EINVAL:		return NFSERR_INVAL;
	case EFBIG:		return NFSERR_FBIG;
	case ENOSPC:		return NFSERR_NOSPC;
	case EROFS:		return NFSERR_ROFS;
	case EMLINK:		return NFSERR_MLINK;
	case ENAMETOOLONG:	return NFSERR_NAMETOL;
	case ENOTEMPTY:		return NFSERR_NOTEMPTY;
	case EDQUOT:		return NFSERR_DQUOT;
	case ESTALE:		return NFSERR_STALE;
	case EBADF:		return NFSERR_STALE;
	case EAGAIN:		return NFSERR_JUKEBOX;
	case ENOMEM:		return NFSERR_JUKEBOX;
	case EOPNOTSUPP:	return NFSERR_NOTSUPP;
	default:		return NFSERR_IO;
	}
}

/*
 * Version 2: a handle that is not good is NFSERR_STALE, as
 * nfsacld_map_status() [L2] and illumos [IS 87-90].  The statuses that
 * version 2 does not have go as illumos' puterrno() sends them, the
 * errno itself [IN 3649-3650].
 */
static uint32_t
nfsacl_errno2(int error)
{
	uint32_t st;

	st = nfsacl_errno(error);
	switch (st) {
	case NFSERR_BADHANDLE:
		return NFSERR_STALE;
	case NFSERR_NOTSUPP:
		return NFSERR_V2_OPNOTSUPP;
	case NFSERR_JUKEBOX:
		/*
		 * A choice: illumos would send the errno, whose number is
		 * not the client's, and Linux 10008, which version 2 lacks.
		 */
		return NFSERR_IO;
	default:
		return st;
	}
}

/*
 * nfs_fh3, RFC 1813 s2.5, with the bounds of nfsm_srvmtofh(); or for
 * version 2 the fhandle of RFC 1094 s2.3.3, NFSX_V2FH bytes.
 */
static bool
nfsacl_get_fh(XDR *x, nfsrvfh_t *nsfh, bool v3)
{
	uint32_t len;

	if (!v3) {
		nsfh->nsfh_size = NFSX_V2FH;
		return xdr_opaque(x, (char *)NFSRVFH_DATA(nsfh), NFSX_V2FH);
	}
	if (!xdr_u_int32_t(x, &len))
		return false;
	if (len > NFSX_V3FHMAX || (len > 0 && len < FHANDLE_SIZE_MIN))
		return false;
	nsfh->nsfh_size = len;
	return len == 0 || xdr_opaque(x, (char *)NFSRVFH_DATA(nsfh), len);
}

/* post_op_attr, RFC 1813 s2.6, of these or NULL for none. */
static bool
nfsacl_put_va(XDR *x, const struct vattr *va)
{
	struct nfsrv_descript nd;
	struct nfs_fattr fa;
	uint32_t follows;

	follows = va != NULL;
	if (!xdr_u_int32_t(x, &follows))
		return false;
	if (!follows)
		return true;
	/* nfsm_srvfattr() looks at nd_flag only. */
	memset(&nd, 0, sizeof(nd));
	nd.nd_flag = ND_NFSV3;
	memset(&fa, 0, sizeof(fa));
	nfsm_srvfattr(&nd, __UNCONST(va), &fa);
	CTASSERT(sizeof(fa) >= NFSX_V3FATTR);
	return xdr_opaque(x, (char *)&fa, NFSX_V3FATTR);
}

/*
 * What a handle is: the file, or a node of its named attributes, whose
 * attributes are made once by nfs_xattr_vattr() (nfs_srvxattr.c).
 */
struct nfsacl_node {
	bool		nn_xattr;
	struct vattr	nn_va;
};

static int
nfsacl_getattr(struct vnode *vp, kauth_cred_t cred,
    const struct nfsacl_node *nn, struct vattr *va)
{

	if (nn->nn_xattr) {
		*va = nn->nn_va;
		return 0;
	}
	return VOP_GETATTR(vp, va, cred);
}

/* post_op_attr, RFC 1813 s2.6, with vp locked or NULL for none. */
static bool
nfsacl_put_attr(XDR *x, struct vnode *vp, kauth_cred_t cred,
    const struct nfsacl_node *nn)
{
	struct vattr va;

	return nfsacl_put_va(x, vp != NULL &&
	    nfsacl_getattr(vp, cred, nn, &va) == 0 ? &va : NULL);
}

/* fattr, RFC 1094 s2.3.5, of a locked vnode. */
static bool
nfsacl_put_fattr2(XDR *x, const struct vattr *va)
{
	struct nfsrv_descript nd;
	struct nfs_fattr fa;

	memset(&nd, 0, sizeof(nd));
	memset(&fa, 0, sizeof(fa));
	nfsm_srvfattr(&nd, __UNCONST(va), &fa);
	CTASSERT(sizeof(fa) >= NFSX_V2FATTR);
	return xdr_opaque(x, (char *)&fa, NFSX_V2FATTR);
}

/*
 * One of the two lists of secattr [X 72-75], as Linux decodes it
 * [LC 386-422]: the count, at most NFS_ACL_MAX_ENTRIES, then the array,
 * no longer than the count.  The entries are read when want, which is
 * when the mask asks for the list; otherwise they are only skipped
 * [L3 174-179, LC 393].  Linux wants the array as long as the count
 * when it keeps the list [LC 412]; illumos lets an empty array go with
 * any count [illumos nfs_acl_xdr.c:99], which is what a count-only
 * reply carries.  This is Linux's, being the stricter for a call.
 */
static bool
nfsacl_get_list(XDR *x, struct nfsacl_list *nl, bool want)
{
	struct nfsacl_ent e;
	uint32_t i;

	nl->nl_ent = NULL;
	if (!xdr_u_int32_t(x, &nl->nl_cnt) ||
	    nl->nl_cnt > NFS_ACL_MAX_ENTRIES ||
	    !xdr_u_int32_t(x, &nl->nl_len) ||
	    nl->nl_len > nl->nl_cnt)
		return false;
	if (want && nl->nl_len != nl->nl_cnt)
		return false;
	if (want && nl->nl_len > 0)
		nl->nl_ent = kmem_alloc(nl->nl_len * sizeof(e), KM_SLEEP);
	for (i = 0; i < nl->nl_len; i++) {
		if (!xdr_u_int32_t(x, &e.ne_type) ||
		    !xdr_u_int32_t(x, &e.ne_id) ||
		    !xdr_u_int32_t(x, &e.ne_perm))
			return false;
		if (!want)
			continue;
		/* xdr_nfsace_decode() [LC 237-265]. */
		e.ne_type &= ~NA_ACL_DEFAULT;
		switch (e.ne_type) {
		case NA_USER:
		case NA_GROUP:
			/* make_kuid() of -1 is invalid [LC 244-251]. */
			if (e.ne_id == (uint32_t)ACL_UNDEFINED_ID)
				return false;
			break;
		case NA_USER_OBJ:
		case NA_GROUP_OBJ:
		case NA_OTHER_OBJ:
			if (e.ne_perm & ~NA_PERMS)
				return false;
			break;
		case NA_CLASS_OBJ:
			/* "Solaris sometimes sets additional bits" [LC 260]. */
			e.ne_perm &= NA_PERMS;
			break;
		default:
			return false;
		}
		nl->nl_ent[i] = e;
	}
	return true;
}

static void
nfsacl_free_list(struct nfsacl_list *nl)
{

	if (nl->nl_ent != NULL)
		kmem_free(nl->nl_ent, nl->nl_len * sizeof(*nl->nl_ent));
	nl->nl_ent = NULL;
}

/*
 * The wire list into a struct acl, as posix_acl_from_nfsacl() [LC
 * 292-327]: the ACL_MASK of a four entry ACL that has the permissions
 * of ACL_GROUP_OBJ is Solaris' and goes.  Linux sorts by (tag, id)
 * first; the order of a struct acl does not matter to acl_posix1e_check()
 * or to the file systems, so it is kept as sent.  The ids of the _OBJ
 * entries and of the mask are those of the file [LC 17-19] and are
 * not kept, which acl_posix1e_check() wants.  Permissions of ACL_USER
 * and ACL_GROUP over NA_PERMS, which the decoder lets through, are
 * EINVAL as from posix_acl_valid() in set_posix_acl() [LP 957-960].
 */
static int
nfsacl_to_acl(const struct nfsacl_list *nl, struct acl *acl)
{
	const struct nfsacl_ent *e;
	int group = -1, mask = -1;
	uint32_t i, n;

	if (nl->nl_len > ACL_MAX_ENTRIES)
		return EINVAL;
	for (i = 0; i < nl->nl_len; i++) {
		e = &nl->nl_ent[i];
		if (e->ne_type == NA_GROUP_OBJ)
			group = i;
		else if (e->ne_type == NA_CLASS_OBJ)
			mask = i;
	}
	if (nl->nl_len == 4 && group >= 0 && mask >= 0 &&
	    nl->nl_ent[group].ne_perm == nl->nl_ent[mask].ne_perm)
		;	/* the mask is skipped below */
	else
		mask = -1;
	for (i = n = 0; i < nl->nl_len; i++) {
		if ((int)i == mask)
			continue;
		e = &nl->nl_ent[i];
		acl->acl_entry[n].ae_tag = nfsacl_na_to_tag(e->ne_type);
		acl->acl_entry[n].ae_id =
		    e->ne_type == NA_USER || e->ne_type == NA_GROUP ?
		    e->ne_id : ACL_UNDEFINED_ID;
		if (e->ne_perm & ~NA_PERMS)
			return EINVAL;
		acl->acl_entry[n].ae_perm = nfsacl_na_to_perm(e->ne_perm);
		n++;
	}
	acl->acl_cnt = n;
	return 0;
}

/* The three entry ACL of a mode, as posix_acl_from_mode() [LP]. */
static void
nfsacl_acl_from_mode(mode_t mode, struct acl *acl)
{

	acl->acl_cnt = 3;
	acl->acl_entry[0] = acl_posix1e_mode_to_entry(ACL_USER_OBJ,
	    ACL_UNDEFINED_ID, ACL_UNDEFINED_ID, mode);
	acl->acl_entry[1] = acl_posix1e_mode_to_entry(ACL_GROUP_OBJ,
	    ACL_UNDEFINED_ID, ACL_UNDEFINED_ID, mode);
	acl->acl_entry[2] = acl_posix1e_mode_to_entry(ACL_OTHER,
	    ACL_UNDEFINED_ID, ACL_UNDEFINED_ID, mode);
}

/*
 * One list of a GETACL reply, as nfs_stream_encode_acl() [LC 154-209]:
 * the count, then the entries if the mask asks for them, else an empty
 * array.  A three entry ACL goes as four, with an ACL_MASK of the
 * group's permissions, in the order USER_OBJ, GROUP_OBJ, MASK, OTHER
 * ("other orders seem to confuse Solaris VxFS", [LC 114-132]).  The
 * _OBJ entries carry the owner and group of the file, the rest of the
 * entries that are not named 0 ("Solaris depends on that!", [LC 59-76]).
 */
static bool
nfsacl_put_list(XDR *x, const struct acl *acl, bool entries, uint32_t flag,
    uid_t uid, gid_t gid)
{
	static const acl_tag_t minimal[] = {
		ACL_USER_OBJ, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER
	};
	struct acl_entry ae;
	uint32_t cnt, len, i, j, type, id, perm;

	cnt = acl == NULL || acl->acl_cnt == 0 ? 0 :
	    MAX(acl->acl_cnt, __arraycount(minimal));
	/* A POSIX.1e ACL that is not empty has the three _OBJ entries. */
	if (cnt > NFS_ACL_MAX_ENTRIES || (cnt > 0 && acl->acl_cnt < 3))
		return false;
	len = entries ? cnt : 0;
	if (!xdr_u_int32_t(x, &cnt) || !xdr_u_int32_t(x, &len))
		return false;
	for (i = 0; i < len; i++) {
		if (acl->acl_cnt == 3) {
			/* GROUP_OBJ stands for the mask it lacks. */
			acl_tag_t want = minimal[i] == ACL_MASK ?
			    ACL_GROUP_OBJ : minimal[i];

			for (j = 0; j < 3; j++)
				if (acl->acl_entry[j].ae_tag == want)
					break;
			if (j == 3)
				return false;
			ae = acl->acl_entry[j];
			ae.ae_tag = minimal[i];
		} else
			ae = acl->acl_entry[i];
		type = nfsacl_tag_to_na(ae.ae_tag) | flag;
		switch (ae.ae_tag) {
		case ACL_USER_OBJ:	id = uid;		break;
		case ACL_GROUP_OBJ:	id = gid;		break;
		case ACL_USER:
		case ACL_GROUP:		id = ae.ae_id;		break;
		default:		id = 0;			break;
		}
		perm = nfsacl_perm_to_na(ae.ae_perm);
		if (!xdr_u_int32_t(x, &type) || !xdr_u_int32_t(x, &id) ||
		    !xdr_u_int32_t(x, &perm))
			return false;
	}
	return true;
}

static bool
nfsacl_posix(struct vnode *vp)
{
	register_t v;

	return VOP_PATHCONF(vp, _PC_ACL_EXTENDED, &v) == 0 && v != 0;
}

/* nd_flag & ND_KERBAUTH for nfsrv_fhtovp(), as nfs_oncrpc_dispatch(). */
static int
nfsacl_kerbflag(const struct oncrpc_req *rq)
{

	if (rq->rq_flavor != RPCSEC_GSS)
		return 0;
	return (rq->rq_secflavor == RPCSEC_GSS_KRB5 ? NFS_EXSEC_KRB5 :
	    rq->rq_secflavor == RPCSEC_GSS_KRB5I ? NFS_EXSEC_KRB5I :
	    NFS_EXSEC_KRB5P) << ND_SECSHIFT;
}

/*
 * The handle to a locked vnode, with the checks of the export.  A call
 * with no credential is AUTH_NONE, which nfs_oncrpc_dispatch() refuses
 * for all but NULL; here that is NFS3ERR_ACCES like a weak flavor.
 */
static int
nfsacl_fhtovp(struct oncrpc_req *rq, kauth_cred_t cred, nfsrvfh_t *nsfh,
    struct vnode **vpp, int *rdonly, struct nfsacl_node *nn)
{
	char name[NFS_XATTR_NAMEMAX + 1];
	bool v3 = rq->rq_vers == NFS_ACL_V3;
	int error, kind;

	*vpp = NULL;
	nn->nn_xattr = false;
	if (cred == NULL || (rq->rq_flavor != RPCAUTH_UNIX &&
	    rq->rq_flavor != RPCSEC_GSS))
		return NFSERR_AUTHERR | AUTH_TOOWEAK;
	if (nfsrv_xattr_marked(nsfh, v3, NULL, NULL) == 0)
		return nfsrv_fhtovp(nsfh, 1, vpp, cred, NULL, rq->rq_nam,
		    rdonly, nfsacl_kerbflag(rq), false);
	/*
	 * A named attribute or its directory.  illumos answers for them
	 * as for any file: VOP_GETSECATTR() of the ZFS file that holds the
	 * attribute, or of the gfs directory, which has none, is ENOSYS for
	 * these ACLs and fs_fab_acl() makes one of the mode [IS 89-113].
	 * The vnode is the file's, which says who may do what, and the
	 * attributes are the node's.
	 */
	error = nfsrv_xattr_fhtovp(nsfh, v3, cred, NULL, rq->rq_nam,
	    nfsacl_kerbflag(rq), vpp, &kind, name, rdonly, NULL);
	if (error == 0)
		error = nfs_xattr_vattr(*vpp, cred, kind, name, &nn->nn_va);
	if (error != 0) {
		if (*vpp != NULL)
			vrele(*vpp);
		*vpp = NULL;
		return error;
	}
	nn->nn_xattr = true;
	vn_lock(*vpp, LK_EXCLUSIVE | LK_RETRY);
	return 0;
}

/*
 * Taken, not shared, as in nfs_oncrpc_dispatch(): nfsrv_fhtovp() maps
 * root by changing the credential, which wants the only reference.
 */
static kauth_cred_t
nfsacl_takecred(struct oncrpc_req *rq)
{
	kauth_cred_t cred = rq->rq_cred;

	rq->rq_cred = NULL;
	return cred;
}

static void
nfsacl_freecred(kauth_cred_t cred)
{

	if (cred != NULL)
		kauth_cred_free(cred);
}

/*
 * GETACL, [X 209-228] and [L3 42-97, 189-220].  The reply's mask is the
 * call's [L3 61].  The default ACL of a file that is not a directory is
 * empty: Linux gets none from get_inode_acl() there, and leaves "Check
 * how Solaris handles" open [L3 75-84]; the file systems here refuse
 * the question with EINVAL instead.
 */
static enum oncrpc_dispatch
nfsacl_getacl(struct oncrpc_req *rq)
{
	XDR *ax = rq->rq_args, *rx = rq->rq_res;
	struct acl *acl = NULL, *dfacl = NULL;
	struct vnode *vp = NULL;
	struct vattr va;
	kauth_cred_t cred;
	nfsrvfh_t nsfh;
	struct nfsacl_node nn;
	uint32_t mask, status;
	int error, rdonly;
	bool ok;

	bool v3 = rq->rq_vers == NFS_ACL_V3;

	if (!nfsacl_get_fh(ax, &nsfh, v3) || !xdr_u_int32_t(ax, &mask))
		return ONCRPC_ERR_ARGS;

	cred = nfsacl_takecred(rq);
	vattr_null(&va);
	error = nfsacl_fhtovp(rq, cred, &nsfh, &vp, &rdonly, &nn);
	if (error != 0)
		goto out;
	/* Version 2 has no NFSERR_INVAL: Linux sends NFSERR_IO [L2]. */
	if (mask & ~NA_MASK) {
		error = v3 ? EINVAL : EIO;
		goto out;
	}
	error = nfsacl_getattr(vp, cred, &nn, &va);
	if (error != 0)
		goto out;
	if (mask & (NA_ACL | NA_ACLCNT)) {
		acl = acl_alloc(KM_SLEEP);
		if (!nn.nn_xattr && nfsacl_posix(vp)) {
			error = VOP_GETACL(vp, ACL_TYPE_ACCESS, acl, cred);
			if (error != 0)
				goto out;
		} else
			nfsacl_acl_from_mode(va.va_mode, acl);
	}
	if (mask & (NA_DFACL | NA_DFACLCNT)) {
		dfacl = acl_alloc(KM_SLEEP);
		/* fs_fab_acl() makes no default ACL [IF 623]. */
		if (vp->v_type == VDIR && !nn.nn_xattr && nfsacl_posix(vp)) {
			error = VOP_GETACL(vp, ACL_TYPE_DEFAULT, dfacl, cred);
			if (error != 0)
				goto out;
		}
	}
out:
	/*
	 * GETACL2res [X 97-107]: the attributes only with NFS_OK, those
	 * that were read before the ACL, as Linux [L2] and illumos [IS
	 * 124-128] send them.  GETACL3res has post_op_attr either way.
	 */
	if (v3) {
		status = nfsacl_errno(error);
		ok = xdr_u_int32_t(rx, &status) &&
		    nfsacl_put_attr(rx, vp, cred, &nn);
	} else {
		status = nfsacl_errno2(error);
		ok = xdr_u_int32_t(rx, &status) &&
		    (status != NFS_OK || nfsacl_put_fattr2(rx, &va));
	}
	if (ok && status == NFS_OK) {
		ok = xdr_u_int32_t(rx, &mask) &&
		    nfsacl_put_list(rx, acl, (mask & NA_ACL) != 0, 0,
			va.va_uid, va.va_gid) &&
		    nfsacl_put_list(rx, dfacl, (mask & NA_DFACL) != 0,
			NA_ACL_DEFAULT, va.va_uid, va.va_gid);
	}
	if (vp != NULL)
		vput(vp);
	if (acl != NULL)
		acl_free(acl);
	if (dfacl != NULL)
		acl_free(dfacl);
	nfsacl_freecred(cred);
	return ok ? ONCRPC_DONE : ONCRPC_ERR_SYSTEM;
}

/*
 * The access ACL, or with none sent its removal.  Linux removes it with
 * set_posix_acl(NULL) [L3 124-128], after which the file has the ACL of
 * its mode; the file systems here do not take NULL for the access ACL,
 * so it is the ACL of the mode that is set.
 */
static int
nfsacl_set_access(struct vnode *vp, struct acl *acl, kauth_cred_t cred)
{
	struct vattr va;
	int error;

	if (acl->acl_cnt == 0) {
		error = VOP_GETATTR(vp, &va, cred);
		if (error != 0)
			return error;
		nfsacl_acl_from_mode(va.va_mode, acl);
	}
	return VOP_SETACL(vp, ACL_TYPE_ACCESS, acl, cred);
}

/*
 * The default ACL, or its removal when none is sent.  On a file that is
 * not a directory set_posix_acl() takes removal and refuses an ACL with
 * EACCES [LP 950-951].
 */
static int
nfsacl_set_default(struct vnode *vp, struct acl *acl, kauth_cred_t cred)
{

	if (vp->v_type != VDIR)
		return acl->acl_cnt == 0 ? 0 : EACCES;
	return VOP_SETACL(vp, ACL_TYPE_DEFAULT,
	    acl->acl_cnt == 0 ? NULL : acl, cred);
}

/*
 * SETACL, [X 234-252] and [L3 102-144, 163-182]: the access ACL first,
 * and the default only if that went.  A mask with neither list asks for
 * nothing and is NFS3_OK, wherever the file is.
 */
static enum oncrpc_dispatch
nfsacl_setacl(struct oncrpc_req *rq)
{
	XDR *ax = rq->rq_args, *rx = rq->rq_res;
	struct nfsacl_list al, dl;
	struct acl *acl = NULL;
	struct vnode *vp = NULL;
	kauth_cred_t cred;
	nfsrvfh_t nsfh;
	struct nfsacl_node nn;
	uint32_t mask, status;
	int error, rdonly;
	bool ok;

	struct vattr va;
	bool v3 = rq->rq_vers == NFS_ACL_V3;

	memset(&al, 0, sizeof(al));
	memset(&dl, 0, sizeof(dl));
	/* [L3 168-181], [L2]: a mask over the four is GARBAGE_ARGS. */
	if (!nfsacl_get_fh(ax, &nsfh, v3) || !xdr_u_int32_t(ax, &mask) ||
	    (mask & ~NA_MASK) != 0 ||
	    !nfsacl_get_list(ax, &al, (mask & NA_ACL) != 0) ||
	    !nfsacl_get_list(ax, &dl, (mask & NA_DFACL) != 0)) {
		nfsacl_free_list(&al);
		nfsacl_free_list(&dl);
		return ONCRPC_ERR_ARGS;
	}

	cred = nfsacl_takecred(rq);
	error = nfsacl_fhtovp(rq, cred, &nsfh, &vp, &rdonly, &nn);
	if (error != 0)
		goto out;
	if ((mask & (NA_ACL | NA_DFACL)) == 0)
		goto out;
	/* [IS 578-581]; Linux's fh_want_write() [L3 117]. */
	if (rdonly || (vp->v_mount->mnt_flag & MNT_RDONLY)) {
		error = EROFS;
		goto out;
	}
	if (nn.nn_xattr || !nfsacl_posix(vp)) {
		error = EOPNOTSUPP;
		goto out;
	}
	acl = acl_alloc(KM_SLEEP);
	if (mask & NA_ACL) {
		error = nfsacl_to_acl(&al, acl);
		if (error == 0)
			error = nfsacl_set_access(vp, acl, cred);
		if (error != 0)
			goto out;
	}
	if (mask & NA_DFACL) {
		memset(acl, 0, sizeof(*acl));
		acl->acl_maxcnt = ACL_MAX_ENTRIES;
		error = nfsacl_to_acl(&dl, acl);
		if (error == 0)
			error = nfsacl_set_default(vp, acl, cred);
	}
out:
	if (v3) {
		status = nfsacl_errno(error);
		ok = xdr_u_int32_t(rx, &status) &&
		    nfsacl_put_attr(rx, vp, cred, &nn);
	} else {
		/* SETACL2res [X 118-127]: attrstat, as fh_getattr() [L2]. */
		if (error == 0)
			error = nfsacl_getattr(vp, cred, &nn, &va);
		status = nfsacl_errno2(error);
		ok = xdr_u_int32_t(rx, &status) &&
		    (status != NFS_OK || nfsacl_put_fattr2(rx, &va));
	}
	if (vp != NULL)
		vput(vp);
	if (acl != NULL)
		acl_free(acl);
	nfsacl_free_list(&al);
	nfsacl_free_list(&dl);
	nfsacl_freecred(cred);
	return ok ? ONCRPC_DONE : ONCRPC_ERR_SYSTEM;
}

/*
 * Version 2 GETATTR [X 137-150]: attrstat, as acl2_getattr() [IS
 * 248-276] and nfsacld_proc_getattr() [L2].
 */
static enum oncrpc_dispatch
nfsacl_getattr2(struct oncrpc_req *rq)
{
	XDR *ax = rq->rq_args, *rx = rq->rq_res;
	struct vnode *vp = NULL;
	struct vattr va;
	kauth_cred_t cred;
	nfsrvfh_t nsfh;
	struct nfsacl_node nn;
	uint32_t status;
	int error, rdonly;
	bool ok;

	if (!nfsacl_get_fh(ax, &nsfh, false))
		return ONCRPC_ERR_ARGS;
	cred = nfsacl_takecred(rq);
	error = nfsacl_fhtovp(rq, cred, &nsfh, &vp, &rdonly, &nn);
	if (error == 0)
		error = nfsacl_getattr(vp, cred, &nn, &va);
	status = nfsacl_errno2(error);
	ok = xdr_u_int32_t(rx, &status) &&
	    (status != NFS_OK || nfsacl_put_fattr2(rx, &va));
	if (vp != NULL)
		vput(vp);
	nfsacl_freecred(cred);
	return ok ? ONCRPC_DONE : ONCRPC_ERR_SYSTEM;
}

/*
 * Version 2 ACCESS [X 156-182], as acl2_access() [IS 287-372]: each bit
 * asked for is VOP_ACCESS of the mode it needs, LOOKUP and DELETE only
 * on a directory, and on an export that is read only no MODIFY, EXTEND
 * or DELETE for a file or directory; a special file is left to the
 * client.  Linux's map [L2] asks the same of each bit.  Then the
 * attributes, read after the checks.
 *
 * A node of named attributes goes by its own type, not by the file's
 * vnode, and by the rules of xa_access3(): VREAD of the file to read
 * or look up, VWRITE to change, and nothing executes.  Taking the
 * file's type left the directory without LOOKUP, and illumos' runat
 * over version 2 then failed with EACCES.
 */
static enum oncrpc_dispatch
nfsacl_access2(struct oncrpc_req *rq)
{
	XDR *ax = rq->rq_args, *rx = rq->rq_res;
	struct vnode *vp = NULL;
	struct vattr va;
	kauth_cred_t cred;
	nfsrvfh_t nsfh;
	struct nfsacl_node nn;
	uint32_t want, got = 0, status;
	int error, rdonly, lookmode;
	enum vtype type;
	bool ok, wperm;

	if (!nfsacl_get_fh(ax, &nsfh, false) || !xdr_u_int32_t(ax, &want))
		return ONCRPC_ERR_ARGS;
	cred = nfsacl_takecred(rq);
	error = nfsacl_fhtovp(rq, cred, &nsfh, &vp, &rdonly, &nn);
	if (error != 0)
		goto out;
	type = nn.nn_xattr ? nn.nn_va.va_type : vp->v_type;
	lookmode = nn.nn_xattr ? VREAD : VEXEC;
	wperm = !((rdonly || (vp->v_mount->mnt_flag & MNT_RDONLY)) &&
	    (type == VREG || type == VDIR));
	if ((want & ACCESS2_READ) && VOP_ACCESS(vp, VREAD, cred) == 0)
		got |= ACCESS2_READ;
	if ((want & ACCESS2_LOOKUP) && type == VDIR &&
	    VOP_ACCESS(vp, lookmode, cred) == 0)
		got |= ACCESS2_LOOKUP;
	if (wperm && (want & (ACCESS2_MODIFY | ACCESS2_EXTEND)) &&
	    VOP_ACCESS(vp, VWRITE, cred) == 0)
		got |= want & (ACCESS2_MODIFY | ACCESS2_EXTEND);
	if (wperm && (want & ACCESS2_DELETE) && type == VDIR &&
	    VOP_ACCESS(vp, VWRITE, cred) == 0)
		got |= ACCESS2_DELETE;
	if ((want & ACCESS2_EXECUTE) && !nn.nn_xattr &&
	    VOP_ACCESS(vp, VEXEC, cred) == 0)
		got |= ACCESS2_EXECUTE;
	error = nfsacl_getattr(vp, cred, &nn, &va);
out:
	status = nfsacl_errno2(error);
	ok = xdr_u_int32_t(rx, &status) &&
	    (status != NFS_OK ||
	     (nfsacl_put_fattr2(rx, &va) && xdr_u_int32_t(rx, &got)));
	if (vp != NULL)
		vput(vp);
	nfsacl_freecred(cred);
	return ok ? ONCRPC_DONE : ONCRPC_ERR_SYSTEM;
}

/*
 * GETXATTRDIR [X 185-203, 255-273], as acl2_getxattrdir() and
 * acl3_getxattrdir() [IS 383-440, 623-679]: without create, a file with
 * no named attributes is NOENT; otherwise the handle of its attribute
 * directory, which is not made, there being nothing to make, and its
 * attributes.  illumos asks the file system with _PC_XATTR_EXISTS; here
 * it is whether the list of the namespace user is empty.  A file system
 * without extended attributes is EOPNOTSUPP, NFS3ERR_NOTSUPP or
 * NFSERR_OPNOTSUPP, where illumos' VOP_LOOKUP() gives EINVAL; the same
 * answer comes from version 2 where the handle has no room for the mark,
 * see nfs_srvxattr.c.  A handle that is itself of a named attribute is
 * EINVAL, as illumos refuses attributes of an attribute.
 */
static enum oncrpc_dispatch
nfsacl_getxattrdir(struct oncrpc_req *rq)
{
	XDR *ax = rq->rq_args, *rx = rq->rq_res;
	struct vnode *vp = NULL;
	struct vattr va;
	kauth_cred_t cred;
	nfsrvfh_t nsfh, dfh;
	struct nfsacl_node nn;
	uint32_t create, status, len;
	int error, rdonly;
	bool ok, any, v3 = rq->rq_vers == NFS_ACL_V3;

	if (!nfsacl_get_fh(ax, &nsfh, v3) || !xdr_u_int32_t(ax, &create))
		return ONCRPC_ERR_ARGS;
	dfh.nsfh_size = 0;
	vattr_null(&va);
	cred = nfsacl_takecred(rq);
	error = nfsacl_fhtovp(rq, cred, &nsfh, &vp, &rdonly, &nn);
	/* No attributes of an attribute, zfs_vnops.c:1488-1495. */
	if (error == 0 && nn.nn_xattr) {
		VOP_UNLOCK(vp);
		error = EINVAL;
	} else if (error == 0) {
		error = nfsrv_composefh(vp, &nsfh, v3);
		VOP_UNLOCK(vp);
	}
	if (error == 0)
		error = nfs_xattr_any(vp, cred, &any);
	if (error == 0 && !any && !create)
		error = ENOENT;
	if (error == 0)
		error = nfsrv_xattr_mkfh(&nsfh, v3, NFS_XATTR_DIR, NULL, &dfh);
	if (error == 0)
		error = nfs_xattr_vattr(vp, cred, NFS_XATTR_DIR, "", &va);
	if (vp != NULL)
		vrele(vp);
	if (v3) {
		status = nfsacl_errno(error);
		len = NFSRVFH_SIZE(&dfh);
		ok = xdr_u_int32_t(rx, &status) &&
		    (status != NFS_OK ||
		     (xdr_u_int32_t(rx, &len) &&
		      xdr_opaque(rx, (char *)NFSRVFH_DATA(&dfh), len) &&
		      nfsacl_put_va(rx, &va)));
	} else {
		status = nfsacl_errno2(error);
		ok = xdr_u_int32_t(rx, &status) &&
		    (status != NFS_OK ||
		     (xdr_opaque(rx, (char *)NFSRVFH_DATA(&dfh), NFSX_V2FH) &&
		      nfsacl_put_fattr2(rx, &va)));
	}
	nfsacl_freecred(cred);
	return ok ? ONCRPC_DONE : ONCRPC_ERR_SYSTEM;
}

/*
 * No reply cache: Linux has RC_NOCACHE for all of them [L3 267-292,
 * L2].  GETACL, GETATTR, ACCESS and GETXATTRDIR change nothing, and
 * SETACL done twice sets the same lists.
 */
static enum oncrpc_dispatch
nfsacl_dispatch(struct oncrpc_req *rq)
{

	/* The address is what the exports go by. */
	if (rq->rq_nam == NULL)
		return ONCRPC_ERR_SYSTEM;
	if (rq->rq_vers == NFS_ACL_V2) {
		switch (rq->rq_proc) {
		case ACLPROC2_NULL:
			return ONCRPC_DONE;
		case ACLPROC2_GETACL:
			return nfsacl_getacl(rq);
		case ACLPROC2_SETACL:
			return nfsacl_setacl(rq);
		case ACLPROC2_GETATTR:
			return nfsacl_getattr2(rq);
		case ACLPROC2_ACCESS:
			return nfsacl_access2(rq);
		case ACLPROC2_GETXATTRDIR:
			return nfsacl_getxattrdir(rq);
		default:
			return ONCRPC_ERR_PROC;
		}
	}
	switch (rq->rq_proc) {
	case ACLPROC3_NULL:
		return ONCRPC_DONE;
	case ACLPROC3_GETACL:
		return nfsacl_getacl(rq);
	case ACLPROC3_SETACL:
		return nfsacl_setacl(rq);
	case ACLPROC3_GETXATTRDIR:
		return nfsacl_getxattrdir(rq);
	default:
		return ONCRPC_ERR_PROC;
	}
}

/* The procedures differ by version, so the dispatch tells PROC_UNAVAIL. */
const struct oncrpc_program nfs_acl_program = {
	.op_prog = NFS_ACL_PROGRAM,
	.op_vers_low = NFS_ACL_V2,
	.op_vers_high = NFS_ACL_V3,
	.op_nprocs = 0,
	.op_dispatch = nfsacl_dispatch,
	.op_owner = nfs_oncrpc_tag,
};

/*
 * vfs.nfsserver.nfsacl, the versions served as bits (1 << version), for
 * nfsd(8) to register them with rpcbind as illumos' nfsd does
 * (usr/src/cmd/fs.d/nfs/nfsd/nfsd.c:556-565).  Neither client looks
 * there: both call on the address of the NFS mount (Linux
 * rpc_bind_new_program(), illumos nfs_subr.c:506), but rpcinfo and
 * anything that asks rpcbind see the program.
 */
static struct sysctllog *nfs_acl_sysctllog;
static int nfs_acl_versions = (1 << NFS_ACL_V2) | (1 << NFS_ACL_V3);

void
nfs_acl_init(void)
{
	const struct sysctlnode *node = NULL;

	sysctl_createv(&nfs_acl_sysctllog, 0, NULL, &node,
	    CTLFLAG_PERMANENT, CTLTYPE_NODE, "nfsserver",
	    SYSCTL_DESCR("NFS server, versions 2 and 3"),
	    NULL, 0, NULL, 0, CTL_VFS, CTL_CREATE, CTL_EOL);
	if (node == NULL)
		return;
	sysctl_createv(&nfs_acl_sysctllog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READONLY, CTLTYPE_INT, "nfsacl",
	    SYSCTL_DESCR("Versions of NFSACL served, as 1 << version"),
	    NULL, 0, &nfs_acl_versions, 0,
	    CTL_VFS, node->sysctl_num, CTL_CREATE, CTL_EOL);
}

void
nfs_acl_fini(void)
{

	sysctl_teardown(&nfs_acl_sysctllog);
}
