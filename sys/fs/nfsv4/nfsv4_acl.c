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
 * The acl attribute, RFC 7530 s6.2.1, and struct acl.  ALLOW and DENY are
 * what the file systems here keep; aclsupport says so.  An ACE that cannot
 * be stored is NFS4ERR_ATTRNOTSUPP, s6.2.1.2, and that includes the special
 * identifiers other than OWNER@, GROUP@ and EVERYONE@: this server has no
 * way of telling them apart when it checks access.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/acl.h>
#include <sys/kauth.h>
#include <sys/kmem.h>
#include <sys/mount.h>
#include <sys/systm.h>
#include <sys/vnode.h>

#include <fs/nfsv4/nfsv4_var.h>

/* s6.2.1.3 and <sys/acl.h>.  The two number the same rights differently. */
static const struct {
	uint32_t	am_ace4;
	acl_perm_t	am_perm;
} acl_masks[] = {
	{ ACE4_READ_DATA,		ACL_READ_DATA },
	{ ACE4_WRITE_DATA,		ACL_WRITE_DATA },
	{ ACE4_APPEND_DATA,		ACL_APPEND_DATA },
	{ ACE4_READ_NAMED_ATTRS,	ACL_READ_NAMED_ATTRS },
	{ ACE4_WRITE_NAMED_ATTRS,	ACL_WRITE_NAMED_ATTRS },
	{ ACE4_EXECUTE,			ACL_EXECUTE },
	{ ACE4_DELETE_CHILD,		ACL_DELETE_CHILD },
	{ ACE4_READ_ATTRIBUTES,		ACL_READ_ATTRIBUTES },
	{ ACE4_WRITE_ATTRIBUTES,	ACL_WRITE_ATTRIBUTES },
	{ ACE4_DELETE,			ACL_DELETE },
	{ ACE4_READ_ACL,		ACL_READ_ACL },
	{ ACE4_WRITE_ACL,		ACL_WRITE_ACL },
	{ ACE4_WRITE_OWNER,		ACL_WRITE_OWNER },
	{ ACE4_SYNCHRONIZE,		ACL_SYNCHRONIZE },
};

/* s6.2.1.4.  ACE4_IDENTIFIER_GROUP is in ae_tag, ACL_ENTRY_INHERITED is v4.1. */
static const struct {
	uint32_t	af_ace4;
	acl_flag_t	af_flag;
} acl_flags[] = {
	{ ACE4_FILE_INHERIT_ACE,	ACL_ENTRY_FILE_INHERIT },
	{ ACE4_DIRECTORY_INHERIT_ACE,	ACL_ENTRY_DIRECTORY_INHERIT },
	{ ACE4_NO_PROPAGATE_INHERIT_ACE, ACL_ENTRY_NO_PROPAGATE_INHERIT },
	{ ACE4_INHERIT_ONLY_ACE,	ACL_ENTRY_INHERIT_ONLY },
	{ ACE4_SUCCESSFUL_ACCESS_ACE_FLAG, ACL_ENTRY_SUCCESSFUL_ACCESS },
	{ ACE4_FAILED_ACCESS_ACE_FLAG,	ACL_ENTRY_FAILED_ACCESS },
};

static const struct {
	const char	*as_who;
	acl_tag_t	as_tag;
} acl_special[] = {
	{ "OWNER@",	ACL_USER_OBJ },
	{ "GROUP@",	ACL_GROUP_OBJ },
	{ "EVERYONE@",	ACL_EVERYONE },
};

/*
 * The longest who that can mean anything: the special identifiers of
 * s6.2.1.5 and a number, s5.9.
 */

/* Is there an ACL to be had here?  A pseudo node has none. */
bool
nfsv4_acl_supported(struct vnode *vp)
{

	return vp != NULL && (vp->v_mount->mnt_flag & MNT_NFS4ACLS) != 0;
}

/* The ACL of vp, to be given to acl_free(), or an NFS4ERR_. */
uint32_t
nfsv4_acl_get(struct vnode *vp, kauth_cred_t cred, struct acl **aclp)
{
	struct acl *acl;
	int error;

	acl = acl_alloc(KM_SLEEP);
	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = VOP_GETACL(vp, ACL_TYPE_NFS4, acl, cred);
	VOP_UNLOCK(vp);
	if (error != 0) {
		acl_free(acl);
		return nfsv4_errno(error);
	}
	*aclp = acl;
	return NFS4_OK;
}

static bool
acl_put_who(XDR *x, const struct acl_entry *ae)
{
	char buf[NFSV4_IDSTR_MAX];
	const char *who = NULL;
	uint32_t len;
	u_int i;

	for (i = 0; i < __arraycount(acl_special); i++) {
		if (ae->ae_tag == acl_special[i].as_tag)
			who = acl_special[i].as_who;
	}
	if (who == NULL) {
		len = nfsv4_idmap_out(ae->ae_tag == ACL_GROUP, ae->ae_id, buf);
		who = buf;
	} else
		len = strlen(who);
	return xdr_u_int32_t(x, &len) && xdr_opaque(x, __UNCONST(who), len);
}

/*
 * The nfsace4 array of an fattr4_acl, or of the dacl, which has only the
 * ALLOW and DENY ACEs and keeps ACE4_INHERITED_ACE; the acl has it
 * cleared (RFC 8881 s6.4.3.2).  False if it does not fit.
 */
static bool
acl_put_aces(XDR *x, const struct acl *acl, bool dacl)
{
	const struct acl_entry *ae;
	uint32_t cnt, type, flag, mask;
	u_int i, j;

	cnt = 0;
	for (i = 0; i < acl->acl_cnt; i++) {
		if (!dacl ||
		    acl->acl_entry[i].ae_entry_type == ACL_ENTRY_TYPE_ALLOW ||
		    acl->acl_entry[i].ae_entry_type == ACL_ENTRY_TYPE_DENY)
			cnt++;
	}
	if (!xdr_u_int32_t(x, &cnt))
		return false;
	for (i = 0; i < acl->acl_cnt; i++) {
		ae = &acl->acl_entry[i];
		if (dacl && ae->ae_entry_type != ACL_ENTRY_TYPE_ALLOW &&
		    ae->ae_entry_type != ACL_ENTRY_TYPE_DENY)
			continue;
		switch (ae->ae_entry_type) {
		case ACL_ENTRY_TYPE_ALLOW:
			type = ACE4_ACCESS_ALLOWED_ACE_TYPE;
			break;
		case ACL_ENTRY_TYPE_DENY:
			type = ACE4_ACCESS_DENIED_ACE_TYPE;
			break;
		case ACL_ENTRY_TYPE_AUDIT:
			type = ACE4_SYSTEM_AUDIT_ACE_TYPE;
			break;
		default:
			type = ACE4_SYSTEM_ALARM_ACE_TYPE;
			break;
		}
		/* s6.2.1.5: zero on the special identifiers. */
		flag = ae->ae_tag == ACL_GROUP ? ACE4_IDENTIFIER_GROUP : 0;
		for (j = 0; j < __arraycount(acl_flags); j++) {
			if ((ae->ae_flags & acl_flags[j].af_flag) != 0)
				flag |= acl_flags[j].af_ace4;
		}
		if (dacl && (ae->ae_flags & ACL_ENTRY_INHERITED) != 0)
			flag |= ACE4_INHERITED_ACE;
		mask = 0;
		for (j = 0; j < __arraycount(acl_masks); j++) {
			if ((ae->ae_perm & acl_masks[j].am_perm) != 0)
				mask |= acl_masks[j].am_ace4;
		}
		if (!xdr_u_int32_t(x, &type) || !xdr_u_int32_t(x, &flag) ||
		    !xdr_u_int32_t(x, &mask) || !acl_put_who(x, ae))
			return false;
	}
	return true;
}

/* An fattr4_acl.  False if it does not fit. */
bool
nfsv4_acl_put(XDR *x, const struct acl *acl)
{

	return acl_put_aces(x, acl, false);
}

/* An fattr4_dacl, nfsacl41 of RFC 8881 s6.4.3.2. */
bool
nfsv4_dacl_put(XDR *x, const struct acl *acl, uint32_t flags)
{

	return xdr_u_int32_t(x, &flags) && acl_put_aces(x, acl, true);
}

static uint32_t
acl_parse_who(XDR *x, struct acl_entry *ae, bool group, uint32_t flavor)
{
	char buf[NFSV4_IDSTR_MAX];
	uint32_t len, id, st;
	u_int i;

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
	buf[len] = '\0';

	for (i = 0; i < __arraycount(acl_special); i++) {
		if (strcmp(buf, acl_special[i].as_who) == 0) {
			ae->ae_tag = acl_special[i].as_tag;
			ae->ae_id = ACL_UNDEFINED_ID;
			return NFS4_OK;
		}
	}
	if (buf[len - 1] == '@')
		return NFS4ERR_ATTRNOTSUPP;

	st = nfsv4_attr_strid(group, buf, len, flavor, &id);
	if (st != NFS4_OK)
		return st;
	ae->ae_tag = group ? ACL_GROUP : ACL_USER;
	ae->ae_id = id;
	return NFS4_OK;
}

/*
 * The nfsace4 array of an fattr4_acl, or of a dacl, to *aclp, which the
 * compound frees if nothing else does.
 */
static uint32_t
acl_parse_aces(XDR *x, uint32_t flavor, struct acl **aclp, bool dacl)
{
	struct acl *acl;
	struct acl_entry *ae;
	uint32_t cnt, type, flag, mask, st;
	u_int i, j;

	if (!xdr_u_int32_t(x, &cnt))
		return NFS4ERR_BADXDR;
	if (cnt > ACL_MAX_ENTRIES)
		return NFS4ERR_ATTRNOTSUPP;	/* s6.2.1.2 */

	acl = acl_alloc(KM_SLEEP);
	*aclp = acl;
	acl->acl_maxcnt = ACL_MAX_ENTRIES;
	acl->acl_cnt = cnt;
	for (i = 0; i < cnt; i++) {
		ae = &acl->acl_entry[i];
		if (!xdr_u_int32_t(x, &type) || !xdr_u_int32_t(x, &flag) ||
		    !xdr_u_int32_t(x, &mask))
			return NFS4ERR_BADXDR;
		switch (type) {
		case ACE4_ACCESS_ALLOWED_ACE_TYPE:
			ae->ae_entry_type = ACL_ENTRY_TYPE_ALLOW;
			break;
		case ACE4_ACCESS_DENIED_ACE_TYPE:
			ae->ae_entry_type = ACL_ENTRY_TYPE_DENY;
			break;
		default:
			return NFS4ERR_ATTRNOTSUPP;
		}
		st = acl_parse_who(x, ae,
		    (flag & ACE4_IDENTIFIER_GROUP) != 0, flavor);
		if (st != NFS4_OK)
			return st;
		/* RFC 8881 s6.2.1.4.1: it would apply to nothing, ever. */
		if ((flag & ACE4_INHERIT_ONLY_ACE) != 0 && (flag &
		    (ACE4_FILE_INHERIT_ACE | ACE4_DIRECTORY_INHERIT_ACE)) == 0)
			return NFS4ERR_ATTRNOTSUPP;
		flag &= ~ACE4_IDENTIFIER_GROUP;
		ae->ae_flags = 0;
		/* s6.4.3.2: in a dacl, not in the acl. */
		if (dacl && (flag & ACE4_INHERITED_ACE) != 0) {
			ae->ae_flags |= ACL_ENTRY_INHERITED;
			flag &= ~ACE4_INHERITED_ACE;
		}
		for (j = 0; j < __arraycount(acl_flags); j++) {
			if ((flag & acl_flags[j].af_ace4) != 0) {
				ae->ae_flags |= acl_flags[j].af_flag;
				flag &= ~acl_flags[j].af_ace4;
			}
		}
		ae->ae_perm = 0;
		for (j = 0; j < __arraycount(acl_masks); j++) {
			if ((mask & acl_masks[j].am_ace4) != 0) {
				ae->ae_perm |= acl_masks[j].am_perm;
				mask &= ~acl_masks[j].am_ace4;
			}
		}
		if (flag != 0 || mask != 0)
			return NFS4ERR_ATTRNOTSUPP;
	}
	return NFS4_OK;
}

uint32_t
nfsv4_acl_parse(XDR *x, uint32_t flavor, struct acl **aclp)
{

	return acl_parse_aces(x, flavor, aclp, false);
}

/*
 * An fattr4_dacl, RFC 8881 s6.2.2: ALLOW and DENY only, which is all
 * acl_parse_aces() takes; aclflag4 bits that s6.4.3.2 does not define
 * "must be cleared", so are NFS4ERR_INVAL.
 */
uint32_t
nfsv4_dacl_parse(XDR *x, uint32_t flavor, struct acl **aclp,
    uint32_t *flagsp)
{

	if (!xdr_u_int32_t(x, flagsp))
		return NFS4ERR_BADXDR;
	if ((*flagsp & ~ACL4_FLAGS) != 0)
		return NFS4ERR_INVAL;
	return acl_parse_aces(x, flavor, aclp, true);
}

/*
 * The dacl, RFC 8881 s6.2.2: its ACEs are the ACL's, and its aclflag4 is
 * kept in the extended attributes as archive is, so it is had only where
 * both are.  No sacl (s6.2.3): no AUDIT or ALARM ACE is supported (see
 * aclsupport), and s6.4.3.2 lets a server have the one without the other.
 */
#define	DACL_FLAGS	"nfsv4.daclflags"

bool
nfsv4_dacl_supported(struct vnode *vp)
{

	return nfsv4_acl_supported(vp) && nfsv4_xstore_ok(vp);
}

uint32_t
nfsv4_dacl_flags(struct vnode *vp)
{

	return nfsv4_xstore_u32(vp, DACL_FLAGS) & ACL4_FLAGS;
}

/*
 * s6.4.3.2, for vp made in dvp with no ACL given: ACL4_PROTECTED clear,
 * ACL4_AUTO_INHERIT as the parent's, and ACL4_DEFAULTED where the ACL
 * was the server's choice (nothing to inherit, or EXCLUSIVE4's).  Only
 * case 4 of s6.4.3 comes here; a file made with a mode keeps no flags.
 */
static void
dacl_created(struct vnode *dvp, struct vnode *vp, bool defaulted)
{
	uint32_t f;

	if (!nfsv4_dacl_supported(dvp) || !nfsv4_dacl_supported(vp))
		return;
	f = (nfsv4_dacl_flags(dvp) & ACL4_AUTO_INHERIT) |
	    (defaulted ? ACL4_DEFAULTED : 0);
	if (f != 0)
		(void)nfsv4_xstore_set_u32(vp, DACL_FLAGS, f);
}

/*
 * After an ACL is set: a dacl's flags as given; for the acl attribute,
 * ACL4_PROTECTED, which s6.4.3.2 SHOULD, as such a client "may not
 * understand automatic inheritance".
 */
static void
dacl_after_set(struct nfsv4_compound *c, struct vnode *vp)
{
	uint32_t f;

	if (!nfsv4_dacl_supported(vp))
		return;
	f = c->c_xs.xs_dacl ? c->c_xs.xs_daclflags :
	    nfsv4_dacl_flags(vp) | ACL4_PROTECTED;
	(void)nfsv4_xstore_set_u32(vp, DACL_FLAGS, f);
}

/*
 * vfs.nfsv4.excl_inherit, from the option NFSV4_EXCL_INHERIT (see the
 * module's Makefile).  Off, an OPEN with EXCLUSIVE4, which carries no
 * attributes, makes a file that inherits nothing and that denies all
 * access, as RFC 8881 s6.4.3 SHOULD, case 4: the trivial ACL of mode 0,
 * which still lets the owner SETATTR the attributes meant.  On, it is
 * deliberately left to the file system, which inherits the parent's ACEs
 * with their rights masked by mode 0, as for a local open(2) with that
 * mode.  The file system's way is kept as the option for whoever wants
 * NFS and local creation to agree; nothing is known to need it.
 */
#ifdef NFSV4_EXCL_INHERIT
int nfsv4_excl_inherit = 1;
#else
int nfsv4_excl_inherit = 0;
#endif

/*
 * vfs.nfsv4.create_mode_mask, from the option NFSV4_CREATE_MODE_MASK (see
 * the module's Makefile).  Off, a file or directory made with neither mode
 * nor ACL in the call, other than by EXCLUSIVE4, gets the parent's
 * inheritable ACEs as they are, s6.4.3, case 4: "inheritance SHOULD take
 * place, and no modifications to the ACL will happen".  On, it is
 * deliberately left to the file system, which is given the server's
 * default mode (0644, 0755 for a directory) and masks the inherited rights
 * by its group bits and takes WRITE_ACL, WRITE_OWNER and the attribute
 * writes away, as for a local creat(2).  Where the parent has nothing
 * inheritable the RFC leaves the result to the implementation, and the
 * default mode stands either way.
 */
#ifdef NFSV4_CREATE_MODE_MASK
int nfsv4_create_mode_mask = 1;
#else
int nfsv4_create_mode_mask = 0;
#endif

/*
 * s6.4.3, case 4, for vp just made in dvp with neither mode nor ACL given;
 * excl for EXCLUSIVE4.  Whatever the file system inherited is replaced.
 */
uint32_t
nfsv4_acl_noattr(struct vnode *dvp, struct vnode *vp, bool excl,
    kauth_cred_t cred)
{
	struct acl *pacl, *acl;
	struct acl_entry *ae;
	struct vattr va;
	bool isdir = vp->v_type == VDIR;
	acl_flag_t flags;
	uint32_t st;
	u_int i;
	int error;

	if (excl ? nfsv4_excl_inherit : nfsv4_create_mode_mask)
		return NFS4_OK;
	if (!nfsv4_acl_supported(dvp) || !nfsv4_acl_supported(vp))
		return NFS4_OK;
	acl = acl_alloc(KM_SLEEP);
	acl->acl_maxcnt = ACL_MAX_ENTRIES;
	if (excl) {
		vn_lock(vp, LK_SHARED | LK_RETRY);
		error = VOP_GETATTR(vp, &va, cred);
		VOP_UNLOCK(vp);
		if (error != 0) {
			acl_free(acl);
			return nfsv4_errno(error);
		}
		acl_nfs4_sync_acl_from_mode(acl, 0, va.va_uid);
	} else {
		st = nfsv4_acl_get(dvp, cred, &pacl);
		if (st != NFS4_OK) {
			acl_free(acl);
			return st;
		}
		/*
		 * RFC 8881 s6.2.1.4.1.  FILE_INHERIT reaches files in
		 * subdirectories too, so a new directory carries it as
		 * INHERIT_ONLY unless NO_PROPAGATE stops it there; the
		 * flags are the same as subr_acl_nfs4.c gives them.
		 */
		for (i = 0; i < pacl->acl_cnt; i++) {
			ae = &pacl->acl_entry[i];
			flags = ae->ae_flags;
			if (isdir ? (flags & ACL_ENTRY_DIRECTORY_INHERIT) == 0 &&
			    ((flags & ACL_ENTRY_FILE_INHERIT) == 0 ||
			    (flags & ACL_ENTRY_NO_PROPAGATE_INHERIT) != 0) :
			    (flags & ACL_ENTRY_FILE_INHERIT) == 0)
				continue;
			acl->acl_entry[acl->acl_cnt] = *ae;
			ae = &acl->acl_entry[acl->acl_cnt++];
			ae->ae_flags &= ~ACL_ENTRY_INHERIT_ONLY;
			ae->ae_flags |= ACL_ENTRY_INHERITED;
			if (!isdir || (flags & ACL_ENTRY_NO_PROPAGATE_INHERIT) != 0)
				ae->ae_flags &= ~(ACL_ENTRY_FILE_INHERIT |
				    ACL_ENTRY_DIRECTORY_INHERIT |
				    ACL_ENTRY_NO_PROPAGATE_INHERIT);
			else if ((flags & ACL_ENTRY_DIRECTORY_INHERIT) == 0)
				ae->ae_flags |= ACL_ENTRY_INHERIT_ONLY;
		}
		acl_free(pacl);
		/* Nothing inheritable: the implementation's choice. */
		if (acl->acl_cnt == 0) {
			acl_free(acl);
			dacl_created(dvp, vp, true);
			return NFS4_OK;
		}
	}
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	error = VOP_SETACL(vp, ACL_TYPE_NFS4, acl, cred);
	VOP_UNLOCK(vp);
	acl_free(acl);
	if (error == 0)
		dacl_created(dvp, vp, excl);
	return nfsv4_errno(error);
}

/*
 * Set the ACL that nfsv4_attr_parse() found, if it found one.  After the
 * mode, s6.4.1.3.  The file system derives the mode from it, s6.4.1.2,
 * and decides who may do this.
 */
uint32_t
nfsv4_acl_set(struct nfsv4_compound *c, struct vnode *vp, kauth_cred_t cred)
{
	uint32_t st0;

	st0 = nfsv4_xstore_apply(c, vp, cred);
	if (st0 != NFS4_OK)
		return st0;
	struct acl *acl = c->c_setacl;
	int error;

	if (acl == NULL)
		return NFS4_OK;
	c->c_setacl = NULL;
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	error = VOP_SETACL(vp, ACL_TYPE_NFS4, acl, cred);
	VOP_UNLOCK(vp);
	acl_free(acl);
	if (error == 0)
		dacl_after_set(c, vp);
	/* An ACL that cannot be stored, s6.2.1.2. */
	if (error == EINVAL || error == EOPNOTSUPP)
		return NFS4ERR_ATTRNOTSUPP;
	return nfsv4_errno(error);
}
