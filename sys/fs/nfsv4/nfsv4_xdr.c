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
 * XDR filters for NFS version 4.0, RFC 7531 s2.  They touch nothing but
 * the stream and the structure in hand, so tests/fs/nfsv4 builds this
 * file in userland.  See nfsv4_xdr.h for the form of the structures.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <string.h>
#endif

#include <fs/nfsv4/nfsv4_xdr.h>

/* The padding of an opaque of length len, RFC 4506 s4.10. */
#define	XDR_PADLEN(len)	((4 - ((len) & 3)) & 3)

#define	U32(x, p)	xdr_u_int32_t((x), (p))
#define	U64(x, p)	xdr_u_int64_t((x), (p))

/*
 * Step over len bytes of data and their padding, without reading them.
 * The sum is done in 64 bits, as len came off the wire; XDR_SETPOS then
 * refuses anything past the end of the stream.
 */
bool
nfsv4_xdr_skip(XDR *x, u_int len)
{
	uint64_t pos;

	pos = (uint64_t)XDR_GETPOS(x) + len + XDR_PADLEN(len);
	if (pos > UINT32_MAX)
		return false;
	return XDR_SETPOS(x, (u_int)pos);
}

/* Write the padding after len bytes of data. */
bool
nfsv4_xdr_pad(XDR *x, u_int len)
{
	static const char zero[3];
	u_int pad = XDR_PADLEN(len);

	/* Not xdr_opaque(), which would pad the padding. */
	return pad == 0 || XDR_PUTBYTES(x, __UNCONST(zero), pad) != 0;
}

/* A variable opaque with a bound; over the bound does not decode. */
static bool
xdr_vopaque(XDR *x, void *buf, uint32_t *lenp, uint32_t max)
{

	if (!U32(x, lenp) || *lenp > max)
		return false;
	return xdr_opaque(x, buf, *lenp) != 0;
}

bool
nfsv4_xdr_bitmap(XDR *x, struct nfsv4_bitmap *bm)
{
	uint32_t n, i, w;

	if (x->x_op == XDR_ENCODE) {
		if (!U32(x, &bm->bm_n))
			return false;
		for (i = 0; i < bm->bm_n; i++) {
			if (!U32(x, &bm->bm_w[i]))
				return false;
		}
		return true;
	}

	memset(bm, 0, sizeof(*bm));
	if (!U32(x, &n) || n > NFSV4_BITMAP_READ)
		return false;
	for (i = 0; i < n; i++) {
		if (!U32(x, &w))
			return false;
		if (i < NFSV4_BITMAP_WORDS) {
			bm->bm_w[i] = w;
			bm->bm_n = i + 1;
		} else if (w != 0)
			bm->bm_more = true;
	}
	return true;
}

/*
 * str and len of a name or link.  Longer than max is marked; it is a
 * result of the operation and not a failure to decode.
 */
static bool
xdr_string_mark(XDR *x, char *str, uint32_t *lenp, bool *toolong, u_int max)
{

	if (x->x_op == XDR_ENCODE)
		return U32(x, lenp) && xdr_opaque(x, str, *lenp) != 0;

	*toolong = false;
	if (!U32(x, lenp))
		return false;
	if (*lenp > max) {
		*toolong = true;
		str[0] = '\0';
		return nfsv4_xdr_skip(x, *lenp);
	}
	if (xdr_opaque(x, str, *lenp) == 0)
		return false;
	str[*lenp] = '\0';
	return true;
}

bool
nfsv4_xdr_name(XDR *x, struct nfsv4_name *nm)
{

	return xdr_string_mark(x, nm->nm_str, &nm->nm_len, &nm->nm_toolong,
	    NFSV4_NAME_MAX);
}

bool
nfsv4_xdr_link(XDR *x, struct nfsv4_link *ln)
{

	return xdr_string_mark(x, ln->ln_str, &ln->ln_len, &ln->ln_toolong,
	    NFSV4_LINK_MAX);
}

bool
nfsv4_xdr_fh(XDR *x, struct nfsv4_fh *fh)
{

	return xdr_vopaque(x, fh->fh_data, &fh->fh_len, NFS4_FHSIZE);
}

bool
nfsv4_xdr_stateid(XDR *x, struct nfsv4_stateid *si)
{

	return U32(x, &si->si_seqid) &&
	    xdr_opaque(x, (char *)si->si_other, NFS4_OTHER_SIZE) != 0;
}

bool
nfsv4_xdr_verifier(XDR *x, struct nfsv4_verifier *v)
{

	return xdr_opaque(x, (char *)v->v_data, NFS4_VERIFIER_SIZE) != 0;
}

bool
nfsv4_xdr_fattr(XDR *x, struct nfsv4_fattr *fa)
{

	if (!nfsv4_xdr_bitmap(x, &fa->fa_mask) || !U32(x, &fa->fa_len))
		return false;
	if (x->x_op == XDR_ENCODE)
		return true;
	fa->fa_pos = XDR_GETPOS(x);
	return nfsv4_xdr_skip(x, fa->fa_len);
}

bool
nfsv4_xdr_owner(XDR *x, struct nfsv4_owner *ow)
{

	return U64(x, &ow->ow_clientid) &&
	    xdr_vopaque(x, ow->ow_data, &ow->ow_len, NFS4_OPAQUE_LIMIT);
}

bool
nfsv4_xdr_change_info(XDR *x, struct nfsv4_change_info *ci)
{

	return U32(x, &ci->ci_atomic) && U64(x, &ci->ci_before) &&
	    U64(x, &ci->ci_after);
}

bool
nfsv4_xdr_clientaddr(XDR *x, struct nfsv4_clientaddr *ca)
{

	return xdr_vopaque(x, ca->ca_netid, &ca->ca_netidlen,
	    NFSV4_NETID_MAX) &&
	    xdr_vopaque(x, ca->ca_addr, &ca->ca_addrlen, NFSV4_NETADDR_MAX);
}

/* LOCK4denied; encode only, ld_owner being a pointer. */
bool
nfsv4_xdr_lock_denied(XDR *x, struct nfsv4_lock_denied *ld)
{

	return U64(x, &ld->ld_offset) && U64(x, &ld->ld_length) &&
	    U32(x, &ld->ld_type) && U64(x, &ld->ld_clientid) &&
	    U32(x, &ld->ld_ownerlen) &&
	    xdr_opaque(x, __UNCONST(ld->ld_owner), ld->ld_ownerlen) != 0;
}

/*
 * open_delegation4.  The nfsace4 denies everything, as s10.4 allows, so
 * that a client asks with ACCESS rather than be told from the file's
 * ACL here.  nfs_space_limit4 gives no room: s10.4.1 has the server
 * ensure that what it names can be flushed, and nothing here reserves
 * space, so all modified data is to be flushed on close.
 */
bool
nfsv4_xdr_open_deleg(XDR *x, struct nfsv4_open_deleg *od)
{
	static const char who[] = "EVERYONE@";
	uint32_t ty = ACE4_ACCESS_DENIED_ACE_TYPE, flag = 0;
	uint32_t mask = ACE4_GENERIC_READ | ACE4_GENERIC_WRITE |
	    ACE4_GENERIC_EXECUTE;
	uint32_t limitby = NFS_LIMIT_SIZE, wholen = sizeof(who) - 1;
	uint64_t size = 0;

	if (!U32(x, &od->od_type))
		return false;
	if (od->od_type == OPEN_DELEGATE_NONE)
		return true;
	if (!nfsv4_xdr_stateid(x, &od->od_stateid) || !U32(x, &od->od_recall))
		return false;
	if (od->od_type == OPEN_DELEGATE_WRITE &&
	    (!U32(x, &limitby) || !U64(x, &size)))
		return false;
	return U32(x, &ty) && U32(x, &flag) && U32(x, &mask) &&
	    U32(x, &wholen) && xdr_opaque(x, __UNCONST(who), wholen) != 0;
}

static bool
xdr_args_close(XDR *x, struct nfsv4_args_close *a)
{

	return U32(x, &a->seqid) && nfsv4_xdr_stateid(x, &a->stateid);
}

static bool
xdr_args_commit(XDR *x, struct nfsv4_args_commit *a)
{

	return U64(x, &a->offset) && U32(x, &a->count);
}

/* createtype4, then the rest of CREATE4args */
static bool
xdr_args_create(XDR *x, struct nfsv4_args_create *a)
{

	if (!U32(x, &a->type))
		return false;
	switch (a->type) {
	case NF4LNK:
		if (!nfsv4_xdr_link(x, &a->link))
			return false;
		break;
	case NF4BLK:
	case NF4CHR:
		if (!U32(x, &a->spec1) || !U32(x, &a->spec2))
			return false;
		break;
	default:	/* the union's default is void */
		break;
	}
	return nfsv4_xdr_name(x, &a->name) && nfsv4_xdr_fattr(x, &a->attrs);
}

static bool
xdr_args_lock(XDR *x, struct nfsv4_args_lock *a)
{

	if (!U32(x, &a->type) || !U32(x, &a->reclaim) ||
	    !U64(x, &a->offset) || !U64(x, &a->length) ||
	    !U32(x, &a->newowner))
		return false;
	/* A boolean is 0 or 1, RFC 4506 s4.4. */
	if (a->newowner > 1 || a->reclaim > 1)
		return false;
	if (a->newowner)
		return U32(x, &a->open_seqid) &&
		    nfsv4_xdr_stateid(x, &a->open_stateid) &&
		    U32(x, &a->lock_seqid) &&
		    nfsv4_xdr_owner(x, &a->owner);
	return nfsv4_xdr_stateid(x, &a->lock_stateid) &&
	    U32(x, &a->lock_seqid);
}

static bool
xdr_args_lockt(XDR *x, struct nfsv4_args_lockt *a)
{

	return U32(x, &a->type) && U64(x, &a->offset) &&
	    U64(x, &a->length) && nfsv4_xdr_owner(x, &a->owner);
}

static bool
xdr_args_locku(XDR *x, struct nfsv4_args_locku *a)
{

	return U32(x, &a->type) && U32(x, &a->seqid) &&
	    nfsv4_xdr_stateid(x, &a->stateid) && U64(x, &a->offset) &&
	    U64(x, &a->length);
}

/* openflag4 and open_claim4 are the variable parts of OPEN4args. */
static bool
xdr_args_open(XDR *x, struct nfsv4_args_open *a)
{

	if (!U32(x, &a->seqid) || !U32(x, &a->share_access) ||
	    !U32(x, &a->share_deny) || !nfsv4_xdr_owner(x, &a->owner) ||
	    !U32(x, &a->opentype))
		return false;
	switch (a->opentype) {
	case OPEN4_CREATE:
		if (!U32(x, &a->createmode))
			return false;
		switch (a->createmode) {
		case UNCHECKED4:
		case GUARDED4:
			if (!nfsv4_xdr_fattr(x, &a->createattrs))
				return false;
			break;
		case EXCLUSIVE4:
			if (!nfsv4_xdr_verifier(x, &a->createverf))
				return false;
			break;
		default:
			return false;	/* no default arm in createhow4 */
		}
		break;
	default:			/* the union's default is void */
		break;
	}

	if (!U32(x, &a->claim))
		return false;
	switch (a->claim) {
	case CLAIM_NULL:
	case CLAIM_DELEGATE_PREV:
		return nfsv4_xdr_name(x, &a->file);
	case CLAIM_PREVIOUS:
		return U32(x, &a->delegate_type);
	case CLAIM_DELEGATE_CUR:
		return nfsv4_xdr_stateid(x, &a->delegate_stateid) &&
		    nfsv4_xdr_name(x, &a->file);
	default:
		return false;		/* no default arm in open_claim4 */
	}
}

static bool
xdr_args_open_downgrade(XDR *x, struct nfsv4_args_open_downgrade *a)
{

	return nfsv4_xdr_stateid(x, &a->stateid) && U32(x, &a->seqid) &&
	    U32(x, &a->share_access) && U32(x, &a->share_deny);
}

static bool
xdr_args_read(XDR *x, struct nfsv4_args_read *a)
{

	return nfsv4_xdr_stateid(x, &a->stateid) && U64(x, &a->offset) &&
	    U32(x, &a->count);
}

static bool
xdr_args_readdir(XDR *x, struct nfsv4_args_readdir *a)
{

	return U64(x, &a->cookie) &&
	    nfsv4_xdr_verifier(x, &a->cookieverf) &&
	    U32(x, &a->dircount) && U32(x, &a->maxcount) &&
	    nfsv4_xdr_bitmap(x, &a->mask);
}

static bool
xdr_args_setclientid(XDR *x, struct nfsv4_args_setclientid *a)
{

	return nfsv4_xdr_verifier(x, &a->verifier) &&
	    xdr_vopaque(x, a->id, &a->idlen, NFS4_OPAQUE_LIMIT) &&
	    U32(x, &a->cb_program) &&
	    nfsv4_xdr_clientaddr(x, &a->cb_location) &&
	    U32(x, &a->cb_ident);
}

static bool
xdr_args_write(XDR *x, struct nfsv4_args_write *a)
{

	if (!nfsv4_xdr_stateid(x, &a->stateid) || !U64(x, &a->offset) ||
	    !U32(x, &a->stable) || !U32(x, &a->len))
		return false;
	if (x->x_op == XDR_ENCODE)
		return true;
	a->pos = XDR_GETPOS(x);
	return nfsv4_xdr_skip(x, a->len);
}

bool
nfsv4_xdr_args(XDR *x, uint32_t op, union nfsv4_args *a)
{

	switch (op) {
	case NFSV4_OP_ACCESS:
		return U32(x, &a->access.access);
	case NFSV4_OP_CLOSE:
		return xdr_args_close(x, &a->close);
	case NFSV4_OP_COMMIT:
		return xdr_args_commit(x, &a->commit);
	case NFSV4_OP_CREATE:
		return xdr_args_create(x, &a->create);
	case NFSV4_OP_DELEGPURGE:
	case NFSV4_OP_RENEW:
		return U64(x, &a->clientid.clientid);
	case NFSV4_OP_DELEGRETURN:
		return nfsv4_xdr_stateid(x, &a->stateid.stateid);
	case NFSV4_OP_GETATTR:
		return nfsv4_xdr_bitmap(x, &a->getattr.mask);
	case NFSV4_OP_LINK:
	case NFSV4_OP_LOOKUP:
	case NFSV4_OP_REMOVE:
	case NFSV4_OP_SECINFO:
		return nfsv4_xdr_name(x, &a->name.name);
	case NFSV4_OP_LOCK:
		return xdr_args_lock(x, &a->lock);
	case NFSV4_OP_LOCKT:
		return xdr_args_lockt(x, &a->lockt);
	case NFSV4_OP_LOCKU:
		return xdr_args_locku(x, &a->locku);
	case NFSV4_OP_NVERIFY:
	case NFSV4_OP_VERIFY:
		return nfsv4_xdr_fattr(x, &a->verify.attrs);
	case NFSV4_OP_OPEN:
		return xdr_args_open(x, &a->open);
	case NFSV4_OP_OPENATTR:
		return U32(x, &a->openattr.createdir) &&
		    a->openattr.createdir <= 1;
	case NFSV4_OP_OPEN_CONFIRM:
		return nfsv4_xdr_stateid(x, &a->open_confirm.stateid) &&
		    U32(x, &a->open_confirm.seqid);
	case NFSV4_OP_OPEN_DOWNGRADE:
		return xdr_args_open_downgrade(x, &a->open_downgrade);
	case NFSV4_OP_PUTFH:
		return nfsv4_xdr_fh(x, &a->putfh.fh);
	case NFSV4_OP_READ:
		return xdr_args_read(x, &a->read);
	case NFSV4_OP_READDIR:
		return xdr_args_readdir(x, &a->readdir);
	case NFSV4_OP_RENAME:
		return nfsv4_xdr_name(x, &a->rename.oldname) &&
		    nfsv4_xdr_name(x, &a->rename.newname);
	case NFSV4_OP_SETATTR:
		return nfsv4_xdr_stateid(x, &a->setattr.stateid) &&
		    nfsv4_xdr_fattr(x, &a->setattr.attrs);
	case NFSV4_OP_SETCLIENTID:
		return xdr_args_setclientid(x, &a->setclientid);
	case NFSV4_OP_SETCLIENTID_CONFIRM:
		return U64(x, &a->setclientid_confirm.clientid) &&
		    nfsv4_xdr_verifier(x, &a->setclientid_confirm.verifier);
	case NFSV4_OP_WRITE:
		return xdr_args_write(x, &a->write);
	case NFSV4_OP_RELEASE_LOCKOWNER:
		return nfsv4_xdr_owner(x, &a->release_lockowner.owner);
	default:			/* those with void arguments */
		return true;
	}
}
