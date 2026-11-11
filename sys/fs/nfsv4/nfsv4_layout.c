/*	$NetBSD$	*/

/*-
 * Copyright (c) 2026 The NetBSD Foundation, Inc.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * pNFS, RFC 8881 s12 and s13: the file layout, with this server as the
 * metadata server and as the one data server.
 *
 * The data server is reached at the address in vfs.nfsv4.pnfs_ds, as
 * "netid uaddr" (RFC 5665 s5.2.3.3), and pNFS is on while that is set.
 * A client then gets USE_PNFS_MDS and USE_PNFS_DS together (s13.1,
 * Table 8), so one client ID serves both.  The filehandle in a layout is
 * the metadata server's own (s13.3 allows it), and the stateids for I/O
 * are those of the metadata server, valid on both as s13.9.1 asks, as
 * the two are one.  So every operation on a filehandle from a layout is
 * of class 1 of s13.6, and no COMPOUND can mix the two personalities.
 *
 * A layout is a state of type NFSV4_ST_LAYOUT, one per client and file,
 * under an owner NFSV4_OWNER_LAYOUT with no name, as delegations are.
 * It covers all of the file, in the modes of st_liomode; a LAYOUTRETURN
 * of less than all of it leaves it held (s18.44.3 lets a part be
 * returned, and holding more than asked is what Table 22 allows).
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/atomic.h>
#include <sys/endian.h>
#include <sys/kmem.h>
#include <sys/mount.h>
#include <sys/systm.h>
#include <sys/vnode.h>

#include <fs/nfsv4/nfsv4_var.h>
#include <fs/nfsv4/nfsv4_state.h>

#define	NFS4_UINT64_MAX		UINT64_MAX	/* RFC 8881 s18.43.3 */

/* The stripe unit, a multiple of 64 (s13.3); layout_blksize too. */
#define	NFSV4_STRIPE_UNIT	NFSV4_MAXIO

#define	NFSV4_DS_NETID		16
#define	NFSV4_DS_UADDR		64

static char ds_netid[NFSV4_DS_NETID];
static char ds_uaddr[NFSV4_DS_UADDR];
static uint32_t ds_gen;		/* in the device ID; changes with the address */
int nfsv4_layouts_given;		/* vfs.nfsv4.layouts_given, to be counted */

/* pNFS is on; under nfsv4_state_lock, or as a hint. */
bool
nfsv4_pnfs_on(void)
{

	return ds_uaddr[0] != '\0';
}

/*
 * vfs.nfsv4.pnfs_ds: "netid uaddr", or "" for off.  A new address is a
 * new device ID, so that one still in a client's hands is unknown,
 * NFS4ERR_NOENT, s18.40.3; device ID notifications are not offered.
 */
int
nfsv4_layout_setds(const char *line)
{
	const char *sp;
	size_t n;

	if (*line == '\0') {
		mutex_enter(&nfsv4_state_lock);
		ds_uaddr[0] = ds_netid[0] = '\0';
		ds_gen++;
		mutex_exit(&nfsv4_state_lock);
		return 0;
	}
	sp = strchr(line, ' ');
	if (sp == NULL || (n = sp - line) == 0 || n >= sizeof(ds_netid) ||
	    sp[1] == '\0' || strlen(sp + 1) >= sizeof(ds_uaddr) ||
	    strchr(sp + 1, ' ') != NULL)
		return EINVAL;
	mutex_enter(&nfsv4_state_lock);
	memcpy(ds_netid, line, n);
	ds_netid[n] = '\0';
	strlcpy(ds_uaddr, sp + 1, sizeof(ds_uaddr));
	ds_gen++;
	mutex_exit(&nfsv4_state_lock);
	return 0;
}

/* s3.3.14: the one device ID; not valid across restarts, s12.2.10. */
static void
ds_devid(uint8_t *id)
{

	memset(id, 0, NFS4_DEVICEID4_SIZE);
	be32enc(id, nfsv4_boot);
	be32enc(id + 4, ds_gen);
	memcpy(id + 8, "NetBSDds", 8);
}

/* The roles of EXCHANGE_ID, s13.1: ours and what the client asked. */
uint32_t
nfsv4_pnfs_flags(uint32_t asked, bool *pnfsp)
{

	/*
	 * Table 8 and the paragraph after it: the higher of the roles,
	 * matching the client's where possible; one that asks only to be
	 * a client of a non-pNFS server is given that.
	 */
	*pnfsp = nfsv4_pnfs_on() && (asked & EXCHGID4_FLAG_MASK_PNFS) !=
	    EXCHGID4_FLAG_USE_NON_PNFS;
	return *pnfsp ? EXCHGID4_FLAG_USE_PNFS_MDS | EXCHGID4_FLAG_USE_PNFS_DS :
	    EXCHGID4_FLAG_USE_NON_PNFS;
}

/* s13.1: of a server that is not a metadata server, these are unknown. */
static uint32_t
layout_client(const struct nfsv4_compound *c)
{

	if (c->c_client == NULL || !c->c_client->cl_pnfs)
		return NFS4ERR_NOTSUPP;
	return NFS4_OK;
}

/* s12.5.5.2.1.4: the seqid goes round past 0, which is never used. */
static void
layout_bump(struct nfsv4_state *st)
{

	if (++st->st_seqid == 0)
		st->st_seqid = 1;
}

/*
 * The layout stateid si, for this client and vp.  s12.5.5.2.1.4: a seqid
 * of 0 or ahead of the server's is BAD_STATEID; any one behind is within
 * VALID_SEQID_RANGE, which is taken at its maximum, 2^32 - 2.
 */
static uint32_t
layout_lookup(const struct nfsv4_compound *c, const struct nfsv4_stateid *si,
    struct vnode *vp, struct nfsv4_state **stp)
{
	struct nfsv4_state *st;
	uint32_t status;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if (si->si_seqid == 0)
		return NFS4ERR_BAD_STATEID;
	status = nfsv4_stateid_lookup(c, si, &st);
	if (status != NFS4_OK)
		return status;
	if (st->st_type != NFSV4_ST_LAYOUT)
		return NFS4ERR_BAD_STATEID;
	if (st->st_revoked)
		return NFS4ERR_DELEG_REVOKED;	/* s8.2.4, of any revoked */
	if (st->st_file == NULL)
		return NFS4ERR_BAD_STATEID;	/* s12.5.3, all returned */
	if (vp != NULL && st->st_file->f_vp != vp)
		return NFS4ERR_BAD_STATEID;
	if ((int32_t)(si->si_seqid - st->st_seqid) > 0)
		return NFS4ERR_BAD_STATEID;
	nfsv4_client_renew(st->st_owner->sw_client);
	*stp = st;
	return NFS4_OK;
}

/* This client's layout on vp, if it has one. */
static struct nfsv4_state *
layout_find(const struct nfsv4_client *cl, struct vnode *vp)
{
	struct nfsv4_file *f;
	struct nfsv4_state *st;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if ((f = nfsv4_file_find(vp)) == NULL)
		return NULL;
	LIST_FOREACH(st, &f->f_states, st_flist) {
		if (st->st_type == NFSV4_ST_LAYOUT &&
		    st->st_owner->sw_client == cl)
			return st;
	}
	return NULL;
}

/* s13.3, nfsv4_1_file_layout_ds_addr4, in da_addr_body of s3.3.15. */
static u_int
ds_addr_len(void)
{
	size_t n = strlen(ds_netid), u = strlen(ds_uaddr);

	/* indices<1>, list<1> of multipath<1> of netaddr4 */
	return 4 + 4 + 4 + 4 + 4 + roundup(n, 4) + 4 + roundup(u, 4);
}

static bool
ds_addr_put(XDR *x)
{
	char *n = ds_netid, *u = ds_uaddr;

	return nfsv4_xdr_u32(x, 1) && nfsv4_xdr_u32(x, 0) &&
	    nfsv4_xdr_u32(x, 1) && nfsv4_xdr_u32(x, 1) &&
	    xdr_string(x, &n, NFSV4_DS_NETID) &&
	    xdr_string(x, &u, NFSV4_DS_UADDR);
}

/* s18.40, GETDEVICEINFO */
uint32_t
nfsv4_op_getdeviceinfo(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_getdeviceinfo *ga = &a->getdeviceinfo;
	uint8_t id[NFS4_DEVICEID4_SIZE];
	char netid[NFSV4_DS_NETID], uaddr[NFSV4_DS_UADDR];
	uint32_t status, len, need;
	bool ok;

	if ((status = layout_client(c)) != NFS4_OK)
		return status;
	if (ga->type != LAYOUT4_NFSV4_1_FILES)
		return NFS4ERR_UNKNOWN_LAYOUTTYPE;
	mutex_enter(&nfsv4_state_lock);
	ds_devid(id);
	memcpy(netid, ds_netid, sizeof(netid));
	memcpy(uaddr, ds_uaddr, sizeof(uaddr));
	len = ds_addr_len();
	mutex_exit(&nfsv4_state_lock);
	if (uaddr[0] == '\0' ||
	    memcmp(id, ga->devid, NFS4_DEVICEID4_SIZE) != 0)
		return NFS4ERR_NOENT;
	/* type, body<>, and an empty gdir_notification: none are sent. */
	need = 4 + 4 + len + 4;
	/* s18.40.3: maxcount 0 has an empty body, never TOOSMALL. */
	if (ga->maxcount != 0 && ga->maxcount < need) {
		(void)nfsv4_xdr_u32(c->c_rx, need);	/* gdir_mincount */
		return NFS4ERR_TOOSMALL;
	}
	if (ga->maxcount == 0)
		len = 0;
	ok = nfsv4_xdr_u32(c->c_rx, LAYOUT4_NFSV4_1_FILES) &&
	    nfsv4_xdr_u32(c->c_rx, len);
	if (ok && len != 0) {
		mutex_enter(&nfsv4_state_lock);
		ok = ds_addr_put(c->c_rx);
		mutex_exit(&nfsv4_state_lock);
	}
	if (!ok || !nfsv4_xdr_u32(c->c_rx, 0))
		return NFS4ERR_RESOURCE;
	return NFS4_OK;
}

/* s18.41, GETDEVICELIST: the one device, whatever the file system. */
uint32_t
nfsv4_op_getdevicelist(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_getdevicelist *ga = &a->getdevicelist;
	uint8_t id[NFS4_DEVICEID4_SIZE];
	struct nfsv4_verifier verf;
	uint32_t status, n;

	if ((status = layout_client(c)) != NFS4_OK)
		return status;
	if (ga->type != LAYOUT4_NFSV4_1_FILES)
		return NFS4ERR_UNKNOWN_LAYOUTTYPE;
	if (c->c_cur.cf_vp == NULL)
		return NFS4ERR_NOTSUPP;		/* the pseudo file system */
	mutex_enter(&nfsv4_state_lock);
	ds_devid(id);
	mutex_exit(&nfsv4_state_lock);
	/* The verifier is the generation; a cookie of 0 needs none. */
	memset(&verf, 0, sizeof(verf));
	memcpy(verf.v_data, id + 4, 4);
	if (ga->cookie != 0 &&
	    memcmp(&verf, &ga->verf, sizeof(verf)) != 0)
		return NFS4ERR_NOT_SAME;
	n = ga->cookie == 0 && ga->maxdevices > 0 ? 1 : 0;
	if (ga->cookie > 1)
		return NFS4ERR_BAD_COOKIE;
	if (!xdr_u_int64_t(c->c_rx, &(uint64_t){ n }) ||
	    !nfsv4_xdr_verifier(c->c_rx, &verf) ||
	    !nfsv4_xdr_u32(c->c_rx, n) ||
	    (n != 0 && !XDR_PUTBYTES(c->c_rx, (char *)id, sizeof(id))) ||
	    !nfsv4_xdr_u32(c->c_rx, ga->cookie != 0 || n != 0))
		return NFS4ERR_RESOURCE;
	return NFS4_OK;
}

/*
 * s18.43, LAYOUTGET.  The layout is all of the file, in the mode asked:
 * offset 0 and length NFS4_UINT64_MAX meet every row of Table 22 and
 * Table 23.
 */
uint32_t
nfsv4_op_layoutget(struct nfsv4_compound *c, union nfsv4_args *a)
{
	struct nfsv4_args_layoutget *la = &a->layoutget;
	struct vnode *vp = c->c_cur.cf_vp;
	struct nfsv4_state *st, *sst = NULL, *ost;
	struct nfsv4_owner_s *sw, *ssw = NULL;
	struct nfsv4_file *sf = NULL;
	struct nfsv4_stateid si;
	struct nfsv4_fh fh = c->c_cur.cf_fh;
	uint8_t id[NFS4_DEVICEID4_SIZE];
	uint32_t status, need, body, util;
	XDR *x = c->c_rx;

	if ((status = layout_client(c)) != NFS4_OK)
		return status;
	if ((status = nfsv4_file_check(c, &c->c_cur)) != NFS4_OK)
		return status;
	if (la->type != LAYOUT4_NFSV4_1_FILES)
		return NFS4ERR_UNKNOWN_LAYOUTTYPE;
	if (la->iomode != LAYOUTIOMODE4_READ && la->iomode != LAYOUTIOMODE4_RW)
		return NFS4ERR_BADIOMODE;
	if (la->length < la->minlength)
		return NFS4ERR_INVAL;
	if (la->minlength != NFS4_UINT64_MAX &&
	    la->offset > NFS4_UINT64_MAX - la->minlength)
		return NFS4ERR_INVAL;
	if (la->length != NFS4_UINT64_MAX &&
	    la->offset > NFS4_UINT64_MAX - la->length)
		return NFS4ERR_INVAL;
	/* s18.43.3: layouts are not kept across a restart. */
	if (nfsv4_grace_active())
		return NFS4ERR_GRACE;
	/* nfl_fh_list<1>, s13.3, in layout_content4 of one layout4. */
	body = NFS4_DEVICEID4_SIZE + 4 + 4 + 8 + 4 + 4 + roundup(fh.fh_len, 4);
	need = 4 + 16 + 4 + 8 + 8 + 4 + 4 + 4 + body;
	if (la->maxcount < need)
		return NFS4ERR_TOOSMALL;

	ssw = kmem_zalloc(sizeof(*ssw), KM_SLEEP);
	sst = kmem_zalloc(sizeof(*sst), KM_SLEEP);
	sf = kmem_zalloc(sizeof(*sf), KM_SLEEP);
	mutex_enter(&nfsv4_state_lock);
	if (!nfsv4_pnfs_on()) {
		status = NFS4ERR_LAYOUTUNAVAILABLE;
		goto out;
	}
	st = layout_find(c->c_client, vp);
	status = nfsv4_stateid_lookup(c, &la->stateid, &ost);
	if (status != NFS4_OK)
		goto out;
	if (ost->st_type == NFSV4_ST_LAYOUT) {
		status = layout_lookup(c, &la->stateid, vp, &ost);
		if (status != NFS4_OK)
			goto out;
		st = ost;
	} else {
		/*
		 * s18.43.3: the open, lock or delegation stateid comes only
		 * before a layout is held; after, the layout's own.
		 */
		if (st != NULL) {
			status = NFS4ERR_BAD_STATEID;
			goto out;
		}
		status = nfsv4_stateid_check(&la->stateid, ost, vp, 0);
		if (status != NFS4_OK)
			goto out;
	}
	/* s12.5.5.2.1.3: a recall of it not yet done. */
	if (st != NULL && st->st_lrecall) {
		status = st->st_lanswered ? NFS4ERR_RETURNCONFLICT :
		    NFS4ERR_RECALLCONFLICT;
		goto out;
	}
	if (st == NULL) {
		sw = nfsv4_owner_find(c->c_client, NFSV4_OWNER_LAYOUT,
		    (const uint8_t *)"", 0);
		if (sw == NULL) {
			sw = nfsv4_owner_add(c->c_client, &ssw,
			    NFSV4_OWNER_LAYOUT, (const uint8_t *)"", 0);
			sw->sw_confirmed = true;
		}
		st = nfsv4_state_add(&sst, sw, &sf, vp, NFSV4_ST_LAYOUT);
		if (st->st_file->f_fh.fh_len == 0)
			st->st_file->f_fh = fh;
	} else
		layout_bump(st);		/* s12.5.3 */
	st->st_liomode |= 1U << la->iomode;
	nfsv4_stateid_out(st, &si);
	ds_devid(id);
	mutex_exit(&nfsv4_state_lock);

	/* s13.3: sparse, so the offsets are the file's own; one stripe. */
	util = NFSV4_STRIPE_UNIT & NFL4_UFLG_STRIPE_UNIT_SIZE_MASK;
	if (!nfsv4_xdr_u32(x, 0) ||			/* return_on_close */
	    !nfsv4_xdr_stateid(x, &si) ||
	    !nfsv4_xdr_u32(x, 1) ||			/* logr_layout<> */
	    !xdr_u_int64_t(x, &(uint64_t){ 0 }) ||
	    !xdr_u_int64_t(x, &(uint64_t){ NFS4_UINT64_MAX }) ||
	    !nfsv4_xdr_u32(x, la->iomode) ||
	    !nfsv4_xdr_u32(x, LAYOUT4_NFSV4_1_FILES) ||
	    !nfsv4_xdr_u32(x, body) ||
	    !XDR_PUTBYTES(x, (char *)id, sizeof(id)) ||
	    !nfsv4_xdr_u32(x, util) ||
	    !nfsv4_xdr_u32(x, 0) ||			/* first_stripe_index */
	    !xdr_u_int64_t(x, &(uint64_t){ 0 }) ||	/* pattern_offset */
	    !nfsv4_xdr_u32(x, 1) || !nfsv4_xdr_fh(x, &fh))
		status = NFS4ERR_RESOURCE;
	else {
		c->c_curst = si;		/* s18.43.3 */
		atomic_inc_uint((volatile u_int *)&nfsv4_layouts_given);
	}
	goto done;
out:
	mutex_exit(&nfsv4_state_lock);
	/* s18.43.3: the signal for when one is available is not given. */
	if (status == NFS4ERR_LAYOUTTRYLATER)
		(void)nfsv4_xdr_u32(x, 0);
done:
	if (ssw != NULL)
		kmem_free(ssw, sizeof(*ssw));
	if (sst != NULL)
		kmem_free(sst, sizeof(*sst));
	if (sf != NULL)
		kmem_free(sf, sizeof(*sf));
	return status;
}

/* Of a layout whose last mode has gone: it ends, s12.5.3. */
static void
layout_end(struct nfsv4_state *st, struct nfsv4_reap *reap)
{

	KASSERT(mutex_owned(&nfsv4_state_lock));

	nfsv4_state_unlink(st, reap, false);
}

/* Give back the modes of iomode, LAYOUTIOMODE4_ANY for all. */
static bool
layout_drop(struct nfsv4_state *st, uint32_t iomode, struct nfsv4_reap *reap)
{

	if (iomode == LAYOUTIOMODE4_ANY)
		st->st_liomode = 0;
	else
		st->st_liomode &= ~(1U << iomode);
	/* s18.44.3: the recall, of all of it, ends with the last mode. */
	if (st->st_liomode == 0) {
		layout_end(st, reap);
		return true;
	}
	return false;
}

/* s18.44, LAYOUTRETURN */
uint32_t
nfsv4_op_layoutreturn(struct nfsv4_compound *c, union nfsv4_args *a)
{
	struct nfsv4_args_layoutreturn *la = &a->layoutreturn;
	struct vnode *vp = c->c_cur.cf_vp;
	struct nfsv4_owner_s *sw;
	struct nfsv4_state *st, *nst;
	struct nfsv4_stateid si;
	struct nfsv4_reap reap;
	uint32_t status;
	bool gone = false;

	if ((status = layout_client(c)) != NFS4_OK)
		return status;
	if (la->rtype != LAYOUT4_RET_REC_ALL && !c->c_cur.cf_set)
		return NFS4ERR_NOFILEHANDLE;
	if (la->type != LAYOUT4_NFSV4_1_FILES)
		return NFS4ERR_UNKNOWN_LAYOUTTYPE;
	if (la->iomode < LAYOUTIOMODE4_READ || la->iomode > LAYOUTIOMODE4_ANY)
		return NFS4ERR_BADIOMODE;
	if (la->reclaim) {
		if (la->rtype != LAYOUT4_RET_REC_FILE)
			return NFS4ERR_INVAL;
		/* None was kept across the restart; nothing to return. */
		if (!nfsv4_grace_active())
			return NFS4ERR_NO_GRACE;
		return nfsv4_xdr_u32(c->c_rx, 0) ? NFS4_OK : NFS4ERR_RESOURCE;
	}
	if (la->rtype == LAYOUT4_RET_REC_FILE &&
	    (status = nfsv4_file_check(c, &c->c_cur)) != NFS4_OK)
		return status;

	SLIST_INIT(&reap);
	mutex_enter(&nfsv4_state_lock);
	if (la->rtype == LAYOUT4_RET_REC_FILE) {
		status = layout_lookup(c, &la->stateid, vp, &st);
		if (status != NFS4_OK)
			goto out;
		/*
		 * Less than all of it leaves it held, and a recall of it
		 * waiting; all of it, of a mode, gives that mode back.
		 */
		if (la->offset == 0 && la->length == NFS4_UINT64_MAX)
			gone = layout_drop(st, la->iomode, &reap);
		if (!gone) {
			layout_bump(st);
			nfsv4_stateid_out(st, &si);
		}
	} else {
		LIST_FOREACH(sw, &c->c_client->cl_owners, sw_list) {
			if (sw->sw_type != NFSV4_OWNER_LAYOUT)
				continue;
			LIST_FOREACH_SAFE(st, &sw->sw_states, st_olist, nst) {
				if (st->st_file == NULL ||
				    (la->rtype == LAYOUT4_RET_REC_FSID &&
				    (vp == NULL ||
				    st->st_file->f_vp->v_mount != vp->v_mount)))
					continue;
				(void)layout_drop(st, la->iomode, &reap);
			}
		}
		gone = true;
	}
out:
	mutex_exit(&nfsv4_state_lock);
	nfsv4_reap_finish(&reap);
	if (status != NFS4_OK)
		return status;
	/* s18.44.3: none left, no stateid, and the current one all zeros. */
	if (gone) {
		if (la->rtype == LAYOUT4_RET_REC_FILE)
			memset(&c->c_curst, 0, sizeof(c->c_curst));
		return nfsv4_xdr_u32(c->c_rx, 0) ? NFS4_OK : NFS4ERR_RESOURCE;
	}
	c->c_curst = si;
	return nfsv4_xdr_u32(c->c_rx, 1) && nfsv4_xdr_stateid(c->c_rx, &si) ?
	    NFS4_OK : NFS4ERR_RESOURCE;
}

/*
 * s18.42, LAYOUTCOMMIT.  The data server is this server, so what was
 * written is in the file already; only a size the client says is past
 * it is made so, s12.5.4.2.  loca_time_modify may be used or not, and
 * the server's own time is what the write left.
 */
uint32_t
nfsv4_op_layoutcommit(struct nfsv4_compound *c, union nfsv4_args *a)
{
	struct nfsv4_args_layoutcommit *la = &a->layoutcommit;
	struct vnode *vp = c->c_cur.cf_vp;
	struct nfsv4_state *st;
	struct vattr va;
	uint32_t status;
	bool changed = false;
	int error;

	if ((status = layout_client(c)) != NFS4_OK)
		return status;
	if ((status = nfsv4_file_check(c, &c->c_cur)) != NFS4_OK)
		return status;
	if (la->type != LAYOUT4_NFSV4_1_FILES)
		return NFS4ERR_UNKNOWN_LAYOUTTYPE;
	/* s18.42.3: none was kept across the restart to reclaim. */
	if (la->reclaim)
		return nfsv4_grace_active() ? NFS4ERR_RECLAIM_BAD :
		    NFS4ERR_NO_GRACE;
	if (la->length != NFS4_UINT64_MAX &&
	    la->offset > NFS4_UINT64_MAX - la->length)
		return NFS4ERR_INVAL;
	mutex_enter(&nfsv4_state_lock);
	status = layout_lookup(c, &la->stateid, vp, &st);
	/* s18.42.3: of a writable layout. */
	if (status == NFS4_OK &&
	    (st->st_liomode & (1U << LAYOUTIOMODE4_RW)) == 0)
		status = NFS4ERR_BADIOMODE;
	mutex_exit(&nfsv4_state_lock);
	if (status != NFS4_OK)
		return status;
	/* s18.42.3: within the range, and no more than NFS4_MAXFILEOFF. */
	if (la->newoffset && (la->lastoffset < la->offset ||
	    (la->length != NFS4_UINT64_MAX &&
	    la->lastoffset >= la->offset + la->length) ||
	    la->lastoffset >= NFS4_UINT64_MAX))
		return NFS4ERR_INVAL;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	error = VOP_GETATTR(vp, &va, c->c_cur.cf_cred);
	if (error == 0 && la->newoffset && la->lastoffset + 1 > va.va_size) {
		vattr_null(&va);
		va.va_size = la->lastoffset + 1;
		error = VOP_SETATTR(vp, &va, c->c_cur.cf_cred);
		changed = error == 0;
	}
	VOP_UNLOCK(vp);
	if (error != 0)
		return nfsv4_errno(error);
	if (!nfsv4_xdr_u32(c->c_rx, changed) ||
	    (changed && !xdr_u_int64_t(c->c_rx, &(uint64_t){ va.va_size })))
		return NFS4ERR_RESOURCE;
	return NFS4_OK;
}

/*
 * s12.5.5: recall every layout, on vfs.nfsv4.layout_recall.  Each is
 * sent its own CB_LAYOUTRECALL of LAYOUTRECALL4_FILE, with the seqid one
 * past the last, s12.5.3.  Until it is answered and returned, LAYOUTGET
 * of it meets the errors of s12.5.5.2.1.3.  A client that does not
 * return it within a lease loses it, nfsv4_layout_scan().
 */
void
nfsv4_layout_recall_all(void)
{
	struct nfsv4_client *cl;
	struct nfsv4_owner_s *sw;
	struct nfsv4_state *st;

	mutex_enter(&nfsv4_state_lock);
	for (cl = nfsv4_client_next(NULL); cl != NULL;
	    cl = nfsv4_client_next(cl)) {
		LIST_FOREACH(sw, &cl->cl_owners, sw_list) {
			if (sw->sw_type != NFSV4_OWNER_LAYOUT)
				continue;
			LIST_FOREACH(st, &sw->sw_states, st_olist) {
				if (st->st_file == NULL || st->st_lrecall)
					continue;
				layout_bump(st);
				st->st_lrecall = true;
				st->st_lanswered = false;
				st->st_lrend = time_uptime + NFSV4_LEASE;
				if (!nfsv4_cb_layoutrecall(st))
					st->st_lrecall = false;
			}
		}
	}
	mutex_exit(&nfsv4_state_lock);
}

/*
 * What the client said to a CB_LAYOUTRECALL of the state other.  s20.3.3:
 * NOMATCHING_LAYOUT is that it has none, and the recall is done.
 */
void
nfsv4_layout_recalled(uint64_t other, int error, uint32_t status,
    struct nfsv4_reap *reap)
{
	struct nfsv4_state *st;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	st = nfsv4_state_byother(other);
	if (st == NULL || st->st_type != NFSV4_ST_LAYOUT ||
	    st->st_file == NULL || !st->st_lrecall)
		return;
	if (error == 0 && status == NFS4ERR_NOMATCHING_LAYOUT)
		layout_end(st, reap);
	else if (error == 0)
		st->st_lanswered = true;
}

/*
 * s12.5.5: a recalled layout not returned within its time is let go.
 * The data server is this server, so nothing is to be fenced: I/O goes
 * by the open and lock stateids, which stay good (s13.9.1).
 */
void
nfsv4_layout_scan(struct nfsv4_reap *reap)
{
	struct nfsv4_client *cl;
	struct nfsv4_owner_s *sw;
	struct nfsv4_state *st, *nst;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	for (cl = nfsv4_client_next(NULL); cl != NULL;
	    cl = nfsv4_client_next(cl)) {
		LIST_FOREACH(sw, &cl->cl_owners, sw_list) {
			if (sw->sw_type != NFSV4_OWNER_LAYOUT)
				continue;
			LIST_FOREACH_SAFE(st, &sw->sw_states, st_olist, nst) {
				if (st->st_file != NULL && st->st_lrecall &&
				    time_uptime >= st->st_lrend)
					layout_end(st, reap);
			}
		}
	}
}

/* The layout attributes, s5.12: what this file system offers. */
uint32_t
nfsv4_layout_types(struct vnode *vp)
{

	return vp != NULL && nfsv4_pnfs_on() ? LAYOUT4_NFSV4_1_FILES : 0;
}

uint32_t
nfsv4_layout_blksize(void)
{

	return NFSV4_STRIPE_UNIT;
}
