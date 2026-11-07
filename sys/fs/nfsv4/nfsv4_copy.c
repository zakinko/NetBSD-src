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
 * Inter-server copy, RFC 7862 s4.5 to s4.9, by NFSv4.2 itself as the
 * copy protocol, s4.6.2, and host-based security, s4.9.1.2: RPCSEC_GSSv3
 * is not here.  As the source, COPY_NOTIFY hands out a copy stateid good
 * for READ of one file for cnr_lease_time; as the destination, COPY runs
 * a client of its own against the source with the stateid it was given.
 *
 * Where the source is reached is the address in vfs.nfsv4.copy_addr, a
 * universal address: the kernel has no way to tell which of its
 * addresses a peer reaches it on, and s4.5 lets the source name others.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/kauth.h>
#include <sys/kmem.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/vnode.h>

#include <fs/nfsv4/nfsv4_var.h>
#include <fs/nfsv4/nfsv4_state.h>

/* A choice: what one READ asks of the source, under CLNT_MAXREPLY. */
#define	NFSV4_RCOPY_IO		(32 * 1024)
#define	NFSV4_RCOPY_TIMEO	30
#define	NFSV4_CNR_MAX		64

char nfsv4_copy_addr[NFSV4_NETADDR_MAX];

/* What COPY_NOTIFY gave out, s15.3.3. */
struct nfsv4_cnr {
	LIST_ENTRY(nfsv4_cnr) cn_list;
	uint8_t		cn_other[NFS4_OTHER_SIZE];
	struct vnode	*cn_vp;		/* a reference */
	uid_t		cn_uid;		/* s4.1.2, for OFFLOAD_CANCEL */
	time_t		cn_expire;	/* time_uptime */
	bool		cn_used;	/* a READ came, s15.3.3 */
};

static LIST_HEAD(, nfsv4_cnr) cnrs = LIST_HEAD_INITIALIZER(cnrs);
static u_int cnr_count;
static uint64_t cnr_next;

static void
cnr_expire(void)
{
	struct nfsv4_cnr *cn, *next;

	KASSERT(mutex_owned(&nfsv4_state_lock));
	LIST_FOREACH_SAFE(cn, &cnrs, cn_list, next) {
		/* s15.3.3: one already reading may finish. */
		if (cn->cn_used || time_uptime <= cn->cn_expire)
			continue;
		LIST_REMOVE(cn, cn_list);
		cnr_count--;
		vrele(cn->cn_vp);	/* only a reference; never the last */
		kmem_free(cn, sizeof(*cn));
	}
}

/*
 * Whether si is a copy stateid good for a READ of vp, s4.6.2.  Any
 * client may present it: it is the destination's, on the client's
 * behalf, s4.3.1.
 */
bool
nfsv4_cnr_ok(const struct nfsv4_stateid *si, struct vnode *vp)
{
	struct nfsv4_cnr *cn;

	KASSERT(mutex_owned(&nfsv4_state_lock));
	LIST_FOREACH(cn, &cnrs, cn_list) {
		if (memcmp(cn->cn_other, si->si_other, NFS4_OTHER_SIZE) != 0)
			continue;
		if (cn->cn_vp != vp ||
		    (!cn->cn_used && time_uptime > cn->cn_expire))
			return false;
		cn->cn_used = true;
		return true;
	}
	return false;
}

/* s15.8.3 at the source: no more copying with it. */
bool
nfsv4_cnr_cancel(const struct nfsv4_stateid *si, struct vnode *vp, uid_t uid)
{
	struct nfsv4_cnr *cn;

	mutex_enter(&nfsv4_state_lock);
	LIST_FOREACH(cn, &cnrs, cn_list) {
		if (memcmp(cn->cn_other, si->si_other, NFS4_OTHER_SIZE) == 0 &&
		    cn->cn_vp == vp && cn->cn_uid == uid) {
			LIST_REMOVE(cn, cn_list);
			cnr_count--;
			mutex_exit(&nfsv4_state_lock);
			vrele(cn->cn_vp);
			kmem_free(cn, sizeof(*cn));
			return true;
		}
	}
	mutex_exit(&nfsv4_state_lock);
	return false;
}

void
nfsv4_cnr_drain(void)
{
	struct nfsv4_cnr *cn;

	mutex_enter(&nfsv4_state_lock);
	while ((cn = LIST_FIRST(&cnrs)) != NULL) {
		LIST_REMOVE(cn, cn_list);
		mutex_exit(&nfsv4_state_lock);
		vrele(cn->cn_vp);
		kmem_free(cn, sizeof(*cn));
		mutex_enter(&nfsv4_state_lock);
	}
	cnr_count = 0;
	mutex_exit(&nfsv4_state_lock);
}

/*
 * s15.3.  cna_src_stateid has to be an open or a lock, not one of the
 * special ones.  The copy stateids have the top bits 10 in the second
 * part, where the offload ones of nfsv4_v42.c have 1 and open state 0.
 */
uint32_t
nfsv4_op_copy_notify(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_cfh *cf = &c->c_cur;
	const struct nfsv4_stateid *si = &a->copy.src_stateid;
	struct nfsv4_cnr *cn;
	struct nfsv4_stateid out;
	uint64_t sec = NFSV4_LEASE, id;
	uint32_t st, nsec = 0, n, len, three = NL4_NETADDR;

	if (cf->cf_vp == NULL || cf->cf_vp->v_type != VREG)
		return cf->cf_vp != NULL && cf->cf_vp->v_type == VDIR ?
		    NFS4ERR_ISDIR : NFS4ERR_WRONG_TYPE;
	if (nfsv4_stateid_special(si))
		return NFS4ERR_BAD_STATEID;
	st = nfsv4_io_check(c, si, false);
	if (st == NFS4_OK)
		st = nfsv4_errno(nfsv4_access_vp(cf, VREAD));
	if (st != NFS4_OK)
		return st;

	cn = kmem_zalloc(sizeof(*cn), KM_SLEEP);
	mutex_enter(&nfsv4_state_lock);
	cnr_expire();
	if (cnr_count >= NFSV4_CNR_MAX) {
		mutex_exit(&nfsv4_state_lock);
		kmem_free(cn, sizeof(*cn));
		return NFS4ERR_DELAY;
	}
	id = ++cnr_next;
	be32enc(cn->cn_other, nfsv4_boot);
	be64enc(cn->cn_other + 4, id | (2ULL << 62));
	cn->cn_vp = cf->cf_vp;
	vref(cn->cn_vp);
	cn->cn_uid = nfsv4_client_principal(c);
	cn->cn_expire = time_uptime + NFSV4_LEASE;
	LIST_INSERT_HEAD(&cnrs, cn, cn_list);
	cnr_count++;
	memcpy(out.si_other, cn->cn_other, NFS4_OTHER_SIZE);
	mutex_exit(&nfsv4_state_lock);
	out.si_seqid = 1;

	len = strlen(nfsv4_copy_addr);
	n = len != 0 ? 1 : 0;
	/* COPY_NOTIFY4resok: cnr_lease_time, cnr_stateid, cnr_source_server */
	return xdr_u_int64_t(c->c_rx, &sec) && xdr_u_int32_t(c->c_rx, &nsec) &&
	    nfsv4_xdr_stateid(c->c_rx, &out) && xdr_u_int32_t(c->c_rx, &n) &&
	    (n == 0 || (xdr_u_int32_t(c->c_rx, &three) &&
	    nfsv4_xdr_u32(c->c_rx, 3) &&
	    xdr_opaque(c->c_rx, __UNCONST("tcp"), 3) &&
	    xdr_u_int32_t(c->c_rx, &len) &&
	    xdr_opaque(c->c_rx, nfsv4_copy_addr, len))) ? NFS4_OK :
	    NFS4ERR_RESOURCE;
}

/*
 * The client of the destination: one session at the source for the copy,
 * the calls of RFC 8881 s18 that it takes, each on its own connection,
 * which SP4_NONE lets a session be used on, s2.10.3.1.
 */
struct rcopy {
	struct sockaddr_storage rc_ss;
	char		rc_cred[64];
	u_int		rc_credlen;
	uint64_t	rc_clientid;
	uint32_t	rc_csseq;
	struct nfsv4_sessionid rc_sid;
	uint32_t	rc_seq;
	const struct nfsv4_fh *rc_fh;
	const struct nfsv4_stateid *rc_si;
	uint64_t	rc_off;
	uint32_t	rc_count;
	char		*rc_buf;
	uint32_t	rc_got;
	uint32_t	rc_eof;
	uint32_t	rc_status;
	uint32_t	rc_op;
};

static bool
rc_head(XDR *x, uint32_t nops)
{

	return nfsv4_xdr_u32(x, 0) && nfsv4_xdr_u32(x, 2) &&
	    nfsv4_xdr_u32(x, nops);
}

static bool
rc_sequence(XDR *x, struct rcopy *rc)
{

	return nfsv4_xdr_u32(x, NFSV4_OP_SEQUENCE) &&
	    nfsv4_xdr_sessionid(x, &rc->rc_sid) &&
	    nfsv4_xdr_u32(x, rc->rc_seq) && nfsv4_xdr_u32(x, 0) &&
	    nfsv4_xdr_u32(x, 0) && nfsv4_xdr_u32(x, 0);
}

static bool
rc_encode(XDR *x, void *arg)
{
	struct rcopy *rc = arg;
	struct nfsv4_verifier v;
	char owner[48];
	uint32_t n;
	struct nfsv4_stateid si;

	switch (rc->rc_op) {
	case NFSV4_OP_EXCHANGE_ID:
		memset(&v, 0, sizeof(v));
		be32enc(v.v_data, nfsv4_boot);
		n = snprintf(owner, sizeof(owner), "netbsd-nfsv4-copy-%u-%p",
		    nfsv4_boot, rc);
		return rc_head(x, 1) &&
		    nfsv4_xdr_u32(x, NFSV4_OP_EXCHANGE_ID) &&
		    nfsv4_xdr_verifier(x, &v) && xdr_u_int32_t(x, &n) &&
		    xdr_opaque(x, owner, n) && nfsv4_xdr_u32(x, 0) &&
		    nfsv4_xdr_u32(x, SP4_NONE) && nfsv4_xdr_u32(x, 0);
	case NFSV4_OP_CREATE_SESSION:
		/* Fore channel enough for a READ, no back channel use. */
		return rc_head(x, 1) &&
		    nfsv4_xdr_u32(x, NFSV4_OP_CREATE_SESSION) &&
		    xdr_u_int64_t(x, &rc->rc_clientid) &&
		    nfsv4_xdr_u32(x, rc->rc_csseq) && nfsv4_xdr_u32(x, 0) &&
		    nfsv4_xdr_u32(x, 0) && nfsv4_xdr_u32(x, 65536) &&
		    nfsv4_xdr_u32(x, 65536) && nfsv4_xdr_u32(x, 0) &&
		    nfsv4_xdr_u32(x, 8) && nfsv4_xdr_u32(x, 1) &&
		    nfsv4_xdr_u32(x, 0) &&
		    nfsv4_xdr_u32(x, 0) && nfsv4_xdr_u32(x, 4096) &&
		    nfsv4_xdr_u32(x, 4096) && nfsv4_xdr_u32(x, 0) &&
		    nfsv4_xdr_u32(x, 2) && nfsv4_xdr_u32(x, 1) &&
		    nfsv4_xdr_u32(x, 0) &&
		    nfsv4_xdr_u32(x, 0x40000000) &&
		    nfsv4_xdr_u32(x, 1) && nfsv4_xdr_u32(x, 0);
	case NFSV4_OP_READ:
		si = *rc->rc_si;
		return rc_head(x, 3) && rc_sequence(x, rc) &&
		    nfsv4_xdr_u32(x, NFSV4_OP_PUTFH) &&
		    nfsv4_xdr_fh(x, __UNCONST(rc->rc_fh)) &&
		    nfsv4_xdr_u32(x, NFSV4_OP_READ) &&
		    nfsv4_xdr_stateid(x, &si) &&
		    xdr_u_int64_t(x, &rc->rc_off) &&
		    xdr_u_int32_t(x, &rc->rc_count);
	case NFSV4_OP_DESTROY_SESSION:
		return rc_head(x, 1) &&
		    nfsv4_xdr_u32(x, NFSV4_OP_DESTROY_SESSION) &&
		    nfsv4_xdr_sessionid(x, &rc->rc_sid);
	case NFSV4_OP_DESTROY_CLIENTID:
		return rc_head(x, 1) &&
		    nfsv4_xdr_u32(x, NFSV4_OP_DESTROY_CLIENTID) &&
		    xdr_u_int64_t(x, &rc->rc_clientid);
	default:
		return false;
	}
}

/* COMPOUND4res up to the result of the last operation, s16.2.2. */
static bool
rc_decode(XDR *x, void *arg)
{
	struct rcopy *rc = arg;
	uint32_t status, tag, n, op, st, i, len;
	u_int pos;

	if (!xdr_u_int32_t(x, &status) || !xdr_u_int32_t(x, &tag) ||
	    tag > NFS4_OPAQUE_LIMIT ||
	    !XDR_SETPOS(x, XDR_GETPOS(x) + ((tag + 3) & ~3U)) ||
	    !xdr_u_int32_t(x, &n))
		return false;
	rc->rc_status = status;
	for (i = 0; i < n; i++) {
		if (!xdr_u_int32_t(x, &op) || !xdr_u_int32_t(x, &st))
			return false;
		if (st != NFS4_OK) {
			rc->rc_status = st;
			return true;
		}
		switch (op) {
		case NFSV4_OP_EXCHANGE_ID:
			return xdr_u_int64_t(x, &rc->rc_clientid) &&
			    xdr_u_int32_t(x, &rc->rc_csseq);
		case NFSV4_OP_CREATE_SESSION:
			return nfsv4_xdr_sessionid(x, &rc->rc_sid);
		case NFSV4_OP_SEQUENCE:
			/* sessionid, seq, slot, highest, target, flags */
			pos = XDR_GETPOS(x);
			if (!XDR_SETPOS(x, pos + NFS4_SESSIONID_SIZE + 20))
				return false;
			break;
		case NFSV4_OP_PUTFH:
			break;
		case NFSV4_OP_READ:
			if (!xdr_u_int32_t(x, &rc->rc_eof) ||
			    !xdr_u_int32_t(x, &len) || len > rc->rc_count)
				return false;
			rc->rc_got = len;
			return len == 0 ||
			    xdr_opaque(x, rc->rc_buf, len) != 0;
		default:
			return true;
		}
	}
	return true;
}

static int
rc_call(struct rcopy *rc, uint32_t op)
{
	struct oncrpc_clnt_call cc;
	int error;

	memset(&cc, 0, sizeof(cc));
	cc.cc_prog = NFSV4_PROGRAM;
	cc.cc_vers = NFSV4_VERSION;
	cc.cc_proc = NFSV4_PROC_COMPOUND;
	cc.cc_flavor = ONCRPC_AUTH_SYS;
	cc.cc_cred = rc->rc_cred;
	cc.cc_credlen = rc->rc_credlen;
	cc.cc_encode = rc_encode;
	cc.cc_arg = rc;
	cc.cc_decode = rc_decode;
	cc.cc_res = rc;
	rc->rc_op = op;
	rc->rc_status = NFS4ERR_SERVERFAULT;
	error = oncrpc_clnt_call((struct sockaddr *)&rc->rc_ss, &cc,
	    NFSV4_RCOPY_TIMEO);
	if (error != 0)
		return error;
	return rc->rc_status == NFS4_OK ? 0 : EIO;
}

/* RFC 5531 App. A, authsys_parms with no name and no groups. */
static u_int
rc_authsys(char *buf, size_t len, kauth_cred_t cred)
{
	uint32_t stamp = (uint32_t)time_second;
	XDR x;

	xdrmem_create(&x, buf, len, XDR_ENCODE);
	(void)(xdr_u_int32_t(&x, &stamp) && nfsv4_xdr_u32(&x, 0) &&
	    nfsv4_xdr_u32(&x, kauth_cred_geteuid(cred)) &&
	    nfsv4_xdr_u32(&x, kauth_cred_getegid(cred)) &&
	    nfsv4_xdr_u32(&x, 0));
	return xdr_getpos(&x);
}

/*
 * Copy up to *countp bytes from the source, a short count if it ends or
 * errs part way, as nfsv4_op_copy() does in the server.
 */
int
nfsv4_rcopy(const struct nfsv4_clientaddr *src, const struct nfsv4_fh *fh,
    const struct nfsv4_stateid *si, uint64_t srcoff, struct vnode *dst,
    kauth_cred_t dstcred, uint64_t dstoff, uint64_t *countp)
{
	struct rcopy *rc;
	uint64_t want = *countp, done = 0;
	int error;

	rc = kmem_zalloc(sizeof(*rc), KM_SLEEP);
	if (!nfsv4_uaddr_parse(src, &rc->rc_ss)) {
		kmem_free(rc, sizeof(*rc));
		return EADDRNOTAVAIL;
	}
	rc->rc_credlen = rc_authsys(rc->rc_cred, sizeof(rc->rc_cred),
	    dstcred);
	rc->rc_buf = kmem_alloc(NFSV4_RCOPY_IO, KM_SLEEP);
	rc->rc_fh = fh;
	rc->rc_si = si;
	error = rc_call(rc, NFSV4_OP_EXCHANGE_ID);
	if (error == 0)
		error = rc_call(rc, NFSV4_OP_CREATE_SESSION);
	if (error != 0)
		goto out;
	rc->rc_seq = 1;
	while (done < want) {
		rc->rc_off = srcoff + done;
		rc->rc_count = MIN(want - done, NFSV4_RCOPY_IO);
		rc->rc_got = 0;
		error = rc_call(rc, NFSV4_OP_READ);
		rc->rc_seq++;
		if (error != 0 || rc->rc_got == 0)
			break;
		vn_lock(dst, LK_EXCLUSIVE | LK_RETRY);
		error = vn_rdwr(UIO_WRITE, dst, rc->rc_buf, rc->rc_got,
		    dstoff + done, UIO_SYSSPACE, IO_NODELOCKED, dstcred, NULL,
		    NULL);
		VOP_UNLOCK(dst);
		if (error != 0)
			break;
		done += rc->rc_got;
		if (rc->rc_eof)
			break;
	}
	(void)rc_call(rc, NFSV4_OP_DESTROY_SESSION);
	(void)rc_call(rc, NFSV4_OP_DESTROY_CLIENTID);
out:
	kmem_free(rc->rc_buf, NFSV4_RCOPY_IO);
	kmem_free(rc, sizeof(*rc));
	*countp = done;
	return done != 0 ? 0 : error;
}
