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
 * Callbacks, RFC 7530 s17 and s18: CB_NULL to find out whether the path
 * works, s10.2, CB_RECALL, and CB_GETATTR.  The last is made in the
 * thread of the GETATTR it serves, which waits for it at most the
 * timeout: a client cannot be asked less directly.
 *
 * Nothing that wants a call made may wait for it, as a peer that has
 * gone can hold a call for the whole timeout, so the work is a pair of
 * queues under nfsv4_state_lock, and links in the client and the state
 * themselves make queueing an operation that cannot fail or sleep.
 * A few threads take from them.  What they need is copied out, and when
 * the call is over the client and the delegation are looked up again by
 * number, since either may be gone by then.
 *
 * The credential of a callback is what SETCLIENTID came with, s3.3.3.
 * RPCSEC_GSS does not exist here, so no client can have asked for it.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/kauth.h>
#include <sys/kmem.h>
#include <sys/kthread.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <fs/nfsv4/nfsv4_var.h>
#include <fs/nfsv4/nfsv4_state.h>

/*
 * Chosen, not from the RFC.  NFSV4_CB_THREADS is how many callback paths
 * can be stuck at once before the others wait; NFSV4_CB_TIMEO the seconds
 * a call has; NFSV4_CB_RETRY the seconds before a recall that failed is
 * tried again, s10.4.5; NFSV4_CB_REPROBE those before a path found down
 * is tried again.
 */
#define	NFSV4_CB_THREADS	4
#define	NFSV4_CB_TIMEO		5
#define	NFSV4_CB_RETRY		10
#define	NFSV4_CB_REPROBE	30

/* RFC 7531 s2, program NFS4_CALLBACK */
#define	NFSV4_CB_VERSION	1
#define	NFSV4_CB_PROC_NULL	0
#define	NFSV4_CB_PROC_COMPOUND	1

union cb_addr {
	struct sockaddr		ca_sa;
	struct sockaddr_in	ca_in;
	struct sockaddr_in6	ca_in6;
};

/* Who to call: a copy, made under the lock. */
struct cb_target {
	struct nfsv4_clientaddr	ct_addr;
	uint64_t	ct_clientid;
	uint32_t	ct_gen;
	uint32_t	ct_prog;
	uint32_t	ct_ident;
	uint32_t	ct_flavor;
	uid_t		ct_uid;
	gid_t		ct_gid;
	struct nfsv4_session *ct_sess;	/* RFC 8881: held, and its slot */
	uint64_t	ct_conn;
	struct nfsv4_sessionid ct_sid;
	uint32_t	ct_seq;
	uint32_t	ct_vers;
	bool		ct_ref;		/* s20.9.2, on the same session */
	uint32_t	ct_refslot;
	uint32_t	ct_refseq;
};

struct cb_recall_args {
	const struct cb_target *ra_ct;
	uint32_t	ra_ident;
	struct nfsv4_stateid ra_stateid;
	struct nfsv4_fh	ra_fh;
};

/*
 * CB_NOTIFY_LOCK4args, RFC 8881 s20.11.1, or with cn_op of
 * CB_LAYOUTRECALL, the LAYOUTRECALL4_FILE of s20.3.1, or of
 * CB_NOTIFY_DEVICEID, one notify_deviceid_delete4 of s20.12.1, and whom
 * to.
 */
struct cb_notify {
	TAILQ_ENTRY(cb_notify) cn_list;
	const struct cb_target *cn_ct;
	uint32_t	cn_op;
	uint64_t	cn_clientid;
	struct nfsv4_fh	cn_fh;
	uint64_t	cn_other;	/* the layout, by st_other */
	struct nfsv4_stateid cn_stateid;
	uint32_t	cn_ltype;	/* CB_LAYOUTRECALL, the layout's type */
	uint8_t		cn_devid[NFS4_DEVICEID4_SIZE];
	uint32_t	cn_keep;	/* CB_RECALL_ANY4args, s20.6.1 */
	uint32_t	cn_mask;
	bool		cn_refset;	/* s2.10.6.3, as st_refset */
	struct nfsv4_sessionid cn_refsid;
	uint32_t	cn_refslot;
	uint32_t	cn_refseq;
	uint32_t	cn_olen;
	uint8_t		cn_owner[NFS4_OPAQUE_LIMIT];
};
#define	CB_NOTIFY_MAX	64	/* queued at once; chosen, they are hints */

static TAILQ_HEAD(, nfsv4_client) cb_probes;
static TAILQ_HEAD(, nfsv4_state) cb_recalls;
static TAILQ_HEAD(, cb_notify) cb_notifies;
static u_int cb_nnotifies;
static kcondvar_t cb_cv;
static struct lwp *cb_lwps[NFSV4_CB_THREADS];
static bool cb_dying;

/*
 * A dotted number up to the end or to ".", in *pp, moved past it.
 */
static bool
cb_octet(const char **pp, u_int *vp)
{
	const char *p = *pp;
	u_int v = 0;

	if (*p < '0' || *p > '9')
		return false;
	for (; *p >= '0' && *p <= '9'; p++) {
		v = v * 10 + (*p - '0');
		if (v > 255)
			return false;
	}
	*vp = v;
	*pp = p;
	return true;
}

/* The text form of an IPv6 address, RFC 4291 s2.2, without the dotted tail. */
static bool
cb_in6(const char *p, const char *end, struct in6_addr *a)
{
	uint16_t w[8];
	u_int n = 0, gap = 8, i, v, nd;

	memset(w, 0, sizeof(w));
	if (p + 1 < end && p[0] == ':' && p[1] == ':') {
		gap = 0;
		p += 2;
	}
	while (p < end) {
		for (v = 0, nd = 0; p < end && *p != ':'; p++, nd++) {
			u_int d;

			if (*p >= '0' && *p <= '9')
				d = *p - '0';
			else if (*p >= 'a' && *p <= 'f')
				d = *p - 'a' + 10;
			else if (*p >= 'A' && *p <= 'F')
				d = *p - 'A' + 10;
			else
				return false;
			v = v * 16 + d;
			if (nd >= 4)
				return false;
		}
		if (nd == 0 || n >= 8)
			return false;
		w[n++] = (uint16_t)v;
		if (p < end) {
			p++;
			if (p < end && *p == ':') {
				if (gap != 8)
					return false;
				gap = n;
				p++;
			} else if (p == end)
				return false;
		}
	}
	if (gap == 8 && n != 8)
		return false;
	for (i = 0; i < 8; i++)
		a->s6_addr16[i] = 0;
	for (i = 0; i < gap && i < n; i++)
		a->s6_addr16[i] = htons(w[i]);
	for (i = 0; i < n - MIN(gap, n); i++)
		a->s6_addr16[8 - (n - gap) + i] = htons(w[gap + i]);
	return true;
}

/*
 * A clientaddr4, s2.2.10: the universal address of RFC 5665 s5.2.3,
 * with the port as two more decimal numbers at the end.  Only TCP is
 * called, s3.1 asking for a transport with congestion control; a client
 * with none to offer says 0.0.0.0.0.0, and a port of 0 is no address.
 */
static bool
cb_addr_parse(const struct nfsv4_clientaddr *ca, union cb_addr *ua)
{
	char s[NFSV4_NETADDR_MAX + 1];
	const char *p, *dot1, *dot2;
	u_int i, v[4], hi, lo;
	bool tcp4, tcp6;

	tcp4 = ca->ca_netidlen == 3 && memcmp(ca->ca_netid, "tcp", 3) == 0;
	tcp6 = ca->ca_netidlen == 4 && memcmp(ca->ca_netid, "tcp6", 4) == 0;
	if ((!tcp4 && !tcp6) || ca->ca_addrlen > NFSV4_NETADDR_MAX)
		return false;
	memcpy(s, ca->ca_addr, ca->ca_addrlen);
	s[ca->ca_addrlen] = '\0';

	dot2 = strrchr(s, '.');
	if (dot2 == NULL || dot2 == s)
		return false;
	for (dot1 = dot2 - 1; dot1 > s && *dot1 != '.'; dot1--)
		continue;
	if (*dot1 != '.')
		return false;
	p = dot1 + 1;
	if (!cb_octet(&p, &hi) || p != dot2)
		return false;
	p = dot2 + 1;
	if (!cb_octet(&p, &lo) || *p != '\0')
		return false;
	if (hi == 0 && lo == 0)
		return false;

	memset(ua, 0, sizeof(*ua));
	if (tcp4) {
		p = s;
		for (i = 0; i < 4; i++) {
			if (!cb_octet(&p, &v[i]))
				return false;
			if (*p != (i == 3 ? *dot1 : '.'))
				return false;
			if (i < 3)
				p++;
		}
		if (p != dot1)
			return false;
		ua->ca_in.sin_len = sizeof(ua->ca_in);
		ua->ca_in.sin_family = AF_INET;
		ua->ca_in.sin_port = htons(hi << 8 | lo);
		ua->ca_in.sin_addr.s_addr = htonl(v[0] << 24 | v[1] << 16 |
		    v[2] << 8 | v[3]);
		return true;
	}
	if (!cb_in6(s, dot1, &ua->ca_in6.sin6_addr))
		return false;
	ua->ca_in6.sin6_len = sizeof(ua->ca_in6);
	ua->ca_in6.sin6_family = AF_INET6;
	ua->ca_in6.sin6_port = htons(hi << 8 | lo);
	return true;
}

/* RFC 5531 App. A, struct authsys_parms with no name and no groups. */
static u_int
cb_authsys(char *buf, size_t len, uid_t uid, gid_t gid)
{
	uint32_t stamp = (uint32_t)time_second, zero = 0, u = uid, g = gid;
	u_int n;
	XDR x;

	xdrmem_create(&x, buf, len, XDR_ENCODE);
	(void)(xdr_u_int32_t(&x, &stamp) && xdr_u_int32_t(&x, &zero) &&
	    xdr_u_int32_t(&x, &u) && xdr_u_int32_t(&x, &g) &&
	    xdr_u_int32_t(&x, &zero));
	n = xdr_getpos(&x);
	return n;
}

/*
 * CB_COMPOUND4args up to the one operation that matters, s17.2.2.  RFC
 * 8881 s18.36.3 has minor version 1, and s20.9 a CB_SEQUENCE first, with
 * the call that a recall may overtake, s2.10.6.3.
 */
static bool
cb_head(XDR *x, const struct cb_target *ct, uint32_t ident)
{
	uint32_t zero = 0, one = 1, two = 2, seqop = NFSV4_OP_CB_SEQUENCE;
	uint32_t seq = ct->ct_seq;
	struct nfsv4_sessionid sid = ct->ct_sid;

	if (ct->ct_sess == NULL)
		return xdr_u_int32_t(x, &zero) &&	/* tag */
		    xdr_u_int32_t(x, &zero) &&		/* minorversion */
		    xdr_u_int32_t(x, &ident) &&		/* s17.2.4 */
		    xdr_u_int32_t(x, &one);
	return xdr_u_int32_t(x, &zero) && xdr_u_int32_t(x, &one) &&
	    xdr_u_int32_t(x, &zero) && xdr_u_int32_t(x, &two) &&
	    xdr_u_int32_t(x, &seqop) && nfsv4_xdr_sessionid(x, &sid) &&
	    xdr_u_int32_t(x, &seq) &&
	    xdr_u_int32_t(x, &zero) &&		/* csa_slotid */
	    xdr_u_int32_t(x, &zero) &&		/* csa_highest_slotid */
	    xdr_u_int32_t(x, &zero) &&		/* csa_cachethis */
	    (!ct->ct_ref ? xdr_u_int32_t(x, &zero) :
	    xdr_u_int32_t(x, &one) && nfsv4_xdr_sessionid(x, &sid) &&
	    xdr_u_int32_t(x, &one) &&
	    xdr_u_int32_t(x, __UNCONST(&ct->ct_refseq)) &&
	    xdr_u_int32_t(x, __UNCONST(&ct->ct_refslot)));
}

/* CB_COMPOUND4args, s17.2.2, of the one operation that is used here. */
static bool
cb_recall_encode(XDR *x, void *arg)
{
	struct cb_recall_args *ra = arg;
	const struct cb_target *ct = ra->ra_ct;
	uint32_t zero = 0, op = NFSV4_OP_CB_RECALL;

	if (!cb_head(x, ct, ra->ra_ident))
		return false;
	return xdr_u_int32_t(x, &op) &&
	    nfsv4_xdr_stateid(x, &ra->ra_stateid) &&
	    xdr_u_int32_t(x, &zero) &&		/* truncate, s18.2.4 */
	    nfsv4_xdr_fh(x, &ra->ra_fh);
}

/* CB_COMPOUND4args of CB_NOTIFY_LOCK, RFC 8881 s20.11.1. */
static bool
cb_notify_encode(XDR *x, void *arg)
{
	struct cb_notify *cn = arg;
	uint32_t op = cn->cn_op, zero = 0;
	uint32_t type = cn->cn_ltype, any = LAYOUTIOMODE4_ANY;
	uint32_t file = LAYOUT4_RET_REC_FILE;
	uint64_t len = UINT64_MAX;

	/* s20.6.1, s20.7.1: a bitmap4 of one word, bits up to 17 */
	if (op == NFSV4_OP_CB_RECALL_ANY ||
	    op == NFSV4_OP_CB_RECALLABLE_OBJ_AVAIL)
		return cb_head(x, cn->cn_ct, 0) && xdr_u_int32_t(x, &op) &&
		    xdr_u_int32_t(x, &cn->cn_keep) &&
		    xdr_u_int32_t(x, &(uint32_t){ 1 }) &&
		    xdr_u_int32_t(x, &cn->cn_mask);
	/* s20.12.1: cnda_changes<1>, a bitmap4 of one word and the value */
	if (op == NFSV4_OP_CB_NOTIFY_DEVICEID)
		return cb_head(x, cn->cn_ct, 0) && xdr_u_int32_t(x, &op) &&
		    xdr_u_int32_t(x, &(uint32_t){ 1 }) &&
		    xdr_u_int32_t(x, &(uint32_t){ 1 }) &&
		    xdr_u_int32_t(x,
		    &(uint32_t){ 1U << NOTIFY_DEVICEID4_DELETE }) &&
		    xdr_u_int32_t(x, &(uint32_t){ 4 + NFS4_DEVICEID4_SIZE }) &&
		    xdr_u_int32_t(x, &type) &&
		    XDR_PUTBYTES(x, (char *)cn->cn_devid, NFS4_DEVICEID4_SIZE);
	/* s20.3.1: all of the file, of any mode; not changed, s20.3.3. */
	if (op == NFSV4_OP_CB_LAYOUTRECALL)
		return cb_head(x, cn->cn_ct, 0) && xdr_u_int32_t(x, &op) &&
		    xdr_u_int32_t(x, &type) && xdr_u_int32_t(x, &any) &&
		    xdr_u_int32_t(x, &zero) && xdr_u_int32_t(x, &file) &&
		    nfsv4_xdr_fh(x, &cn->cn_fh) &&
		    xdr_u_int64_t(x, &(uint64_t){ 0 }) &&
		    xdr_u_int64_t(x, &len) &&
		    nfsv4_xdr_stateid(x, &cn->cn_stateid);
	return cb_head(x, cn->cn_ct, 0) && xdr_u_int32_t(x, &op) &&
	    nfsv4_xdr_fh(x, &cn->cn_fh) &&
	    xdr_u_int64_t(x, &cn->cn_clientid) &&
	    xdr_bytes(x, &(char *){ (char *)cn->cn_owner }, &cn->cn_olen,
	    NFS4_OPAQUE_LIMIT);
}

/* All that matters of CB_COMPOUND4res is the status, s17.2.4. */
static bool
cb_status_decode(XDR *x, void *res)
{

	return xdr_u_int32_t(x, (uint32_t *)res);
}

struct cb_getattr {
	const struct cb_target *ga_ct;
	uint32_t	ga_ident;
	struct nfsv4_fh	ga_fh;
	uint64_t	ga_size;
	uint64_t	ga_change;
	bool		ga_got;
};

/* CB_COMPOUND4args of one CB_GETATTR, s18.1, of change and size. */
static bool
cb_getattr_encode(XDR *x, void *arg)
{
	struct cb_getattr *ga = arg;
	uint32_t one = 1, op = NFSV4_OP_CB_GETATTR;
	uint32_t mask = (1U << FATTR4_CHANGE) | (1U << FATTR4_SIZE);

	if (!cb_head(x, ga->ga_ct, ga->ga_ident))
		return false;
	return xdr_u_int32_t(x, &op) && nfsv4_xdr_fh(x, &ga->ga_fh) &&
	    xdr_u_int32_t(x, &one) && xdr_u_int32_t(x, &mask);
}

/* CB_COMPOUND4res, s17.2.3, with CB_GETATTR4res, s18.1.3. */
static bool
cb_getattr_decode(XDR *x, void *res)
{
	struct cb_getattr *ga = res;
	struct nfsv4_bitmap bm;
	uint32_t status, n, op, len, opst;

	if (!xdr_u_int32_t(x, &status) || !xdr_u_int32_t(x, &n) ||
	    !nfsv4_xdr_skip(x, n) || !xdr_u_int32_t(x, &n))
		return false;
	/*
	 * Version 4.1 has CB_SEQUENCE first, s20.9; its CB_SEQUENCE4resok
	 * is a sessionid4 and four counters, s20.9.2.  Expecting one result
	 * only, as before, failed every CB_GETATTR to such a client, and
	 * the GETATTR that asked fell back to a recall.
	 */
	if (status != NFS4_OK || n != (ga->ga_ct->ct_sess != NULL ? 2 : 1))
		return true;
	if (ga->ga_ct->ct_sess != NULL &&
	    (!xdr_u_int32_t(x, &op) || !xdr_u_int32_t(x, &opst) ||
	    op != NFSV4_OP_CB_SEQUENCE || opst != NFS4_OK ||
	    !nfsv4_xdr_skip(x, NFS4_SESSIONID_SIZE + 4 * 4)))
		return false;
	if (!xdr_u_int32_t(x, &op) || !xdr_u_int32_t(x, &opst) ||
	    op != NFSV4_OP_CB_GETATTR || opst != NFS4_OK ||
	    !nfsv4_xdr_bitmap(x, &bm) || !xdr_u_int32_t(x, &len))
		return false;
	if (bm.bm_n < 1 || bm.bm_w[0] != ((1U << FATTR4_CHANGE) |
	    (1U << FATTR4_SIZE)) || len != 16)
		return false;
	ga->ga_got = xdr_u_int64_t(x, &ga->ga_change) &&
	    xdr_u_int64_t(x, &ga->ga_size);
	return ga->ga_got;
}

static int
cb_call(const struct cb_target *ct, uint32_t proc,
    bool (*enc)(XDR *, void *), void *arg, bool (*dec)(XDR *, void *),
    void *res)
{
	struct oncrpc_clnt_call cc;
	union cb_addr ua;
	char cred[ONCRPC_MAX_AUTH_BYTES];

	if (ct->ct_sess == NULL && !cb_addr_parse(&ct->ct_addr, &ua))
		return EADDRNOTAVAIL;
	memset(&cc, 0, sizeof(cc));
	cc.cc_prog = ct->ct_prog;
	cc.cc_vers = ct->ct_vers;
	cc.cc_proc = proc;
	cc.cc_flavor = ct->ct_flavor;
	if (ct->ct_flavor == ONCRPC_AUTH_SYS) {
		cc.cc_cred = cred;
		cc.cc_credlen = cb_authsys(cred, sizeof(cred), ct->ct_uid,
		    ct->ct_gid);
	}
	cc.cc_encode = enc;
	cc.cc_arg = arg;
	cc.cc_decode = dec;
	cc.cc_res = res;
	if (ct->ct_sess != NULL)
		return nfsv4_conn_call(ct->ct_conn, &cc, NFSV4_CB_TIMEO);
	return oncrpc_clnt_call(&ua.ca_sa, &cc, NFSV4_CB_TIMEO);
}

/* False for a client of version 4.1 with no backchannel free. */
static bool
cb_target_get(struct nfsv4_client *cl, struct cb_target *ct)
{
	struct nfsv4_session *se;

	ct->ct_addr = cl->cl_cb;
	ct->ct_clientid = cl->cl_id;
	ct->ct_gen = cl->cl_cbgen;
	ct->ct_prog = cl->cl_cbprog;
	ct->ct_ident = cl->cl_cbident;
	ct->ct_flavor = cl->cl_flavor;
	ct->ct_uid = cl->cl_uid;
	ct->ct_gid = cl->cl_gid;
	ct->ct_sess = NULL;
	ct->ct_ref = false;
	ct->ct_vers = NFSV4_CB_VERSION;
	if (cl->cl_minor == 0)
		return true;
	se = nfsv4_session_cbget(cl, &ct->ct_conn);
	if (se == NULL)
		return false;
	ct->ct_sess = se;
	ct->ct_sid = se->se_id;
	ct->ct_seq = se->se_cbseq;
	ct->ct_vers = se->se_cbvers;
	ct->ct_prog = se->se_cbprog;
	ct->ct_flavor = se->se_cbsec.cs_flavor;
	ct->ct_uid = se->se_cbsec.cs_uid;
	ct->ct_gid = se->se_cbsec.cs_gid;
	return true;
}

static void
cb_target_put(struct cb_target *ct, int error)
{

	if (ct->ct_sess != NULL)
		nfsv4_session_cbdone(ct->ct_sess, error == 0);
}

/* What became of a call to the client of ct. */
static void
cb_path(const struct cb_target *ct, bool up)
{
	struct nfsv4_client *cl;

	cl = nfsv4_client_byid(ct->ct_clientid);
	if (cl == NULL || cl->cl_cbgen != ct->ct_gen)
		return;
	cl->cl_cbstate = up ? NFSV4_CB_UP : NFSV4_CB_DOWN;
	cl->cl_cbnext = time_uptime + NFSV4_CB_REPROBE;
}

static void
cb_do_probe(struct nfsv4_client *cl)
{
	struct cb_target ct;
	int error;

	if (!cb_target_get(cl, &ct)) {
		cl->cl_cbnext = time_uptime + NFSV4_CB_REPROBE;
		cl->cl_cbstate = nfsv4_session_cbany(cl) ? NFSV4_CB_UP :
		    NFSV4_CB_DOWN;
		return;
	}
	mutex_exit(&nfsv4_state_lock);
	error = cb_call(&ct, NFSV4_CB_PROC_NULL, NULL, NULL, NULL, NULL);
	/* RFC 8881 s18.36.3: version 4, and what is tried first. */
	if (error == EPROTO && ct.ct_sess != NULL && nfsv4_cb_vers1) {
		ct.ct_vers = NFSV4_CB_VERSION;
		error = cb_call(&ct, NFSV4_CB_PROC_NULL, NULL, NULL, NULL,
		    NULL);
		if (error == 0)
			ct.ct_sess->se_cbvers = ct.ct_vers;
	}
	mutex_enter(&nfsv4_state_lock);
	/* Nothing in CB_NULL is sequenced. */
	cb_target_put(&ct, EAGAIN);
	cb_path(&ct, error == 0);
}

/*
 * vfs.nfsv4.cb_vers1, from the option NFSV4_CB_VERS1 (see the module's
 * Makefile).  Deliberately on: s18.36.3 has the server call back with
 * version 4 and nothing else, but the XDR of RFC 5662 has "version NFS_CB
 * = 1", and a client that followed it refuses 4 with PROG_MISMATCH and
 * would never get a callback.  On, that refusal makes the session use 1
 * from then on.  Without the option, or with 0 here, only 4 is sent, and
 * such a client has no backchannel, as the RFC has it.
 */
#ifdef NFSV4_CB_VERS1
int nfsv4_cb_vers1 = 1;
#else
int nfsv4_cb_vers1 = 0;
#endif

static void
cb_do_recall(struct nfsv4_state *st)
{
	struct cb_recall_args ra;
	struct cb_target ct;
	uint64_t other = st->st_other;
	uint32_t status = NFS4ERR_RESOURCE;
	int error;

	if (!cb_target_get(st->st_owner->sw_client, &ct)) {
		st->st_cbnext = time_uptime + NFSV4_CB_RETRY;
		return;
	}
	ra.ra_ct = &ct;
	ra.ra_ident = ct.ct_ident;
	nfsv4_stateid_out(st, &ra.ra_stateid);
	/* RFC 8881 s8.2.2: what a callback carries has seqid 0. */
	if (st->st_owner->sw_client->cl_minor != 0)
		ra.ra_stateid.si_seqid = 0;
	/*
	 * s2.10.6.3: while the slot has seen no later request the client
	 * may not have the reply that gave it this.  Calls come by way of
	 * one session, and the others' replies are not looked for.
	 */
	if (ct.ct_sess != NULL && st->st_refset &&
	    memcmp(&st->st_refsid, &ct.ct_sid, sizeof(ct.ct_sid)) == 0 &&
	    ct.ct_sess->se_slots[st->st_refslot].sl_seq == st->st_refseq) {
		ct.ct_ref = true;
		ct.ct_refslot = st->st_refslot;
		ct.ct_refseq = st->st_refseq;
	}
	ra.ra_fh = st->st_file->f_fh;
	mutex_exit(&nfsv4_state_lock);
	error = cb_call(&ct, NFSV4_CB_PROC_COMPOUND, cb_recall_encode, &ra,
	    cb_status_decode, &status);
	mutex_enter(&nfsv4_state_lock);
	cb_target_put(&ct, error);

	/* s10.2: a reply of any kind says that the path works. */
	cb_path(&ct, error == 0);
	st = nfsv4_state_byother(other);
	if (st == NULL || st->st_file == NULL)
		return;
	/*
	 * s18.2.5: an error ends the recall, but for s10.4.5's
	 * NFS4ERR_BADHANDLE, and any other client reply than success is
	 * not worth telling from that one: the delegation stays out until
	 * it is returned or the time is up, and asking again costs little.
	 */
	if (error == 0 && status == NFS4_OK)
		st->st_cbnext = 0;
	else {
		st->st_cbnext = time_uptime + NFSV4_CB_RETRY;
		/* s10.4.5: the client is not to pay for the race. */
		if (error == 0)
			nfsv4_client_renew(st->st_owner->sw_client);
	}
}

/*
 * One CB_NOTIFY_LOCK.  A hint: whatever comes of it, nothing is tried
 * again (s20.11.4), but a reply still says whether the path works.
 */
static void
cb_do_notify(struct cb_notify *cn)
{
	struct nfsv4_client *cl;
	struct cb_target ct;
	struct nfsv4_reap reap;
	uint32_t status = NFS4_OK;
	int error;

	cl = nfsv4_client_byid(cn->cn_clientid);
	if (cl == NULL || cl->cl_minor == 0 || !cb_target_get(cl, &ct))
		return;
	cn->cn_ct = &ct;
	/* s2.10.6.3, as for CB_RECALL in cb_do_recall(). */
	if (cn->cn_op == NFSV4_OP_CB_LAYOUTRECALL && ct.ct_sess != NULL &&
	    cn->cn_refset &&
	    memcmp(&cn->cn_refsid, &ct.ct_sid, sizeof(ct.ct_sid)) == 0 &&
	    ct.ct_sess->se_slots[cn->cn_refslot].sl_seq == cn->cn_refseq) {
		ct.ct_ref = true;
		ct.ct_refslot = cn->cn_refslot;
		ct.ct_refseq = cn->cn_refseq;
	}
	mutex_exit(&nfsv4_state_lock);
	error = cb_call(&ct, NFSV4_CB_PROC_COMPOUND, cb_notify_encode, cn,
	    cb_status_decode, &status);
	mutex_enter(&nfsv4_state_lock);
	cb_target_put(&ct, error);
	cb_path(&ct, error == 0);
	if (cn->cn_op == NFSV4_OP_CB_LAYOUTRECALL) {
		SLIST_INIT(&reap);
		nfsv4_layout_recalled(cn->cn_other, error, status, &reap);
		mutex_exit(&nfsv4_state_lock);
		nfsv4_reap_finish(&reap);
		mutex_enter(&nfsv4_state_lock);
	}
}

static void
cb_thread(void *arg)
{
	struct nfsv4_client *cl;
	struct nfsv4_state *st;
	struct cb_notify *cn;

	mutex_enter(&nfsv4_state_lock);
	for (;;) {
		cl = TAILQ_FIRST(&cb_probes);
		st = TAILQ_FIRST(&cb_recalls);
		cn = TAILQ_FIRST(&cb_notifies);
		if (cl == NULL && st == NULL && cn == NULL) {
			if (cb_dying)
				break;
			cv_wait(&cb_cv, &nfsv4_state_lock);
			continue;
		}
		if (cb_dying)
			break;
		if (st != NULL) {
			TAILQ_REMOVE(&cb_recalls, st, st_cbq);
			st->st_cbqueued = false;
			cb_do_recall(st);
		} else if (cn != NULL) {
			TAILQ_REMOVE(&cb_notifies, cn, cn_list);
			cb_nnotifies--;
			cb_do_notify(cn);
			mutex_exit(&nfsv4_state_lock);
			kmem_free(cn, sizeof(*cn));
			mutex_enter(&nfsv4_state_lock);
		} else {
			TAILQ_REMOVE(&cb_probes, cl, cl_cbq);
			cl->cl_cbqueued = false;
			cb_do_probe(cl);
		}
	}
	mutex_exit(&nfsv4_state_lock);
	kthread_exit(0);
}

/*
 * Ask cl about the file of fh.  The caller holds the lock, which is
 * dropped for the call: 0 and the two values, or an errno.  cl may be
 * gone on return.
 */
int
nfsv4_cb_getattr(const struct nfsv4_client *cl, const struct nfsv4_fh *fh,
    uint64_t *sizep, uint64_t *changep)
{
	struct cb_target ct;
	struct cb_getattr *ga;
	int error;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if (!cb_target_get(__UNCONST(cl), &ct))
		return EAGAIN;
	mutex_exit(&nfsv4_state_lock);
	ga = kmem_zalloc(sizeof(*ga), KM_SLEEP);
	ga->ga_ct = &ct;
	ga->ga_ident = ct.ct_ident;
	ga->ga_fh = *fh;
	error = cb_call(&ct, NFSV4_CB_PROC_COMPOUND, cb_getattr_encode, ga,
	    cb_getattr_decode, ga);
	if (error == 0 && !ga->ga_got)
		error = EIO;
	if (error == 0) {
		*sizep = ga->ga_size;
		*changep = ga->ga_change;
	}
	kmem_free(ga, sizeof(*ga));
	mutex_enter(&nfsv4_state_lock);
	cb_target_put(&ct, error);
	return error;
}

/* Find out whether cl can be called, s10.2. */
void
nfsv4_cb_probe(struct nfsv4_client *cl)
{

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if (cl->cl_cbqueued)
		return;
	cl->cl_cbqueued = true;
	cl->cl_cbnext = time_uptime + NFSV4_CB_REPROBE;
	TAILQ_INSERT_TAIL(&cb_probes, cl, cl_cbq);
	if (!cb_dying)
		cv_signal(&cb_cv);
}

/* The callback information of cl has changed, s16.34. */
void
nfsv4_cb_reset(struct nfsv4_client *cl)
{

	KASSERT(mutex_owned(&nfsv4_state_lock));

	cl->cl_cbstate = NFSV4_CB_UNKNOWN;
	cl->cl_cbgen++;
	nfsv4_cb_probe(cl);
}

void
nfsv4_cb_recall(struct nfsv4_state *st)
{

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if (st->st_cbqueued)
		return;
	st->st_cbqueued = true;
	st->st_cbnext = 0;
	TAILQ_INSERT_TAIL(&cb_recalls, st, st_cbq);
	if (!cb_dying)
		cv_signal(&cb_cv);
}

/* RFC 8881 s20.11: lw may be able to have its lock on the file of fh. */
void
nfsv4_cb_notify_lock(const struct nfsv4_lockwait *lw,
    const struct nfsv4_fh *fh)
{
	struct cb_notify *cn;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if (cb_dying || cb_nnotifies >= CB_NOTIFY_MAX)
		return;
	cn = kmem_zalloc(sizeof(*cn), KM_NOSLEEP);
	if (cn == NULL)
		return;
	cn->cn_op = NFSV4_OP_CB_NOTIFY_LOCK;
	cn->cn_clientid = lw->lw_clientid;
	cn->cn_fh = *fh;
	cn->cn_olen = lw->lw_olen;
	memcpy(cn->cn_owner, lw->lw_owner, lw->lw_olen);
	TAILQ_INSERT_TAIL(&cb_notifies, cn, cn_list);
	cb_nnotifies++;
	cv_signal(&cb_cv);
}

/*
 * RFC 8881 s20.3: recall the layout st, whose seqid has been moved on.
 * Queued as the notifications are, but not dropped for their bound.
 */
bool
nfsv4_cb_layoutrecall(struct nfsv4_state *st)
{
	struct cb_notify *cn;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if (cb_dying)
		return false;
	cn = kmem_zalloc(sizeof(*cn), KM_NOSLEEP);
	if (cn == NULL)
		return false;
	cn->cn_op = NFSV4_OP_CB_LAYOUTRECALL;
	cn->cn_clientid = st->st_owner->sw_client->cl_id;
	cn->cn_fh = st->st_file->f_fh;
	cn->cn_other = st->st_other;
	cn->cn_ltype = st->st_ltype;
	cn->cn_refset = st->st_refset;
	cn->cn_refsid = st->st_refsid;
	cn->cn_refslot = st->st_refslot;
	cn->cn_refseq = st->st_refseq;
	nfsv4_stateid_out(st, &cn->cn_stateid);
	TAILQ_INSERT_TAIL(&cb_notifies, cn, cn_list);
	cb_nnotifies++;
	cv_signal(&cb_cv);
	return true;
}

/*
 * RFC 8881 s20.12: the device ID id of type is deleted.  A notification,
 * queued and bounded as the others.
 */
void
nfsv4_cb_notify_deviceid(const struct nfsv4_client *cl, uint32_t type,
    const uint8_t *id)
{
	struct cb_notify *cn;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if (cb_dying || cb_nnotifies >= CB_NOTIFY_MAX)
		return;
	cn = kmem_zalloc(sizeof(*cn), KM_NOSLEEP);
	if (cn == NULL)
		return;
	cn->cn_op = NFSV4_OP_CB_NOTIFY_DEVICEID;
	cn->cn_clientid = cl->cl_id;
	cn->cn_ltype = type;
	memcpy(cn->cn_devid, id, NFS4_DEVICEID4_SIZE);
	TAILQ_INSERT_TAIL(&cb_notifies, cn, cn_list);
	cb_nnotifies++;
	cv_signal(&cb_cv);
}

/*
 * RFC 8881 s20.6, CB_RECALL_ANY, or s20.7, CB_RECALLABLE_OBJ_AVAIL, as
 * op, with craa_objects_to_keep keep and craa_type_mask mask.
 */
void
nfsv4_cb_recall_any(const struct nfsv4_client *cl, uint32_t op,
    uint32_t keep, uint32_t mask)
{
	struct cb_notify *cn;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if (cb_dying || cb_nnotifies >= CB_NOTIFY_MAX || cl->cl_minor == 0)
		return;
	cn = kmem_zalloc(sizeof(*cn), KM_NOSLEEP);
	if (cn == NULL)
		return;
	cn->cn_op = op;
	cn->cn_clientid = cl->cl_id;
	cn->cn_keep = keep;
	cn->cn_mask = mask;
	TAILQ_INSERT_TAIL(&cb_notifies, cn, cn_list);
	cb_nnotifies++;
	cv_signal(&cb_cv);
}

void
nfsv4_cb_forget_client(struct nfsv4_client *cl)
{

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if (cl->cl_cbqueued) {
		TAILQ_REMOVE(&cb_probes, cl, cl_cbq);
		cl->cl_cbqueued = false;
	}
}

void
nfsv4_cb_forget_state(struct nfsv4_state *st)
{

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if (st->st_cbqueued) {
		TAILQ_REMOVE(&cb_recalls, st, st_cbq);
		st->st_cbqueued = false;
	}
}

void
nfsv4_cb_init(void)
{
	u_int i;

	TAILQ_INIT(&cb_probes);
	TAILQ_INIT(&cb_recalls);
	TAILQ_INIT(&cb_notifies);
	cb_nnotifies = 0;
	cv_init(&cb_cv, "nfsv4cb");
	cb_dying = false;
	for (i = 0; i < NFSV4_CB_THREADS; i++) {
		if (kthread_create(PRI_NONE, KTHREAD_MPSAFE | KTHREAD_MUSTJOIN,
		    NULL, cb_thread, NULL, &cb_lwps[i], "nfsv4cb/%u", i) != 0)
			panic("nfsv4_cb_init: kthread_create");
	}
}

void
nfsv4_cb_fini(void)
{
	struct cb_notify *cn;
	u_int i;

	mutex_enter(&nfsv4_state_lock);
	cb_dying = true;
	cv_broadcast(&cb_cv);
	mutex_exit(&nfsv4_state_lock);
	for (i = 0; i < NFSV4_CB_THREADS; i++)
		kthread_join(cb_lwps[i]);
	while ((cn = TAILQ_FIRST(&cb_notifies)) != NULL) {
		TAILQ_REMOVE(&cb_notifies, cn, cn_list);
		kmem_free(cn, sizeof(*cn));
	}
	cv_destroy(&cb_cv);
}
