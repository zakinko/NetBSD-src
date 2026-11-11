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

#include <oncrpc/oncrpc_gss.h>

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
	uint32_t	ct_service;
	char		ct_principal[NFSV4_PRINCIPAL_MAX];
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

static TAILQ_HEAD(, nfsv4_client) cb_probes;
static TAILQ_HEAD(, nfsv4_state) cb_recalls;
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
	if (status != NFS4_OK || n != 1)
		return true;
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
	struct oncrpc_gssc *gc = NULL;
	int error;

	if (ct->ct_sess == NULL && !cb_addr_parse(&ct->ct_addr, &ua))
		return EADDRNOTAVAIL;
	/*
	 * RFC 7530 s3.3.3: the flavor of SETCLIENTID, to the principal
	 * that used it, with the server authenticated in return.  One
	 * context to a call; these are rare, and the client may be gone.
	 * A session's backchannel has the client's own contexts, RFC 8881
	 * s2.10.8.2, and is not this.
	 */
	if (ct->ct_sess == NULL && ct->ct_flavor == RPCSEC_GSS) {
		error = oncrpc_gssc_create(&ua.ca_sa, ct->ct_prog,
		    ct->ct_vers, ct->ct_principal, ct->ct_service,
		    NFSV4_CB_TIMEO, &gc);
		if (error != 0)
			return error;
	}
	memset(&cc, 0, sizeof(cc));
	cc.cc_prog = ct->ct_prog;
	cc.cc_vers = ct->ct_vers;
	cc.cc_proc = proc;
	cc.cc_flavor = ct->ct_flavor;
	cc.cc_gss = gc;
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
	error = oncrpc_clnt_call(&ua.ca_sa, &cc, NFSV4_CB_TIMEO);
	if (gc != NULL)
		oncrpc_gssc_close(&ua.ca_sa, ct->ct_prog, NFSV4_CB_VERSION, gc,
		    NFSV4_CB_TIMEO);
	return error;
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
	ct->ct_service = cl->cl_cbservice;
	strlcpy(ct->ct_principal, cl->cl_principal, sizeof(ct->ct_principal));
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
	/*
	 * RFC 8881 s18.36.3 says version 4, and is what is tried, but the
	 * XDR of RFC 5662 has "version NFS_CB = 1": a client may have
	 * followed that, and refuse the other with PROG_MISMATCH.
	 */
	if (error == EPROTO && ct.ct_sess != NULL) {
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

static void
cb_thread(void *arg)
{
	struct nfsv4_client *cl;
	struct nfsv4_state *st;

	mutex_enter(&nfsv4_state_lock);
	for (;;) {
		cl = TAILQ_FIRST(&cb_probes);
		st = TAILQ_FIRST(&cb_recalls);
		if (cl == NULL && st == NULL) {
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
	u_int i;

	mutex_enter(&nfsv4_state_lock);
	cb_dying = true;
	cv_broadcast(&cb_cv);
	mutex_exit(&nfsv4_state_lock);
	for (i = 0; i < NFSV4_CB_THREADS; i++)
		kthread_join(cb_lwps[i]);
	cv_destroy(&cb_cv);
}
