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
 * Client IDs and sessions of version 4.1, RFC 8881 s2.10 and s18.33 to
 * s18.51.  The lock is nfsv4_state_lock, as for the rest of the state;
 * see nfsv4_state.h.
 *
 * The reply cache is the slot table, s2.10.6.1: a COMPOUND holds its slot
 * from SEQUENCE to its end, with a reference on the session and on the
 * client, and the DRC of nfsv4_drc.c never sees one.  A session is kept
 * in memory until the last COMPOUND on it ends, but goes from the table
 * as soon as it is destroyed.
 *
 * The backchannel is the connections bound to it, and calls go out on
 * them by nfsv4_cb.c.  It has one slot, so one call at a time, whatever
 * the client offered: the server's choice among ca_maxrequests slots.
 *
 * The state protection of s2.10.8.3 needs RPCSEC_GSS, which the RPC layer
 * does not have, so only SP4_NONE is accepted.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/kauth.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/lockf.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/vnode.h>

#include <oncrpc/oncrpc_gss.h>
#include <oncrpc/oncrpc_xdr.h>

#include <fs/nfsv4/nfsv4_var.h>
#include <fs/nfsv4/nfsv4_state.h>

/*
 * All chosen, none from the RFC.  NFSV4_SES_SLOTS is what ca_maxrequests
 * is cut to, the most calls oncrpc takes at once from a connection.
 * NFSV4_SES_MAXMSG leaves a reply room under NFSV4_RES_LIMIT with a
 * READ of NFSV4_MAXIO in it.  NFSV4_SES_MAXCACHED has to hold what a
 * non-idempotent COMPOUND returns, with a GETATTR.  NFSV4_SES_MINMSG is
 * below which no COMPOUND with a SEQUENCE and something else would fit.
 * NFSV4_SES_BUDGET bounds what all reply caches can come to.
 */
#define	NFSV4_SES_SLOTS		64
#define	NFSV4_SES_MAXOPS	128
#define	NFSV4_SES_MAXMSG	(512 * 1024)
#define	NFSV4_SES_MAXCACHED	8192
#define	NFSV4_SES_MINMSG	256
#define	NFSV4_SES_BUDGET	(64 * 1024 * 1024)
#define	NFSV4_SES_HASH		64

/*
 * A COMPOUND with a SEQUENCE alone and no tag, RFC 8881 s16.2.2 and
 * s18.46.2: status, tag length, count, the operation and its status, then
 * the session ID and five words.
 */
#define	NFSV4_SEQ_REPLYLEN	(5 * 4 + NFS4_SESSIONID_SIZE + 5 * 4)

/* s18.35.1, those defined for eia_flags */
#define	EXCHGID4_ARG_FLAGS	\
	(EXCHGID4_FLAG_SUPP_MOVED_REFER | EXCHGID4_FLAG_SUPP_MOVED_MIGR | \
	 EXCHGID4_FLAG_BIND_PRINC_STATEID | EXCHGID4_FLAG_USE_NON_PNFS | \
	 EXCHGID4_FLAG_USE_PNFS_MDS | EXCHGID4_FLAG_USE_PNFS_DS | \
	 EXCHGID4_FLAG_UPD_CONFIRMED_REC_A)

/* s18.36.1 */
#define	CREATE_SESSION4_FLAGS	\
	(CREATE_SESSION4_FLAG_PERSIST | CREATE_SESSION4_FLAG_CONN_BACK_CHAN | \
	 CREATE_SESSION4_FLAG_CONN_RDMA)

/* A choice, like the bound on them. */
char nfsv4_impl_domain[NFSV4_IMPL_MAX] = "netbsd.org";
char nfsv4_impl_name[NFSV4_IMPL_MAX] = "NetBSD NFSv4 server";

static LIST_HEAD(, nfsv4_session) nfsv4_ses_hash[NFSV4_SES_HASH];
static size_t nfsv4_ses_cost;
static uint64_t nfsv4_ses_counter;

void
nfsv4_session_init(void)
{
	u_int i;

	for (i = 0; i < NFSV4_SES_HASH; i++)
		LIST_INIT(&nfsv4_ses_hash[i]);
	nfsv4_ses_cost = 0;
	nfsv4_ses_counter = 0;
}

/* Every client is gone, and so every session. */
void
nfsv4_session_fini(void)
{

	KASSERT(nfsv4_ses_cost == 0);
}

static inline u_int
session_hash(const struct nfsv4_sessionid *sid)
{

	return be64dec(sid->sid_data + 4) & (NFSV4_SES_HASH - 1);
}

static inline size_t
session_size(uint32_t nslots)
{

	return offsetof(struct nfsv4_session, se_slots[nslots]);
}

static struct nfsv4_session *
session_find(const struct nfsv4_sessionid *sid)
{
	struct nfsv4_session *se;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	LIST_FOREACH(se, &nfsv4_ses_hash[session_hash(sid)], se_hash) {
		if (memcmp(&se->se_id, sid, sizeof(*sid)) == 0)
			return se;
	}
	return NULL;
}

static void
session_rele(struct nfsv4_session *se)
{
	uint32_t i;

	KASSERT(mutex_owned(&nfsv4_state_lock));
	KASSERT(se->se_refs > 0);

	if (--se->se_refs != 0)
		return;
	KASSERT(se->se_gone);
	for (i = 0; i < se->se_nslots; i++) {
		if (se->se_slots[i].sl_reply != NULL)
			kmem_free(se->se_slots[i].sl_reply,
			    se->se_slots[i].sl_len);
	}
	nfsv4_ses_cost -= se->se_cost;
	kmem_free(se, se->se_size);
}

/* Take a session from the table, for what comes next. */
static void
session_drop(struct nfsv4_session *se)
{

	KASSERT(mutex_owned(&nfsv4_state_lock));

	se->se_gone = true;
	LIST_REMOVE(se, se_hash);
	LIST_REMOVE(se, se_list);
	session_rele(se);
}

void
nfsv4_session_drop_all(struct nfsv4_client *cl)
{
	struct nfsv4_session *se;

	while ((se = LIST_FIRST(&cl->cl_sessions)) != NULL)
		session_drop(se);
}

static struct nfsv4_sesconn *
session_conn(struct nfsv4_session *se, uint64_t id)
{
	u_int i;

	for (i = 0; i < se->se_nconn; i++) {
		if (se->se_conns[i].sc_id == id)
			return &se->se_conns[i];
	}
	return NULL;
}

/* Is a live connection bound to the backchannel of se.  Forget dead ones. */
static uint64_t
session_cbconn(struct nfsv4_session *se)
{
	u_int i, n = 0;
	uint64_t id = 0;

	for (i = 0; i < se->se_nconn; i++) {
		if (!nfsv4_conn_alive(se->se_conns[i].sc_id))
			continue;
		/* s2.10.8.2: with no flavor offered, no call can be made. */
		if ((se->se_conns[i].sc_dir & CDFS4_BACK) != 0 && id == 0 &&
		    se->se_cbsec.cs_any)
			id = se->se_conns[i].sc_id;
		se->se_conns[n++] = se->se_conns[i];
	}
	se->se_nconn = n;
	return id;
}

/* A session of cl to call on, made busy, and its connection in *idp. */
struct nfsv4_session *
nfsv4_session_cbget(struct nfsv4_client *cl, uint64_t *idp)
{
	struct nfsv4_session *se;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	LIST_FOREACH(se, &cl->cl_sessions, se_list) {
		if (!se->se_cbbusy && (*idp = session_cbconn(se)) != 0) {
			se->se_cbbusy = true;
			se->se_refs++;
			return se;
		}
	}
	return NULL;
}

/* Has cl any backchannel, busy or not. */
bool
nfsv4_session_cbany(struct nfsv4_client *cl)
{
	struct nfsv4_session *se;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	LIST_FOREACH(se, &cl->cl_sessions, se_list) {
		if (session_cbconn(se) != 0)
			return true;
	}
	return false;
}

/* s2.10.6.1: only a reply says the sequence ID was seen. */
void
nfsv4_session_cbdone(struct nfsv4_session *se, bool replied)
{

	KASSERT(mutex_owned(&nfsv4_state_lock));

	se->se_cbbusy = false;
	if (replied)
		se->se_cbseq++;
	session_rele(se);
}

static void
session_conn_add(struct nfsv4_session *se, uint64_t id, uint32_t dir)
{
	u_int i;

	if (se->se_nconn == NFSV4_SES_CONNS) {
		for (i = 1; i < NFSV4_SES_CONNS; i++)
			se->se_conns[i - 1] = se->se_conns[i];
		se->se_nconn--;
	}
	se->se_conns[se->se_nconn].sc_id = id;
	se->se_conns[se->se_nconn].sc_dir = dir;
	se->se_nconn++;
}

/*
 * The lease, for a SEQUENCE that succeeded, s18.46.3.  A client that
 * expired with nothing to lose never noticed; with state lost it hears of
 * it until it has freed the stateids.
 */
static uint32_t
session_lease(struct nfsv4_client *cl)
{

	if (cl->cl_expired) {
		if (nfsv4_client_has_state(cl))
			return SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED;
		cl->cl_expired = false;
	}
	cl->cl_expire = time_uptime + NFSV4_LEASE;
	return 0;
}

/*
 * SEQUENCE, s18.46.3, ahead of everything else in the COMPOUND; see
 * compound_sequence().  An error leaves the slot and the lease as they
 * were.  *replyp gets a reply that is the whole answer.
 */
uint32_t
nfsv4_seq_begin(struct nfsv4_compound *c, const struct nfsv4_args_sequence *sa,
    char **replyp, u_int *lenp)
{
	const struct oncrpc_xdrmbuf *ax =
	    (const struct oncrpc_xdrmbuf *)c->c_ax;
	struct nfsv4_session *se;
	struct nfsv4_slot *sl;
	char *old = NULL, *buf;
	u_int oldlen = 0, len;

	mutex_enter(&nfsv4_state_lock);
	se = session_find(&sa->sessionid);
	if (se == NULL) {
		mutex_exit(&nfsv4_state_lock);
		return NFS4ERR_BADSESSION;
	}
	if (c->c_numops > se->se_maxops) {
		mutex_exit(&nfsv4_state_lock);
		return NFS4ERR_TOO_MANY_OPS;
	}
	/* s2.10.6.4: on the first operation, so the slot does not change. */
	if (ax->xm_len > se->se_maxreq) {
		mutex_exit(&nfsv4_state_lock);
		return NFS4ERR_REQ_TOO_BIG;
	}
	if (sa->slotid >= se->se_nslots) {
		mutex_exit(&nfsv4_state_lock);
		return NFS4ERR_BADSLOT;
	}
	/* s2.10.6.4: there is no room to keep even this. */
	if (sa->cachethis && se->se_maxcached < NFSV4_SEQ_REPLYLEN) {
		mutex_exit(&nfsv4_state_lock);
		return NFS4ERR_REP_TOO_BIG_TO_CACHE;
	}
	sl = &se->se_slots[sa->slotid];

	if (sa->sequenceid == sl->sl_seq && sl->sl_used) {
		/* s18.46.3, a MAY: the client reused the slot and sequence. */
		if (sl->sl_sum != c->c_argsum ||
		    sl->sl_uid != nfsv4_client_principal(c)) {
			mutex_exit(&nfsv4_state_lock);
			return NFS4ERR_SEQ_FALSE_RETRY;
		}
		/* s2.10.6.2 */
		if (sl->sl_busy) {
			mutex_exit(&nfsv4_state_lock);
			return NFS4ERR_DELAY;
		}
		/* s18.46.3: the lease, on a retry too. */
		if (!se->se_client->cl_expired)
			se->se_client->cl_expire = time_uptime + NFSV4_LEASE;
		if (sl->sl_reply != NULL) {
			/* Busy, it keeps its reply while this copies it. */
			sl->sl_busy = true;
			se->se_refs++;
			len = sl->sl_len;
			mutex_exit(&nfsv4_state_lock);
			buf = kmem_alloc(len, KM_SLEEP);
			memcpy(buf, sl->sl_reply, len);
			mutex_enter(&nfsv4_state_lock);
			sl->sl_busy = false;
			session_rele(se);
			mutex_exit(&nfsv4_state_lock);
			*replyp = buf;
			*lenp = len;
			return NFS4_OK;
		}
		c->c_uncached = true;
	} else if (sa->sequenceid == sl->sl_seq + 1 && !sl->sl_busy) {
		sl->sl_seq = sa->sequenceid;
		sl->sl_used = true;
		sl->sl_busy = true;
		sl->sl_sum = c->c_argsum;
		sl->sl_uid = nfsv4_client_principal(c);
		old = sl->sl_reply;
		oldlen = sl->sl_len;
		sl->sl_reply = NULL;
		sl->sl_len = 0;
		c->c_slot = sl;
		c->c_cachethis = sa->cachethis != 0;
	} else {
		mutex_exit(&nfsv4_state_lock);
		return NFS4ERR_SEQ_MISORDERED;
	}

	/* s2.10.3.1: with SP4_NONE this binds the connection. */
	if (session_conn(se, c->c_rq->rq_connid) == NULL)
		session_conn_add(se, c->c_rq->rq_connid, CDFS4_FORE);
	c->c_seqflags = session_lease(se->se_client);
	/* s18.46.3 */
	if (se->se_client->cl_nrevoked != 0)
		c->c_seqflags |= SEQ4_STATUS_RECALLABLE_STATE_REVOKED;
	if (session_cbconn(se) == 0)
		c->c_seqflags |= SEQ4_STATUS_CB_PATH_DOWN_SESSION;
	if (!nfsv4_session_cbany(se->se_client))
		c->c_seqflags |= SEQ4_STATUS_CB_PATH_DOWN;
	c->c_maxslot = se->se_nslots - 1;
	c->c_resmax = se->se_maxresp;
	c->c_cachemax = se->se_maxcached;
	c->c_sess = se;
	c->c_client = se->se_client;
	se->se_refs++;
	se->se_client->cl_refs++;
	mutex_exit(&nfsv4_state_lock);
	if (old != NULL)
		kmem_free(old, oldlen);
	return NFS4_OK;
}

/*
 * The end of a COMPOUND under SEQUENCE.  With ok the reply is complete,
 * and if asked for it goes in the slot, s2.10.6.1.3.  One that came out
 * over the size of the cache had REP_TOO_BIG_TO_CACHE, unless it is a
 * SEQUENCE alone, which nfsv4_op_sequence() can say again.
 */
void
nfsv4_seq_end(struct nfsv4_compound *c, bool ok)
{
	struct nfsv4_session *se = c->c_sess;
	struct nfsv4_slot *sl = c->c_slot;
	XDR *rx = c->c_rx;
	char *buf = NULL;
	u_int len = 0, end;

	if (se == NULL)
		return;
	if (sl != NULL && ok && c->c_cachethis) {
		len = XDR_GETPOS(rx);
		if (len > 0 && len <= NFSV4_SES_MAXCACHED) {
			buf = kmem_alloc(len, KM_SLEEP);
			end = len;
			if (!XDR_SETPOS(rx, 0) || !XDR_GETBYTES(rx, buf, len) ||
			    !XDR_SETPOS(rx, end)) {
				kmem_free(buf, len);
				buf = NULL;
			}
		}
	}
	mutex_enter(&nfsv4_state_lock);
	if (sl != NULL) {
		sl->sl_reply = buf;
		sl->sl_len = buf != NULL ? len : 0;
		sl->sl_busy = false;
	}
	/* s2.10.12: a long COMPOUND does not eat the lease it runs under. */
	if (!c->c_client->cl_expired)
		c->c_client->cl_expire = time_uptime + NFSV4_LEASE;
	c->c_client->cl_refs--;
	session_rele(se);
	mutex_exit(&nfsv4_state_lock);
	c->c_sess = NULL;
	c->c_client = NULL;
	c->c_slot = NULL;
}

uint32_t
nfsv4_op_sequence(struct nfsv4_compound *c, union nfsv4_args *a)
{
	struct nfsv4_args_sequence *sa = &a->sequence;

	if (c->c_seqstatus != NFS4_OK)
		return c->c_seqstatus;
	return nfsv4_xdr_sessionid(c->c_rx, &sa->sessionid) &&
	    xdr_u_int32_t(c->c_rx, &sa->sequenceid) &&
	    xdr_u_int32_t(c->c_rx, &sa->slotid) &&
	    xdr_u_int32_t(c->c_rx, &c->c_maxslot) &&
	    xdr_u_int32_t(c->c_rx, &c->c_maxslot) &&
	    xdr_u_int32_t(c->c_rx, &c->c_seqflags) ? NFS4_OK :
	    NFS4ERR_RESOURCE;
}

static bool
put_opaque(XDR *x, const char *p, uint32_t len)
{

	return xdr_u_int32_t(x, &len) && xdr_opaque(x, __UNCONST(p), len) != 0;
}

/* Anyone who has not named the machine still gets a name to compare. */
static bool
put_hostname(XDR *x)
{

	return hostnamelen > 0 ? put_opaque(x, hostname, hostnamelen) :
	    put_opaque(x, "netbsd", 6);
}

/*
 * nfs_impl_id4<1>, s18.35.3, which a system manager can change or empty
 * with sysctl, as that section requires.  The date is left as zero.
 */
static bool
put_impl(XDR *x)
{
	char domain[NFSV4_IMPL_MAX], name[NFSV4_IMPL_MAX];
	uint32_t zero = 0, one = 1;
	uint64_t zero64 = 0;

	strlcpy(domain, nfsv4_impl_domain, sizeof(domain));
	strlcpy(name, nfsv4_impl_name, sizeof(name));
	if (domain[0] == '\0' && name[0] == '\0')
		return xdr_u_int32_t(x, &zero);
	return xdr_u_int32_t(x, &one) &&
	    put_opaque(x, domain, strlen(domain)) &&
	    put_opaque(x, name, strlen(name)) &&
	    xdr_u_int64_t(x, &zero64) && xdr_u_int32_t(x, &zero);
}

/*
 * The machine credential of SP4_MACH_CRED, s18.35.3: the principal and
 * the GSS mechanism of the EXCHANGE_ID, which was sent with integrity or
 * privacy.  The mechanism is always Kerberos V5 here, the one RPCSEC_GSS
 * has, so the principal and the service are what is compared.
 */
static bool
mach_cred_is(const struct nfsv4_compound *c, const struct nfsv4_client *cl)
{
	const struct oncrpc_req *rq = c->c_rq;

	return rq->rq_flavor == RPCSEC_GSS &&
	    (rq->rq_secflavor == RPCSEC_GSS_KRB5I ||
	    rq->rq_secflavor == RPCSEC_GSS_KRB5P) &&
	    rq->rq_principal != NULL &&
	    strcmp(rq->rq_principal, cl->cl_principal) == 0;
}

/* The principal of a client record, s18.35.4: its machine credential if any. */
static bool
client_same_principal(const struct nfsv4_compound *c,
    const struct nfsv4_client *cl)
{

	if (cl->cl_sp4 == SP4_MACH_CRED)
		return mach_cred_is(c, cl);
	return cl->cl_uid == nfsv4_client_principal(c);
}

static bool
op_in(const struct nfsv4_bitmap *bm, uint32_t op)
{

	return op / 32 < bm->bm_n && op / 32 < NFSV4_BITMAP_WORDS &&
	    (bm->bm_w[op / 32] & (1U << (op % 32))) != 0;
}

/*
 * s18.35.3: an operation of spo_must_enforce under another credential.
 * The error is NFS4ERR_WRONG_CRED, s15.1.6.4, which s15.2 lists for most
 * of the operations of the set; for BIND_CONN_TO_SESSION, BACKCHANNEL_CTL
 * and SET_SSV the RFC lists no error of the kind, and the same one is
 * used.
 */
uint32_t
nfsv4_mach_check(const struct nfsv4_compound *c, const struct nfsv4_client *cl,
    uint32_t op)
{

	if (cl == NULL || cl->cl_sp4 != SP4_MACH_CRED ||
	    !op_in(&cl->cl_enforce, op))
		return NFS4_OK;
	return mach_cred_is(c, cl) ? NFS4_OK : NFS4ERR_WRONG_CRED;
}

/* EXCHANGE_ID4resok, s18.35.2. */
static uint32_t
exchange_reply(struct nfsv4_compound *c, uint64_t id, uint32_t seq,
    uint32_t flags, uint32_t how, const struct nfsv4_bitmap *enforce,
    const struct nfsv4_bitmap *allow)
{
	uint64_t minor = 0;
	XDR *x = c->c_rx;

	if (!xdr_u_int64_t(x, &id) || !xdr_u_int32_t(x, &seq) ||
	    !xdr_u_int32_t(x, &flags) || !xdr_u_int32_t(x, &how))
		return NFS4ERR_RESOURCE;
	/* state_protect4_r: spr_mach_ops for SP4_MACH_CRED */
	if (how == SP4_MACH_CRED &&
	    (!nfsv4_xdr_bitmap(x, __UNCONST(enforce)) ||
	    !nfsv4_xdr_bitmap(x, __UNCONST(allow))))
		return NFS4ERR_RESOURCE;
	return xdr_u_int64_t(x, &minor) && put_hostname(x) && put_hostname(x) &&
	    put_impl(x) ? NFS4_OK : NFS4ERR_RESOURCE;
}

/* The numbered cases of s18.35.4 are marked. */
uint32_t
nfsv4_op_exchange_id(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_exchange_id *ea = &a->exchange_id;
	struct nfsv4_client *conf, *unconf, *n;
	uid_t uid = nfsv4_client_principal(c);
	/* s18.35.3: referrals and migration can both be seen here. */
	uint32_t flags = EXCHGID4_FLAG_USE_NON_PNFS |
	    EXCHGID4_FLAG_SUPP_MOVED_REFER | EXCHGID4_FLAG_SUPP_MOVED_MIGR;
	uint32_t seq, st, how;
	uint64_t id;
	bool same_verf, same_uid;
	struct nfsv4_bitmap enforce, allow;

	/* s18.35.3 */
	if ((ea->flags & ~EXCHGID4_ARG_FLAGS) != 0)
		return NFS4ERR_INVAL;
	/*
	 * s18.35.3: SP4_MACH_CRED MUST come with RPCSEC_GSS and integrity
	 * or privacy; the RFC names no error for a client that does not,
	 * and the argument is taken for invalid.  SP4_SSV needs the SSV
	 * mechanism of s2.10.9, which is not here.
	 */
	if (ea->how == SP4_SSV)
		return NFS4ERR_INVAL;
	if (ea->how == SP4_MACH_CRED &&
	    (c->c_rq->rq_flavor != RPCSEC_GSS ||
	    (c->c_rq->rq_secflavor != RPCSEC_GSS_KRB5I &&
	    c->c_rq->rq_secflavor != RPCSEC_GSS_KRB5P)))
		return NFS4ERR_INVAL;

	n = kmem_zalloc(sizeof(*n), KM_SLEEP);
	mutex_enter(&nfsv4_state_lock);
	conf = nfsv4_client_find(ea->id, ea->idlen, true, 1);
	unconf = nfsv4_client_find(ea->id, ea->idlen, false, 1);
	same_verf = conf != NULL && memcmp(&conf->cl_verf, &ea->verifier,
	    sizeof(ea->verifier)) == 0;
	/* s18.35.3: under SP4_MACH_CRED, the same machine credential. */
	same_uid = conf != NULL && client_same_principal(c, conf);

	if ((ea->flags & EXCHGID4_FLAG_UPD_CONFIRMED_REC_A) != 0) {
		if (conf == NULL)
			st = NFS4ERR_NOENT;		/* 7 */
		else if (!same_verf)
			st = NFS4ERR_NOT_SAME;		/* 8 */
		else if (!same_uid)
			st = NFS4ERR_PERM;		/* 9 */
		else
			goto existing;			/* 6 */
		mutex_exit(&nfsv4_state_lock);
		kmem_free(n, sizeof(*n));
		return st;
	}
	if (conf != NULL && same_verf && same_uid) {	/* 2 */
existing:
		id = conf->cl_id;
		seq = conf->cl_csseq + 1;
		flags |= EXCHGID4_FLAG_CONFIRMED_R;
		how = conf->cl_sp4;
		enforce = conf->cl_enforce;
		allow = conf->cl_allow;
		mutex_exit(&nfsv4_state_lock);
		kmem_free(n, sizeof(*n));
		return exchange_reply(c, id, seq, flags, how, &enforce, &allow);
	}
	if (conf != NULL && !same_uid) {		/* 3 */
		if (!conf->cl_expired && time_uptime <= conf->cl_expire &&
		    (nfsv4_client_has_state(conf) ||
		    !LIST_EMPTY(&conf->cl_sessions))) {
			mutex_exit(&nfsv4_state_lock);
			kmem_free(n, sizeof(*n));
			return NFS4ERR_CLID_INUSE;
		}
		nfsv4_client_retire(conf);
		unconf = nfsv4_client_find(ea->id, ea->idlen, false, 1);
	}
	if (unconf != NULL)				/* 4, and 5 */
		nfsv4_client_retire(unconf);

	/* 1, 3, 4 and 5 end alike; for 5 the old record stays for now. */
	n->cl_minor = 1;
	n->cl_id = id = nfsv4_clientid_new();
	n->cl_verf = ea->verifier;
	n->cl_uid = uid;
	n->cl_idlen = ea->idlen;
	memcpy(n->cl_idstr, ea->id, ea->idlen);
	n->cl_flavor = c->c_rq->rq_flavor;
	if (n->cl_flavor == RPCSEC_GSS && c->c_rq->rq_principal != NULL)
		strlcpy(n->cl_principal, c->c_rq->rq_principal,
		    sizeof(n->cl_principal));
	/*
	 * s18.35.3: the server's lists.  Every operation asked to be
	 * enforced is, which includes those of the set the RFC says MUST
	 * be; spo_must_allow is granted as asked, there being no binding
	 * of stateids to principals here for it to relax.
	 */
	n->cl_sp4 = ea->how;
	n->cl_enforce = ea->must_enforce;
	n->cl_allow = ea->must_allow;
	how = n->cl_sp4;
	enforce = n->cl_enforce;
	allow = n->cl_allow;
	seq = 1;
	/* s18.36.4: the slot, and a contrived reply in it. */
	n->cl_csseq = seq - 1;
	n->cl_csstatus = NFS4ERR_SEQ_MISORDERED;
	(void)nfsv4_client_insert(n);
	mutex_exit(&nfsv4_state_lock);
	return exchange_reply(c, id, seq, flags, how, &enforce, &allow);
}

static uint32_t
min32(uint32_t a, uint32_t b)
{

	return a < b ? a : b;
}

/* Fill in cl_csreply; the room for it is counted in nfsv4_state.h. */
static void
cs_reply(struct nfsv4_client *cl, struct nfsv4_session *se, uint32_t seq,
    uint32_t flags, const struct nfsv4_chanattrs *fore,
    const struct nfsv4_chanattrs *back)
{
	struct nfsv4_chanattrs f = *fore, b = *back;
	XDR x;

	f.ca_nird = b.ca_nird = 0;
	f.ca_headerpad = b.ca_headerpad = 0;
	xdrmem_create(&x, cl->cl_csreply, sizeof(cl->cl_csreply), XDR_ENCODE);
	(void)nfsv4_xdr_sessionid(&x, &se->se_id);
	(void)xdr_u_int32_t(&x, &seq);
	(void)xdr_u_int32_t(&x, &flags);
	(void)nfsv4_xdr_chanattrs(&x, &f);
	(void)nfsv4_xdr_chanattrs(&x, &b);
	cl->cl_cslen = xdr_getpos(&x);
}

/* The phases of s18.36.4 are marked. */
uint32_t
nfsv4_op_create_session(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_create_session *ca = &a->create_session;
	struct nfsv4_client *cl, *old;
	struct nfsv4_session *se;
	struct nfsv4_chanattrs fore = ca->fore;
	char reply[NFSV4_CSREPLY_MAX];
	uint32_t st, flags, nslots;
	u_int len = 0;
	size_t size, cost;

	if ((ca->flags & ~CREATE_SESSION4_FLAGS) != 0)
		return NFS4ERR_INVAL;
	if (ca->fore.ca_maxreqs == 0)
		return NFS4ERR_INVAL;
	/* s18.36.3 */
	if (ca->fore.ca_maxreq < NFSV4_SES_MINMSG ||
	    ca->fore.ca_maxresp < NFSV4_SES_MINMSG ||
	    ca->back.ca_maxreq < NFSV4_SES_MINMSG ||
	    ca->back.ca_maxresp < NFSV4_SES_MINMSG)
		return NFS4ERR_TOOSMALL;

	fore.ca_maxreq = min32(fore.ca_maxreq, NFSV4_SES_MAXMSG);
	fore.ca_maxresp = min32(fore.ca_maxresp, NFSV4_SES_MAXMSG);
	fore.ca_maxcached = min32(fore.ca_maxcached, NFSV4_SES_MAXCACHED);
	fore.ca_maxops = min32(fore.ca_maxops, NFSV4_SES_MAXOPS);
	nslots = min32(fore.ca_maxreqs, NFSV4_SES_SLOTS);
	fore.ca_maxreqs = nslots;
	size = session_size(nslots);
	se = kmem_zalloc(size, KM_SLEEP);

	mutex_enter(&nfsv4_state_lock);
	/* 1 */
	cl = nfsv4_client_byid41(ca->clientid);
	if (cl == NULL) {
		st = NFS4ERR_STALE_CLIENTID;
		goto out;
	}
	/* 2 */
	if (ca->sequence == cl->cl_csseq) {
		st = cl->cl_csstatus;
		len = cl->cl_cslen;
		memcpy(reply, cl->cl_csreply, len);
		goto out;
	}
	if (ca->sequence != cl->cl_csseq + 1) {
		st = NFS4ERR_SEQ_MISORDERED;
		goto out;
	}
	cl->cl_csseq = ca->sequence;
	cl->cl_cslen = 0;
	/*
	 * 3: once confirmed, the principal is not compared, but for
	 * SP4_MACH_CRED, whose machine credential is, s18.35.3, by
	 * spo_must_enforce as for any operation.
	 */
	if ((!cl->cl_confirmed && !client_same_principal(c, cl)) ||
	    nfsv4_mach_check(c, cl, NFSV4_OP_CREATE_SESSION) != NFS4_OK) {
		st = cl->cl_csstatus = NFS4ERR_CLID_INUSE;
		goto out;
	}
	/* 4; s18.36.3, there being no RPCSEC_GSS handle at all. */
	if (ca->sec.cs_gss) {
		st = cl->cl_csstatus = NFS4ERR_NOENT;
		goto out;
	}
	cost = nslots * (size_t)fore.ca_maxcached;
	if (nfsv4_ses_cost + cost > NFSV4_SES_BUDGET) {
		st = cl->cl_csstatus = NFS4ERR_NOSPC;
		goto out;
	}
	old = NULL;
	if (!cl->cl_confirmed) {
		old = nfsv4_client_find(cl->cl_idstr, cl->cl_idlen, true, 1);
		cl->cl_confirmed = true;
	}
	cl->cl_expire = time_uptime + NFSV4_LEASE;

	be32enc(se->se_id.sid_data, nfsv4_boot);
	be64enc(se->se_id.sid_data + 4, ++nfsv4_ses_counter);
	se->se_client = cl;
	se->se_size = size;
	se->se_refs = 1;
	se->se_maxreq = fore.ca_maxreq;
	se->se_maxresp = fore.ca_maxresp;
	se->se_maxcached = fore.ca_maxcached;
	se->se_maxops = fore.ca_maxops;
	se->se_nslots = nslots;
	se->se_cbprog = ca->cb_program;
	se->se_cbsec = ca->sec;
	se->se_cbseq = 1;		/* s18.36.3 */
	se->se_cbvers = NFSV4_VERSION;	/* s18.36.3 */
	se->se_cost = cost;
	nfsv4_ses_cost += cost;
	flags = ca->flags & CREATE_SESSION4_FLAG_CONN_BACK_CHAN;
	session_conn_add(se, c->c_rq->rq_connid,
	    flags != 0 ? CDFS4_BOTH : CDFS4_FORE);
	LIST_INSERT_HEAD(&nfsv4_ses_hash[session_hash(&se->se_id)], se,
	    se_hash);
	LIST_INSERT_HEAD(&cl->cl_sessions, se, se_list);

	cs_reply(cl, se, ca->sequence, flags, &fore, &ca->back);
	st = cl->cl_csstatus = NFS4_OK;
	len = cl->cl_cslen;
	memcpy(reply, cl->cl_csreply, len);
	if (flags != 0)
		nfsv4_cb_reset(cl);
	se = NULL;
	/* s18.35.4 case 5: the old record goes with the confirmation. */
	if (old != NULL)
		nfsv4_client_retire(old);
out:
	mutex_exit(&nfsv4_state_lock);
	if (se != NULL)
		kmem_free(se, size);
	if (st == NFS4_OK && !XDR_PUTBYTES(c->c_rx, reply, len))
		return NFS4ERR_RESOURCE;
	return st;
}

uint32_t
nfsv4_op_destroy_session(struct nfsv4_compound *c, union nfsv4_args *a)
{
	struct nfsv4_session *se;
	uint32_t st = NFS4_OK;

	mutex_enter(&nfsv4_state_lock);
	se = session_find(&a->sessionid.sessionid);
	if (se == NULL)
		st = NFS4ERR_BADSESSION;
	else if ((st = nfsv4_mach_check(c, se->se_client,
	    NFSV4_OP_DESTROY_SESSION)) != NFS4_OK)
		/* s18.35.3 */;
	else if (session_conn(se, c->c_rq->rq_connid) == NULL)
		st = NFS4ERR_CONN_NOT_BOUND_TO_SESSION;	/* s18.37.3 */
	else if (se == c->c_sess && c->c_opi + 1 != c->c_numops)
		st = NFS4ERR_NOT_ONLY_OP;		/* s18.37.3 */
	else
		session_drop(se);
	mutex_exit(&nfsv4_state_lock);
	return st;
}

uint32_t
nfsv4_op_destroy_clientid(struct nfsv4_compound *c, union nfsv4_args *a)
{
	struct nfsv4_client *cl;
	uint32_t st = NFS4_OK;

	mutex_enter(&nfsv4_state_lock);
	cl = nfsv4_client_byid41(a->clientid.clientid);
	if (cl == NULL)
		st = NFS4ERR_STALE_CLIENTID;
	else if ((st = nfsv4_mach_check(c, cl, NFSV4_OP_DESTROY_CLIENTID)) !=
	    NFS4_OK)
		/* s18.35.3 */;
	else if (cl == c->c_client || cl->cl_refs != 0 ||
	    !LIST_EMPTY(&cl->cl_sessions) ||
	    (nfsv4_client_has_state(cl) && !cl->cl_expired))
		st = NFS4ERR_CLIENTID_BUSY;		/* s18.50.3 */
	else
		nfsv4_client_retire(cl);
	mutex_exit(&nfsv4_state_lock);
	return st;
}

/* s18.34.3 */
uint32_t
nfsv4_op_bind_conn(struct nfsv4_compound *c, union nfsv4_args *a)
{
	struct nfsv4_args_bind_conn *ba = &a->bind_conn;
	struct nfsv4_session *se;
	struct nfsv4_sesconn *sc;
	uint32_t dir, st = NFS4_OK, no = 0;

	switch (ba->dir) {
	case CDFC4_FORE:
		dir = CDFS4_FORE;
		break;
	case CDFC4_BACK:
		dir = CDFS4_BACK;
		break;
	case CDFC4_FORE_OR_BOTH:
	case CDFC4_BACK_OR_BOTH:
		dir = CDFS4_BOTH;
		break;
	default:
		return NFS4ERR_INVAL;
	}

	mutex_enter(&nfsv4_state_lock);
	se = session_find(&ba->sessionid);
	if (se == NULL)
		st = NFS4ERR_BADSESSION;
	else if ((st = nfsv4_mach_check(c, se->se_client,
	    NFSV4_OP_BIND_CONN_TO_SESSION)) != NFS4_OK)
		/* s18.35.3 */;
	else if ((sc = session_conn(se, c->c_rq->rq_connid)) == NULL)
		session_conn_add(se, c->c_rq->rq_connid, dir);
	else if (ba->dir == CDFC4_FORE_OR_BOTH &&
	    (sc->sc_dir & CDFS4_FORE) != 0)
		dir = sc->sc_dir;
	else if (ba->dir == CDFC4_BACK_OR_BOTH &&
	    (sc->sc_dir & CDFS4_BACK) != 0)
		dir = sc->sc_dir;
	else if (sc->sc_dir != dir)
		st = NFS4ERR_INVAL;
	if (st == NFS4_OK && (dir & CDFS4_BACK) != 0)
		nfsv4_cb_reset(se->se_client);
	mutex_exit(&nfsv4_state_lock);
	if (st != NFS4_OK)
		return st;
	return nfsv4_xdr_sessionid(c->c_rx, &ba->sessionid) &&
	    xdr_u_int32_t(c->c_rx, &dir) && xdr_u_int32_t(c->c_rx, &no) ?
	    NFS4_OK : NFS4ERR_RESOURCE;
}

/* s18.33.3; no RPCSEC_GSS handle exists. */
uint32_t
nfsv4_op_backchannel_ctl(struct nfsv4_compound *c, union nfsv4_args *a)
{

	if (a->backchannel_ctl.sec.cs_gss)
		return NFS4ERR_NOENT;
	mutex_enter(&nfsv4_state_lock);
	c->c_sess->se_cbprog = a->backchannel_ctl.cb_program;
	c->c_sess->se_cbsec = a->backchannel_ctl.sec;
	mutex_exit(&nfsv4_state_lock);
	return NFS4_OK;
}

/* s18.47.3: only for SP4_SSV, which is not accepted. */
uint32_t
nfsv4_op_set_ssv(struct nfsv4_compound *c, union nfsv4_args *a)
{

	return NFS4ERR_INVAL;
}

/* s18.51.3, and s18.51.4 on a per-fs one: no migration, so it is ignored. */
uint32_t
nfsv4_op_reclaim_complete(struct nfsv4_compound *c, union nfsv4_args *a)
{
	uint32_t st = NFS4_OK;

	if (a->u32.value != 0)
		return c->c_cur.cf_set ? NFS4_OK : NFS4ERR_NOFILEHANDLE;
	mutex_enter(&nfsv4_state_lock);
	if (c->c_client->cl_reclaimed)
		st = NFS4ERR_COMPLETE_ALREADY;
	c->c_client->cl_reclaimed = true;
	mutex_exit(&nfsv4_state_lock);
	return st;
}

/* The seqid part of s8.2.4. */
static uint32_t
stateid_age(const struct nfsv4_stateid *si, const struct nfsv4_state *st)
{
	int32_t d;

	d = (int32_t)(si->si_seqid - st->st_seqid);
	if (si->si_seqid != 0 && d > 0)
		return NFS4ERR_BAD_STATEID;
	if (si->si_seqid != 0 && d < 0)
		return NFS4ERR_OLD_STATEID;
	return NFS4_OK;
}

/*
 * What s18.38.3 frees: a lock stateid with no locks left, and whatever
 * the lease took away.  For the last of those the client has then owned
 * up to all it lost, s18.46.3, and is alive again.
 */
uint32_t
nfsv4_op_free_stateid(struct nfsv4_compound *c, union nfsv4_args *a)
{
	struct nfsv4_client *cl = c->c_client;
	struct nfsv4_state *st, *ls;
	struct nfsv4_owner_s *sw;
	struct nfsv4_reap reap;
	struct vnode *vp;
	struct flock fl;
	uint32_t status;

	SLIST_INIT(&reap);
	mutex_enter(&nfsv4_state_lock);
	status = nfsv4_stateid_lookup(c, &a->stateid.stateid, &st);
	if (status != NFS4_OK)
		goto out;
	status = stateid_age(&a->stateid.stateid, st);
	if (status != NFS4_OK)
		goto out;
	sw = st->st_owner;
	nfsv4_owner_busy(sw);
	/* It may have changed while this waited. */
	status = nfsv4_stateid_lookup(c, &a->stateid.stateid, &st);
	if (status != NFS4_OK || st->st_owner != sw) {
		nfsv4_owner_idle(sw);
		status = NFS4ERR_BAD_STATEID;
		goto out;
	}
	if (st->st_file != NULL) {
		if (st->st_type != NFSV4_ST_LOCK) {
			nfsv4_owner_idle(sw);
			status = NFS4ERR_LOCKS_HELD;
			goto out;
		}
		vp = st->st_file->f_vp;
		vref(vp);
		mutex_exit(&nfsv4_state_lock);
		memset(&fl, 0, sizeof(fl));
		fl.l_whence = SEEK_SET;
		fl.l_type = F_WRLCK;
		if (VOP_ADVLOCK(vp, sw, F_HASLK, &fl, 0) != 0 ||
		    fl.l_type != F_UNLCK)
			status = NFS4ERR_LOCKS_HELD;
		vrele(vp);
		mutex_enter(&nfsv4_state_lock);
	} else {
		if (st->st_revoked)
			cl->cl_nrevoked--;
		/* The locks under an open have stateids of their own. */
		while ((ls = LIST_FIRST(&st->st_locks)) != NULL) {
			LIST_REMOVE(ls, st_plist);
			ls->st_open = NULL;
		}
	}
	if (status == NFS4_OK)
		nfsv4_state_unlink(st, &reap, false);
	nfsv4_owner_idle(sw);
	if (cl->cl_expired && !nfsv4_client_has_state(cl)) {
		cl->cl_expired = false;
		cl->cl_expire = time_uptime + NFSV4_LEASE;
	}
out:
	mutex_exit(&nfsv4_state_lock);
	nfsv4_reap_finish(&reap);
	return status;
}

/* s18.48.3: as in use, but of any type and on any file. */
static uint32_t
stateid_test(struct nfsv4_compound *c, const struct nfsv4_stateid *si)
{
	struct nfsv4_state *st;
	uint32_t status;

	mutex_enter(&nfsv4_state_lock);
	status = nfsv4_stateid_lookup(c, si, &st);
	if (status == NFS4_OK) {
		if (st->st_closed)
			status = NFS4ERR_BAD_STATEID;
		else if (st->st_revoked)
			status = NFS4ERR_DELEG_REVOKED;
		else if (st->st_file == NULL)
			status = NFS4ERR_EXPIRED;
		else
			status = stateid_age(si, st);
	}
	mutex_exit(&nfsv4_state_lock);
	return status;
}

uint32_t
nfsv4_op_test_stateid(struct nfsv4_compound *c, union nfsv4_args *a)
{
	struct nfsv4_args_test_stateid *ta = &a->test_stateid;
	struct nfsv4_stateid si;
	uint32_t i, status;
	u_int end;

	if (!xdr_u_int32_t(c->c_rx, &ta->count))
		return NFS4ERR_RESOURCE;
	end = XDR_GETPOS(c->c_ax);
	if (!XDR_SETPOS(c->c_ax, ta->pos))
		return NFS4ERR_BADXDR;
	for (i = 0; i < ta->count; i++) {
		if (!nfsv4_xdr_stateid(c->c_ax, &si))
			return NFS4ERR_BADXDR;
		status = stateid_test(c, &si);
		if (!xdr_u_int32_t(c->c_rx, &status))
			return NFS4ERR_RESOURCE;
	}
	return XDR_SETPOS(c->c_ax, end) ? NFS4_OK : NFS4ERR_BADXDR;
}
