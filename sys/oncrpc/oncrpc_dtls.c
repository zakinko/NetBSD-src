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
 * RPC-with-TLS on UDP, RFC 9289 s5.1.2: DTLS 1.3, RFC 9147, on the UDP
 * socket an RPC server already has.  The socket's inp_overudp_cb sees
 * every datagram first, as wg(4) and the NAT-T of ESP do, and sorts it
 * by the peer it came from:
 *
 *   no association   plain RPC, left in the socket.  s5.1.2 leaves the
 *                    distinction to "existing DTLS session state", and
 *                    the xid an RPC call starts with is any value, so
 *                    the first byte alone cannot tell.
 *   PROBED           STARTTLS went out to the peer's AUTH_TLS probe:
 *                    only a DTLSPlaintext handshake record is kept for
 *                    the handshake, and anything else MUST be dropped
 *                    without a response, s5.1.2.
 *   HANDSHAKE        the handshake daemon has the peer: its datagrams
 *                    are kept for it.
 *   ESTABLISHED      DTLSCiphertext is the kernel's, opened here and
 *                    served as RPC.  A first byte RFC 9147 s4.1 rejects
 *                    fails the matching, and s5.1.2 makes that plain
 *                    RPC; it is served as such, and oncrpc_req_tls()
 *                    says it did not come over DTLS.  DTLSPlaintext is
 *                    the handshake's, left behind with its epoch, and
 *                    is dropped.
 *   CLOSED           after a closure alert: everything is dropped for
 *                    ONCRPC_DTLS_CLOSEWAIT, s5.1.2 MUST.
 *
 * The callback runs with the socket locked, in softint, and so only
 * queues; the svc workers open the records, oncrpc_dtls_getmsg().
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#ifdef _KERNEL_OPT
#include "opt_oncrpc.h"
#endif

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <netinet/ip.h>

#include <oncrpc/oncrpc.h>
#include <oncrpc/oncrpc_dtls.h>
#include <oncrpc/oncrpc_tls.h>
#include <oncrpc/tls13_crypto.h>

/*
 * RFC 9289 s5.1.2: "In the absence of more specific data, a period of
 * 60 seconds is expected to suffice."
 */
#define	ONCRPC_DTLS_CLOSEWAIT	60

/*
 * None of these come from an RFC.  A PROBED association can be made
 * by anyone able to send a datagram with a forged source, so the table
 * is bounded and those that never start a handshake go; the cookie of
 * the HelloRetryRequest, RFC 9147 s5.1, is what keeps the daemon from
 * working for a forged one.
 */
#define	ONCRPC_DTLS_MAXPEERS	1024
#define	ONCRPC_DTLS_PROBEWAIT	30	/* PROBED, for the ClientHello */
#define	ONCRPC_DTLS_HSWAIT	60	/* HANDSHAKE, for the daemon */
#define	ONCRPC_DTLS_MAXQ	256	/* datagrams waiting for a worker */
#define	ONCRPC_DTLS_MAXHSQ	16	/* per peer, for the handshake */
#define	ONCRPC_DTLS_NHASH	64

#define	DP_PROBED	1
#define	DP_HANDSHAKE	2
#define	DP_ESTABLISHED	3
#define	DP_CLOSED	4

/* RFC 9147 s6.1: application data is protected under epoch 3. */
#define	DTLS13_EPOCH_APP	3

/* A datagram, or an opened RPC message, with the peer it is from. */
struct dtls_dgram {
	SIMPLEQ_ENTRY(dtls_dgram) dg_next;
	struct mbuf		*dg_m;
	struct oncrpc_dtlspeer	*dg_peer;	/* a reference */
};
SIMPLEQ_HEAD(dtls_dgramq, dtls_dgram);

struct oncrpc_dtlspeer {
	LIST_ENTRY(oncrpc_dtlspeer) dp_hash;
	struct oncrpc_dtls	*dp_dtls;
	struct sockaddr_storage	 dp_addr;
	/* Under d_lock: */
	u_int			 dp_state;	/* DP_* */
	u_int			 dp_refs;	/* the table's is one */
	time_t			 dp_until;	/* time_uptime; not ESTABLISHED */
	struct dtls_dgramq	 dp_hsq;	/* for the handshake daemon */
	u_int			 dp_hsqlen;
	/* Set before ESTABLISHED and constant after: */
	uint8_t			 dp_rcid[DTLS13_MAXCID];	/* ours */
	uint8_t			 dp_tcid[DTLS13_MAXCID];	/* the peer's */
	size_t			 dp_rcidlen, dp_tcidlen;
	uint8_t			 dp_exporter[ONCRPC_TLS_EXPORTERLEN];
	/* One opener and one sealer at a time: */
	kmutex_t		 dp_rxlock;
	struct dtls13_dir	 dp_rx;
	kmutex_t		 dp_txlock;
	struct dtls13_dir	 dp_tx;
};

struct oncrpc_dtls {
	kmutex_t		 d_lock;
	LIST_HEAD(, oncrpc_dtlspeer) d_hash[ONCRPC_DTLS_NHASH];
	u_int			 d_npeers;
	struct dtls_dgramq	 d_q;		/* ESTABLISHED, to be opened */
	u_int			 d_qlen;
	struct dtls_dgramq	 d_msgs;	/* opened, to be served */
	void			(*d_wake)(void *);
	void			*d_arg;
};

static bool
dtls_sameaddr(const struct sockaddr *a, const struct sockaddr *b)
{
	const struct sockaddr_in *a4, *b4;
	const struct sockaddr_in6 *a6, *b6;

	if (a->sa_family != b->sa_family)
		return false;
	switch (a->sa_family) {
	case AF_INET:
		a4 = (const struct sockaddr_in *)a;
		b4 = (const struct sockaddr_in *)b;
		return a4->sin_port == b4->sin_port &&
		    a4->sin_addr.s_addr == b4->sin_addr.s_addr;
	case AF_INET6:
		a6 = (const struct sockaddr_in6 *)a;
		b6 = (const struct sockaddr_in6 *)b;
		return a6->sin6_port == b6->sin6_port &&
		    a6->sin6_scope_id == b6->sin6_scope_id &&
		    memcmp(&a6->sin6_addr, &b6->sin6_addr,
		    sizeof(a6->sin6_addr)) == 0;
	default:
		return false;
	}
}

static u_int
dtls_hash(const struct sockaddr *sa)
{
	const uint8_t *p;
	size_t i, n;
	uint32_t h = 2166136261U;	/* FNV-1a */

	switch (sa->sa_family) {
	case AF_INET:
		p = (const uint8_t *)&((const struct sockaddr_in *)sa)->sin_port;
		n = sizeof(in_port_t) + sizeof(struct in_addr);
		break;
	case AF_INET6:
		p = (const uint8_t *)&((const struct sockaddr_in6 *)sa)->sin6_port;
		n = sizeof(in_port_t);
		for (i = 0; i < n; i++)
			h = (h ^ p[i]) * 16777619U;
		p = (const uint8_t *)&((const struct sockaddr_in6 *)sa)->sin6_addr;
		n = sizeof(struct in6_addr);
		break;
	default:
		return 0;
	}
	for (i = 0; i < n; i++)
		h = (h ^ p[i]) * 16777619U;
	return h % ONCRPC_DTLS_NHASH;
}

static bool
dtls_addrok(const struct sockaddr *sa)
{

	switch (sa->sa_family) {
	case AF_INET:
		return sa->sa_len >= sizeof(struct sockaddr_in);
	case AF_INET6:
		return sa->sa_len >= sizeof(struct sockaddr_in6);
	default:
		return false;
	}
}

static void
dtls_dgramq_free(struct dtls_dgramq *q)
{
	struct dtls_dgram *dg;

	while ((dg = SIMPLEQ_FIRST(q)) != NULL) {
		SIMPLEQ_REMOVE_HEAD(q, dg_next);
		m_freem(dg->dg_m);
		KASSERT(dg->dg_peer == NULL);
		kmem_intr_free(dg, sizeof(*dg));
	}
}

static void
dtls_peer_free(struct oncrpc_dtlspeer *p)
{

	KASSERT(p->dp_refs == 0);
	dtls_dgramq_free(&p->dp_hsq);
	dtls13_dir_fini(&p->dp_rx);
	dtls13_dir_fini(&p->dp_tx);
	explicit_memset(p->dp_exporter, 0, sizeof(p->dp_exporter));
	mutex_destroy(&p->dp_rxlock);
	mutex_destroy(&p->dp_txlock);
	kmem_intr_free(p, sizeof(*p));
}

/* Drop the table's reference; the caller has d_lock. */
static void
dtls_peer_unhash(struct oncrpc_dtls *d, struct oncrpc_dtlspeer *p)
{

	KASSERT(mutex_owned(&d->d_lock));
	LIST_REMOVE(p, dp_hash);
	d->d_npeers--;
	if (--p->dp_refs == 0)
		dtls_peer_free(p);
}

static bool
dtls_expired(const struct oncrpc_dtlspeer *p)
{

	return p->dp_state != DP_ESTABLISHED &&
	    (time_t)time_uptime >= p->dp_until;
}

/* The association with sa, expired ones gone.  Under d_lock. */
static struct oncrpc_dtlspeer *
dtls_lookup(struct oncrpc_dtls *d, const struct sockaddr *sa)
{
	struct oncrpc_dtlspeer *p, *np;

	KASSERT(mutex_owned(&d->d_lock));
	LIST_FOREACH_SAFE(p, &d->d_hash[dtls_hash(sa)], dp_hash, np) {
		if (!dtls_sameaddr(sa, (const struct sockaddr *)&p->dp_addr))
			continue;
		if (dtls_expired(p)) {
			dtls_peer_unhash(d, p);
			return NULL;
		}
		return p;
	}
	return NULL;
}

static void
dtls_sweep(struct oncrpc_dtls *d)
{
	struct oncrpc_dtlspeer *p, *np;
	u_int i;

	KASSERT(mutex_owned(&d->d_lock));
	for (i = 0; i < ONCRPC_DTLS_NHASH; i++) {
		LIST_FOREACH_SAFE(p, &d->d_hash[i], dp_hash, np) {
			if (dtls_expired(p))
				dtls_peer_unhash(d, p);
		}
	}
}

static void
dtls_close(struct oncrpc_dtlspeer *p)
{

	KASSERT(mutex_owned(&p->dp_dtls->d_lock));
	p->dp_state = DP_CLOSED;
	p->dp_until = time_uptime + ONCRPC_DTLS_CLOSEWAIT;
	dtls_dgramq_free(&p->dp_hsq);
	p->dp_hsqlen = 0;
}

/*
 * The associations of one UDP socket.  wake(arg) is called, with the
 * socket locked, when a datagram is queued for oncrpc_dtls_getmsg().
 */
struct oncrpc_dtls *
oncrpc_dtls_create(void (*wake)(void *), void *arg)
{
	struct oncrpc_dtls *d;
	u_int i;

	d = kmem_zalloc(sizeof(*d), KM_SLEEP);
	mutex_init(&d->d_lock, MUTEX_DEFAULT, IPL_NONE);
	for (i = 0; i < ONCRPC_DTLS_NHASH; i++)
		LIST_INIT(&d->d_hash[i]);
	SIMPLEQ_INIT(&d->d_q);
	SIMPLEQ_INIT(&d->d_msgs);
	d->d_wake = wake;
	d->d_arg = arg;
	return d;
}

/*
 * After the callback is off the socket and with no message from
 * oncrpc_dtls_getmsg() still held: every peer is the table's alone.
 */
void
oncrpc_dtls_destroy(struct oncrpc_dtls *d)
{
	struct oncrpc_dtlspeer *p;
	struct dtls_dgram *dg;
	u_int i;

	if (d == NULL)
		return;
	mutex_enter(&d->d_lock);
	while ((dg = SIMPLEQ_FIRST(&d->d_q)) != NULL) {
		SIMPLEQ_REMOVE_HEAD(&d->d_q, dg_next);
		SIMPLEQ_INSERT_TAIL(&d->d_msgs, dg, dg_next);
	}
	while ((dg = SIMPLEQ_FIRST(&d->d_msgs)) != NULL) {
		SIMPLEQ_REMOVE_HEAD(&d->d_msgs, dg_next);
		m_freem(dg->dg_m);
		p = dg->dg_peer;
		if (--p->dp_refs == 0)
			dtls_peer_free(p);
		kmem_intr_free(dg, sizeof(*dg));
	}
	for (i = 0; i < ONCRPC_DTLS_NHASH; i++) {
		while ((p = LIST_FIRST(&d->d_hash[i])) != NULL) {
			KASSERT(p->dp_refs == 1);
			dtls_peer_unhash(d, p);
		}
	}
	KASSERT(d->d_npeers == 0);
	mutex_exit(&d->d_lock);
	mutex_destroy(&d->d_lock);
	kmem_free(d, sizeof(*d));
}

static void
dtls_drop(struct mbuf **mp)
{

	m_freem(*mp);
	*mp = NULL;
}

/*
 * The socket's inp_overudp_cb: 0 leaves the datagram to the socket, as
 * plain RPC; 1 means it was taken, -1 that it was dropped.
 */
int
oncrpc_dtls_input(struct mbuf **mp, int off, struct socket *so,
    struct sockaddr *src, void *arg)
{
	struct oncrpc_dtls *d = arg;
	struct oncrpc_dtlspeer *p;
	struct dtls_dgram *dg;
	struct mbuf *m = *mp;
	uint8_t b0;

	if (m->m_pkthdr.len <= off)
		return 0;
	m_copydata(m, off, 1, &b0);

	mutex_enter(&d->d_lock);
	p = dtls_lookup(d, src);
	if (p == NULL) {
		mutex_exit(&d->d_lock);
		return 0;
	}
	switch (p->dp_state) {
	case DP_PROBED:
	case DP_HANDSHAKE:
		/*
		 * s5.1.2 MUST: what comes between the probe and the
		 * handshake is discarded without a response.  The
		 * handshake opens with a DTLSPlaintext ClientHello, RFC
		 * 9147 s5.
		 */
		if (p->dp_state == DP_PROBED && b0 != TLS13_CT_HANDSHAKE)
			break;
		if (p->dp_hsqlen >= ONCRPC_DTLS_MAXHSQ)
			break;
		dg = kmem_intr_alloc(sizeof(*dg), KM_NOSLEEP);
		if (dg == NULL)
			break;
		m_adj(m, off);
		dg->dg_m = m;
		dg->dg_peer = NULL;
		SIMPLEQ_INSERT_TAIL(&p->dp_hsq, dg, dg_next);
		p->dp_hsqlen++;
		mutex_exit(&d->d_lock);
		*mp = NULL;
		return 1;

	case DP_ESTABLISHED:
		switch (dtls13_demux(b0)) {
		case DTLS13_REJECT:
			/* No DTLS, so RPC, s5.1.2; see the top. */
			mutex_exit(&d->d_lock);
			return 0;
		case DTLS13_PLAINTEXT:
			/*
			 * Epoch 0 after the handshake: a retransmission
			 * the handshake no longer needs, or a forged
			 * alert, which s4.5.2 would have us not act on.
			 */
			goto drop;
		}
		if (d->d_qlen >= ONCRPC_DTLS_MAXQ)
			break;
		dg = kmem_intr_alloc(sizeof(*dg), KM_NOSLEEP);
		if (dg == NULL)
			break;
		m_adj(m, off);
		dg->dg_m = m;
		dg->dg_peer = p;
		p->dp_refs++;
		SIMPLEQ_INSERT_TAIL(&d->d_q, dg, dg_next);
		d->d_qlen++;
		mutex_exit(&d->d_lock);
		*mp = NULL;
		(*d->d_wake)(d->d_arg);
		return 1;

	case DP_CLOSED:
		/* s5.1.2 MUST, for ONCRPC_DTLS_CLOSEWAIT */
		break;
	}
drop:
	mutex_exit(&d->d_lock);
	dtls_drop(mp);
	return -1;
}

/*
 * Open the records of one datagram, RFC 9147 s4.3, and queue the RPC
 * messages among them on d_msgs.  Each application data record is one
 * message, RFC 9289 s5.1.2.
 */
static void
dtls_open_dgram(struct oncrpc_dtls *d, struct dtls_dgram *dg)
{
	struct oncrpc_dtlspeer *p = dg->dg_peer;
	struct dtls_dgram *out;
	struct mbuf *m;
	uint8_t *buf, *rec, *content, type;
	size_t len, rest, used, clen;
	bool closed = false;
	int error;

	len = dg->dg_m->m_pkthdr.len;
	if (len == 0 || len > IP_MAXPACKET) {
		m_freem(dg->dg_m);
		goto out;
	}
	buf = kmem_alloc(len, KM_SLEEP);
	m_copydata(dg->dg_m, 0, len, buf);
	m_freem(dg->dg_m);

	mutex_enter(&p->dp_rxlock);
	for (rec = buf, rest = len; rest > 0 && !closed;
	    rec += used, rest -= used) {
		/*
		 * s4.1 again for every record but the first, which the
		 * callback looked at: a plaintext record behind a
		 * protected one is no handshake of this association.
		 */
		if (dtls13_demux(rec[0]) != DTLS13_CIPHERTEXT)
			break;
		error = dtls13_open(&p->dp_rx, p->dp_rcidlen, rec, rest,
		    &used, &type, &content, &clen);
		if (error != 0) {
			/* s4.5.2 SHOULD: silently discarded. */
			if (used == 0)
				break;
			continue;
		}
		switch (type) {
		case TLS13_CT_APPDATA:
			if (clen == 0)
				break;
			m = m_gethdr(M_WAIT, MT_DATA);
			m->m_len = m->m_pkthdr.len = 0;
			m_copyback(m, 0, clen, content);
			if (m->m_pkthdr.len != (int)clen) {
				m_freem(m);
				break;
			}
			out = kmem_intr_alloc(sizeof(*out), KM_SLEEP);
			out->dg_m = m;
			out->dg_peer = p;
			mutex_enter(&d->d_lock);
			p->dp_refs++;
			SIMPLEQ_INSERT_TAIL(&d->d_msgs, out, dg_next);
			mutex_exit(&d->d_lock);
			break;
		case TLS13_CT_ALERT:
			/*
			 * RFC 8446 s6: a close_notify ends the session
			 * and so does any fatal alert; RFC 9289 s5.1.2
			 * then has the 5-tuple discarded for a while.
			 * A warning other than close_notify changes
			 * nothing.
			 */
			if (clen != 2)
				break;
			if (content[1] == ONCRPC_TLS_CLOSE_NOTIFY ||
			    content[0] == ONCRPC_TLS_FATAL)
				closed = true;
			break;
		default:
			/*
			 * Handshake (KeyUpdate, NewConnectionId) and ACK,
			 * RFC 9147 s7-s9, have no handler yet: they are
			 * dropped, and a peer's KeyUpdate goes unanswered.
			 */
			break;
		}
	}
	mutex_exit(&p->dp_rxlock);
	explicit_memset(buf, 0, len);
	kmem_free(buf, len);

	if (closed) {
		mutex_enter(&d->d_lock);
		if (p->dp_state == DP_ESTABLISHED)
			dtls_close(p);
		mutex_exit(&d->d_lock);
	}
out:
	oncrpc_dtls_rele(p);
	kmem_intr_free(dg, sizeof(*dg));
}

/*
 * The next RPC message that came over DTLS, with its sender in *namp and
 * a reference to its association in *pp, or NULL.
 */
struct mbuf *
oncrpc_dtls_getmsg(struct oncrpc_dtls *d, struct mbuf **namp,
    struct oncrpc_dtlspeer **pp)
{
	struct dtls_dgram *dg;
	struct oncrpc_dtlspeer *p;
	struct mbuf *m, *nam;
	const struct sockaddr *sa;

	for (;;) {
		mutex_enter(&d->d_lock);
		if ((dg = SIMPLEQ_FIRST(&d->d_msgs)) != NULL) {
			SIMPLEQ_REMOVE_HEAD(&d->d_msgs, dg_next);
			mutex_exit(&d->d_lock);
			break;
		}
		if ((dg = SIMPLEQ_FIRST(&d->d_q)) == NULL) {
			mutex_exit(&d->d_lock);
			return NULL;
		}
		SIMPLEQ_REMOVE_HEAD(&d->d_q, dg_next);
		d->d_qlen--;
		mutex_exit(&d->d_lock);
		dtls_open_dgram(d, dg);
	}

	m = dg->dg_m;
	p = dg->dg_peer;
	kmem_intr_free(dg, sizeof(*dg));
	sa = (const struct sockaddr *)&p->dp_addr;
	nam = m_get(M_WAIT, MT_SONAME);
	KASSERT(sa->sa_len <= MLEN);
	memcpy(mtod(nam, void *), sa, sa->sa_len);
	nam->m_len = sa->sa_len;
	*namp = nam;
	*pp = p;
	return m;
}

/*
 * STARTTLS went out to sa's AUTH_TLS probe, RFC 9289 s4.1: until its
 * handshake starts, nothing else from it is RPC, s5.1.2.  An
 * association already there stays as it is.
 */
int
oncrpc_dtls_probed(struct oncrpc_dtls *d, const struct sockaddr *sa)
{
	struct oncrpc_dtlspeer *p, *np;
	int error;

	if (!dtls_addrok(sa) || sa->sa_len > sizeof(np->dp_addr))
		return EAFNOSUPPORT;
	np = kmem_intr_zalloc(sizeof(*np), KM_SLEEP);
	mutex_init(&np->dp_rxlock, MUTEX_DEFAULT, IPL_NONE);
	mutex_init(&np->dp_txlock, MUTEX_DEFAULT, IPL_NONE);
	SIMPLEQ_INIT(&np->dp_hsq);
	memcpy(&np->dp_addr, sa, sa->sa_len);
	np->dp_state = DP_PROBED;
	np->dp_refs = 1;
	np->dp_until = time_uptime + ONCRPC_DTLS_PROBEWAIT;

	mutex_enter(&d->d_lock);
	if ((p = dtls_lookup(d, sa)) != NULL) {
		error = p->dp_state == DP_PROBED ? 0 : EALREADY;
		mutex_exit(&d->d_lock);
		np->dp_refs = 0;
		dtls_peer_free(np);
		return error;
	}
	if (d->d_npeers >= ONCRPC_DTLS_MAXPEERS)
		dtls_sweep(d);
	if (d->d_npeers >= ONCRPC_DTLS_MAXPEERS) {
		mutex_exit(&d->d_lock);
		np->dp_refs = 0;
		dtls_peer_free(np);
		return ENOSPC;
	}
	np->dp_dtls = d;
	LIST_INSERT_HEAD(&d->d_hash[dtls_hash(sa)], np, dp_hash);
	d->d_npeers++;
	mutex_exit(&d->d_lock);
	return 0;
}

/*
 * The handshake with sa is done: its application traffic secrets, the
 * connection IDs, cid of ours that the peer puts on what it sends and of
 * its that we put on ours, RFC 9147 s9, and the "tls-exporter" value.
 */
int
oncrpc_dtls_establish(struct oncrpc_dtls *d, const struct sockaddr *sa,
    const uint8_t *csecret, const uint8_t *ssecret, const uint8_t *rcid,
    size_t rcidlen, const uint8_t *tcid, size_t tcidlen,
    const uint8_t *exporter)
{
	struct oncrpc_dtlspeer *p;

	if (rcidlen > DTLS13_MAXCID || tcidlen > DTLS13_MAXCID)
		return EINVAL;
	mutex_enter(&d->d_lock);
	p = dtls_lookup(d, sa);
	if (p == NULL ||
	    (p->dp_state != DP_PROBED && p->dp_state != DP_HANDSHAKE)) {
		mutex_exit(&d->d_lock);
		return ESRCH;
	}
	/* Nothing opens or seals before ESTABLISHED. */
	dtls13_dir_init(&p->dp_rx, csecret, DTLS13_EPOCH_APP);
	dtls13_dir_init(&p->dp_tx, ssecret, DTLS13_EPOCH_APP);
	memcpy(p->dp_rcid, rcid, rcidlen);
	p->dp_rcidlen = rcidlen;
	memcpy(p->dp_tcid, tcid, tcidlen);
	p->dp_tcidlen = tcidlen;
	memcpy(p->dp_exporter, exporter, sizeof(p->dp_exporter));
	dtls_dgramq_free(&p->dp_hsq);
	p->dp_hsqlen = 0;
	p->dp_state = DP_ESTABLISHED;
	mutex_exit(&d->d_lock);
	return 0;
}

/*
 * Protect the RPC message m, consumed, into one record for the peer of
 * p, in *outp.  RFC 9289 s5.1.2: "Each RPC message MUST fit in a single
 * DTLS record"; one that does not is EMSGSIZE and not sent.  The record
 * is not cut to the path MTU, RFC 9147 s4.3 SHOULD: the message cannot
 * be split, and a reply too large for the path is the client's rsize to
 * fix, as on plain UDP, where IP fragments it.
 */
int
oncrpc_dtls_output(struct oncrpc_dtlspeer *p, struct mbuf *m,
    struct mbuf **outp)
{
	struct oncrpc_dtls *d = p->dp_dtls;
	struct mbuf *n;
	uint8_t *buf;
	size_t len, hmax, size, reclen;
	int error;

	*outp = NULL;
	len = m->m_pkthdr.len;
	/* RFC 9147 s4, DTLSInnerPlaintext; RFC 8446 s5.1, 2^14 */
	if (len > TLS13_MAXPLAIN) {
		m_freem(m);
		return EMSGSIZE;
	}
	hmax = 1 + DTLS13_MAXCID + 2 + 2;
	size = hmax + len + 1 + TLS13_TAGLEN;
	buf = kmem_alloc(size, KM_SLEEP);
	m_copydata(m, 0, len, buf + hmax);
	m_freem(m);

	mutex_enter(&d->d_lock);
	error = p->dp_state == DP_ESTABLISHED ? 0 : EPIPE;
	mutex_exit(&d->d_lock);
	if (error == 0) {
		mutex_enter(&p->dp_txlock);
		error = dtls13_seal(&p->dp_tx, TLS13_CT_APPDATA, p->dp_tcid,
		    p->dp_tcidlen, buf + hmax, len, buf, &reclen);
		mutex_exit(&p->dp_txlock);
	}
	if (error == 0) {
		n = m_gethdr(M_WAIT, MT_DATA);
		n->m_len = n->m_pkthdr.len = 0;
		m_copyback(n, 0, reclen, buf);
		if (n->m_pkthdr.len != (int)reclen) {
			m_freem(n);
			error = ENOBUFS;
		} else
			*outp = n;
	}
	explicit_memset(buf, 0, size);
	kmem_free(buf, size);
	return error;
}

void
oncrpc_dtls_exporter(const struct oncrpc_dtlspeer *p, uint8_t *exporter)
{

	memcpy(exporter, p->dp_exporter, ONCRPC_TLS_EXPORTERLEN);
}

void
oncrpc_dtls_rele(struct oncrpc_dtlspeer *p)
{
	struct oncrpc_dtls *d = p->dp_dtls;
	bool last;

	mutex_enter(&d->d_lock);
	KASSERT(p->dp_refs > 0);
	last = --p->dp_refs == 0;	/* off the table already, then */
	mutex_exit(&d->d_lock);
	if (last)
		dtls_peer_free(p);
}
