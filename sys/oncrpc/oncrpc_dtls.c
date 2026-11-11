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
 *
 * The handshake is rpc.tlsservd's.  A peer whose ClientHello came goes
 * on dtls_ready; oncrpc_dtls_take() gives the daemon one end of an
 * AF_LOCAL datagram pair, and d_work carries datagrams across: the
 * peer's into the pair, the daemon's out of the UDP socket to the peer.
 * oncrpc_dtls_done() ends it with the traffic secrets.
 *
 * Locks: the UDP socket's, then d_lock; dtls_glock before d_lock, and
 * never taken holding it.  The pair's socket lock is taken with none
 * of these held, and its upcall takes only d_lock.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#ifdef _KERNEL_OPT
#include "opt_oncrpc.h"
#endif

#include <sys/param.h>
#include <sys/atomic.h>
#include <sys/callout.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/protosw.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/workqueue.h>

#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

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
#define	ONCRPC_DTLS_MAXRETX	6	/* then the association is closed */
#define	ONCRPC_DTLS_NACK	8	/* RecordNumbers in one ACK */
#define	ONCRPC_DTLS_NPENDRN	8	/* transmissions of one message kept */

/*
 * RFC 9147 s5.8.2: "an initial timer value of 1000 ms and double the
 * value at each retransmission, up to no less than 60 seconds".  The
 * timer is looked at every ONCRPC_DTLS_TICK, ours.
 */
#define	ONCRPC_DTLS_RTO0	1000	/* ms */
#define	ONCRPC_DTLS_RTOMAX	60000	/* ms */
#define	ONCRPC_DTLS_TICK	(hz / 4)

/* The largest post-handshake message of ours, a NewConnectionId of none. */
#define	DTLS_PENDMAX		(DTLS13_HS_HDRLEN + 3)

#define	DP_PROBED	1
#define	DP_HANDSHAKE	2
#define	DP_ESTABLISHED	3
#define	DP_CLOSED	4

/*
 * Not for a production kernel: every record after the handshake and
 * what came of it, on the console.
 */
#ifdef ONCRPC_DTLS_DEBUG
#define	DTLS_DPRINTF(...)	printf("rpcdtls: " __VA_ARGS__)
#else
#define	DTLS_DPRINTF(...)	do { if (0) printf(__VA_ARGS__); } while (0)
#endif

/* The top bit tells a datagram association's cookie from a stream's. */
#define	ONCRPC_DTLS_COOKIE	(1ULL << 63)

/* RFC 9147 s6.1: application data is protected under epoch 3. */
#define	DTLS13_EPOCH_APP	3

/* A datagram, or an opened RPC message, with the peer it is from. */
struct dtls_dgram {
	SIMPLEQ_ENTRY(dtls_dgram) dg_next;
	struct mbuf		*dg_m;
	struct oncrpc_dtlspeer	*dg_peer;	/* a reference */
	bool			 dg_plain;	/* RPC, not DTLS; see below */
};
SIMPLEQ_HEAD(dtls_dgramq, dtls_dgram);

/* A socket of a pair to close in d_work, where that may sleep. */
struct dtls_reap {
	SIMPLEQ_ENTRY(dtls_reap) dr_next;
	struct socket		*dr_so;
};

struct oncrpc_dtlspeer {
	LIST_ENTRY(oncrpc_dtlspeer) dp_hash;
	LIST_ENTRY(oncrpc_dtlspeer) dp_glist;	/* dtls_ready, dtls_busy */
	struct oncrpc_dtls	*dp_dtls;
	struct sockaddr_storage	 dp_addr;
	uint64_t		 dp_id;		/* the daemon's cookie */
	/* Under d_lock: */
	bool			 dp_hashed;
	bool			 dp_queued;	/* on dtls_ready or after */
	struct socket		*dp_kso;	/* HANDSHAKE: the pair, ours */
	struct dtls_reap	*dp_reap;	/* for dp_kso */
	/* Under d_lock: */
	u_int			 dp_state;	/* DP_* */
	u_int			 dp_refs;	/* the table's is one */
	time_t			 dp_until;	/* time_uptime; not ESTABLISHED */
	struct dtls_dgramq	 dp_hsq;	/* for the handshake daemon */
	u_int			 dp_hsqlen;
	u_int			 dp_qn;		/* its records not yet opened */
	/* Set before ESTABLISHED and constant after: */
	uint8_t			 dp_rcid[DTLS13_MAXCID];	/* ours */
	uint8_t			 dp_tcid[DTLS13_MAXCID];	/* the peer's */
	size_t			 dp_rcidlen, dp_tcidlen;
	uint8_t			 dp_exporter[ONCRPC_TLS_EXPORTERLEN];
	/* One opener and one sealer at a time: */
	kmutex_t		 dp_rxlock;
	struct dtls13_dir	 dp_rx;
	struct dtls13_dir	 dp_rxnext;	/* after the peer's KeyUpdate */
	bool			 dp_rxnexton;
	uint32_t		 dp_hsrx;	/* next message_seq expected */
	kmutex_t		 dp_txlock;
	struct dtls13_dir	 dp_tx;
	uint16_t		 dp_hstx;	/* next message_seq of ours */
	/* Our handshake message awaiting its ACK, RFC 9147 s7, s8: */
	uint8_t			 dp_pend[DTLS_PENDMAX];
	size_t			 dp_pendlen;	/* 0: none */
	uint8_t			 dp_pendtype;
	uint64_t		 dp_pendrn[ONCRPC_DTLS_NPENDRN][2];
	u_int			 dp_npendrn;
	u_int			 dp_rto;	/* ms */
	u_int			 dp_tries;
	int			 dp_due;	/* getticks() */
	bool			 dp_txpend;	/* under d_lock: dp_pendlen */
};

/* What one datagram's records asked of the sending side. */
struct dtls_ctl {
	uint64_t		 c_ack[ONCRPC_DTLS_NACK][2];
	u_int			 c_nack;
	bool			 c_acked;	/* our pending message */
	bool			 c_keyupdate;	/* the peer asked for ours */
	bool			 c_reqcid;	/* RequestConnectionId came */
	bool			 c_newcid;
	uint8_t			 c_cid[DTLS13_MAXCID];
	size_t			 c_cidlen;
	int			 c_alert;	/* to send, fatal; or -1 */
};

struct oncrpc_dtls {
	kmutex_t		 d_lock;
	LIST_HEAD(, oncrpc_dtlspeer) d_hash[ONCRPC_DTLS_NHASH];
	u_int			 d_npeers;
	struct dtls_dgramq	 d_q;		/* ESTABLISHED, to be opened */
	u_int			 d_qlen;
	struct dtls_dgramq	 d_msgs;	/* opened, to be served */
	bool			 d_opening;	/* a worker is at d_q */
	void			(*d_wake)(void *);
	void			*d_arg;
	struct socket		*d_so;		/* the UDP socket */
	struct workqueue	*d_wq;
	struct work		 d_work;
	bool			 d_workq;	/* d_work enqueued */
	callout_t		 d_tick;	/* while d_npend */
	u_int			 d_npend;	/* peers with dp_txpend */
	bool			 d_dying;
	SIMPLEQ_HEAD(, dtls_reap) d_reap;
};

/* Peers for the daemon, and those it has, under dtls_glock. */
LIST_HEAD(dtls_peerlist, oncrpc_dtlspeer);
static kmutex_t dtls_glock;
static struct dtls_peerlist dtls_ready = LIST_HEAD_INITIALIZER(dtls_ready);
static struct dtls_peerlist dtls_busy = LIST_HEAD_INITIALIZER(dtls_busy);
static void (*dtls_readyfn)(void);
static volatile uint64_t dtls_nextid;

static void dtls_work(struct work *, void *);
static void dtls_tick(void *);
static void dtls_reapall(struct oncrpc_dtls *);
static void dtls_unpair(struct oncrpc_dtlspeer *);

/* Under d_lock. */
static void
dtls_kick(struct oncrpc_dtls *d)
{

	KASSERT(mutex_owned(&d->d_lock));
	if (d->d_workq || d->d_wq == NULL)
		return;
	d->d_workq = true;
	workqueue_enqueue(d->d_wq, &d->d_work, NULL);
}

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

/* With d_lock held when the peer has been in a table. */
static void
dtls_peer_free(struct oncrpc_dtlspeer *p)
{
	struct oncrpc_dtls *d = p->dp_dtls;

	KASSERT(p->dp_refs == 0);
	if (p->dp_txpend) {
		KASSERT(mutex_owned(&d->d_lock));
		d->d_npend--;
	}
	if (p->dp_kso != NULL) {
		KASSERT(mutex_owned(&d->d_lock));
		p->dp_reap->dr_so = p->dp_kso;
		SIMPLEQ_INSERT_TAIL(&d->d_reap, p->dp_reap, dr_next);
		p->dp_reap = NULL;
		p->dp_kso = NULL;
		dtls_kick(d);
	}
	if (p->dp_reap != NULL)
		kmem_free(p->dp_reap, sizeof(*p->dp_reap));
	dtls_dgramq_free(&p->dp_hsq);
	dtls13_dir_fini(&p->dp_rx);
	dtls13_dir_fini(&p->dp_rxnext);
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
	p->dp_hashed = false;
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

/* The pair's end goes to d_work to close.  Under d_lock. */
static void
dtls_unpair(struct oncrpc_dtlspeer *p)
{
	struct oncrpc_dtls *d = p->dp_dtls;

	KASSERT(mutex_owned(&d->d_lock));
	if (p->dp_kso == NULL)
		return;
	p->dp_reap->dr_so = p->dp_kso;
	SIMPLEQ_INSERT_TAIL(&d->d_reap, p->dp_reap, dr_next);
	p->dp_reap = NULL;
	p->dp_kso = NULL;
	dtls_kick(d);
}

static void
dtls_close(struct oncrpc_dtlspeer *p)
{

	KASSERT(mutex_owned(&p->dp_dtls->d_lock));
	p->dp_state = DP_CLOSED;
	p->dp_until = time_uptime + ONCRPC_DTLS_CLOSEWAIT;
	dtls_dgramq_free(&p->dp_hsq);
	p->dp_hsqlen = 0;
	dtls_unpair(p);
}

/*
 * The associations of one UDP socket.  wake(arg) is called, with the
 * socket locked, when a datagram is queued for oncrpc_dtls_getmsg().
 */
struct oncrpc_dtls *
oncrpc_dtls_create(struct socket *so, void (*wake)(void *), void *arg)
{
	struct oncrpc_dtls *d;
	u_int i;

	d = kmem_zalloc(sizeof(*d), KM_SLEEP);
	d->d_so = so;
	callout_init(&d->d_tick, CALLOUT_MPSAFE);
	callout_setfunc(&d->d_tick, dtls_tick, d);
	SIMPLEQ_INIT(&d->d_reap);
	if (workqueue_create(&d->d_wq, "rpcdtls", dtls_work, d, PRI_NONE,
	    IPL_NONE, WQ_MPSAFE) != 0)
		d->d_wq = NULL;	/* no handshakes then; see dtls_kick() */
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
	d->d_dying = true;
	mutex_exit(&d->d_lock);
	callout_halt(&d->d_tick, NULL);
	callout_destroy(&d->d_tick);
	/* The daemon's lists hold references too. */
	mutex_enter(&dtls_glock);
	for (i = 0; i < 2; i++) {
		struct oncrpc_dtlspeer *np;

		LIST_FOREACH_SAFE(p, i == 0 ? &dtls_ready : &dtls_busy,
		    dp_glist, np) {
			if (p->dp_dtls != d)
				continue;
			LIST_REMOVE(p, dp_glist);
			mutex_enter(&d->d_lock);
			if (--p->dp_refs == 0)
				dtls_peer_free(p);
			mutex_exit(&d->d_lock);
		}
	}
	mutex_exit(&dtls_glock);
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
	if (d->d_wq != NULL) {
		workqueue_wait(d->d_wq, &d->d_work);
		workqueue_destroy(d->d_wq);
	}
	dtls_reapall(d);
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
		if (p->dp_state == DP_HANDSHAKE) {
			dtls_kick(d);
			mutex_exit(&d->d_lock);
		} else if (!p->dp_queued) {
			/* For the daemon, with the list's reference. */
			p->dp_queued = true;
			p->dp_refs++;
			mutex_exit(&d->d_lock);
			mutex_enter(&dtls_glock);
			LIST_INSERT_HEAD(&dtls_ready, p, dp_glist);
			mutex_exit(&dtls_glock);
			if (dtls_readyfn != NULL)
				(*dtls_readyfn)();
		} else
			mutex_exit(&d->d_lock);
		*mp = NULL;
		return 1;

	case DP_ESTABLISHED:
		switch (dtls13_demux(b0)) {
		case DTLS13_REJECT:
			/*
			 * No DTLS, so RPC, s5.1.2; see the top.  Behind a
			 * record not yet opened it waits its turn: that
			 * may be a closure, after which s5.1.2 has it
			 * discarded.
			 */
			if (p->dp_qn == 0) {
				mutex_exit(&d->d_lock);
				return 0;
			}
			if (d->d_qlen >= ONCRPC_DTLS_MAXQ ||
			    (dg = kmem_intr_alloc(sizeof(*dg),
			    KM_NOSLEEP)) == NULL)
				goto drop;
			m_adj(m, off);
			dg->dg_m = m;
			dg->dg_peer = p;
			dg->dg_plain = true;
			p->dp_refs++;
			SIMPLEQ_INSERT_TAIL(&d->d_q, dg, dg_next);
			d->d_qlen++;
			mutex_exit(&d->d_lock);
			*mp = NULL;
			(*d->d_wake)(d->d_arg);
			return 1;
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
		dg->dg_plain = false;
		p->dp_refs++;
		p->dp_qn++;
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
 * Records sealed under dp_txlock and sent after it is released: sending
 * may sleep, and a mutex must not be held across that.
 */
#define	DTLS_RECMAX	(1 + DTLS13_MAXCID + 2 + 2 + 2 + \
			 ONCRPC_DTLS_NACK * DTLS13_RECNUMLEN + 1 + TLS13_TAGLEN)
#define	DTLS_NOUT	3	/* an alert or an ACK, and our message */

struct dtls_out {
	uint8_t		o_rec[DTLS_NOUT][DTLS_RECMAX];
	size_t		o_len[DTLS_NOUT];
	u_int		o_n;
};

/*
 * Seal one record of type into o, under the current sending epoch,
 * which s7 makes a MUST for an ACK after the handshake.  With
 * dp_txlock; *rnp is the record's RecordNumber when rnp is not NULL.
 */
static int
dtls_send(struct oncrpc_dtlspeer *p, uint8_t type, const uint8_t *in,
    size_t len, uint64_t *rnp, struct dtls_out *o)
{
	size_t hmax = 1 + DTLS13_MAXCID + 2 + 2;
	uint8_t *rec;
	int error;

	KASSERT(mutex_owned(&p->dp_txlock));
	if (o->o_n == DTLS_NOUT || hmax + len + 1 + TLS13_TAGLEN > DTLS_RECMAX)
		return EMSGSIZE;
	rec = o->o_rec[o->o_n];
	memcpy(rec + hmax, in, len);
	if (rnp != NULL) {
		rnp[0] = p->dp_tx.dd_epoch;
		rnp[1] = p->dp_tx.dd_seq;
	}
	error = dtls13_seal(&p->dp_tx, type, p->dp_tcid, p->dp_tcidlen,
	    rec + hmax, len, rec, &o->o_len[o->o_n]);
	DTLS_DPRINTF("seal type %u len %zu epoch %ju: %d\n", type, len,
	    (uintmax_t)p->dp_tx.dd_epoch, error);
	if (error == 0)
		o->o_n++;
	return error;
}

/* Send what dtls_send() sealed, with no lock held. */
static void
dtls_flush(struct oncrpc_dtlspeer *p, struct dtls_out *o)
{
	struct oncrpc_dtls *d = p->dp_dtls;
	struct mbuf *m;
	u_int i;
	int error;

	for (i = 0; i < o->o_n; i++) {
		m = m_gethdr(M_WAIT, MT_DATA);
		m->m_len = m->m_pkthdr.len = 0;
		m_copyback(m, 0, o->o_len[i], o->o_rec[i]);
		if (m->m_pkthdr.len != (int)o->o_len[i]) {
			m_freem(m);
			continue;	/* lost, as on the wire */
		}
		error = (*d->d_so->so_send)(d->d_so,
		    (struct sockaddr *)&p->dp_addr, NULL, m, NULL, 0, curlwp);
		DTLS_DPRINTF("sent %u bytes: %d\n", (u_int)o->o_len[i], error);
	}
	o->o_n = 0;
}

/* (Re)transmit the pending message as a new record, s5.2.  dp_txlock. */
static void
dtls_send_pend(struct oncrpc_dtlspeer *p, struct dtls_out *o)
{
	uint64_t rn[2];

	KASSERT(mutex_owned(&p->dp_txlock));
	if (dtls_send(p, TLS13_CT_HANDSHAKE, p->dp_pend, p->dp_pendlen,
	    rn, o) != 0)
		return;		/* the timer tries again */
	if (p->dp_npendrn < ONCRPC_DTLS_NPENDRN) {
		p->dp_pendrn[p->dp_npendrn][0] = rn[0];
		p->dp_pendrn[p->dp_npendrn][1] = rn[1];
		p->dp_npendrn++;
	}
	p->dp_due = getticks() + mstohz(p->dp_rto);
}

/* Queue a handshake message of ours, with dp_txlock and none pending. */
static void
dtls_pend(struct oncrpc_dtlspeer *p, uint8_t type, const uint8_t *body,
    size_t blen, struct dtls_out *o)
{
	struct oncrpc_dtls *d = p->dp_dtls;

	KASSERT(mutex_owned(&p->dp_txlock));
	KASSERT(p->dp_pendlen == 0 && DTLS13_HS_HDRLEN + blen <= DTLS_PENDMAX);
	p->dp_pendlen = dtls13_hs_build(p->dp_pend, type, p->dp_hstx++,
	    body, blen);
	p->dp_pendtype = type;
	p->dp_npendrn = 0;
	p->dp_tries = 0;
	mutex_enter(&d->d_lock);
	if (!p->dp_txpend) {
		p->dp_txpend = true;
		if (d->d_npend++ == 0 && !d->d_dying)
			callout_schedule(&d->d_tick, ONCRPC_DTLS_TICK);
	}
	mutex_exit(&d->d_lock);
	dtls_send_pend(p, o);
}

/* The pending message is acknowledged, or given up.  dp_txlock. */
static void
dtls_unpend(struct oncrpc_dtlspeer *p)
{
	struct oncrpc_dtls *d = p->dp_dtls;

	KASSERT(mutex_owned(&p->dp_txlock));
	p->dp_pendlen = 0;
	mutex_enter(&d->d_lock);
	if (p->dp_txpend) {
		p->dp_txpend = false;
		d->d_npend--;
	}
	mutex_exit(&d->d_lock);
}

/*
 * Do what the records of a datagram asked of the sending side: ACKs,
 * s7; acting on the ACK of our KeyUpdate, s8, which only then changes
 * our sending keys; our KeyUpdate when asked for, RFC 8446 s4.6.3; the
 * connection ID messages, s9; and a fatal alert, which closes.
 */
static void
dtls_ctl(struct oncrpc_dtls *d, struct oncrpc_dtlspeer *p, struct dtls_ctl *c)
{
	uint8_t buf[2 + ONCRPC_DTLS_NACK * DTLS13_RECNUMLEN], b;
	static const uint8_t nonecid[3] = { 0, 0, 1 };	/* cids<>, spare */
	struct dtls_out o;
	size_t n;

	o.o_n = 0;
	mutex_enter(&p->dp_txlock);
	if (c->c_alert >= 0) {
		buf[0] = ONCRPC_TLS_FATAL;
		buf[1] = (uint8_t)c->c_alert;
		(void)dtls_send(p, TLS13_CT_ALERT, buf, 2, NULL, &o);
		if (p->dp_pendlen != 0)
			dtls_unpend(p);
		mutex_exit(&p->dp_txlock);
		/* Closed before the peer can hear of it, s5.1.2. */
		mutex_enter(&d->d_lock);
		if (p->dp_state == DP_ESTABLISHED)
			dtls_close(p);
		mutex_exit(&d->d_lock);
		dtls_flush(p, &o);
		return;
	}
	if (c->c_acked && p->dp_pendlen != 0) {
		/*
		 * s8: the new sending keys only now; a retransmission
		 * that succeeded at once also resets the timer, s5.8.2,
		 * which keeps 1000 ms rather than measure the round trip.
		 */
		if (p->dp_pendtype == DTLS13_HS_KEY_UPDATE)
			dtls13_dir_update(&p->dp_tx);
		if (p->dp_tries == 0)
			p->dp_rto = ONCRPC_DTLS_RTO0;
		dtls_unpend(p);
	}
	if (c->c_newcid)
		memcpy(p->dp_tcid, c->c_cid, p->dp_tcidlen = c->c_cidlen);
	if (c->c_nack != 0) {
		n = dtls13_ack_build(buf, sizeof(buf), &c->c_ack[0][0],
		    c->c_nack);
		(void)dtls_send(p, TLS13_CT_ACK, buf, n, NULL, &o);
	}
	/*
	 * Only one message of ours outstanding, s8 and s9: a request
	 * finding one is dropped, and the peer, unanswered, asks again.
	 * s8: "MUST NOT allow the epoch to exceed 2^48-1".
	 */
	if (c->c_keyupdate && p->dp_pendlen == 0 &&
	    p->dp_tx.dd_epoch < (1ULL << 48) - 1) {
		b = 0;		/* update_not_requested, RFC 8446 s4.6.3 */
		dtls_pend(p, DTLS13_HS_KEY_UPDATE, &b, 1, &o);
	} else if (c->c_reqcid && p->dp_pendlen == 0) {
		/* s9 MAY: "fewer than num_cids CIDs, including no CIDs" */
		dtls_pend(p, DTLS13_HS_NEW_CID, nonecid, sizeof(nonecid),
		    &o);
	}
	mutex_exit(&p->dp_txlock);
	dtls_flush(p, &o);
}

/*
 * The handshake messages of one record after the handshake, RFC 9147
 * s5.2, opened under (epoch, seq).  With dp_rxlock.
 */
static void
dtls_hs_input(struct oncrpc_dtlspeer *p, const uint8_t *q, size_t len,
    uint64_t epoch, uint64_t seq, struct dtls_ctl *c)
{
	const uint8_t *body;
	uint8_t type;
	uint16_t mseq;
	size_t blen, used, n;
	bool cids = p->dp_rcidlen != 0 || p->dp_tcidlen != 0;
	bool processed = false;
	int error;

	while (len > 0) {
		error = dtls13_hs_parse(q, len, &type, &mseq, &body, &blen,
		    &used);
		if (error == EINPROGRESS)
			break;	/* not processed: s7 MUST NOT ACK it */
		if (error != 0) {
			c->c_alert = ONCRPC_TLS_DECODE_ERROR;
			return;
		}
		DTLS_DPRINTF("hs type %u mseq %u expected %u len %zu\n", type,
		    mseq, p->dp_hsrx, blen);
		if (mseq < p->dp_hsrx) {
			/* s7: a copy already received is ACKed too. */
			processed = true;
			q += used, len -= used;
			continue;
		}
		switch (type) {
		case DTLS13_HS_KEY_UPDATE:
			/* RFC 8446 s4.6.3 */
			if (blen != 1 || body[0] > 1) {
				c->c_alert = blen != 1 ?
				    ONCRPC_TLS_DECODE_ERROR :
				    ONCRPC_TLS_ILLEGAL_PARAMETER;
				return;
			}
			/*
			 * s8 MUST: the old keys stay until a record opens
			 * under the new.
			 */
			if (!p->dp_rxnexton) {
				p->dp_rxnext = p->dp_rx;
				dtls13_dir_update(&p->dp_rxnext);
				p->dp_rxnexton = true;
			}
			if (body[0] == 1)
				c->c_keyupdate = true;
			break;
		case DTLS13_HS_NEW_CID:
		case DTLS13_HS_REQUEST_CID:
			/* s9 MUST, without negotiated connection IDs */
			if (!cids) {
				c->c_alert = ONCRPC_TLS_UNEXPECTED_MESSAGE;
				return;
			}
			if (type == DTLS13_HS_REQUEST_CID) {
				if (blen != 1) {
					c->c_alert = ONCRPC_TLS_DECODE_ERROR;
					return;
				}
				c->c_reqcid = true;
				break;
			}
			/* cids<0..2^16-1>, each ConnectionId<0..2^8-1> */
			if (blen < 3 || (n = (size_t)body[0] << 8 | body[1]) !=
			    blen - 3 || (n > 0 && (body[2] > n - 1))) {
				c->c_alert = ONCRPC_TLS_DECODE_ERROR;
				return;
			}
			/*
			 * cid_immediate(0): the first is used from now on;
			 * cid_spare(1) ones are discarded, as s9 allows.
			 */
			if (body[blen - 1] == 0 && n > 0 && body[2] != 0 &&
			    body[2] <= DTLS13_MAXCID) {
				c->c_newcid = true;
				c->c_cidlen = body[2];
				memcpy(c->c_cid, body + 3, body[2]);
			}
			break;
		default:
			/* RFC 8446 s4: no other after the handshake here */
			c->c_alert = ONCRPC_TLS_UNEXPECTED_MESSAGE;
			return;
		}
		p->dp_hsrx = mseq + 1;
		processed = true;
		q += used, len -= used;
	}
	if (processed && c->c_nack < ONCRPC_DTLS_NACK) {
		c->c_ack[c->c_nack][0] = epoch;
		c->c_ack[c->c_nack][1] = seq;
		c->c_nack++;
	}
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
	struct dtls_ctl c;
	struct mbuf *m;
	uint8_t *buf, *rec, *content, type;
	size_t len, rest, used, clen;
	uint64_t epoch;
	bool closed = false, any = false;
	int error;

	memset(&c, 0, sizeof(c));
	c.c_alert = -1;
	len = dg->dg_m->m_pkthdr.len;
	if (len == 0 || len > IP_MAXPACKET) {
		m_freem(dg->dg_m);
		goto out;
	}
	buf = kmem_alloc(len, KM_SLEEP);
	m_copydata(dg->dg_m, 0, len, buf);
	m_freem(dg->dg_m);

	mutex_enter(&p->dp_rxlock);
	for (rec = buf, rest = len; rest > 0 && !closed && c.c_alert < 0;
	    rec += used, rest -= used) {
		/*
		 * s4.1 again for every record but the first, which the
		 * callback looked at: a plaintext record behind a
		 * protected one is no handshake of this association.
		 */
		if (dtls13_demux(rec[0]) != DTLS13_CIPHERTEXT)
			break;
		epoch = p->dp_rx.dd_epoch;
		error = dtls13_open(&p->dp_rx, p->dp_rcidlen, rec, rest,
		    &used, &type, &content, &clen);
		if (error == EAGAIN && p->dp_rxnexton) {
			/* s8: the peer's new keys, used for the first time? */
			epoch = p->dp_rxnext.dd_epoch;
			error = dtls13_open(&p->dp_rxnext, p->dp_rcidlen, rec,
			    rest, &used, &type, &content, &clen);
			if (error == 0) {
				dtls13_dir_fini(&p->dp_rx);
				p->dp_rx = p->dp_rxnext;
				explicit_memset(&p->dp_rxnext, 0,
				    sizeof(p->dp_rxnext));
				p->dp_rxnexton = false;
			}
		}
		DTLS_DPRINTF("open b0 %02x epoch %ju: error %d type %u len %zu\n",
		    rec[0], (uintmax_t)epoch, error, error == 0 ? type : 0,
		    error == 0 ? clen : 0);
		if (error != 0) {
			/* s4.5.2 SHOULD: silently discarded. */
			if (used == 0)
				break;
			continue;
		}
		any = true;
		switch (type) {
		case TLS13_CT_APPDATA:
			if (clen == 0)
				break;
			/* Under dp_rxlock: nothing that sleeps; lost if so. */
			if ((m = m_gethdr(M_DONTWAIT, MT_DATA)) == NULL)
				break;
			m->m_len = m->m_pkthdr.len = 0;
			m_copyback(m, 0, clen, content);
			if (m->m_pkthdr.len != (int)clen ||
			    (out = kmem_intr_alloc(sizeof(*out),
			    KM_NOSLEEP)) == NULL) {
				m_freem(m);
				break;
			}
			out->dg_m = m;
			out->dg_peer = p;
			out->dg_plain = false;
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
		case TLS13_CT_HANDSHAKE:
			dtls_hs_input(p, content, clen, epoch,
			    p->dp_rxnexton && epoch == p->dp_rxnext.dd_epoch ?
			    p->dp_rxnext.dd_last : p->dp_rx.dd_last, &c);
			break;
		case TLS13_CT_ACK:
			mutex_enter(&p->dp_txlock);
			for (u_int i = 0; i < p->dp_npendrn; i++) {
				if (dtls13_ack_has(content, clen,
				    p->dp_pendrn[i][0],
				    p->dp_pendrn[i][1]) == 1)
					c.c_acked = true;
			}
			mutex_exit(&p->dp_txlock);
			break;
		default:
			/* RFC 8446 s5: an unknown type */
			c.c_alert = ONCRPC_TLS_UNEXPECTED_MESSAGE;
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
	} else if (any)
		dtls_ctl(d, p, &c);
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
	bool plain;

	/*
	 * One worker at d_q at a time, so that its datagrams are taken in
	 * the order they came: a closure takes effect before what followed
	 * it, RFC 9289 s5.1.2.  The others serve what is opened.
	 */
	for (;;) {
		mutex_enter(&d->d_lock);
		if ((dg = SIMPLEQ_FIRST(&d->d_msgs)) != NULL) {
			SIMPLEQ_REMOVE_HEAD(&d->d_msgs, dg_next);
			mutex_exit(&d->d_lock);
			break;
		}
		if (d->d_opening || (dg = SIMPLEQ_FIRST(&d->d_q)) == NULL) {
			mutex_exit(&d->d_lock);
			return NULL;
		}
		SIMPLEQ_REMOVE_HEAD(&d->d_q, dg_next);
		d->d_qlen--;
		d->d_opening = true;
		p = dg->dg_peer;
		if (dg->dg_plain) {
			/* Plain RPC unless a closure came before it. */
			if (p->dp_state == DP_ESTABLISHED) {
				SIMPLEQ_INSERT_TAIL(&d->d_msgs, dg, dg_next);
				dg = NULL;
			}
			d->d_opening = false;
			mutex_exit(&d->d_lock);
			if (dg != NULL) {
				m_freem(dg->dg_m);
				oncrpc_dtls_rele(p);
				kmem_intr_free(dg, sizeof(*dg));
			}
			continue;
		}
		p->dp_refs++;		/* past dtls_open_dgram() */
		mutex_exit(&d->d_lock);
		dtls_open_dgram(d, dg);	/* releases dg and its reference */
		mutex_enter(&d->d_lock);
		KASSERT(p->dp_qn > 0);
		p->dp_qn--;
		d->d_opening = false;
		mutex_exit(&d->d_lock);
		oncrpc_dtls_rele(p);
	}

	m = dg->dg_m;
	p = dg->dg_peer;
	plain = dg->dg_plain;
	kmem_intr_free(dg, sizeof(*dg));
	sa = (const struct sockaddr *)&p->dp_addr;
	nam = m_get(M_WAIT, MT_SONAME);
	KASSERT(sa->sa_len <= MLEN);
	memcpy(mtod(nam, void *), sa, sa->sa_len);
	nam->m_len = sa->sa_len;
	*namp = nam;
	if (plain) {
		oncrpc_dtls_rele(p);
		p = NULL;	/* not over DTLS, for oncrpc_req_tls() */
	}
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
	np->dp_hashed = true;
	np->dp_id = atomic_inc_64_nv(&dtls_nextid) | ONCRPC_DTLS_COOKIE;
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
static int
dtls_establish(struct oncrpc_dtlspeer *p, const uint8_t *csecret,
    const uint8_t *ssecret, const uint8_t *rcid, size_t rcidlen,
    const uint8_t *tcid, size_t tcidlen, const uint8_t *exporter,
    uint16_t hstx, uint16_t hsrx, uint64_t txseq, uint64_t rxseq)
{
	struct oncrpc_dtls *d = p->dp_dtls;

	/* s4.2.1: sequence numbers stop at 2^48. */
	if (rcidlen > DTLS13_MAXCID || tcidlen > DTLS13_MAXCID ||
	    txseq >= (1ULL << 48) || rxseq >= (1ULL << 48))
		return EINVAL;
#ifndef ONCRPC_DTLS_NOCID
	/*
	 * RFC 9289 s5.1.2: "each DTLS handshake MUST include the
	 * connection_id(54) extension ... and RPC-with-DTLS peer endpoints
	 * MUST provide a ConnectionID with a nonzero length."
	 */
	if (rcidlen == 0 || tcidlen == 0)
		return EPROTONOSUPPORT;
#endif
	mutex_enter(&d->d_lock);
	if (!p->dp_hashed || dtls_expired(p) || p->dp_state != DP_HANDSHAKE) {
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
	p->dp_hstx = hstx;
	p->dp_hsrx = hsrx;
	/*
	 * The daemon may have used epoch 3 already, for the ACK of the
	 * client's Finished that s7 makes a MUST: a sequence number used
	 * again would repeat a GCM nonce.  What it read is taken as seen,
	 * so the replay window refuses it again, s4.5.1.
	 */
	p->dp_tx.dd_seq = txseq;
	if (rxseq != 0) {
		p->dp_rx.dd_any = true;
		p->dp_rx.dd_top = rxseq - 1;
		p->dp_rx.dd_window = rxseq >= DTLS13_WINDOW ? ~0ULL :
		    (1ULL << rxseq) - 1;
	}
	p->dp_rto = ONCRPC_DTLS_RTO0;
	dtls_dgramq_free(&p->dp_hsq);
	p->dp_hsqlen = 0;
	dtls_unpair(p);
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
	if (last)
		dtls_peer_free(p);
	mutex_exit(&d->d_lock);
}

/*
 * The largest datagram payload toward sa, for the handshake's records,
 * RFC 9147 s4.4: the path MTU of the route, less the IP and UDP headers.
 * Without a route, IPv6's minimum link MTU, RFC 8200 s5, which IPv4
 * paths in practice also carry.
 */
static uint32_t
dtls_pmtu(const struct sockaddr *sa)
{
	struct rtentry *rt;
	uint64_t mtu = 1280;		/* RFC 8200 s5 */
	uint32_t hdr;

	hdr = (sa->sa_family == AF_INET6 ? sizeof(struct ip6_hdr) :
	    sizeof(struct ip)) + sizeof(struct udphdr);
	rt = rtalloc1(sa, 1);
	if (rt != NULL) {
		if (rt->rt_rmx.rmx_mtu != 0)
			mtu = rt->rt_rmx.rmx_mtu;
		else if (rt->rt_ifp != NULL)
			mtu = rt->rt_ifp->if_mtu;
		rt_unref(rt);
	}
	if (mtu > IP_MAXPACKET)
		mtu = IP_MAXPACKET;
	return mtu > hdr ? (uint32_t)(mtu - hdr) : 0;
}

/* The pair's end that is ours has something, or room. */
static void
dtls_kupcall(struct socket *so, void *arg, int events, int waitflag)
{
	struct oncrpc_dtls *d = arg;

	mutex_enter(&d->d_lock);
	dtls_kick(d);
	mutex_exit(&d->d_lock);
}

static void
dtls_reapall(struct oncrpc_dtls *d)
{
	struct dtls_reap *dr;

	for (;;) {
		mutex_enter(&d->d_lock);
		dr = SIMPLEQ_FIRST(&d->d_reap);
		if (dr != NULL)
			SIMPLEQ_REMOVE_HEAD(&d->d_reap, dr_next);
		mutex_exit(&d->d_lock);
		if (dr == NULL)
			return;
		solock(dr->dr_so);
		dr->dr_so->so_upcall = NULL;
		dr->dr_so->so_upcallarg = NULL;
		dr->dr_so->so_rcv.sb_flags &= ~SB_UPCALL;
		sounlock(dr->dr_so);
		(void)soclose(dr->dr_so);
		kmem_free(dr, sizeof(*dr));
	}
}

/*
 * Carry one peer's handshake datagrams across the pair: the peer's in,
 * the daemon's out of the UDP socket.  A datagram either way is whole,
 * as SOCK_DGRAM keeps it.
 */
static void
dtls_carry(struct oncrpc_dtls *d, struct oncrpc_dtlspeer *p)
{
	struct dtls_dgram *dg;
	struct socket *kso;
	struct mbuf *m;
	struct uio uio;
	int flags;

	for (;;) {
		mutex_enter(&d->d_lock);
		kso = p->dp_kso;
		dg = SIMPLEQ_FIRST(&p->dp_hsq);
		if (dg != NULL && kso != NULL) {
			SIMPLEQ_REMOVE_HEAD(&p->dp_hsq, dg_next);
			p->dp_hsqlen--;
		} else
			dg = NULL;
		mutex_exit(&d->d_lock);
		if (dg == NULL)
			break;
		/* Lost if the daemon does not read: as on the wire. */
		(void)(*kso->so_send)(kso, NULL, NULL, dg->dg_m, NULL,
		    MSG_DONTWAIT, curlwp);
		kmem_intr_free(dg, sizeof(*dg));
	}
	if (kso == NULL)
		return;
	for (;;) {
		m = NULL;
		memset(&uio, 0, sizeof(uio));
		uio.uio_resid = IP_MAXPACKET;
		flags = MSG_DONTWAIT;
		(void)(*kso->so_receive)(kso, NULL, &uio, &m, NULL, &flags);
		if (m == NULL)
			break;
		(void)(*d->d_so->so_send)(d->d_so,
		    (struct sockaddr *)&p->dp_addr, NULL, m, NULL, 0, curlwp);
	}
}

/* The retransmission timer: d_work looks at what is due. */
static void
dtls_tick(void *arg)
{
	struct oncrpc_dtls *d = arg;

	mutex_enter(&d->d_lock);
	dtls_kick(d);
	if (d->d_npend != 0 && !d->d_dying)
		callout_schedule(&d->d_tick, ONCRPC_DTLS_TICK);
	mutex_exit(&d->d_lock);
}

/* A pending message whose time came: s5.8.2, or the end of the peer. */
static void
dtls_retransmit(struct oncrpc_dtls *d, struct oncrpc_dtlspeer *p)
{
	struct dtls_out o;
	bool giveup = false;

	o.o_n = 0;
	mutex_enter(&p->dp_txlock);
	if (p->dp_pendlen != 0 && getticks() - p->dp_due >= 0) {
		if (++p->dp_tries > ONCRPC_DTLS_MAXRETX) {
			dtls_unpend(p);
			giveup = true;
		} else {
			p->dp_rto = MIN(p->dp_rto * 2, ONCRPC_DTLS_RTOMAX);
			dtls_send_pend(p, &o);
		}
	}
	mutex_exit(&p->dp_txlock);
	dtls_flush(p, &o);
	if (giveup) {
		mutex_enter(&d->d_lock);
		if (p->dp_state == DP_ESTABLISHED)
			dtls_close(p);
		mutex_exit(&d->d_lock);
	}
}

static void
dtls_work(struct work *wk, void *arg)
{
	struct oncrpc_dtls *d = arg;
	struct oncrpc_dtlspeer *p, **v;
	u_int i, n, nv;

	mutex_enter(&d->d_lock);
	d->d_workq = false;
	nv = d->d_npeers;
	mutex_exit(&d->d_lock);
	v = nv != 0 ? kmem_alloc(nv * sizeof(*v), KM_SLEEP) : NULL;
	n = 0;
	mutex_enter(&d->d_lock);
	for (i = 0; i < ONCRPC_DTLS_NHASH; i++) {
		LIST_FOREACH(p, &d->d_hash[i], dp_hash) {
			if (n == nv || (p->dp_kso == NULL && !p->dp_txpend))
				continue;
			p->dp_refs++;
			v[n++] = p;
		}
	}
	mutex_exit(&d->d_lock);
	for (i = 0; i < n; i++) {
		dtls_carry(d, v[i]);
		dtls_retransmit(d, v[i]);
		oncrpc_dtls_rele(v[i]);
	}
	if (v != NULL)
		kmem_free(v, nv * sizeof(*v));
	/* After the carrying, which may have been using these. */
	dtls_reapall(d);
	if (n == nv && nv != 0) {
		/* Peers may have come since d_npeers was read. */
		mutex_enter(&d->d_lock);
		dtls_kick(d);
		mutex_exit(&d->d_lock);
	}
}

/*
 * For the handshake daemon in oncrpc_tls_wait(): a peer whose
 * ClientHello came, as a new descriptor of the calling process, one end
 * of an AF_LOCAL datagram pair, with the cookie oncrpc_dtls_done() is to
 * name it by.  ENOENT if there is none.
 */
int
oncrpc_dtls_take(uint64_t *cookiep, int *fdp, struct oncrpc_tls_dgram *td)
{
	struct oncrpc_dtlspeer *p;
	struct oncrpc_dtls *d;
	struct socket *dso, *kso;
	struct dtls_reap *dr;
	file_t *fp;
	bool more;
	int error, fd;

	mutex_enter(&dtls_glock);
	p = LIST_FIRST(&dtls_ready);
	if (p == NULL) {
		mutex_exit(&dtls_glock);
		return ENOENT;
	}
	LIST_REMOVE(p, dp_glist);
	more = !LIST_EMPTY(&dtls_ready);
	mutex_exit(&dtls_glock);
	if (more && dtls_readyfn != NULL)
		(*dtls_readyfn)();	/* for the next daemon */
	d = p->dp_dtls;

	error = fsocreate(AF_LOCAL, &dso, SOCK_DGRAM, 0, &fd, &fp, NULL);
	if (error != 0)
		goto fail;
	error = socreate(AF_LOCAL, &kso, SOCK_DGRAM, 0, curlwp, dso);
	if (error != 0) {
		fd_abort(curproc, fp, fd);
		goto fail;
	}
	solock(dso);
	error = soconnect2(dso, kso);
	if (error == 0)
		error = soconnect2(kso, dso);	/* asymmetric, as socketpair */
	if (error == 0) {
		kso->so_upcallarg = d;
		kso->so_upcall = dtls_kupcall;
		kso->so_rcv.sb_flags |= SB_UPCALL;
	}
	sounlock(dso);
	if (error != 0) {
		(void)soclose(kso);
		fd_abort(curproc, fp, fd);
		goto fail;
	}
	dr = kmem_zalloc(sizeof(*dr), KM_SLEEP);

	mutex_enter(&d->d_lock);
	if (!p->dp_hashed || dtls_expired(p) || p->dp_state != DP_PROBED) {
		mutex_exit(&d->d_lock);
		kmem_free(dr, sizeof(*dr));
		(void)soclose(kso);
		fd_abort(curproc, fp, fd);
		error = ESRCH;
		goto fail;
	}
	p->dp_state = DP_HANDSHAKE;
	p->dp_until = time_uptime + ONCRPC_DTLS_HSWAIT;
	p->dp_kso = kso;
	p->dp_reap = dr;
	dtls_kick(d);			/* the ClientHello, into the pair */
	mutex_exit(&d->d_lock);

	td->td_is = true;
	td->td_pmtu = dtls_pmtu((const struct sockaddr *)&p->dp_addr);
	memcpy(&td->td_peer, &p->dp_addr, sizeof(td->td_peer));
	*cookiep = p->dp_id;
	mutex_enter(&dtls_glock);
	LIST_INSERT_HEAD(&dtls_busy, p, dp_glist);	/* the list's ref */
	mutex_exit(&dtls_glock);
	fd_affix(curproc, fp, fd);
	*fdp = fd;
	return 0;

fail:
	oncrpc_dtls_rele(p);
	return error;
}

/* Whether cookie names a datagram association. */
bool
oncrpc_dtls_cookie(uint64_t cookie)
{

	return (cookie & ONCRPC_DTLS_COOKIE) != 0;
}

/*
 * The daemon's verdict on the association named by cookie, as
 * oncrpc_tls_done() for a stream.  A handshake that failed leaves the
 * 5-tuple discarded for a while, RFC 9289 s5.1.2, as after a closure.
 */
int
oncrpc_dtls_done(uint64_t cookie, int error, const struct oncrpc_tls_params *tp)
{
	struct oncrpc_dtlspeer *p;
	struct oncrpc_dtls *d;
	int rv;

	mutex_enter(&dtls_glock);
	LIST_FOREACH(p, &dtls_busy, dp_glist) {
		if (p->dp_id == cookie)
			break;
	}
	if (p != NULL)
		LIST_REMOVE(p, dp_glist);
	mutex_exit(&dtls_glock);
	if (p == NULL)
		return ESRCH;
	d = p->dp_dtls;

	rv = 0;
	if (error == 0 && tp != NULL) {
		/* Only the suite RFC 8446 s9.1 makes mandatory, as TLS. */
		if (tp->tp_suite != TLS13_AES_128_GCM_SHA256 ||
		    tp->tp_secretlen != TLS13_SECRETLEN)
			rv = EPROTONOSUPPORT;
		else
			rv = dtls_establish(p, tp->tp_csecret, tp->tp_ssecret,
			    tp->tp_rcid, tp->tp_rcidlen, tp->tp_tcid,
			    tp->tp_tcidlen, tp->tp_exporter, tp->tp_hstxseq,
			    tp->tp_hsrxseq, tp->tp_txseq, tp->tp_rxseq);
	} else if (error == 0)
		rv = EINVAL;
	if (error != 0 || rv != 0) {
		mutex_enter(&d->d_lock);
		if (p->dp_hashed)
			dtls_close(p);
		mutex_exit(&d->d_lock);
	}
	oncrpc_dtls_rele(p);
	return rv;
}

/* ready() is called when a peer goes on dtls_ready, from softint. */
void
oncrpc_dtls_init(void (*ready)(void))
{

	mutex_init(&dtls_glock, MUTEX_DEFAULT, IPL_NONE);
	dtls_readyfn = ready;
}

void
oncrpc_dtls_fini(void)
{

	KASSERT(LIST_EMPTY(&dtls_ready) && LIST_EMPTY(&dtls_busy));
	mutex_destroy(&dtls_glock);
}
