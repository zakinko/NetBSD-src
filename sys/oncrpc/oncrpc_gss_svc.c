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
 * RPCSEC_GSS on the server, RFC 2203 and RFC 5403.
 *
 * A context is built by gssd(8), which has the keytab and Heimdal: the
 * token of a creation request goes up over a local socket, and what
 * comes back with the last answer is the context's key.  From then on
 * every message is handled here, with gss_krb5.c.  Nothing is known of
 * NFS: a program sees rq_cred and rq_secflavor, and its arguments and
 * results in the clear.
 *
 * A context is found by its handle, which is random and means nothing
 * else.  gss_lock covers the table and the list by age; a context has
 * its own lock for the window.  A call holds a reference from
 * oncrpc_gss_accept() to oncrpc_gss_done(), so a context can leave the
 * table with calls in progress.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/cprng.h>
#include <sys/errno.h>
#include <sys/kauth.h>
#include <sys/kmem.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/sha2.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/uio.h>

#include <oncrpc/gss_krb5.h>
#include <oncrpc/oncrpc_gss.h>
#include <oncrpc/oncrpc_gssd.h>
#include <oncrpc/oncrpc_var.h>

/*
 * Chosen.  RFC 2203 s5.4 asks for an LRU or aging, as a client need
 * never say it has finished.  An unfinished context gets a minute.  A
 * creation token past the limit is not a Kerberos one.
 */
#define	GSS_MAXCTX		16384
#define	GSS_HASHSIZE		1024
#define	GSS_HANDLELEN		16
#define	GSS_INITLIFE		60
#define	GSS_MAXTOKEN		ONCRPC_GSSD_MAXTOKEN

struct oncrpc_gss_ctx {
	LIST_ENTRY(oncrpc_gss_ctx) gx_hash;
	TAILQ_ENTRY(oncrpc_gss_ctx) gx_age;
	u_int		gx_refs;
	bool		gx_intable;
	bool		gx_complete;
	uint8_t		gx_handle[GSS_HANDLELEN];
	uint32_t	gx_vers;	/* of the credential that created it */
	uint32_t	gx_xid;		/* of the creation request */
	uint8_t		gx_tokensum[SHA256_DIGEST_LENGTH];
	uint64_t	gx_dh;		/* gssd's, until complete */
	time_t		gx_expire;	/* time_uptime */
	kmutex_t	gx_lock;	/* gx_seq */
	struct oncrpc_gss_seq gx_seq;
	struct gss_krb5_ctx *gx_krb;
	kauth_cred_t	gx_cred;	/* NULL for a principal with no user */
	bool		gx_used;	/* gx_initres is not needed any more */
	void		*gx_initres;	/* for a retransmitted request */
	size_t		gx_initreslen;
};

static kmutex_t gss_lock;
static LIST_HEAD(, oncrpc_gss_ctx) gss_hash[GSS_HASHSIZE];
static TAILQ_HEAD(oncrpc_gss_ctxq, oncrpc_gss_ctx) gss_age;	/* oldest use first */
static u_int gss_nctx;

void
oncrpc_gss_init(void)
{
	u_int i;

	mutex_init(&gss_lock, MUTEX_DEFAULT, IPL_NONE);
	for (i = 0; i < GSS_HASHSIZE; i++)
		LIST_INIT(&gss_hash[i]);
	TAILQ_INIT(&gss_age);
}

static u_int
gss_hashof(const uint8_t *h)
{

	return be32dec(h) % GSS_HASHSIZE;
}

static void
gss_ctx_free(struct oncrpc_gss_ctx *gx)
{

	if (gx->gx_krb != NULL)
		gss_krb5_ctx_destroy(gx->gx_krb);
	if (gx->gx_cred != NULL)
		kauth_cred_free(gx->gx_cred);
	if (gx->gx_initres != NULL)
		kmem_free(gx->gx_initres, gx->gx_initreslen);
	mutex_destroy(&gx->gx_lock);
	kmem_free(gx, sizeof(*gx));
}

static void
gss_ctx_rele(struct oncrpc_gss_ctx *gx)
{
	bool last;

	mutex_enter(&gss_lock);
	KASSERT(gx->gx_refs > 0);
	last = --gx->gx_refs == 0;
	mutex_exit(&gss_lock);
	if (last)
		gss_ctx_free(gx);
}

/* Off the table; the table's reference is the caller's to drop. */
static void
gss_ctx_unhash(struct oncrpc_gss_ctx *gx)
{

	KASSERT(mutex_owned(&gss_lock));
	KASSERT(gx->gx_intable);
	gx->gx_intable = false;
	LIST_REMOVE(gx, gx_hash);
	TAILQ_REMOVE(&gss_age, gx, gx_age);
	gss_nctx--;
}

void
oncrpc_gss_fini(void)
{
	struct oncrpc_gss_ctx *gx;

	mutex_enter(&gss_lock);
	while ((gx = TAILQ_FIRST(&gss_age)) != NULL) {
		gss_ctx_unhash(gx);
		KASSERT(gx->gx_refs == 1);
		gss_ctx_free(gx);
	}
	mutex_exit(&gss_lock);
	mutex_destroy(&gss_lock);
}

static struct oncrpc_gss_ctx *
gss_ctx_lookup(const struct oncrpc_gss_cred *gc)
{
	struct oncrpc_gss_ctx *gx;

	if (gc->gc_handlelen != GSS_HANDLELEN)
		return NULL;
	mutex_enter(&gss_lock);
	LIST_FOREACH(gx, &gss_hash[gss_hashof(gc->gc_handle)], gx_hash) {
		if (memcmp(gx->gx_handle, gc->gc_handle, GSS_HANDLELEN) == 0) {
			gx->gx_refs++;
			TAILQ_REMOVE(&gss_age, gx, gx_age);
			TAILQ_INSERT_TAIL(&gss_age, gx, gx_age);
			break;
		}
	}
	mutex_exit(&gss_lock);
	return gx;
}

static void
gss_ctx_insert(struct oncrpc_gss_ctx *gx)
{
	struct oncrpc_gss_ctx *old, *dead = NULL;

	mutex_enter(&gss_lock);
	/* RFC 2203 s5.4: what has run out, and the longest idle if full. */
	old = TAILQ_FIRST(&gss_age);
	if (old != NULL &&
	    (gss_nctx >= GSS_MAXCTX || old->gx_expire <= time_uptime)) {
		gss_ctx_unhash(old);
		if (--old->gx_refs == 0)
			dead = old;
	}
	gx->gx_refs++;
	gx->gx_intable = true;
	LIST_INSERT_HEAD(&gss_hash[gss_hashof(gx->gx_handle)], gx, gx_hash);
	TAILQ_INSERT_TAIL(&gss_age, gx, gx_age);
	gss_nctx++;
	mutex_exit(&gss_lock);
	if (dead != NULL)
		gss_ctx_free(dead);
}

/*
 * The creation request retransmitted, RFC 2203 s5.2.3.1 says nothing of
 * it: Kerberos would see the replay of an authenticator and say no,
 * failing a client whose only trouble was a lost reply.  The answer is
 * sent again, until the context is used.
 */
static struct oncrpc_gss_ctx *
gss_ctx_retransmit(uint32_t xid, const uint8_t *sum)
{
	struct oncrpc_gss_ctx *gx;

	mutex_enter(&gss_lock);
	TAILQ_FOREACH_REVERSE(gx, &gss_age, oncrpc_gss_ctxq, gx_age) {
		if (gx->gx_initres != NULL && !gx->gx_used &&
		    gx->gx_xid == xid &&
		    memcmp(gx->gx_tokensum, sum, sizeof(gx->gx_tokensum)) == 0) {
			gx->gx_refs++;
			break;
		}
	}
	mutex_exit(&gss_lock);
	return gx;
}

/*
 * The length of a message.  Not m_length(), which believes the packet
 * header, and that of a stream's record is of its first segment.
 */
static u_int
gss_chainlen(const struct mbuf *m)
{
	u_int len = 0;

	for (; m != NULL; m = m->m_next)
		len += m->m_len;
	return len;
}

/* len bytes of the chain from off, in new memory.  False if it is short. */
static bool
gss_copyin(struct mbuf *m, u_int off, uint32_t len, u_int total, void **bufp)
{

	if (off > total || len > total - off)
		return false;
	*bufp = kmem_alloc(MAX(len, 1), KM_SLEEP);
	m_copydata(m, off, len, *bufp);
	return true;
}

static uint32_t
gss_get32(struct mbuf *m, u_int off)
{
	uint32_t v;

	m_copydata(m, off, sizeof(v), &v);
	return ntohl(v);
}

/* A new chain of a copy of the bytes. */
static struct mbuf *
gss_mbufof(const void *p, size_t len)
{
	struct oncrpc_xdrmbuf x;
	struct mbuf *m;

	if (len == 0) {
		m = m_gethdr(M_WAIT, MT_DATA);
		m->m_len = m->m_pkthdr.len = 0;
		return m;
	}
	oncrpc_xdrmbuf_create(&x, NULL, len + 4, XDR_ENCODE);
	if (!xdr_opaque(&x.xm_xdr, __UNCONST(p), len)) {
		XDR_DESTROY(&x.xm_xdr);
		return NULL;
	}
	oncrpc_xdrmbuf_truncate(&x.xm_xdr, len);
	return oncrpc_xdrmbuf_detach(&x);
}

/* The header as signed, RFC 2203 s5.3.1: from the xid to the credential. */
static size_t
gss_header(const struct oncrpc_call *c, uint8_t *buf)
{
	uint32_t *p = (uint32_t *)buf;
	size_t len;

	*p++ = htonl(c->c_xid);
	*p++ = htonl(ONCRPC_CALL);
	*p++ = htonl(ONCRPC_VERS);
	*p++ = htonl(c->c_prog);
	*p++ = htonl(c->c_vers);
	*p++ = htonl(c->c_proc);
	*p++ = htonl(c->c_cred.oa_flavor);
	*p++ = htonl(c->c_cred.oa_len);
	len = roundup(c->c_cred.oa_len, 4);
	memset(p, 0, len);
	memcpy(p, c->c_cred.oa_body, c->c_cred.oa_len);
	return 8 * sizeof(uint32_t) + len;
}

static bool
gss_mic_of32(struct oncrpc_gss_call *gg, struct gss_krb5_ctx *krb, uint32_t v)
{
	size_t len;

	v = htonl(v);
	if (gss_krb5_get_mic(krb, &v, sizeof(v), gg->gg_verfbody,
	    sizeof(gg->gg_verfbody), &len) != GSS_S_COMPLETE)
		return false;
	gg->gg_verf = RPCSEC_GSS;
	gg->gg_verflen = len;
	return true;
}

/* RFC 2203 s5.2.3.1, struct rpc_gss_init_res */
static struct mbuf *
gss_init_res(const struct oncrpc_gss_ctx *gx, uint32_t major, uint32_t minor,
    const void *token, uint32_t tokenlen, void **savep, size_t *savelen)
{
	bool good = major == GSS_S_COMPLETE ||
	    major == RPCSEC_GSS_S_CONTINUE_NEEDED;
	uint32_t hlen = good ? GSS_HANDLELEN : 0, window = RPCSEC_GSS_WINDOW;
	uint32_t tlen = good ? tokenlen : 0;
	size_t len = 24 + hlen + roundup(tlen, 4);
	uint8_t *buf;
	uint32_t *p;
	struct mbuf *m;

	buf = kmem_zalloc(len, KM_SLEEP);
	p = (uint32_t *)buf;
	*p++ = htonl(hlen);
	if (good)
		memcpy(p, gx->gx_handle, hlen);
	p += hlen / sizeof(*p);
	*p++ = htonl(major);
	*p++ = htonl(minor);
	*p++ = htonl(window);
	*p++ = htonl(tlen);
	if (tlen != 0)
		memcpy(p, token, tlen);
	m = gss_mbufof(buf, len);
	if (savep != NULL && m != NULL) {
		*savep = buf;
		*savelen = len;
	} else
		kmem_free(buf, len);
	return m;
}

/* The key and the user of a finished context. */
static int
gss_ctx_complete(struct oncrpc_gss_ctx *gx, struct oncrpc_gssd_accept_res *ar)
{
	gid_t gids[ONCRPC_GSSD_MAXGROUPS];
	kauth_cred_t cred;
	uint32_t i;
	int error;

	error = gss_krb5_ctx_create(&ar->ar_import, &gx->gx_krb);
	explicit_memset(&ar->ar_import, 0, sizeof(ar->ar_import));
	if (error != 0)
		return error;
	gx->gx_expire = time_uptime + MIN(ar->ar_lifetime, 86400U * 365);
	if (ar->ar_mapped) {
		cred = kauth_cred_alloc();
		kauth_cred_setuid(cred, ar->ar_uid);
		kauth_cred_seteuid(cred, ar->ar_uid);
		kauth_cred_setsvuid(cred, ar->ar_uid);
		kauth_cred_setgid(cred, ar->ar_gid);
		kauth_cred_setegid(cred, ar->ar_gid);
		kauth_cred_setsvgid(cred, ar->ar_gid);
		for (i = 0; i < ar->ar_ngroups; i++)
			gids[i] = ar->ar_groups[i];
		if (ar->ar_ngroups > 0)
			kauth_cred_setgroups(cred, gids, ar->ar_ngroups, -1,
			    UIO_SYSSPACE);
		gx->gx_cred = cred;
	}
	oncrpc_gss_seq_init(&gx->gx_seq);
	gx->gx_dh = 0;
	gx->gx_complete = true;
	return 0;
}

/*
 * RPCSEC_GSS_INIT and CONTINUE_INIT, RFC 2203 s5.2.  A failure of the
 * mechanism or of the way to it is a major status in a successful RPC
 * reply; neither new auth_stat may be used here, s5.2.3.2.
 */
static enum oncrpc_gss_verdict
gss_create(struct oncrpc_gss_call *gg, const struct oncrpc_call *c,
    struct oncrpc_xdrmbuf *args, struct mbuf *msg, struct mbuf **resp,
    uint32_t *whyp)
{
	struct oncrpc_gss_cred *gc = &gg->gg_cred;
	struct oncrpc_gss_ctx *gx = NULL;
	struct oncrpc_gssd_accept_res *ar;
	uint8_t sum[SHA256_DIGEST_LENGTH];
	SHA256_CTX sc;
	void *token = NULL, *save = NULL;
	size_t savelen = 0;
	uint32_t tlen, major, minor = 0;
	u_int pos, total;
	int error;

	/* s5.2.2 */
	if (c->c_proc != 0) {
		*whyp = ONCRPC_AUTH_BADCRED;
		return ONCRPC_GSS_DENY;
	}
	if (c->c_verf.oa_flavor != ONCRPC_AUTH_NONE) {
		*whyp = ONCRPC_AUTH_BADVERF;
		return ONCRPC_GSS_DENY;
	}

	pos = XDR_GETPOS(&args->xm_xdr);
	total = gss_chainlen(msg);
	if (pos + 4 > total)
		return ONCRPC_GSS_GARBAGE;
	tlen = gss_get32(msg, pos);
	if (tlen > GSS_MAXTOKEN ||
	    !gss_copyin(msg, pos + 4, tlen, total, &token))
		return ONCRPC_GSS_GARBAGE;

	SHA256_Init(&sc);
	SHA256_Update(&sc, token, tlen);
	SHA256_Final(sum, &sc);
	if (gc->gc_proc == RPCSEC_GSS_INIT &&
	    (gx = gss_ctx_retransmit(c->c_xid, sum)) != NULL) {
		kmem_free(token, MAX(tlen, 1));
		*resp = gss_mbufof(gx->gx_initres, gx->gx_initreslen);
		if (gx->gx_complete &&
		    !gss_mic_of32(gg, gx->gx_krb, RPCSEC_GSS_WINDOW)) {
			gss_ctx_rele(gx);
			m_freem(*resp);
			*resp = NULL;
			return ONCRPC_GSS_DROP;
		}
		gss_ctx_rele(gx);
		return *resp != NULL ? ONCRPC_GSS_REPLY : ONCRPC_GSS_DROP;
	}

	if (gc->gc_proc == RPCSEC_GSS_CONTINUE_INIT) {
		gx = gss_ctx_lookup(gc);
		if (gx == NULL || gx->gx_complete ||
		    gx->gx_vers != gc->gc_vers) {
			if (gx != NULL)
				gss_ctx_rele(gx);
			kmem_free(token, MAX(tlen, 1));
			*resp = gss_init_res(NULL, GSS_S_NO_CONTEXT, 0, NULL, 0,
			    NULL, NULL);
			return *resp != NULL ? ONCRPC_GSS_REPLY :
			    ONCRPC_GSS_DROP;
		}
	} else {
		gx = kmem_zalloc(sizeof(*gx), KM_SLEEP);
		mutex_init(&gx->gx_lock, MUTEX_DEFAULT, IPL_NONE);
		gx->gx_refs = 1;
		gx->gx_vers = gc->gc_vers;
		cprng_strong(kern_cprng, gx->gx_handle, GSS_HANDLELEN, 0);
		gx->gx_expire = time_uptime + GSS_INITLIFE;
	}

	ar = kmem_zalloc(sizeof(*ar), KM_SLEEP);
	error = oncrpc_gssd_accept(gx->gx_dh, token, tlen, ar);
	kmem_free(token, MAX(tlen, 1));
	major = error != 0 ? GSS_S_FAILURE : ar->ar_major;
	if (error == 0)
		minor = ar->ar_minor;
	if (major == RPCSEC_GSS_S_CONTINUE_NEEDED)
		gx->gx_dh = ar->ar_dh;
	else if (major == GSS_S_COMPLETE &&
	    gss_ctx_complete(gx, ar) != 0)
		major = GSS_S_FAILURE;

	if (major == GSS_S_COMPLETE || major == RPCSEC_GSS_S_CONTINUE_NEEDED) {
		gx->gx_xid = c->c_xid;
		memcpy(gx->gx_tokensum, sum, sizeof(sum));
		*resp = gss_init_res(gx, major, minor, ar->ar_token,
		    ar->ar_tokenlen, &save, &savelen);
		if (major == GSS_S_COMPLETE && *resp != NULL &&
		    !gss_mic_of32(gg, gx->gx_krb, RPCSEC_GSS_WINDOW)) {
			m_freem(*resp);
			*resp = NULL;
		}
	} else
		*resp = gss_init_res(NULL, major, minor, NULL, 0, NULL, NULL);
	kmem_free(ar, sizeof(*ar));

	if (major != GSS_S_COMPLETE && major != RPCSEC_GSS_S_CONTINUE_NEEDED) {
		if (gc->gc_proc == RPCSEC_GSS_CONTINUE_INIT) {
			mutex_enter(&gss_lock);
			if (gx->gx_intable) {
				gss_ctx_unhash(gx);
				gx->gx_refs--;
			}
			mutex_exit(&gss_lock);
		}
		gss_ctx_rele(gx);
	} else {
		if (gx->gx_initres != NULL)
			kmem_free(gx->gx_initres, gx->gx_initreslen);
		gx->gx_initres = save;
		gx->gx_initreslen = savelen;
		if (gc->gc_proc == RPCSEC_GSS_INIT)
			gss_ctx_insert(gx);
		gss_ctx_rele(gx);
	}
	return *resp != NULL ? ONCRPC_GSS_REPLY : ONCRPC_GSS_DROP;
}

/*
 * The arguments under integrity, RFC 2203 s5.3.2.2: seq_num and the
 * arguments, then a MIC of those.  Replaces the message with the
 * arguments alone.
 */
static bool
gss_unwrap_integ(struct oncrpc_gss_call *gg, struct mbuf **msgp,
    struct oncrpc_xdrmbuf *args)
{
	struct mbuf *msg = *msgp, *n;
	uint8_t mic[GSS_KRB5_MAXMIC];
	void *body;
	u_int pos = XDR_GETPOS(&args->xm_xdr), total = gss_chainlen(msg);
	uint32_t blen, mlen;
	size_t off;
	bool ok = false;

	if (pos + 4 > total)
		return false;
	blen = gss_get32(msg, pos);
	if (blen < 4 || blen > total - pos - 4)
		return false;
	off = (size_t)pos + 4 + roundup((size_t)blen, 4);
	if (off + 4 > total)
		return false;
	mlen = gss_get32(msg, off);
	if (mlen > sizeof(mic) || off + 4 + mlen > total)
		return false;
	m_copydata(msg, off + 4, mlen, mic);
	if (!gss_copyin(msg, pos + 4, blen, total, &body))
		return false;
	if (gss_krb5_verify_mic(gg->gg_ctx->gx_krb, body, blen, mic, mlen) !=
	    GSS_S_COMPLETE ||
	    be32dec(body) != gg->gg_cred.gc_seq)
		goto out;
	n = gss_mbufof((char *)body + 4, blen - 4);
	if (n == NULL)
		goto out;
	m_freem(msg);
	*msgp = n;
	oncrpc_xdrmbuf_create(args, n, 0, XDR_DECODE);
	ok = true;
out:
	kmem_free(body, MAX(blen, 1));
	return ok;
}

/* And under privacy, s5.3.2.3. */
static bool
gss_unwrap_priv(struct oncrpc_gss_call *gg, struct mbuf **msgp,
    struct oncrpc_xdrmbuf *args)
{
	struct mbuf *msg = *msgp, *n;
	void *body, *plain;
	u_int pos = XDR_GETPOS(&args->xm_xdr), total = gss_chainlen(msg);
	uint32_t blen;
	size_t plen;
	bool conf, ok = false;

	if (pos + 4 > total)
		return false;
	blen = gss_get32(msg, pos);
	if (!gss_copyin(msg, pos + 4, blen, total, &body))
		return false;
	if (gss_krb5_unwrap(gg->gg_ctx->gx_krb, body, blen, NULL, &plain,
	    &plen, &conf) != GSS_S_COMPLETE || !conf || plen < 4 ||
	    be32dec(plain) != gg->gg_cred.gc_seq)
		goto out;
	n = gss_mbufof((char *)plain + 4, plen - 4);
	if (n == NULL)
		goto out;
	m_freem(msg);
	*msgp = n;
	oncrpc_xdrmbuf_create(args, n, 0, XDR_DECODE);
	ok = true;
out:
	explicit_memset(body, 0, MAX(blen, 1));
	kmem_free(body, MAX(blen, 1));
	return ok;
}

/*
 * RPCSEC_GSS_BIND_CHANNEL, RFC 5403 s3.3.  ONC RPC over plain TCP and
 * UDP is no secure channel, so there are no channel bindings here to
 * hash, and so nothing for rbcva_chan_mic to be checked against.  The
 * answer is RGSS2_BIND_CHAN_PREF_NOTSUPP with an empty list of prefixes,
 * which binds nothing.  It does not move the window: the request has
 * proved nothing.
 */
static enum oncrpc_gss_verdict
gss_bind_channel(struct oncrpc_gss_call *gg, struct mbuf **resp)
{
	uint32_t in[4], *v = (uint32_t *)gg->gg_verfbody;
	size_t len;

	in[0] = htonl(gg->gg_cred.gc_seq);
	in[1] = 0;				/* rbcmr_bind_chan_hash<0> */
	in[2] = htonl(1);			/* PREF_NOTSUPP */
	in[3] = 0;				/* rbcr_pref_list<0> */
	v[0] = in[2];
	v[1] = in[3];
	if (gss_krb5_get_mic(gg->gg_ctx->gx_krb, in, sizeof(in), v + 3,
	    sizeof(gg->gg_verfbody) - 3 * sizeof(*v), &len) != GSS_S_COMPLETE)
		return ONCRPC_GSS_DROP;
	v[2] = htonl(len);
	memset((char *)(v + 3) + len, 0, roundup(len, 4) - len);
	gg->gg_verf = RPCSEC_GSS;
	gg->gg_verflen = 3 * sizeof(*v) + roundup(len, 4);
	*resp = NULL;
	return ONCRPC_GSS_REPLY;
}

/*
 * Everything a request must pass, RFC 2203 s5.3.3.1, in that order, and
 * the destruction of s5.4.
 */
enum oncrpc_gss_verdict
oncrpc_gss_accept(struct oncrpc_gss_call *gg, const struct oncrpc_call *c,
    struct oncrpc_xdrmbuf *args, struct mbuf **msgp, struct oncrpc_req *rq,
    struct mbuf **resp, uint32_t *whyp)
{
	struct oncrpc_gss_cred *gc = &gg->gg_cred;
	struct oncrpc_gss_ctx *gx;
	uint8_t hdr[8 * sizeof(uint32_t) + ONCRPC_MAX_AUTH_BYTES];
	size_t hlen;
	XDR xdrs;
	bool ok;

	rq->rq_secflavor = RPCSEC_GSS;
	gg->gg_verf = ONCRPC_AUTH_NONE;
	xdrmem_create(&xdrs, __UNCONST(c->c_cred.oa_body), c->c_cred.oa_len,
	    XDR_DECODE);
	*whyp = oncrpc_gss_cred_decode(&xdrs, gc);
	if (*whyp != 0)
		return ONCRPC_GSS_DENY;

	if (gc->gc_proc == RPCSEC_GSS_INIT ||
	    gc->gc_proc == RPCSEC_GSS_CONTINUE_INIT)
		return gss_create(gg, c, args, *msgp, resp, whyp);

	/* s5.3.3.3: a handle we do not have, as after a reboot. */
	gx = gss_ctx_lookup(gc);
	if (gx == NULL || !gx->gx_complete) {
		if (gx != NULL)
			gss_ctx_rele(gx);
		*whyp = RPCSEC_GSS_CREDPROBLEM;
		return ONCRPC_GSS_DENY;
	}
	gg->gg_ctx = gx;
	*whyp = ONCRPC_AUTH_BADCRED;
	if (gx->gx_vers != gc->gc_vers)
		return ONCRPC_GSS_DENY;
	/* s5.4 and RFC 5403 s3.3: only NULLPROC carries a control message. */
	if (gc->gc_proc != RPCSEC_GSS_DATA && c->c_proc != 0)
		return ONCRPC_GSS_DENY;
	/*
	 * rpc_gss_svc_channel_prot needs a channel bound with
	 * RPCSEC_GSS_BIND_CHANNEL, RFC 5403 s3.4, and none ever is.
	 */
	if (gc->gc_service < RPCSEC_GSS_SVC_NONE ||
	    gc->gc_service > RPCSEC_GSS_SVC_PRIVACY)
		return ONCRPC_GSS_DENY;

	/* s5.3.3.3 */
	if (gc->gc_seq >= RPCSEC_GSS_MAXSEQ ||
	    gx->gx_expire <= time_uptime) {
		*whyp = RPCSEC_GSS_CTXPROBLEM;
		return ONCRPC_GSS_DENY;
	}

	if (gc->gc_proc == RPCSEC_GSS_BIND_CHANNEL)
		return gss_bind_channel(gg, resp);

	if (c->c_verf.oa_flavor != RPCSEC_GSS) {
		*whyp = RPCSEC_GSS_CREDPROBLEM;
		return ONCRPC_GSS_DENY;
	}
	hlen = gss_header(c, hdr);
	if (gss_krb5_verify_mic(gx->gx_krb, hdr, hlen, c->c_verf.oa_body,
	    c->c_verf.oa_len) != GSS_S_COMPLETE) {
		*whyp = RPCSEC_GSS_CREDPROBLEM;
		return ONCRPC_GSS_DENY;
	}

	/* After the MIC, s5.3.3.1: only a proven request moves the window. */
	mutex_enter(&gx->gx_lock);
	ok = oncrpc_gss_seq_accept(&gx->gx_seq, gc->gc_seq);
	mutex_exit(&gx->gx_lock);
	if (!ok)
		return ONCRPC_GSS_DROP;

	/* The client has the answer to its creation request. */
	gx->gx_used = true;

	if (gc->gc_proc == RPCSEC_GSS_DESTROY) {
		/* The reply is sent as to data; the MIC needs only the key. */
		mutex_enter(&gss_lock);
		if (gx->gx_intable) {
			gss_ctx_unhash(gx);
			gx->gx_refs--;
		}
		mutex_exit(&gss_lock);
		*resp = NULL;
		return ONCRPC_GSS_REPLY;
	}

	switch (gc->gc_service) {
	case RPCSEC_GSS_SVC_INTEGRITY:
		if (!gss_unwrap_integ(gg, msgp, args))
			return ONCRPC_GSS_GARBAGE;
		break;
	case RPCSEC_GSS_SVC_PRIVACY:
		if (!gss_unwrap_priv(gg, msgp, args))
			return ONCRPC_GSS_GARBAGE;
		break;
	}

	/* Each request its own, as a program may change it. */
	rq->rq_cred = gx->gx_cred != NULL ? kauth_cred_dup(gx->gx_cred) : NULL;
	rq->rq_secflavor = gc->gc_service == RPCSEC_GSS_SVC_NONE ?
	    RPCSEC_GSS_KRB5 : gc->gc_service == RPCSEC_GSS_SVC_INTEGRITY ?
	    RPCSEC_GSS_KRB5I : RPCSEC_GSS_KRB5P;
	return ONCRPC_GSS_DISPATCH;
}

/*
 * The verifier of a reply, s5.3.3.2.  One made already, by a creation
 * request or by BIND_CHANNEL, stays.
 */
bool
oncrpc_gss_verifier(struct oncrpc_gss_call *gg)
{

	if (gg->gg_verf == RPCSEC_GSS || gg->gg_ctx == NULL)
		return true;
	return gss_mic_of32(gg, gg->gg_ctx->gx_krb, gg->gg_cred.gc_seq);
}

/*
 * The results, s5.3.3.2: under integrity and privacy, the same shape as
 * the arguments.  With rpc_gss_svc_none they are left alone.  False if
 * they could not be sealed, s5.3.3.4.1 and .4, and then they are gone.
 */
bool
oncrpc_gss_wrap_results(struct oncrpc_gss_call *gg, struct mbuf **resp)
{
	struct gss_krb5_ctx *krb;
	struct oncrpc_xdrmbuf x;
	struct mbuf *res = *resp;
	uint8_t mic[GSS_KRB5_MAXMIC], *plain, *tok = NULL;
	size_t plen, tlen, toksz = 0;
	uint32_t len, mlen, seq;
	u_int rlen;
	bool ok = false;

	if (gg->gg_ctx == NULL ||
	    gg->gg_cred.gc_proc != RPCSEC_GSS_DATA ||
	    gg->gg_cred.gc_service == RPCSEC_GSS_SVC_NONE)
		return true;
	krb = gg->gg_ctx->gx_krb;

	rlen = res != NULL ? res->m_pkthdr.len : 0;
	plen = (size_t)rlen + 4;
	plain = kmem_alloc(plen, KM_SLEEP);
	seq = htonl(gg->gg_cred.gc_seq);
	memcpy(plain, &seq, 4);
	if (rlen != 0)
		m_copydata(res, 0, rlen, plain + 4);
	oncrpc_xdrmbuf_create(&x, NULL, UINT_MAX, XDR_ENCODE);

	if (gg->gg_cred.gc_service == RPCSEC_GSS_SVC_INTEGRITY) {
		size_t ml;

		if (gss_krb5_get_mic(krb, plain, plen, mic, sizeof(mic), &ml) !=
		    GSS_S_COMPLETE)
			goto out;
		len = plen;
		mlen = ml;
		ok = xdr_u_int32_t(&x.xm_xdr, &len) &&
		    xdr_opaque(&x.xm_xdr, (char *)plain, len) &&
		    xdr_u_int32_t(&x.xm_xdr, &mlen) &&
		    xdr_opaque(&x.xm_xdr, (char *)mic, mlen);
	} else {
		toksz = gss_krb5_wrap_size(krb, plen);
		if (toksz == SIZE_MAX)
			goto out;
		tok = kmem_alloc(toksz, KM_SLEEP);
		if (gss_krb5_wrap(krb, plain, plen, tok, toksz, &tlen) !=
		    GSS_S_COMPLETE)
			goto out;
		len = tlen;
		ok = xdr_u_int32_t(&x.xm_xdr, &len) &&
		    xdr_opaque(&x.xm_xdr, (char *)tok, len);
	}
out:
	explicit_memset(plain, 0, plen);
	kmem_free(plain, plen);
	if (tok != NULL)
		kmem_free(tok, toksz);
	m_freem(res);
	*resp = NULL;
	if (!ok) {
		XDR_DESTROY(&x.xm_xdr);
		return false;
	}
	*resp = oncrpc_xdrmbuf_detach(&x);
	return true;
}

void
oncrpc_gss_done(struct oncrpc_gss_call *gg)
{

	if (gg->gg_ctx != NULL) {
		gss_ctx_rele(gg->gg_ctx);
		gg->gg_ctx = NULL;
	}
}
