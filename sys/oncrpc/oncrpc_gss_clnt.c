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
 * RPCSEC_GSS as a client, for what the server itself calls: the
 * callbacks of NFSv4, RFC 7530 s3.3.3.  gssd(8) plays the initiator with
 * the server's keytab, and the tokens go to the peer as RFC 2203 s5.2
 * says.  Callbacks are rare and each has a connection of its own, so
 * each has a context of its own too, which leaves no state to keep for
 * a client that may be gone by the next one.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/mbuf.h>
#include <sys/systm.h>

#include <oncrpc/gss_krb5.h>
#include <oncrpc/oncrpc_gss.h>
#include <oncrpc/oncrpc_gssd.h>
#include <oncrpc/oncrpc_var.h>

struct oncrpc_gssc {
	struct gss_krb5_ctx *gc_krb;
	uint32_t	gc_service;
	uint32_t	gc_seq;		/* the last sent */
	uint32_t	gc_hlen;
	uint8_t		gc_handle[64];	/* its own limit, the peer's choice */
};

struct gssc_res {
	uint32_t	gr_hlen;
	uint8_t		gr_handle[64];
	uint32_t	gr_major;
	uint32_t	gr_minor;
	uint32_t	gr_window;
	uint32_t	gr_tlen;
	uint8_t		*gr_token;
	uint32_t	gr_tmax;
};

struct gssc_arg {
	const void	*ga_token;
	uint32_t	ga_len;
};

static bool
gssc_arg_enc(XDR *x, void *arg)
{
	struct gssc_arg *ga = arg;

	return xdr_u_int32_t(x, &ga->ga_len) && (ga->ga_len == 0 ||
	    xdr_opaque(x, __UNCONST(ga->ga_token), ga->ga_len));
}

/* RFC 2203 s5.2.3.1, struct rpc_gss_init_res */
static bool
gssc_res_dec(XDR *x, void *arg)
{
	struct gssc_res *gr = arg;

	return xdr_u_int32_t(x, &gr->gr_hlen) &&
	    gr->gr_hlen <= sizeof(gr->gr_handle) &&
	    xdr_opaque(x, (char *)gr->gr_handle, gr->gr_hlen) &&
	    xdr_u_int32_t(x, &gr->gr_major) &&
	    xdr_u_int32_t(x, &gr->gr_minor) &&
	    xdr_u_int32_t(x, &gr->gr_window) &&
	    xdr_u_int32_t(x, &gr->gr_tlen) &&
	    gr->gr_tlen <= gr->gr_tmax &&
	    (gr->gr_tlen == 0 ||
	    xdr_opaque(x, (char *)gr->gr_token, gr->gr_tlen));
}

/* The credential, RFC 2203 s5.  Returns its length. */
static uint32_t
gssc_cred(uint8_t *buf, uint32_t proc, uint32_t seq, uint32_t service,
    const uint8_t *handle, uint32_t hlen)
{
	uint32_t *p = (uint32_t *)buf;

	*p++ = htonl(RPCSEC_GSS_VERS_1);
	*p++ = htonl(proc);
	*p++ = htonl(seq);
	*p++ = htonl(service);
	*p++ = htonl(hlen);
	memset(p, 0, roundup(hlen, 4));
	memcpy(p, handle, hlen);
	return 20 + roundup(hlen, 4);
}

/*
 * A context with principal at the peer, at service, one of the
 * RPCSEC_GSS_SVC_*.  The verifier of the last reply proves the peer, the
 * mutual authentication s3.3.3 asks for.
 */
int
oncrpc_gssc_create(const struct sockaddr *to, uint32_t prog, uint32_t vers,
    const char *principal, uint32_t service, int timeo,
    struct oncrpc_gssc **gcp)
{
	struct oncrpc_gssd_accept_res *ar;
	struct oncrpc_clnt_call cc;
	struct oncrpc_opaque_auth *verf;
	struct oncrpc_gssc *gc = NULL;
	struct gssc_res gr;
	struct gssc_arg ga;
	uint8_t cred[20 + 64];
	uint32_t proc = RPCSEC_GSS_INIT, w;
	uint64_t dh = 0;
	bool first = true;
	int error, i;

	ar = kmem_zalloc(sizeof(*ar), KM_SLEEP);
	verf = kmem_zalloc(sizeof(*verf), KM_SLEEP);
	memset(&gr, 0, sizeof(gr));
	gr.gr_tmax = ONCRPC_GSSD_MAXTOKEN;
	gr.gr_token = kmem_alloc(gr.gr_tmax, KM_SLEEP);

	/* A context of more than a few rounds is no Kerberos context. */
	for (i = 0; i < 4; i++) {
		error = oncrpc_gssd_init(dh, principal, gr.gr_token,
		    first ? 0 : gr.gr_tlen, ar);
		if (error != 0)
			goto out;
		first = false;
		dh = ar->ar_dh;
		if (ar->ar_major != 0 &&
		    ar->ar_major != RPCSEC_GSS_S_CONTINUE_NEEDED) {
			error = EAUTH;
			goto out;
		}
		/* The last token was the peer's, and nothing is left to send. */
		if (ar->ar_major == 0 && proc == RPCSEC_GSS_CONTINUE_INIT)
			break;

		memset(&cc, 0, sizeof(cc));
		cc.cc_prog = prog;
		cc.cc_vers = vers;
		cc.cc_proc = 0;
		cc.cc_flavor = RPCSEC_GSS;
		cc.cc_cred = cred;
		cc.cc_credlen = gssc_cred(cred, proc, 0, RPCSEC_GSS_SVC_NONE,
		    gr.gr_handle, gr.gr_hlen);
		ga.ga_token = ar->ar_token;
		ga.ga_len = ar->ar_tokenlen;
		cc.cc_encode = gssc_arg_enc;
		cc.cc_arg = &ga;
		cc.cc_decode = gssc_res_dec;
		cc.cc_res = &gr;
		cc.cc_verfout = verf;
		error = oncrpc_clnt_call(to, &cc, timeo);
		if (error != 0)
			goto out;
		if (gr.gr_major != 0 &&
		    gr.gr_major != RPCSEC_GSS_S_CONTINUE_NEEDED) {
			error = EAUTH;
			goto out;
		}
		proc = RPCSEC_GSS_CONTINUE_INIT;
		if (ar->ar_major == 0 && gr.gr_major == 0)
			break;
	}
	if (ar->ar_major != 0 || gr.gr_major != 0) {
		error = EAUTH;
		goto out;
	}

	gc = kmem_zalloc(sizeof(*gc), KM_SLEEP);
	ar->ar_import.gi_initiator = true;
	error = gss_krb5_ctx_create(&ar->ar_import, &gc->gc_krb);
	if (error != 0) {
		kmem_free(gc, sizeof(*gc));
		goto out;
	}
	gc->gc_service = service;
	gc->gc_hlen = gr.gr_hlen;
	memcpy(gc->gc_handle, gr.gr_handle, gr.gr_hlen);

	/* s5.2.3.1: the checksum of the window, which proves the peer. */
	w = htonl(gr.gr_window);
	if (verf->oa_flavor != RPCSEC_GSS ||
	    gss_krb5_verify_mic(gc->gc_krb, &w, sizeof(w), verf->oa_body,
	    verf->oa_len) != GSS_S_COMPLETE) {
		oncrpc_gssc_destroy(gc);
		error = EAUTH;
		goto out;
	}
	*gcp = gc;
out:
	explicit_memset(ar, 0, sizeof(*ar));
	kmem_free(ar, sizeof(*ar));
	kmem_free(verf, sizeof(*verf));
	kmem_free(gr.gr_token, gr.gr_tmax);
	return error;
}

void
oncrpc_gssc_destroy(struct oncrpc_gssc *gc)
{

	gss_krb5_ctx_destroy(gc->gc_krb);
	kmem_free(gc, sizeof(*gc));
}

/*
 * The credential and verifier of a call, s5.3.1, for
 * oncrpc_msg_encode_call().
 */
bool
oncrpc_gssc_header(struct oncrpc_gssc *gc, uint32_t xid, uint32_t prog,
    uint32_t vers, uint32_t proc, uint8_t *cred, uint32_t *credlen,
    uint8_t *verf, uint32_t *verflen, uint32_t *seqp)
{
	uint8_t hdr[32 + 20 + 64];
	uint32_t *p = (uint32_t *)hdr;
	size_t len;

	*seqp = ++gc->gc_seq;
	*credlen = gssc_cred(cred, RPCSEC_GSS_DATA, gc->gc_seq, gc->gc_service,
	    gc->gc_handle, gc->gc_hlen);
	*p++ = htonl(xid);
	*p++ = htonl(ONCRPC_CALL);
	*p++ = htonl(ONCRPC_VERS);
	*p++ = htonl(prog);
	*p++ = htonl(vers);
	*p++ = htonl(proc);
	*p++ = htonl(RPCSEC_GSS);
	*p++ = htonl(*credlen);
	memcpy(p, cred, *credlen);
	if (gss_krb5_get_mic(gc->gc_krb, hdr, 32 + *credlen, verf,
	    GSS_KRB5_MAXMIC, &len) != GSS_S_COMPLETE)
		return false;
	*verflen = len;
	return true;
}

/* The arguments as s5.3.2 has them.  m is consumed; NULL for failure. */
struct mbuf *
oncrpc_gssc_seal(struct oncrpc_gssc *gc, uint32_t seq, struct mbuf *m)
{
	struct oncrpc_xdrmbuf x;
	uint8_t mic[GSS_KRB5_MAXMIC], *plain, *tok = NULL;
	size_t plen, tlen, toksz = 0, ml;
	uint32_t len, mlen;
	u_int rlen = m != NULL ? m->m_pkthdr.len : 0;
	bool ok = false;

	if (gc->gc_service == RPCSEC_GSS_SVC_NONE)
		return m;
	plen = (size_t)rlen + 4;
	plain = kmem_alloc(plen, KM_SLEEP);
	be32enc(plain, seq);
	if (rlen != 0)
		m_copydata(m, 0, rlen, plain + 4);
	m_freem(m);
	oncrpc_xdrmbuf_create(&x, NULL, UINT_MAX, XDR_ENCODE);
	len = plen;
	if (gc->gc_service == RPCSEC_GSS_SVC_INTEGRITY) {
		if (gss_krb5_get_mic(gc->gc_krb, plain, plen, mic, sizeof(mic),
		    &ml) == GSS_S_COMPLETE) {
			mlen = ml;
			ok = xdr_u_int32_t(&x.xm_xdr, &len) &&
			    xdr_opaque(&x.xm_xdr, (char *)plain, len) &&
			    xdr_u_int32_t(&x.xm_xdr, &mlen) &&
			    xdr_opaque(&x.xm_xdr, (char *)mic, mlen);
		}
	} else {
		toksz = gss_krb5_wrap_size(gc->gc_krb, plen);
		tok = kmem_alloc(toksz, KM_SLEEP);
		if (gss_krb5_wrap(gc->gc_krb, plain, plen, tok, toksz, &tlen) ==
		    GSS_S_COMPLETE) {
			len = tlen;
			ok = xdr_u_int32_t(&x.xm_xdr, &len) &&
			    xdr_opaque(&x.xm_xdr, (char *)tok, len);
		}
	}
	explicit_memset(plain, 0, plen);
	kmem_free(plain, plen);
	if (tok != NULL)
		kmem_free(tok, toksz);
	if (!ok) {
		XDR_DESTROY(&x.xm_xdr);
		return NULL;
	}
	return oncrpc_xdrmbuf_detach(&x);
}

/*
 * A reply, s5.3.3.2.  The verifier must be the MIC of seq.  Under
 * integrity or privacy the results at off are opened into *resp, a new
 * chain; otherwise *resp stays NULL and the results are where they are.
 */
int
oncrpc_gssc_open(struct oncrpc_gssc *gc, uint32_t seq,
    const struct oncrpc_opaque_auth *verf, struct mbuf *m, u_int off,
    struct mbuf **resp)
{
	struct oncrpc_xdrmbuf x;
	const struct mbuf *n;
	uint8_t mic[GSS_KRB5_MAXMIC], *body, *plain;
	uint32_t s = htonl(seq), blen, mlen;
	size_t plen;
	u_int total = 0;
	bool conf;
	int error = EAUTH;

	*resp = NULL;
	if (verf->oa_flavor != RPCSEC_GSS ||
	    gss_krb5_verify_mic(gc->gc_krb, &s, sizeof(s), verf->oa_body,
	    verf->oa_len) != GSS_S_COMPLETE)
		return EAUTH;
	if (gc->gc_service == RPCSEC_GSS_SVC_NONE)
		return 0;

	for (n = m; n != NULL; n = n->m_next)
		total += n->m_len;
	if (off + 4 > total)
		return EBADRPC;
	m_copydata(m, off, 4, &blen);
	blen = ntohl(blen);
	if (blen < 4 || blen > total - off - 4)
		return EBADRPC;
	body = kmem_alloc(blen, KM_SLEEP);
	m_copydata(m, off + 4, blen, body);
	if (gc->gc_service == RPCSEC_GSS_SVC_INTEGRITY) {
		size_t o = (size_t)off + 4 + roundup((size_t)blen, 4);

		if (o + 4 > total)
			goto out;
		m_copydata(m, o, 4, &mlen);
		mlen = ntohl(mlen);
		if (mlen > sizeof(mic) || o + 4 + mlen > total)
			goto out;
		m_copydata(m, o + 4, mlen, mic);
		if (gss_krb5_verify_mic(gc->gc_krb, body, blen, mic, mlen) !=
		    GSS_S_COMPLETE)
			goto out;
		plain = body;
		plen = blen;
	} else {
		void *pp;

		if (gss_krb5_unwrap(gc->gc_krb, body, blen, NULL, &pp, &plen,
		    &conf) != GSS_S_COMPLETE || !conf || plen < 4)
			goto out;
		plain = pp;
	}
	if (be32dec(plain) != seq)
		goto out;
	oncrpc_xdrmbuf_create(&x, NULL, plen + 4, XDR_ENCODE);
	if (plen == 4) {
		XDR_DESTROY(&x.xm_xdr);
		*resp = m_gethdr(M_WAIT, MT_DATA);
		(*resp)->m_len = (*resp)->m_pkthdr.len = 0;
		error = 0;
	} else if (!xdr_opaque(&x.xm_xdr, (char *)plain + 4, plen - 4)) {
		XDR_DESTROY(&x.xm_xdr);
	} else {
		oncrpc_xdrmbuf_truncate(&x.xm_xdr, plen - 4);
		*resp = oncrpc_xdrmbuf_detach(&x);
		error = 0;
	}
out:
	explicit_memset(body, 0, blen);
	kmem_free(body, blen);
	return error;
}
