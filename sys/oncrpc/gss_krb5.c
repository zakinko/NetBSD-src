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
 * The per-message tokens of the Kerberos V5 GSS-API mechanism: RFC 4121 for
 * the AES enctypes, RFC 1964 for DES and 3DES.  The context comes from the
 * daemon that established it; all that is here is what GSS_GetMIC(),
 * GSS_VerifyMIC(), GSS_Wrap() and GSS_Unwrap() do with it.
 *
 * Replay and order are not looked at: RPCSEC_GSS has its own window, RFC
 * 2203 s5.3.3.1, and many threads share a context, so that tokens arrive
 * out of order as a matter of course.
 *
 * RFC 6649 s5 deprecates the single DES of RFC 1964.  It is here for peers
 * that know nothing else; whether to offer it is for whoever imports the
 * context.  RFC 1964 does not define the 3DES tokens either, see gk1_*.
 *
 * A confounder is drawn for every Wrap token, on the path of every RPC, in
 * any thread.  cprng_fast() is ChaCha per CPU, seeded from kern_cprng and
 * reseeded when the entropy epoch moves; it takes no lock and cannot sleep,
 * where cprng_strong() goes through one mutex for the machine.  The value
 * must be unpredictable, RFC 8009 s8, but it is sent encrypted and no key
 * comes of it.
 */

#include <sys/cdefs.h>
#ifdef _KERNEL
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/atomic.h>
#include <sys/cprng.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/md5.h>
#include <sys/mutex.h>

#include <crypto/aes/aes.h>
#include <crypto/des/des.h>

#define	GSS_KRB5_PRIVATE
#include <oncrpc/gss_krb5.h>
#else
#include <errno.h>
#include "gss_krb5_shim.h"
#define	GSS_KRB5_PRIVATE
#include "gss_krb5.h"
#endif

/* RFC 4121 s2 */
#define	KG_USAGE_ACCEPTOR_SEAL	22
#define	KG_USAGE_ACCEPTOR_SIGN	23
#define	KG_USAGE_INITIATOR_SEAL	24
#define	KG_USAGE_INITIATOR_SIGN	25

/* RFC 4121 s4.2.2 */
#define	CFX_SENTBYACCEPTOR	0x01
#define	CFX_SEALED		0x02
#define	CFX_ACCEPTORSUBKEY	0x04

#define	CFX_HDRLEN		16	/* RFC 4121 s4.2.6 */
#define	CFX_TOK_MIC0		0x04	/* RFC 4121 s4.2.6.1 */
#define	CFX_TOK_MIC1		0x04
#define	CFX_TOK_WRAP0		0x05	/* RFC 4121 s4.2.6.2 */
#define	CFX_TOK_WRAP1		0x04
#define	CFX_FILLER		0xff	/* RFC 4121 s4.2.6 */

/* RFC 1964 s1.2.1 and s1.2.2 */
#define	GK1_TOK_MIC0		0x01
#define	GK1_TOK_MIC1		0x01
#define	GK1_TOK_WRAP0		0x02
#define	GK1_TOK_WRAP1		0x01
#define	GK1_FILLER		0xff
#define	GK1_SEAL_NONE		0xff	/* both octets */
#define	GK1_HDRLEN		8	/* TOK_ID to Filler */
#define	GK1_SEQLEN		8
#define	GK1_BLOCK		8	/* s1.2.2.3, DES-CBC */
#define	GK1_DI_INITIATOR	0x00	/* s1.2.1.2 */
#define	GK1_DI_ACCEPTOR		0xff
#define	GK1_SEALXOR		0xf0	/* s1.2, confidentiality key */

#define	GK1_SGN_DES_MAC_MD5	0x00	/* s1.2.1 */
#define	GK1_SEAL_DES		0x00	/* s1.2.2 */
/*
 * Not in any RFC: RFC 1964 stops at DES.  What follows is the behaviour of
 * Heimdal (lib/gssapi/krb5/{get_mic,wrap}.c, mic_des3() and wrap_des3()):
 * SGN_ALG 4 is HMAC-SHA-1 by the Kc of the sign usage, the 20 octets taking
 * the place of the 8 of SGN_CKSUM, and SEAL_ALG 2 is 3DES outer CBC, zero
 * IV, in the context key itself.  So does the sequence number.
 */
#define	GK1_SGN_HMAC_SHA1	0x04
#define	GK1_SEAL_DES3		0x02
#define	GK1_USAGE_SIGN		23	/* KG_USAGE_SIGN in those sources */

/* DES takes a long, and the longest length of the framing here is 4. */
#define	GK1_MAXINNER		0x7fffffffU

#define	GK_TAG_KC		0x99	/* RFC 3961 s5.3 */

/* The two directions of a context's arrays. */
#define	GK_SEND			0
#define	GK_RECV			1

struct gss_krb5_ctx {
	const struct gk_etype	*gc_et;
	bool			gc_cfx;
	bool			gc_initiator;
	bool			gc_acceptor_subkey;
#ifdef __HAVE_ATOMIC64_OPS
	volatile uint64_t	gc_seq;
#else
	kmutex_t		gc_seqlock;
	uint64_t		gc_seq;
#endif
	union {
		struct {
			struct gk_dk	seal[2];
			uint8_t		signkc[2][GSS_KRB5_MAXKEY];
		} cfx;
		struct {
			des_key_schedule ks[3];	/* one for DES */
			des_key_schedule sealks; /* DES, s1.2 */
			uint8_t		kc[GSS_KRB5_MAXKEY]; /* 3DES */
		} v1;
	} gc_u;
};

static uint64_t
gk_next_seq(struct gss_krb5_ctx *ctx)
{
#ifdef __HAVE_ATOMIC64_OPS

	return atomic_inc_64_nv(&ctx->gc_seq) - 1;
#else
	uint64_t seq;

	mutex_enter(&ctx->gc_seqlock);
	seq = ctx->gc_seq++;
	mutex_exit(&ctx->gc_seqlock);
	return seq;
#endif
}

static bool
gk_is_des(const struct gk_etype *et)
{

	return et->ge_enctype == GSS_KRB5_ENC_DES_CBC_CRC ||
	    et->ge_enctype == GSS_KRB5_ENC_DES_CBC_MD5;
}

int
gss_krb5_ctx_create(const struct gss_krb5_import *gi,
    struct gss_krb5_ctx **ctxp)
{
	const struct gk_etype *et;
	struct gss_krb5_ctx *ctx;
	des_cblock k;
	int i;

	et = gk_etype_lookup(gi->gi_enctype);
	if (et == NULL || gi->gi_keylen != et->ge_keylen)
		return EINVAL;
	/* RFC 4121 s1: MUST for AES.  Its MAY for the older is not taken. */
	if (gi->gi_cfx != (et->ge_block == 16))
		return EINVAL;

	ctx = kmem_zalloc(sizeof(*ctx), KM_SLEEP);
	ctx->gc_et = et;
	ctx->gc_cfx = gi->gi_cfx;
	ctx->gc_initiator = gi->gi_initiator;
	ctx->gc_acceptor_subkey = gi->gi_acceptor_subkey;
	ctx->gc_seq = gi->gi_send_seq;
#ifndef __HAVE_ATOMIC64_OPS
	mutex_init(&ctx->gc_seqlock, MUTEX_DEFAULT, IPL_NONE);
#endif

	if (gi->gi_cfx) {
		/* RFC 4121 s2: the usage follows the sender. */
		gk_dk_init(et, gi->gi_key, gi->gi_initiator ?
		    KG_USAGE_INITIATOR_SEAL : KG_USAGE_ACCEPTOR_SEAL,
		    &ctx->gc_u.cfx.seal[GK_SEND]);
		gk_dk_init(et, gi->gi_key, gi->gi_initiator ?
		    KG_USAGE_ACCEPTOR_SEAL : KG_USAGE_INITIATOR_SEAL,
		    &ctx->gc_u.cfx.seal[GK_RECV]);
		gk_derive(et, gi->gi_key, gi->gi_initiator ?
		    KG_USAGE_INITIATOR_SIGN : KG_USAGE_ACCEPTOR_SIGN,
		    GK_TAG_KC, ctx->gc_u.cfx.signkc[GK_SEND]);
		gk_derive(et, gi->gi_key, gi->gi_initiator ?
		    KG_USAGE_ACCEPTOR_SIGN : KG_USAGE_INITIATOR_SIGN,
		    GK_TAG_KC, ctx->gc_u.cfx.signkc[GK_RECV]);
	} else if (gk_is_des(et)) {
		memcpy(k, gi->gi_key, 8);
		des_set_key_unchecked(&k, ctx->gc_u.v1.ks[0]);
		for (i = 0; i < 8; i++)
			k[i] ^= GK1_SEALXOR;
		des_set_key_unchecked(&k, ctx->gc_u.v1.sealks);
		explicit_memset(k, 0, sizeof(k));
	} else {
		for (i = 0; i < 3; i++) {
			memcpy(k, gi->gi_key + i * 8, 8);
			des_set_key_unchecked(&k, ctx->gc_u.v1.ks[i]);
		}
		explicit_memset(k, 0, sizeof(k));
		gk_derive(et, gi->gi_key, GK1_USAGE_SIGN, GK_TAG_KC,
		    ctx->gc_u.v1.kc);
	}

	*ctxp = ctx;
	return 0;
}

void
gss_krb5_ctx_destroy(struct gss_krb5_ctx *ctx)
{

#ifndef __HAVE_ATOMIC64_OPS
	mutex_destroy(&ctx->gc_seqlock);
#endif
	explicit_memset(ctx, 0, sizeof(*ctx));
	kmem_free(ctx, sizeof(*ctx));
}

/* RFC 4121 */

static void
cfx_enc64(uint8_t *p, uint64_t v)
{
	int i;

	for (i = 7; i >= 0; i--) {
		p[i] = (uint8_t)v;
		v >>= 8;
	}
}

static uint8_t
cfx_flags(const struct gss_krb5_ctx *ctx)
{
	uint8_t flags = 0;

	if (!ctx->gc_initiator)
		flags |= CFX_SENTBYACCEPTOR;
	if (ctx->gc_acceptor_subkey)
		flags |= CFX_ACCEPTORSUBKEY;
	return flags;
}

/*
 * RFC 4121 s4.2.2: the peer is the other end, and s2 has every token of a
 * context with an acceptor's subkey say so.  Unknown flags are ignored.
 */
static bool
cfx_flags_ok(const struct gss_krb5_ctx *ctx, uint8_t flags)
{

	if (((flags & CFX_SENTBYACCEPTOR) != 0) != ctx->gc_initiator)
		return false;
	return ((flags & CFX_ACCEPTORSUBKEY) != 0) == ctx->gc_acceptor_subkey;
}

static uint32_t
cfx_get_mic(struct gss_krb5_ctx *ctx, const void *msg, size_t msglen,
    uint8_t *tok, size_t tokmax, size_t *toklenp)
{
	const struct gk_etype *et = ctx->gc_et;

	if (tokmax < CFX_HDRLEN + et->ge_maclen)
		return GSS_S_FAILURE;
	tok[0] = CFX_TOK_MIC0;
	tok[1] = CFX_TOK_MIC1;
	tok[2] = cfx_flags(ctx);
	memset(tok + 3, CFX_FILLER, 5);
	cfx_enc64(tok + 8, gk_next_seq(ctx));
	gk_checksum(et, ctx->gc_u.cfx.signkc[GK_SEND], msg, msglen, tok,
	    CFX_HDRLEN, tok + CFX_HDRLEN);
	*toklenp = CFX_HDRLEN + et->ge_maclen;
	return GSS_S_COMPLETE;
}

static uint32_t
cfx_verify_mic(struct gss_krb5_ctx *ctx, const void *msg, size_t msglen,
    const uint8_t *tok, size_t toklen)
{
	static const uint8_t filler[5] = { 0xff, 0xff, 0xff, 0xff, 0xff };
	const struct gk_etype *et = ctx->gc_et;
	uint8_t mac[GK_MAXHASH];

	if (toklen != CFX_HDRLEN + et->ge_maclen)
		return GSS_S_DEFECTIVE_TOKEN;
	if (tok[0] != CFX_TOK_MIC0 || tok[1] != CFX_TOK_MIC1 ||
	    memcmp(tok + 3, filler, sizeof(filler)) != 0)
		return GSS_S_DEFECTIVE_TOKEN;
	/* RFC 4121 s4.2.2: never in a MIC token. */
	if (!cfx_flags_ok(ctx, tok[2]) || (tok[2] & CFX_SEALED) != 0)
		return GSS_S_DEFECTIVE_TOKEN;
	gk_checksum(et, ctx->gc_u.cfx.signkc[GK_RECV], msg, msglen, tok,
	    CFX_HDRLEN, mac);
	if (!consttime_memequal(mac, tok + CFX_HDRLEN, et->ge_maclen))
		return GSS_S_BAD_SIG;
	return GSS_S_COMPLETE;
}

/*
 * RFC 4121 s4.2.4.  EC is 0: with CTS the message block is one octet, RFC
 * 3962 s6, so nothing is left over from decryption.  RRC is 0, as s4.2.5
 * lets the sender choose.
 */
static uint32_t
cfx_wrap(struct gss_krb5_ctx *ctx, const void *msg, size_t msglen,
    uint8_t *tok, size_t tokmax, size_t *toklenp)
{
	const struct gk_etype *et = ctx->gc_et;
	uint8_t *body = tok + CFX_HDRLEN;

	if (tokmax < gss_krb5_wrap_size(ctx, msglen))
		return GSS_S_FAILURE;
	tok[0] = CFX_TOK_WRAP0;
	tok[1] = CFX_TOK_WRAP1;
	tok[2] = cfx_flags(ctx) | CFX_SEALED;
	tok[3] = CFX_FILLER;
	memset(tok + 4, 0, 4);		/* EC, RRC */
	cfx_enc64(tok + 8, gk_next_seq(ctx));

	cprng_fast(body, et->ge_block);
	if (msglen != 0)
		memcpy(body + et->ge_block, msg, msglen);
	memcpy(body + et->ge_block + msglen, tok, CFX_HDRLEN);
	gk_encrypt(et, &ctx->gc_u.cfx.seal[GK_SEND], body,
	    msglen + CFX_HDRLEN);
	*toklenp = CFX_HDRLEN + et->ge_block + msglen + CFX_HDRLEN +
	    et->ge_maclen;
	return GSS_S_COMPLETE;
}

static void
cfx_reverse(uint8_t *p, size_t n)
{
	uint8_t t;
	size_t i;

	for (i = 0; i < n / 2; i++) {
		t = p[i];
		p[i] = p[n - 1 - i];
		p[n - 1 - i] = t;
	}
}

/* Undoes the rotation to the right of s4.2.5; r is less than n. */
static void
cfx_rotate_left(uint8_t *p, size_t n, size_t r)
{

	if (r == 0)
		return;
	cfx_reverse(p, r);
	cfx_reverse(p + r, n - r);
	cfx_reverse(p, n);
}

static uint32_t
cfx_unwrap(struct gss_krb5_ctx *ctx, uint8_t *tok, size_t toklen,
    void **msgp, size_t *msglenp, bool *confp)
{
	const struct gk_etype *et = ctx->gc_et;
	struct gk_dk *dk = &ctx->gc_u.cfx.seal[GK_RECV];
	uint8_t hdr[CFX_HDRLEN], mac[GK_MAXHASH], *body, *inner;
	size_t n, ptlen;
	unsigned int ec, rrc;

	if (toklen < CFX_HDRLEN)
		return GSS_S_DEFECTIVE_TOKEN;
	if (tok[0] != CFX_TOK_WRAP0 || tok[1] != CFX_TOK_WRAP1 ||
	    tok[3] != CFX_FILLER || !cfx_flags_ok(ctx, tok[2]))
		return GSS_S_DEFECTIVE_TOKEN;
	ec = (unsigned int)tok[4] << 8 | tok[5];
	rrc = (unsigned int)tok[6] << 8 | tok[7];
	body = tok + CFX_HDRLEN;
	n = toklen - CFX_HDRLEN;

	if ((tok[2] & CFX_SEALED) != 0) {
		if (n < et->ge_block + CFX_HDRLEN + et->ge_maclen)
			return GSS_S_DEFECTIVE_TOKEN;
		cfx_rotate_left(body, n, rrc % n);
		if (!gk_decrypt(et, dk, body, n))
			return GSS_S_BAD_SIG;
		ptlen = n - et->ge_block - et->ge_maclen - CFX_HDRLEN;
		if (ec > ptlen)
			return GSS_S_DEFECTIVE_TOKEN;
		/*
		 * The outer header has no MAC, so it must agree with the
		 * copy.  s4.2.4 has the sender put RRC 0 in the copy, but
		 * RRC is not compared: it means nothing there, and Heimdal
		 * (cfx.c, _gssapi_unwrap_cfx_iov) does not look either.
		 */
		inner = body + et->ge_block + ptlen;
		if (memcmp(inner, tok, 6) != 0 ||
		    memcmp(inner + 8, tok + 8, 8) != 0)
			return GSS_S_DEFECTIVE_TOKEN;
		*msgp = body + et->ge_block;
		*msglenp = ptlen - ec;
		*confp = true;
		return GSS_S_COMPLETE;
	}

	/* s4.2.3: EC counts the checksum.  s2: the seal usage all the same. */
	if (ec != et->ge_maclen || n < et->ge_maclen)
		return GSS_S_DEFECTIVE_TOKEN;
	cfx_rotate_left(body, n, n != 0 ? rrc % n : 0);
	memcpy(hdr, tok, sizeof(hdr));
	memset(hdr + 4, 0, 4);		/* s4.2.4 */
	gk_checksum(et, dk->gd_kc, body, n - et->ge_maclen, hdr, sizeof(hdr),
	    mac);
	if (!consttime_memequal(mac, body + n - et->ge_maclen, et->ge_maclen))
		return GSS_S_BAD_SIG;
	*msgp = body;
	*msglenp = n - et->ge_maclen;
	*confp = false;
	return GSS_S_COMPLETE;
}

/* RFC 1964 */

/* { 1 2 840 113554 1 2 2 } of RFC 1964 s1, in DER with tag and length. */
static const uint8_t gk1_oid[] = {
	0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02
};

#define	GK1_TAG			0x60	/* RFC 2743 s3.1, [APPLICATION 0] */
#define	GK1_MAXFRAME		(1 + 5 + sizeof(gk1_oid))

static uint8_t
gk1_sgn_alg(const struct gss_krb5_ctx *ctx)
{

	return gk_is_des(ctx->gc_et) ? GK1_SGN_DES_MAC_MD5 : GK1_SGN_HMAC_SHA1;
}

static uint8_t
gk1_seal_alg(const struct gss_krb5_ctx *ctx)
{

	return gk_is_des(ctx->gc_et) ? GK1_SEAL_DES : GK1_SEAL_DES3;
}

/* The octets of the framing for an inner token of this length. */
static size_t
gk1_frame_len(size_t inner)
{
	size_t body = sizeof(gk1_oid) + inner;

	if (body < 0x80)
		return 2 + sizeof(gk1_oid);
	if (body < 0x100)
		return 3 + sizeof(gk1_oid);
	if (body < 0x10000)
		return 4 + sizeof(gk1_oid);
	if (body < 0x1000000)
		return 5 + sizeof(gk1_oid);
	return 6 + sizeof(gk1_oid);
}

/* Writes the framing, and returns where the inner token goes. */
static uint8_t *
gk1_frame(uint8_t *p, size_t inner)
{
	size_t body = sizeof(gk1_oid) + inner;
	int n, i;

	*p++ = GK1_TAG;
	if (body < 0x80)
		*p++ = (uint8_t)body;
	else {
		n = body < 0x100 ? 1 : body < 0x10000 ? 2 :
		    body < 0x1000000 ? 3 : 4;
		*p++ = (uint8_t)(0x80 | n);
		for (i = n - 1; i >= 0; i--)
			*p++ = (uint8_t)(body >> (i * 8));
	}
	memcpy(p, gk1_oid, sizeof(gk1_oid));
	return p + sizeof(gk1_oid);
}

/*
 * The inner token of a framed one, or NULL.  The token is all there is, so
 * the length must come out exactly, and be DER's shortest form of it.
 */
static const uint8_t *
gk1_unframe(const uint8_t *tok, size_t toklen, size_t *innerp)
{
	const uint8_t *p = tok;
	size_t left = toklen, body;
	unsigned int n, i;

	if (left < 2 || *p != GK1_TAG)
		return NULL;
	p++;
	left--;
	body = *p++;
	left--;
	if (body >= 0x80) {
		n = body & 0x7f;
		if (n < 1 || n > 4 || left < n)
			return NULL;
		body = 0;
		for (i = 0; i < n; i++)
			body = body << 8 | *p++;
		left -= n;
		if (body < 0x80 || (n > 1 && (body >> ((n - 1) * 8)) == 0))
			return NULL;
	}
	if (body != left || left < sizeof(gk1_oid) ||
	    memcmp(p, gk1_oid, sizeof(gk1_oid)) != 0)
		return NULL;
	*innerp = left - sizeof(gk1_oid);
	if (*innerp > GK1_MAXINNER)
		return NULL;
	return p + sizeof(gk1_oid);
}

/*
 * SGN_CKSUM of s1.2.1.1 and s1.2.2.1, ge_maclen octets, over the first 8
 * of the header and the data.
 */
static void
gk1_cksum(struct gss_krb5_ctx *ctx, const uint8_t *hdr, const void *data,
    size_t len, uint8_t *out)
{
	uint8_t md5[16], mac[16];	/* RFC 1321 s3.5 */
	MD5_CTX c;
	des_cblock iv;

	if (!gk_is_des(ctx->gc_et)) {
		gk_checksum(ctx->gc_et, ctx->gc_u.v1.kc, hdr, GK1_HDRLEN,
		    data, len, out);
		return;
	}
	MD5Init(&c);
	MD5Update(&c, hdr, GK1_HDRLEN);
	if (len != 0)	/* GK1_MAXINNER: it fits the unsigned int. */
		MD5Update(&c, data, (unsigned int)len);
	MD5Final(md5, &c);
	memset(iv, 0, sizeof(iv));
	des_ncbc_encrypt(md5, mac, sizeof(md5), ctx->gc_u.v1.ks[0], &iv,
	    DES_ENCRYPT);
	memcpy(out, mac + 8, 8);
}

/* DES-CBC or 3DES outer CBC of whole blocks, in place. */
static void
gk1_cipher(struct gss_krb5_ctx *ctx, bool seal, uint8_t *p, size_t len,
    const uint8_t *ivp, int enc)
{
	des_cblock iv;

	memcpy(iv, ivp, sizeof(iv));
	if (!gk_is_des(ctx->gc_et))
		des_ede3_cbc_encrypt(p, p, (long)len, ctx->gc_u.v1.ks[0],
		    ctx->gc_u.v1.ks[1], ctx->gc_u.v1.ks[2], &iv, enc);
	else
		des_ncbc_encrypt(p, p, (long)len, seal ?
		    ctx->gc_u.v1.sealks : ctx->gc_u.v1.ks[0], &iv, enc);
}

/* s1.2.1.2: little-endian, the direction, in the context key. */
static void
gk1_seq_seal(struct gss_krb5_ctx *ctx, uint32_t seq, const uint8_t *cksum,
    uint8_t *out)
{

	out[0] = (uint8_t)seq;
	out[1] = (uint8_t)(seq >> 8);
	out[2] = (uint8_t)(seq >> 16);
	out[3] = (uint8_t)(seq >> 24);
	memset(out + 4, ctx->gc_initiator ? GK1_DI_INITIATOR : GK1_DI_ACCEPTOR,
	    4);
	gk1_cipher(ctx, false, out, GK1_SEQLEN, cksum, DES_ENCRYPT);
}

/* After the checksum, s1.2.1.2; the number itself is for no one here. */
static bool
gk1_seq_ok(struct gss_krb5_ctx *ctx, const uint8_t *seq, const uint8_t *cksum)
{
	uint8_t p[GK1_SEQLEN], di;
	int i;

	memcpy(p, seq, sizeof(p));
	gk1_cipher(ctx, false, p, sizeof(p), cksum, DES_DECRYPT);
	di = ctx->gc_initiator ? GK1_DI_ACCEPTOR : GK1_DI_INITIATOR;
	for (i = 4; i < 8; i++)
		if (p[i] != di)
			return false;
	return true;
}

static uint32_t
gk1_get_mic(struct gss_krb5_ctx *ctx, const void *msg, size_t msglen,
    uint8_t *tok, size_t tokmax, size_t *toklenp)
{
	size_t inner = GK1_HDRLEN + GK1_SEQLEN + ctx->gc_et->ge_maclen;
	size_t len = gk1_frame_len(inner) + inner;
	uint8_t *p;

	if (msglen > GK1_MAXINNER || tokmax < len)
		return GSS_S_FAILURE;
	p = gk1_frame(tok, inner);
	p[0] = GK1_TOK_MIC0;
	p[1] = GK1_TOK_MIC1;
	p[2] = gk1_sgn_alg(ctx);
	p[3] = 0;
	memset(p + 4, GK1_FILLER, 4);
	gk1_cksum(ctx, p, msg, msglen, p + GK1_HDRLEN + GK1_SEQLEN);
	gk1_seq_seal(ctx, (uint32_t)gk_next_seq(ctx),
	    p + GK1_HDRLEN + GK1_SEQLEN, p + GK1_HDRLEN);
	*toklenp = len;
	return GSS_S_COMPLETE;
}

static uint32_t
gk1_verify_mic(struct gss_krb5_ctx *ctx, const void *msg, size_t msglen,
    const uint8_t *tok, size_t toklen)
{
	static const uint8_t filler[4] = { 0xff, 0xff, 0xff, 0xff };
	size_t maclen = ctx->gc_et->ge_maclen, inner;
	const uint8_t *p;
	uint8_t mac[GK_MAXHASH];

	if (msglen > GK1_MAXINNER)
		return GSS_S_FAILURE;
	p = gk1_unframe(tok, toklen, &inner);
	if (p == NULL || inner != GK1_HDRLEN + GK1_SEQLEN + maclen)
		return GSS_S_DEFECTIVE_TOKEN;
	if (p[0] != GK1_TOK_MIC0 || p[1] != GK1_TOK_MIC1 ||
	    p[2] != gk1_sgn_alg(ctx) || p[3] != 0 ||
	    memcmp(p + 4, filler, sizeof(filler)) != 0)
		return GSS_S_DEFECTIVE_TOKEN;
	gk1_cksum(ctx, p, msg, msglen, mac);
	if (!consttime_memequal(mac, p + GK1_HDRLEN + GK1_SEQLEN, maclen))
		return GSS_S_BAD_SIG;
	if (!gk1_seq_ok(ctx, p + GK1_HDRLEN, p + GK1_HDRLEN + GK1_SEQLEN))
		return GSS_S_BAD_SIG;
	return GSS_S_COMPLETE;
}

/* The octets after the header of a Wrap token: s1.2.2.3 */
static size_t
gk1_body_len(size_t msglen)
{

	return GK1_BLOCK + msglen + (GK1_BLOCK - msglen % GK1_BLOCK);
}

static uint32_t
gk1_wrap(struct gss_krb5_ctx *ctx, const void *msg, size_t msglen,
    uint8_t *tok, size_t tokmax, size_t *toklenp)
{
	static const uint8_t zeroiv[GK1_BLOCK];
	size_t maclen = ctx->gc_et->ge_maclen;
	size_t hlen = GK1_HDRLEN + GK1_SEQLEN + maclen;
	size_t body = gk1_body_len(msglen), inner = hlen + body, pad;
	uint8_t *p, *q;

	if (msglen > GK1_MAXINNER - GK1_MAXFRAME - hlen - 2 * GK1_BLOCK ||
	    tokmax < gk1_frame_len(inner) + inner)
		return GSS_S_FAILURE;
	p = gk1_frame(tok, inner);
	p[0] = GK1_TOK_WRAP0;
	p[1] = GK1_TOK_WRAP1;
	p[2] = gk1_sgn_alg(ctx);
	p[3] = 0;
	p[4] = gk1_seal_alg(ctx);
	p[5] = 0;
	p[6] = GK1_FILLER;
	p[7] = GK1_FILLER;

	q = p + hlen;
	cprng_fast(q, GK1_BLOCK);
	if (msglen != 0)
		memcpy(q + GK1_BLOCK, msg, msglen);
	pad = GK1_BLOCK - msglen % GK1_BLOCK;
	memset(q + GK1_BLOCK + msglen, (int)pad, pad);

	gk1_cksum(ctx, p, q, body, p + GK1_HDRLEN + GK1_SEQLEN);
	gk1_seq_seal(ctx, (uint32_t)gk_next_seq(ctx),
	    p + GK1_HDRLEN + GK1_SEQLEN, p + GK1_HDRLEN);
	gk1_cipher(ctx, true, q, body, zeroiv, DES_ENCRYPT);
	*toklenp = gk1_frame_len(inner) + inner;
	return GSS_S_COMPLETE;
}

static uint32_t
gk1_unwrap(struct gss_krb5_ctx *ctx, uint8_t *tok, size_t toklen,
    void **msgp, size_t *msglenp, bool *confp)
{
	static const uint8_t zeroiv[GK1_BLOCK];
	size_t maclen = ctx->gc_et->ge_maclen;
	size_t hlen = GK1_HDRLEN + GK1_SEQLEN + maclen, inner, body, i;
	uint8_t mac[GK_MAXHASH], *p, *q, pad;
	bool sealed;

	p = __UNCONST(gk1_unframe(tok, toklen, &inner));
	if (p == NULL || inner < hlen)
		return GSS_S_DEFECTIVE_TOKEN;
	if (p[0] != GK1_TOK_WRAP0 || p[1] != GK1_TOK_WRAP1 ||
	    p[2] != gk1_sgn_alg(ctx) || p[3] != 0 ||
	    p[6] != GK1_FILLER || p[7] != GK1_FILLER)
		return GSS_S_DEFECTIVE_TOKEN;
	if (p[4] == GK1_SEAL_NONE && p[5] == GK1_SEAL_NONE)
		sealed = false;
	else if (p[4] == gk1_seal_alg(ctx) && p[5] == 0)
		sealed = true;
	else
		return GSS_S_DEFECTIVE_TOKEN;

	body = inner - hlen;
	if (body < 2 * GK1_BLOCK || body % GK1_BLOCK != 0)
		return GSS_S_DEFECTIVE_TOKEN;
	q = p + hlen;
	if (sealed)
		gk1_cipher(ctx, true, q, body, zeroiv, DES_DECRYPT);
	/* The padding is not looked at before the checksum has passed. */
	gk1_cksum(ctx, p, q, body, mac);
	if (!consttime_memequal(mac, p + GK1_HDRLEN + GK1_SEQLEN, maclen))
		return GSS_S_BAD_SIG;
	if (!gk1_seq_ok(ctx, p + GK1_HDRLEN, p + GK1_HDRLEN + GK1_SEQLEN))
		return GSS_S_BAD_SIG;
	pad = q[body - 1];
	if (pad < 1 || pad > GK1_BLOCK)
		return GSS_S_DEFECTIVE_TOKEN;
	for (i = 1; i <= pad; i++)
		if (q[body - i] != pad)
			return GSS_S_DEFECTIVE_TOKEN;
	*msgp = q + GK1_BLOCK;
	*msglenp = body - GK1_BLOCK - pad;
	*confp = sealed;
	return GSS_S_COMPLETE;
}

/* The interface */

uint32_t
gss_krb5_get_mic(struct gss_krb5_ctx *ctx, const void *msg, size_t msglen,
    void *tok, size_t tokmax, size_t *toklenp)
{

	return ctx->gc_cfx ? cfx_get_mic(ctx, msg, msglen, tok, tokmax, toklenp)
	    : gk1_get_mic(ctx, msg, msglen, tok, tokmax, toklenp);
}

uint32_t
gss_krb5_verify_mic(struct gss_krb5_ctx *ctx, const void *msg, size_t msglen,
    const void *tok, size_t toklen)
{

	return ctx->gc_cfx ? cfx_verify_mic(ctx, msg, msglen, tok, toklen) :
	    gk1_verify_mic(ctx, msg, msglen, tok, toklen);
}

/* SIZE_MAX for a message that no token can hold. */
size_t
gss_krb5_wrap_size(const struct gss_krb5_ctx *ctx, size_t msglen)
{
	const struct gk_etype *et = ctx->gc_et;
	size_t over, inner;

	if (ctx->gc_cfx) {
		over = CFX_HDRLEN + et->ge_block + CFX_HDRLEN + et->ge_maclen;
		return msglen > SIZE_MAX - over ? SIZE_MAX : msglen + over;
	}
	over = GK1_HDRLEN + GK1_SEQLEN + et->ge_maclen;
	if (msglen > GK1_MAXINNER - GK1_MAXFRAME - over - 2 * GK1_BLOCK)
		return SIZE_MAX;
	inner = over + gk1_body_len(msglen);
	return gk1_frame_len(inner) + inner;
}

uint32_t
gss_krb5_wrap(struct gss_krb5_ctx *ctx, const void *msg, size_t msglen,
    void *tok, size_t tokmax, size_t *toklenp)
{

	return ctx->gc_cfx ? cfx_wrap(ctx, msg, msglen, tok, tokmax, toklenp) :
	    gk1_wrap(ctx, msg, msglen, tok, tokmax, toklenp);
}

/* Both token families work in place, so out is never written. */
uint32_t
gss_krb5_unwrap(struct gss_krb5_ctx *ctx, void *tok, size_t toklen,
    void *out __unused, void **msgp, size_t *msglenp, bool *confp)
{

	return ctx->gc_cfx ? cfx_unwrap(ctx, tok, toklen, msgp, msglenp, confp) :
	    gk1_unwrap(ctx, tok, toklen, msgp, msglenp, confp);
}

/*
 * Composition only: the primitives have selftests of their own.  One
 * vector of RFC 3962 App. B, one of RFC 8009 App. A, then a MIC and a Wrap
 * across a pair of contexts for each enctype.
 */
static int
gk_selftest_rt(uint32_t enctype, bool cfx)
{
	static const uint8_t msg[33] = "the quick brown fox jumps over t";
	struct gss_krb5_import gi;
	struct gss_krb5_ctx *a = NULL, *b = NULL;
	uint8_t tok[GSS_KRB5_MAXMIC + sizeof(msg) + 64];
	const struct gk_etype *et = gk_etype_lookup(enctype);
	size_t len, mlen;
	void *m;
	bool conf;
	int i, error = -1;

	memset(&gi, 0, sizeof(gi));
	gi.gi_enctype = enctype;
	gi.gi_keylen = et->ge_keylen;
	gi.gi_cfx = cfx;
	for (i = 0; i < (int)gi.gi_keylen; i++)
		gi.gi_key[i] = (uint8_t)(0x40 + i * 3 + 1);
	gi.gi_initiator = true;
	if (gss_krb5_ctx_create(&gi, &a) != 0)
		goto out;
	gi.gi_initiator = false;
	if (gss_krb5_ctx_create(&gi, &b) != 0)
		goto out;

	if (gss_krb5_get_mic(a, msg, sizeof(msg), tok, sizeof(tok), &len) !=
	    GSS_S_COMPLETE ||
	    gss_krb5_verify_mic(b, msg, sizeof(msg), tok, len) !=
	    GSS_S_COMPLETE)
		goto out;
	tok[len - 1] ^= 1;
	if (gss_krb5_verify_mic(b, msg, sizeof(msg), tok, len) !=
	    GSS_S_BAD_SIG)
		goto out;
	if (gss_krb5_wrap(a, msg, sizeof(msg), tok, sizeof(tok), &len) !=
	    GSS_S_COMPLETE ||
	    gss_krb5_unwrap(b, tok, len, NULL, &m, &mlen, &conf) !=
	    GSS_S_COMPLETE ||
	    !conf || mlen != sizeof(msg) || memcmp(m, msg, mlen) != 0)
		goto out;
	error = 0;
out:
	if (a != NULL)
		gss_krb5_ctx_destroy(a);
	if (b != NULL)
		gss_krb5_ctx_destroy(b);
	return error;
}

int
gss_krb5_selftest(void)
{
	/* RFC 3962 App. B, the vector of 32 octets. */
	static const uint8_t ctskey[16] = {
		0x63, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20,
		0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69,
	};
	static const uint8_t ctspt[] = "I would like the General Gau's C";
	static const uint8_t ctsct[32] = {
		0x39, 0x31, 0x25, 0x23, 0xa7, 0x86, 0x62, 0xd5,
		0xbe, 0x7f, 0xcb, 0xcc, 0x98, 0xeb, 0xf5, 0xa8,
		0x97, 0x68, 0x72, 0x68, 0xd6, 0xec, 0xcc, 0xc0,
		0xc0, 0x7b, 0x25, 0xe2, 0x5e, 0xcf, 0xe5, 0x84,
	};
	/* RFC 8009 App. A, aes128, the plaintext of 6 octets, usage 2. */
	static const uint8_t k8009[16] = {
		0x37, 0x05, 0xd9, 0x60, 0x80, 0xc1, 0x77, 0x28,
		0xa0, 0xe8, 0x00, 0xea, 0xb6, 0xe0, 0xd2, 0x3c,
	};
	static const uint8_t conf8009[16 + 6] = {
		0x7b, 0xca, 0x28, 0x5e, 0x2f, 0xd4, 0x13, 0x0f,
		0xb5, 0x5b, 0x1a, 0x5c, 0x83, 0xbc, 0x5b, 0x24,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	};
	static const uint8_t ct8009[38] = {
		0x84, 0xd7, 0xf3, 0x07, 0x54, 0xed, 0x98, 0x7b,
		0xab, 0x0b, 0xf3, 0x50, 0x6b, 0xeb, 0x09, 0xcf,
		0xb5, 0x54, 0x02, 0xce, 0xf7, 0xe6, 0x87, 0x7c,
		0xe9, 0x9e, 0x24, 0x7e, 0x52, 0xd1, 0x6e, 0xd4,
		0x42, 0x1d, 0xfd, 0xf8, 0x97, 0x6c,
	};
	static const struct {
		uint32_t	enctype;
		bool		cfx;
	} rt[] = {
		{ GSS_KRB5_ENC_DES_CBC_CRC, false },
		{ GSS_KRB5_ENC_DES_CBC_MD5, false },
		{ GSS_KRB5_ENC_DES3_CBC_SHA1, false },
		{ GSS_KRB5_ENC_AES128_SHA1, true },
		{ GSS_KRB5_ENC_AES256_SHA1, true },
		{ GSS_KRB5_ENC_AES128_SHA256, true },
		{ GSS_KRB5_ENC_AES256_SHA384, true },
	};
	struct gk_dk dk;
	struct aesenc enc;
	struct aesdec dec;
	uint8_t buf[sizeof(ct8009)];
	uint32_t nr;
	size_t i;

	nr = aes_setenckey128(&enc, ctskey);
	(void)aes_setdeckey128(&dec, ctskey);
	memcpy(buf, ctspt, sizeof(ctsct));
	gk_cts_encrypt(&enc, nr, buf, sizeof(ctsct));
	if (memcmp(buf, ctsct, sizeof(ctsct)) != 0)
		return -1;
	gk_cts_decrypt(&dec, nr, buf, sizeof(ctsct));
	if (memcmp(buf, ctspt, sizeof(ctsct)) != 0)
		return -1;

	gk_dk_init(gk_etype_lookup(GSS_KRB5_ENC_AES128_SHA256), k8009, 2, &dk);
	memcpy(buf, conf8009, sizeof(conf8009));
	gk_encrypt(gk_etype_lookup(GSS_KRB5_ENC_AES128_SHA256), &dk, buf, 6);
	if (memcmp(buf, ct8009, sizeof(ct8009)) != 0)
		return -1;
	if (!gk_decrypt(gk_etype_lookup(GSS_KRB5_ENC_AES128_SHA256), &dk, buf,
	    sizeof(ct8009)) ||
	    memcmp(buf, conf8009, sizeof(conf8009)) != 0)
		return -1;
	explicit_memset(&dk, 0, sizeof(dk));

	for (i = 0; i < sizeof(rt) / sizeof(rt[0]); i++)
		if (gk_selftest_rt(rt[i].enctype, rt[i].cfx) != 0)
			return -1;
	return 0;
}
