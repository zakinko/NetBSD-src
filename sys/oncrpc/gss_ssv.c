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
 * The Secret State Verifier mechanism of RFC 8881 s2.10.9, for SP4_SSV:
 * a GSS mechanism inside NFSv4.1, whose contexts EXCHANGE_ID makes and
 * whose key SET_SSV sets.  This is the target's side: what this server
 * emits it keys with the T2I subkeys, and what it checks with the I2T
 * ones, on the fore channel and the back alike, s2.10.9.
 *
 * One SSV to a client ID, and one context to an SSV; every RPCSEC_GSS
 * handle made for it holds the same struct gss_ssv.  The last
 * GSS_SSV_MAXWINDOW versions of it keep their subkeys, s18.35.3, for
 * tokens made before a SET_SSV and checked after it.
 */

#ifdef _KERNEL
#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/atomic.h>
#include <sys/cprng.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/sha1.h>
#include <sys/sha2.h>
#include <sys/systm.h>

#include <crypto/aes/aes.h>
#include <crypto/aes/aes_cbc.h>

#include <oncrpc/gss_krb5.h>
#include <oncrpc/gss_mech.h>
#include <oncrpc/gss_ssv.h>
#else
#include "gss_krb5_shim.h"
#include "gss_krb5.h"
#include "gss_mech.h"
#include "gss_ssv.h"
#endif

/* RFC 8881 s2.10.9, enum ssv_subkey4 */
#define	SSV4_SUBKEY_MIC_I2T	1
#define	SSV4_SUBKEY_MIC_T2I	2
#define	SSV4_SUBKEY_SEAL_I2T	3
#define	SSV4_SUBKEY_SEAL_T2I	4

#define	SSV_BLOCK		16	/* AES, RFC 3565 s1.1 */
#define	SSV_CONFOUNDER		16	/* sspt_confounder; its length is ours */

/*
 * The object identifiers as GSS-API has them, RFC 8881 s3.3 for
 * sec_oid4: the DER of the OID without its tag and length.
 */
static const struct {
	uint8_t		len;
	uint8_t		oid[9];
	uint8_t		hlen;		/* the digest, RFC 6234 s1 */
	uint8_t		blk;		/* the block of the HMAC, RFC 2104 s2 */
} ssv_hash[GSS_SSV_NHASH] = {
	/* RFC 4055 s2.1, id-sha1 1.3.14.3.2.26 */
	[GSS_SSV_SHA1] = { 5, { 0x2b, 0x0e, 0x03, 0x02, 0x1a }, 20, 64 },
	/* id-sha224 2.16.840.1.101.3.4.2.4 */
	[GSS_SSV_SHA224] = { 9, { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
	    0x02, 0x04 }, 28, 64 },
	/* id-sha256 2.16.840.1.101.3.4.2.1 */
	[GSS_SSV_SHA256] = { 9, { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
	    0x02, 0x01 }, 32, 64 },
	/* id-sha384 2.16.840.1.101.3.4.2.2 */
	[GSS_SSV_SHA384] = { 9, { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
	    0x02, 0x02 }, 48, 128 },
	/* id-sha512 2.16.840.1.101.3.4.2.3 */
	[GSS_SSV_SHA512] = { 9, { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
	    0x02, 0x03 }, 64, 128 },
};

static const struct {
	uint8_t		len;
	uint8_t		oid[9];
	uint8_t		klen;
} ssv_encr[GSS_SSV_NENCR] = {
	/* RFC 3565 s4.1, id-aes128-CBC 2.16.840.1.101.3.4.1.2 */
	[GSS_SSV_AES128] = { 9, { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
	    0x01, 0x02 }, 16 },
	/* id-aes192-CBC 2.16.840.1.101.3.4.1.22 */
	[GSS_SSV_AES192] = { 9, { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
	    0x01, 0x16 }, 24 },
	/* id-aes256-CBC 2.16.840.1.101.3.4.1.42 */
	[GSS_SSV_AES256] = { 9, { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
	    0x01, 0x2a }, 32 },
};

struct ssv_keys {
	uint32_t	sk_ver;
	uint8_t		sk_mic_i2t[32];
	uint8_t		sk_mic_t2i[32];
	struct aesenc	sk_enc;		/* SEAL_T2I */
	struct aesdec	sk_dec;		/* SEAL_I2T */
};

struct gss_ssv {
	kmutex_t	gs_lock;	/* all but the constants */
	volatile u_int	gs_refs;
	int		gs_hash;
	int		gs_encr;
	uint32_t	gs_window;
	bool		gs_confirmed;	/* s18.35.3: the handles are usable */
	uint32_t	gs_ver;		/* 0 before the first SET_SSV */
	uint8_t		gs_ssv[GSS_SSV_MAXHASH];
	struct ssv_keys	gs_keys[GSS_SSV_MAXWINDOW];
};

union ssv_hctx {
	SHA1_CTX	sha1;
	SHA224_CTX	sha224;
	SHA256_CTX	sha256;
	SHA384_CTX	sha384;
	SHA512_CTX	sha512;
};

static void
ssv_hinit(int h, union ssv_hctx *c)
{

	switch (h) {
	case GSS_SSV_SHA1:	SHA1Init(&c->sha1); break;
	case GSS_SSV_SHA224:	SHA224_Init(&c->sha224); break;
	case GSS_SSV_SHA256:	SHA256_Init(&c->sha256); break;
	case GSS_SSV_SHA384:	SHA384_Init(&c->sha384); break;
	default:		SHA512_Init(&c->sha512); break;
	}
}

static void
ssv_hupdate(int h, union ssv_hctx *c, const void *p, size_t len)
{

	switch (h) {
	case GSS_SSV_SHA1:
		while (len > 0) {	/* SHA1Update takes an unsigned int */
			u_int n = MIN(len, 1U << 20);

			SHA1Update(&c->sha1, p, n);
			p = (const char *)p + n;
			len -= n;
		}
		break;
	case GSS_SSV_SHA224:	SHA224_Update(&c->sha224, p, len); break;
	case GSS_SSV_SHA256:	SHA256_Update(&c->sha256, p, len); break;
	case GSS_SSV_SHA384:	SHA384_Update(&c->sha384, p, len); break;
	default:		SHA512_Update(&c->sha512, p, len); break;
	}
}

static void
ssv_hfinal(int h, union ssv_hctx *c, uint8_t *out)
{

	switch (h) {
	case GSS_SSV_SHA1:	SHA1Final(out, &c->sha1); break;
	case GSS_SSV_SHA224:	SHA224_Final(out, &c->sha224); break;
	case GSS_SSV_SHA256:	SHA256_Final(out, &c->sha256); break;
	case GSS_SSV_SHA384:	SHA384_Final(out, &c->sha384); break;
	default:		SHA512_Final(out, &c->sha512); break;
	}
}

/* RFC 2104 s2, over the concatenation of two pieces. */
static void
ssv_hmac(int h, const uint8_t *key, size_t klen, const void *a, size_t alen,
    const void *b, size_t blen, uint8_t *out)
{
	uint8_t pad[128], inner[GSS_SSV_MAXHASH], k[GSS_SSV_MAXHASH];
	size_t blk = ssv_hash[h].blk, i;
	union ssv_hctx c;

	if (klen > blk) {	/* RFC 2104 s2: a long key is hashed first */
		ssv_hinit(h, &c);
		ssv_hupdate(h, &c, key, klen);
		ssv_hfinal(h, &c, k);
		key = k;
		klen = ssv_hash[h].hlen;
	}
	memset(pad, 0x36, blk);
	for (i = 0; i < klen; i++)
		pad[i] ^= key[i];
	ssv_hinit(h, &c);
	ssv_hupdate(h, &c, pad, blk);
	ssv_hupdate(h, &c, a, alen);
	if (blen != 0)
		ssv_hupdate(h, &c, b, blen);
	ssv_hfinal(h, &c, inner);
	for (i = 0; i < blk; i++)
		pad[i] ^= 0x36 ^ 0x5c;
	ssv_hinit(h, &c);
	ssv_hupdate(h, &c, pad, blk);
	ssv_hupdate(h, &c, inner, ssv_hash[h].hlen);
	ssv_hfinal(h, &c, out);
	explicit_memset(pad, 0, sizeof(pad));
	explicit_memset(inner, 0, sizeof(inner));
	explicit_memset(k, 0, sizeof(k));
	explicit_memset(&c, 0, sizeof(c));
}

/* sec_oid4, with or without the tag and length of the DER. */
static bool
ssv_oid_is(const uint8_t *p, size_t len, const uint8_t *oid, size_t olen)
{

	if (len == olen + 2 && p[0] == 0x06 && p[1] == olen) {
		p += 2;
		len -= 2;
	}
	return len == olen && memcmp(p, oid, olen) == 0;
}

int
gss_ssv_hash_byoid(const void *p, size_t len)
{
	int i;

	for (i = 0; i < GSS_SSV_NHASH; i++)
		if (ssv_oid_is(p, len, ssv_hash[i].oid, ssv_hash[i].len))
			return i;
	return -1;
}

int
gss_ssv_encr_byoid(const void *p, size_t len)
{
	int i;

	for (i = 0; i < GSS_SSV_NENCR; i++)
		if (ssv_oid_is(p, len, ssv_encr[i].oid, ssv_encr[i].len))
			return i;
	return -1;
}

/*
 * RFC 8881 s18.35.3, Table 21 and the key length: may hash h go with
 * encr?  With strict, the SHOULD NOT of the table counts too.
 */
int
gss_ssv_pair_ok(int h, int e, bool strict)
{

	if (ssv_encr[e].klen > ssv_hash[h].hlen)	/* MUST, key <= hash */
		return false;
	if (!strict)
		return true;
	/* SHOULD: the key at least half the hash */
	return ssv_encr[e].klen * 2 >= ssv_hash[h].hlen;
}

size_t
gss_ssv_hashlen(int h)
{

	return ssv_hash[h].hlen;
}

int
gss_ssv_create(int h, int e, uint32_t window, struct gss_ssv **gsp)
{
	struct gss_ssv *gs;

	if (h < 0 || h >= GSS_SSV_NHASH || e < 0 || e >= GSS_SSV_NENCR ||
	    window == 0 || !gss_ssv_pair_ok(h, e, false))
		return EINVAL;
	gs = kmem_zalloc(sizeof(*gs), KM_SLEEP);
	mutex_init(&gs->gs_lock, MUTEX_DEFAULT, IPL_NONE);
	gs->gs_refs = 1;
	gs->gs_hash = h;
	gs->gs_encr = e;
	gs->gs_window = MIN(window, GSS_SSV_MAXWINDOW);
	*gsp = gs;
	return 0;
}

void
gss_ssv_hold(struct gss_ssv *gs)
{

	atomic_inc_uint(&gs->gs_refs);
}

void
gss_ssv_rele(struct gss_ssv *gs)
{

	if (atomic_dec_uint_nv(&gs->gs_refs) != 0)
		return;
	mutex_destroy(&gs->gs_lock);
	explicit_memset(gs, 0, sizeof(*gs));
	kmem_free(gs, sizeof(*gs));
}

/* s18.35.3: the handles are not to be used before the client ID is. */
void
gss_ssv_confirm(struct gss_ssv *gs)
{

	mutex_enter(&gs->gs_lock);
	gs->gs_confirmed = true;
	mutex_exit(&gs->gs_lock);
}

/* The client ID is gone, and with it what its SSV protected. */
void
gss_ssv_kill(struct gss_ssv *gs)
{

	mutex_enter(&gs->gs_lock);
	gs->gs_confirmed = false;
	gs->gs_ver = 0;
	explicit_memset(gs->gs_ssv, 0, sizeof(gs->gs_ssv));
	explicit_memset(gs->gs_keys, 0, sizeof(gs->gs_keys));
	mutex_exit(&gs->gs_lock);
}

/* spi_ssv_len: the hash's length, which s18.35.3 asks for at least. */
size_t
gss_ssv_len(const struct gss_ssv *gs)
{

	return ssv_hash[gs->gs_hash].hlen;
}

/* s2.10.9: a subkey, the HMAC of the XDR of its ssv_subkey4, truncated. */
static void
ssv_subkey(const struct gss_ssv *gs, const uint8_t *ssv, uint32_t which,
    uint8_t *out)
{
	uint8_t mac[GSS_SSV_MAXHASH], x[4];

	be32enc(x, which);
	ssv_hmac(gs->gs_hash, ssv, gss_ssv_len(gs), x, sizeof(x), NULL, 0,
	    mac);
	memcpy(out, mac, ssv_encr[gs->gs_encr].klen);
	explicit_memset(mac, 0, sizeof(mac));
}

static void
ssv_setkey(struct gss_ssv *gs, struct ssv_keys *k, const uint8_t *ssv,
    uint32_t ver)
{
	uint8_t seal[32];

	k->sk_ver = ver;
	ssv_subkey(gs, ssv, SSV4_SUBKEY_MIC_I2T, k->sk_mic_i2t);
	ssv_subkey(gs, ssv, SSV4_SUBKEY_MIC_T2I, k->sk_mic_t2i);
	ssv_subkey(gs, ssv, SSV4_SUBKEY_SEAL_T2I, seal);
	switch (gs->gs_encr) {
	case GSS_SSV_AES128: aes_setenckey128(&k->sk_enc, seal); break;
	case GSS_SSV_AES192: aes_setenckey192(&k->sk_enc, seal); break;
	default: aes_setenckey256(&k->sk_enc, seal); break;
	}
	ssv_subkey(gs, ssv, SSV4_SUBKEY_SEAL_I2T, seal);
	switch (gs->gs_encr) {
	case GSS_SSV_AES128: aes_setdeckey128(&k->sk_dec, seal); break;
	case GSS_SSV_AES192: aes_setdeckey192(&k->sk_dec, seal); break;
	default: aes_setdeckey256(&k->sk_dec, seal); break;
	}
	explicit_memset(seal, 0, sizeof(seal));
}

/*
 * SET_SSV, RFC 8881 s18.47.3 and .4: din is the XDR of the SEQUENCE
 * arguments, checked against digest with the MIC_I2T subkey of the
 * present SSV; the new SSV is the present one xor ssa; dout is the XDR
 * of the SEQUENCE results, whose digest under the MIC_T2I subkey of the
 * new SSV goes to rdigest.  EAUTH for a digest that does not match,
 * NFS4ERR_BAD_SESSION_DIGEST; EINVAL for an ssa of the wrong length.
 */
int
gss_ssv_set(struct gss_ssv *gs, const void *ssa, size_t ssalen,
    const void *din, size_t dinlen, const void *digest, size_t dlen,
    const void *dout, size_t doutlen, void *rdigest, size_t *rdlen)
{
	uint8_t key[32], mac[GSS_SSV_MAXHASH], nssv[GSS_SSV_MAXHASH];
	size_t len = gss_ssv_len(gs), klen = ssv_encr[gs->gs_encr].klen, i;
	int error = 0;

	if (ssalen != len)
		return EINVAL;
	mutex_enter(&gs->gs_lock);
	ssv_subkey(gs, gs->gs_ssv, SSV4_SUBKEY_MIC_I2T, key);
	ssv_hmac(gs->gs_hash, key, klen, din, dinlen, NULL, 0, mac);
	if (dlen != len || !consttime_memequal(mac, digest, len)) {
		error = EAUTH;
		goto out;
	}
	for (i = 0; i < len; i++)
		nssv[i] = gs->gs_ssv[i] ^ ((const uint8_t *)ssa)[i];
	memcpy(gs->gs_ssv, nssv, len);
	gs->gs_ver++;
	ssv_setkey(gs, &gs->gs_keys[gs->gs_ver % gs->gs_window], gs->gs_ssv,
	    gs->gs_ver);
	ssv_subkey(gs, gs->gs_ssv, SSV4_SUBKEY_MIC_T2I, key);
	ssv_hmac(gs->gs_hash, key, klen, dout, doutlen, NULL, 0, rdigest);
	*rdlen = len;
out:
	mutex_exit(&gs->gs_lock);
	explicit_memset(key, 0, sizeof(key));
	explicit_memset(mac, 0, sizeof(mac));
	explicit_memset(nssv, 0, sizeof(nssv));
	return error;
}

/*
 * The keys of version ver, copied out under the lock: none before the
 * first SET_SSV, s2.10.9, before the client ID is confirmed, s18.35.3, or
 * outside the window, s18.35.3.
 */
static bool
ssv_keys_of(struct gss_ssv *gs, uint32_t ver, struct ssv_keys *k)
{
	bool ok;

	mutex_enter(&gs->gs_lock);
	if (ver == 0)
		ver = gs->gs_ver;	/* the present one */
	ok = gs->gs_confirmed && gs->gs_ver != 0 && ver <= gs->gs_ver &&
	    gs->gs_ver - ver < gs->gs_window &&
	    gs->gs_keys[ver % gs->gs_window].sk_ver == ver;
	if (ok)
		*k = gs->gs_keys[ver % gs->gs_window];
	mutex_exit(&gs->gs_lock);
	return ok;
}

static size_t
xlen(size_t n)
{

	return 4 + roundup(n, 4);
}

static uint8_t *
xput32(uint8_t *p, uint32_t v)
{

	be32enc(p, v);
	return p + 4;
}

static uint8_t *
xputop(uint8_t *p, const void *b, size_t n)
{

	p = xput32(p, n);
	memcpy(p, b, n);
	memset(p + n, 0, roundup(n, 4) - n);
	return p + roundup(n, 4);
}

/* An opaque<> at *pp within end; false if it is not whole. */
static bool
xgetop(const uint8_t **pp, const uint8_t *end, const uint8_t **bp, size_t *np)
{
	const uint8_t *p = *pp;
	uint32_t n;

	if (end - p < 4)
		return false;
	n = be32dec(p);
	p += 4;
	if ((size_t)(end - p) < roundup((size_t)n, 4) || n > (1U << 30))
		return false;
	*bp = p;
	*np = n;
	*pp = p + roundup((size_t)n, 4);
	return true;
}

/* s2.10.9: ssv_mic_tkn4 { smt_ssv_seq, smt_hmac<> } */
static uint32_t
ssv_get_mic(void *c, const void *msg, size_t len, void *tok, size_t tmax,
    size_t *tlenp)
{
	struct gss_ssv *gs = c;
	struct ssv_keys k;
	uint8_t head[8], mac[GSS_SSV_MAXHASH], *p = tok;
	size_t hl = gss_ssv_len(gs), pad = roundup(len, 4) - len;
	static const uint8_t zero[4];

	if (!ssv_keys_of(gs, 0, &k))
		return GSS_S_FAILURE;
	if (tmax < 8 + roundup(hl, 4))
		return GSS_S_FAILURE;
	/* ssv_mic_plain_tkn4 { smpt_ssv_seq, smpt_orig_plain<> } */
	be32enc(head, k.sk_ver);
	be32enc(head + 4, len);
	{
		union ssv_hctx hc;
		uint8_t ipad[128], inner[GSS_SSV_MAXHASH];
		size_t blk = ssv_hash[gs->gs_hash].blk, i,
		    klen = ssv_encr[gs->gs_encr].klen;

		/* The HMAC of head, msg and its pad, without a copy. */
		memset(ipad, 0x36, blk);
		for (i = 0; i < klen; i++)
			ipad[i] ^= k.sk_mic_t2i[i];
		ssv_hinit(gs->gs_hash, &hc);
		ssv_hupdate(gs->gs_hash, &hc, ipad, blk);
		ssv_hupdate(gs->gs_hash, &hc, head, sizeof(head));
		ssv_hupdate(gs->gs_hash, &hc, msg, len);
		ssv_hupdate(gs->gs_hash, &hc, zero, pad);
		ssv_hfinal(gs->gs_hash, &hc, inner);
		for (i = 0; i < blk; i++)
			ipad[i] ^= 0x36 ^ 0x5c;
		ssv_hinit(gs->gs_hash, &hc);
		ssv_hupdate(gs->gs_hash, &hc, ipad, blk);
		ssv_hupdate(gs->gs_hash, &hc, inner, hl);
		ssv_hfinal(gs->gs_hash, &hc, mac);
		explicit_memset(ipad, 0, sizeof(ipad));
	}
	p = xput32(p, k.sk_ver);
	p = xputop(p, mac, hl);
	*tlenp = p - (uint8_t *)tok;
	explicit_memset(&k, 0, sizeof(k));
	return GSS_S_COMPLETE;
}

/* The HMAC of ssv_mic_plain_tkn4 under key, as ssv_get_mic() has it. */
static void
ssv_mic_plain(const struct gss_ssv *gs, const uint8_t *key, uint32_t ver,
    const void *msg, size_t len, uint8_t *mac)
{
	uint8_t *buf;
	size_t n = 4 + xlen(len);

	buf = kmem_alloc(n, KM_SLEEP);
	xputop(xput32(buf, ver), msg, len);
	ssv_hmac(gs->gs_hash, key, ssv_encr[gs->gs_encr].klen, buf, n, NULL, 0,
	    mac);
	kmem_free(buf, n);
}

static uint32_t
ssv_verify_mic(void *c, const void *msg, size_t len, const void *tok,
    size_t tlen)
{
	struct gss_ssv *gs = c;
	const uint8_t *p = tok, *end = p + tlen, *hm;
	uint8_t mac[GSS_SSV_MAXHASH];
	struct ssv_keys k;
	size_t hmlen, hl = gss_ssv_len(gs);
	uint32_t ver;

	if (tlen < 4)
		return GSS_S_DEFECTIVE_TOKEN;
	ver = be32dec(p);
	p += 4;
	if (!xgetop(&p, end, &hm, &hmlen) || p != end || hmlen != hl)
		return GSS_S_DEFECTIVE_TOKEN;
	if (ver == 0 || !ssv_keys_of(gs, ver, &k))
		return GSS_S_CONTEXT_EXPIRED;
	ssv_mic_plain(gs, k.sk_mic_i2t, ver, msg, len, mac);
	explicit_memset(&k, 0, sizeof(k));
	return consttime_memequal(mac, hm, hl) ? GSS_S_COMPLETE :
	    GSS_S_BAD_SIG;
}

/* The length of ssv_seal_plain_tkn4 for len bytes, a block multiple. */
static size_t
ssv_plain_len(size_t len, size_t *padp)
{
	size_t n = xlen(SSV_CONFOUNDER) + 4 + xlen(len) + 4;

	*padp = roundup(n, SSV_BLOCK) - n;
	return n + *padp;
}

static size_t
ssv_wrap_size(const void *c, size_t len)
{
	const struct gss_ssv *gs = c;
	size_t pad, n;

	if (len > (1U << 30))
		return SIZE_MAX;
	n = ssv_plain_len(len, &pad);
	return 4 + xlen(SSV_BLOCK) + 4 + n + xlen(gss_ssv_len(gs));
}

/* s2.10.9: ssv_seal_cipher_tkn4 { seq, iv<>, encr_data<>, hmac<> } */
static uint32_t
ssv_wrap(void *c, const void *msg, size_t len, void *tok, size_t tmax,
    size_t *tlenp)
{
	struct gss_ssv *gs = c;
	struct ssv_keys k;
	uint8_t iv[SSV_BLOCK], ivc[SSV_BLOCK], conf[SSV_CONFOUNDER];
	uint8_t mac[GSS_SSV_MAXHASH], *p = tok, *plain;
	size_t pad, n, need = ssv_wrap_size(c, len), hl = gss_ssv_len(gs);
	uint32_t nr;

	if (need == SIZE_MAX || tmax < need || !ssv_keys_of(gs, 0, &k))
		return GSS_S_FAILURE;
	n = ssv_plain_len(len, &pad);
	/* s2.10.9: an IV not to be predicted, and a random confounder. */
	cprng_strong(kern_cprng, iv, sizeof(iv), 0);
	cprng_strong(kern_cprng, conf, sizeof(conf), 0);
	p = xput32(p, k.sk_ver);
	p = xputop(p, iv, sizeof(iv));
	p = xput32(p, n);
	plain = p;
	/* ssv_seal_plain_tkn4 { confounder<>, ssv_seq, orig_plain<>, pad<> } */
	p = xputop(p, conf, sizeof(conf));
	p = xput32(p, k.sk_ver);
	p = xputop(p, msg, len);
	/* sspt_pad<>: its length word, then zeros to the block. */
	p = xput32(p, pad);
	memset(p, 0, pad);
	p += pad;
	KASSERT((size_t)(p - plain) == n);
	/* The HMAC is of the plaintext, under the MIC subkey. */
	ssv_hmac(gs->gs_hash, k.sk_mic_t2i, ssv_encr[gs->gs_encr].klen, plain,
	    n, NULL, 0, mac);
	nr = gs->gs_encr == GSS_SSV_AES128 ? AES_128_NROUNDS :
	    gs->gs_encr == GSS_SSV_AES192 ? AES_192_NROUNDS : AES_256_NROUNDS;
	memcpy(ivc, iv, sizeof(iv));
	aes_cbc_enc(&k.sk_enc, plain, plain, n, ivc, nr);
	p = xputop(p, mac, hl);
	*tlenp = p - (uint8_t *)tok;
	explicit_memset(&k, 0, sizeof(k));
	explicit_memset(mac, 0, sizeof(mac));
	return GSS_S_COMPLETE;
}

static uint32_t
ssv_unwrap(void *c, void *tok, size_t tlen, void *out, void **outp,
    size_t *lenp, bool *confp)
{
	struct gss_ssv *gs = c;
	const uint8_t *p = tok, *end = p + tlen, *iv, *enc, *hm, *q, *qe;
	const uint8_t *b;
	uint8_t ivc[SSV_BLOCK], mac[GSS_SSV_MAXHASH];
	struct ssv_keys k;
	size_t ivlen, enclen, hmlen, bl, hl = gss_ssv_len(gs);
	uint32_t ver, nr;

	if (tlen < 4)
		return GSS_S_DEFECTIVE_TOKEN;
	ver = be32dec(p);
	p += 4;
	if (!xgetop(&p, end, &iv, &ivlen) || ivlen != SSV_BLOCK ||
	    !xgetop(&p, end, &enc, &enclen) || enclen % SSV_BLOCK != 0 ||
	    enclen == 0 || !xgetop(&p, end, &hm, &hmlen) || p != end ||
	    hmlen != hl)
		return GSS_S_DEFECTIVE_TOKEN;
	if (ver == 0 || !ssv_keys_of(gs, ver, &k))
		return GSS_S_CONTEXT_EXPIRED;
	nr = gs->gs_encr == GSS_SSV_AES128 ? AES_128_NROUNDS :
	    gs->gs_encr == GSS_SSV_AES192 ? AES_192_NROUNDS : AES_256_NROUNDS;
	memcpy(ivc, iv, sizeof(ivc));
	aes_cbc_dec(&k.sk_dec, enc, __UNCONST(enc), enclen, ivc, nr);
	ssv_hmac(gs->gs_hash, k.sk_mic_i2t, ssv_encr[gs->gs_encr].klen, enc,
	    enclen, NULL, 0, mac);
	explicit_memset(&k, 0, sizeof(k));
	if (!consttime_memequal(mac, hm, hl))
		return GSS_S_BAD_SIG;
	/* The plaintext, now proven: confounder<>, seq, orig<>, pad<>. */
	q = enc;
	qe = enc + enclen;
	if (!xgetop(&q, qe, &b, &bl) || qe - q < 4 || be32dec(q) != ver)
		return GSS_S_DEFECTIVE_TOKEN;
	q += 4;
	if (!xgetop(&q, qe, &b, &bl))
		return GSS_S_DEFECTIVE_TOKEN;
	*outp = __UNCONST(b);
	*lenp = bl;
	if (!xgetop(&q, qe, &b, &bl) || q != qe)
		return GSS_S_DEFECTIVE_TOKEN;
	*confp = true;
	return GSS_S_COMPLETE;
}

static void
ssv_destroy(void *c)
{

	gss_ssv_rele(c);
}

const struct oncrpc_gss_mech oncrpc_gss_ssv_mech = {
	.gm_get_mic = ssv_get_mic,
	.gm_verify_mic = ssv_verify_mic,
	.gm_wrap_size = ssv_wrap_size,
	.gm_wrap = ssv_wrap,
	.gm_unwrap = ssv_unwrap,
	.gm_destroy = ssv_destroy,
};
