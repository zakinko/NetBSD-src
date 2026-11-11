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
 * The SSV mechanism of RFC 8881 s2.10.9 and SET_SSV of s18.47 against a
 * second rendering of the same text made here with OpenSSL: subkeys,
 * digests, and tokens both ways, then tampering.  The RFC gives no
 * vectors.
 */

#include "gss_krb5_shim.h"
#include "gss_krb5.h"
#include "gss_mech.h"
#include "gss_ssv.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

static int fails, passes;

#define	CHECK(c, ...) do {						\
	if (c) passes++;						\
	else { fails++; printf("FAIL %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); } \
} while (0)

static const EVP_MD *
md(int h)
{

	switch (h) {
	case GSS_SSV_SHA1: return EVP_sha1();
	case GSS_SSV_SHA224: return EVP_sha224();
	case GSS_SSV_SHA256: return EVP_sha256();
	case GSS_SSV_SHA384: return EVP_sha384();
	default: return EVP_sha512();
	}
}

static size_t klen_of(int e) { return e == GSS_SSV_AES128 ? 16 : e == GSS_SSV_AES192 ? 24 : 32; }

static void
hm(int h, const uint8_t *k, size_t kl, const uint8_t *d, size_t dl, uint8_t *o)
{
	unsigned ol;

	HMAC(md(h), k, (int)kl, d, dl, o, &ol);
}

/* s2.10.9: HMAC(SSV, XDR(enum)), truncated to the key length. */
static void
subkey(int h, int e, const uint8_t *ssv, size_t sl, uint32_t which, uint8_t *o)
{
	uint8_t x[4], m[64];

	be32enc(x, which);
	hm(h, ssv, sl, x, 4, m);
	memcpy(o, m, klen_of(e));
}

static size_t
put32(uint8_t *p, uint32_t v)
{

	be32enc(p, v);
	return 4;
}

static size_t
putop(uint8_t *p, const void *b, size_t n)
{

	be32enc(p, (uint32_t)n);
	memcpy(p + 4, b, n);
	memset(p + 4 + n, 0, (4 - n % 4) % 4);
	return 4 + n + (4 - n % 4) % 4;
}

static void
one(int h, int e)
{
	struct gss_ssv *gs;
	struct oncrpc_gss_key key;
	uint8_t ssv[64] = { 0 }, ssa[64], din[40], dout[44], dig[64], rd[64];
	uint8_t k[32], tok[4096], plain[2048], msg[300], buf[4096], exp[64];
	size_t sl = gss_ssv_hashlen(h), kl = klen_of(e), rl, tl, n, i, ml;
	void *outp;
	bool conf;
	uint32_t st;

	if (gss_ssv_create(h, e, 3, &gs) != 0) {
		CHECK(!gss_ssv_pair_ok(h, e, false), "create %d %d", h, e);
		return;
	}
	key.k_mech = &oncrpc_gss_ssv_mech;
	key.k_ctx = gs;
	for (i = 0; i < sizeof(msg); i++)
		msg[i] = (uint8_t)(i * 7);
	/* s2.10.9: no tokens before SET_SSV. */
	CHECK(oncrpc_gssk_get_mic(&key, msg, 10, tok, sizeof(tok), &tl) != 0,
	    "mic before SET_SSV");
	gss_ssv_confirm(gs);
	CHECK(oncrpc_gssk_get_mic(&key, msg, 10, tok, sizeof(tok), &tl) != 0,
	    "mic before SET_SSV, confirmed");

	/* SET_SSV, s18.47.3: digest of the SEQUENCE args under the zero SSV. */
	for (i = 0; i < sizeof(din); i++)
		din[i] = (uint8_t)i;
	for (i = 0; i < sizeof(dout); i++)
		dout[i] = (uint8_t)(0x80 + i);
	RAND_bytes(ssa, (int)sl);
	subkey(h, e, ssv, sl, 1, k);
	hm(h, k, kl, din, sizeof(din), dig);
	dig[0] ^= 1;
	CHECK(gss_ssv_set(gs, ssa, sl, din, sizeof(din), dig, sl, dout,
	    sizeof(dout), rd, &rl) == EAUTH, "bad digest taken");
	dig[0] ^= 1;
	CHECK(gss_ssv_set(gs, ssa, sl - 1, din, sizeof(din), dig, sl, dout,
	    sizeof(dout), rd, &rl) == EINVAL, "short ssa taken");
	CHECK(gss_ssv_set(gs, ssa, sl, din, sizeof(din), dig, sl, dout,
	    sizeof(dout), rd, &rl) == 0, "SET_SSV");
	for (i = 0; i < sl; i++)
		ssv[i] ^= ssa[i];
	subkey(h, e, ssv, sl, 2, k);
	hm(h, k, kl, dout, sizeof(dout), exp);
	CHECK(rl == sl && memcmp(exp, rd, sl) == 0, "ssr_digest");

	for (ml = 0; ml < sizeof(msg); ml += 37) {
		/* Ours, read as the RFC has it: ssv_mic_tkn4, T2I. */
		st = oncrpc_gssk_get_mic(&key, msg, ml, tok, sizeof(tok), &tl);
		n = put32(buf, 1);
		n += putop(buf + n, msg, ml);
		subkey(h, e, ssv, sl, 2, k);
		hm(h, k, kl, buf, n, exp);
		CHECK(st == 0 && tl == 8 + ((sl + 3) & ~3UL) &&
		    be32dec(tok) == 1 && be32dec(tok + 4) == sl &&
		    memcmp(tok + 8, exp, sl) == 0, "mic %zu", ml);
		/* Theirs, I2T. */
		subkey(h, e, ssv, sl, 1, k);
		hm(h, k, kl, buf, n, exp);
		n = put32(tok, 1);
		n += putop(tok + n, exp, sl);
		CHECK(oncrpc_gssk_verify_mic(&key, msg, ml, tok, n) == 0,
		    "verify %zu", ml);
		tok[8] ^= 1;
		CHECK(oncrpc_gssk_verify_mic(&key, msg, ml, tok, n) != 0,
		    "verify tampered %zu", ml);
		tok[8] ^= 1;
		be32enc(tok, 7);
		CHECK(oncrpc_gssk_verify_mic(&key, msg, ml, tok, n) != 0,
		    "verify version 7 %zu", ml);

		/* Ours sealed: decrypt with SEAL_T2I, HMAC with MIC_T2I. */
		st = oncrpc_gssk_wrap(&key, msg, ml, tok, sizeof(tok), &tl);
		CHECK(st == 0 && tl <= oncrpc_gssk_wrap_size(&key, ml),
		    "wrap %zu", ml);
		{
			size_t o = 4, ivl, el;
			uint8_t iv[16], sk[32];
			EVP_CIPHER_CTX *cx = EVP_CIPHER_CTX_new();
			const EVP_CIPHER *ci = kl == 16 ? EVP_aes_128_cbc() :
			    kl == 24 ? EVP_aes_192_cbc() : EVP_aes_256_cbc();
			int ol, ol2;

			ivl = be32dec(tok + o); o += 4;
			memcpy(iv, tok + o, 16); o += 16;
			el = be32dec(tok + o); o += 4;
			subkey(h, e, ssv, sl, 4, sk);
			EVP_DecryptInit_ex(cx, ci, NULL, sk, iv);
			EVP_CIPHER_CTX_set_padding(cx, 0);
			EVP_DecryptUpdate(cx, plain, &ol, tok + o, (int)el);
			EVP_DecryptFinal_ex(cx, plain + ol, &ol2);
			EVP_CIPHER_CTX_free(cx);
			subkey(h, e, ssv, sl, 2, k);
			hm(h, k, kl, plain, el, exp);
			CHECK(ivl == 16 && el % 16 == 0 &&
			    be32dec(tok + o + el) == sl &&
			    memcmp(tok + o + el + 4, exp, sl) == 0,
			    "seal hmac %zu", ml);
			n = 4 + ((be32dec(plain) + 3) & ~3U);
			CHECK(be32dec(plain + n) == 1 &&
			    be32dec(plain + n + 4) == ml &&
			    memcmp(plain + n + 8, msg, ml) == 0, "seal plain %zu", ml);
		}
		/* Theirs sealed with SEAL_I2T, unwrapped by us. */
		{
			uint8_t iv[16], sk[32], conf3[3] = { 9, 8, 7 };
			size_t p = 0, pad, o;
			EVP_CIPHER_CTX *cx = EVP_CIPHER_CTX_new();
			const EVP_CIPHER *ci = kl == 16 ? EVP_aes_128_cbc() :
			    kl == 24 ? EVP_aes_192_cbc() : EVP_aes_256_cbc();
			int ol, ol2;

			p += putop(plain + p, conf3, 3);
			p += put32(plain + p, 1);
			p += putop(plain + p, msg, ml);
			pad = (16 - (p + 4) % 16) % 16;
			p += put32(plain + p, (uint32_t)pad);
			memset(plain + p, 0, pad);
			p += pad;
			subkey(h, e, ssv, sl, 1, k);
			hm(h, k, kl, plain, p, exp);
			RAND_bytes(iv, 16);
			o = put32(tok, 1);
			o += putop(tok + o, iv, 16);
			o += put32(tok + o, (uint32_t)p);
			subkey(h, e, ssv, sl, 3, sk);
			EVP_EncryptInit_ex(cx, ci, NULL, sk, iv);
			EVP_CIPHER_CTX_set_padding(cx, 0);
			EVP_EncryptUpdate(cx, tok + o, &ol, plain, (int)p);
			EVP_EncryptFinal_ex(cx, tok + o + ol, &ol2);
			EVP_CIPHER_CTX_free(cx);
			o += p;
			o += putop(tok + o, exp, sl);
			memcpy(buf, tok, o);
			st = oncrpc_gssk_unwrap(&key, tok, o, NULL, &outp, &n,
			    &conf);
			CHECK(st == 0 && conf && n == ml &&
			    memcmp(outp, msg, ml) == 0, "unwrap %zu", ml);
			for (i = 0; i < o; i += 5) {
				memcpy(tok, buf, o);
				tok[i] ^= 0x10;
				st = oncrpc_gssk_unwrap(&key, tok, o, NULL,
				    &outp, &n, &conf);
				CHECK(st != 0 || (i < 4 && false),
				    "unwrap tampered at %zu of %zu", i, o);
			}
			for (i = 0; i < o; i++) {
				memcpy(tok, buf, i);
				CHECK(oncrpc_gssk_unwrap(&key, tok, i, NULL,
				    &outp, &n, &conf) != 0, "truncated %zu", i);
			}
		}
	}
	gss_ssv_rele(gs);
}

int
main(void)
{
	int h, e;

	for (h = 0; h < GSS_SSV_NHASH; h++)
		for (e = 0; e < GSS_SSV_NENCR; e++)
			one(h, e);
	/* RFC 8881 Table 21, the MUST NOT: aes192 with sha1, aes256 with sha1 and sha224. */
	CHECK(!gss_ssv_pair_ok(GSS_SSV_SHA1, GSS_SSV_AES192, false), "t21 1");
	CHECK(!gss_ssv_pair_ok(GSS_SSV_SHA1, GSS_SSV_AES256, false), "t21 2");
	CHECK(!gss_ssv_pair_ok(GSS_SSV_SHA224, GSS_SSV_AES256, false), "t21 3");
	/* The SHOULD NOT: aes128 with sha384 and sha512, aes192 with sha512. */
	CHECK(!gss_ssv_pair_ok(GSS_SSV_SHA384, GSS_SSV_AES128, true), "t21 4");
	CHECK(!gss_ssv_pair_ok(GSS_SSV_SHA512, GSS_SSV_AES128, true), "t21 5");
	CHECK(!gss_ssv_pair_ok(GSS_SSV_SHA512, GSS_SSV_AES192, true), "t21 6");
	CHECK(gss_ssv_pair_ok(GSS_SSV_SHA256, GSS_SSV_AES256, true), "t21 7");
	printf("%d passed, %d failed\n", passes, fails);
	return fails != 0;
}
