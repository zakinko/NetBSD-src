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
 * The Kerberos crypto under the per-message tokens of gss_krb5.c: HMAC,
 * n-fold, key derivation and AES-CTS, as RFC 3961, RFC 3962 and RFC 8009
 * define them.  The block ciphers and hashes are the kernel's.  opencrypto
 * has no CTS and works by asynchronous sessions, so it is not used.
 *
 * Every message is its own encryption with the initial cipher state, all
 * zero, RFC 4121 s4.2.4 giving no chaining between tokens; so nothing here
 * carries an IV out.
 */

#include <sys/cdefs.h>
#ifdef _KERNEL
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/md5.h>
#include <sys/sha1.h>
#include <sys/sha2.h>

#include <crypto/aes/aes.h>
#include <crypto/aes/aes_cbc.h>
#include <crypto/des/des.h>

#define	GSS_KRB5_PRIVATE
#include <oncrpc/gss_krb5.h>
#else
#include "gss_krb5_shim.h"
#define	GSS_KRB5_PRIVATE
#include "gss_krb5.h"
#endif

/* RFC 3961 s5.3 and RFC 8009 s5 */
#define	GK_TAG_KC	0x99
#define	GK_TAG_KE	0xaa
#define	GK_TAG_KI	0x55

#define	GK_AES_BLOCK	16	/* RFC 3962 s6 */
#define	GK_DES_BLOCK	8	/* RFC 3961 s6.3 */

#define	GK_MAXHBLOCK	128	/* SHA-384 */
#define	GK_MAXSEED	32

static const struct gk_etype gk_etypes[] = {
	/*
	 * Only what a 1964 token needs of DES and 3DES.  RFC 3961 s6.2:
	 * 8 octets of key.  s6.3: 24 octets, 21 of seed, HMAC-SHA-1 of 160
	 * bits, and the DK of the simplified profile.
	 */
	{ .ge_enctype = GSS_KRB5_ENC_DES_CBC_CRC, .ge_keylen = 8,
	  .ge_block = GK_DES_BLOCK, .ge_maclen = 8, .ge_hash = GK_HASH_MD5 },
	{ .ge_enctype = GSS_KRB5_ENC_DES_CBC_MD5, .ge_keylen = 8,
	  .ge_block = GK_DES_BLOCK, .ge_maclen = 8, .ge_hash = GK_HASH_MD5 },
	{ .ge_enctype = GSS_KRB5_ENC_DES3_CBC_SHA1, .ge_keylen = 24,
	  .ge_seedlen = 21, .ge_block = GK_DES_BLOCK, .ge_maclen = 20,
	  .ge_kclen = 24, .ge_kelen = 24, .ge_kilen = 24,
	  .ge_hash = GK_HASH_SHA1 },
	/* RFC 3962 s6: h 12, keys of the protocol key's size. */
	{ .ge_enctype = GSS_KRB5_ENC_AES128_SHA1, .ge_keylen = 16,
	  .ge_seedlen = 16, .ge_block = GK_AES_BLOCK, .ge_maclen = 12,
	  .ge_kclen = 16, .ge_kelen = 16, .ge_kilen = 16,
	  .ge_hash = GK_HASH_SHA1 },
	{ .ge_enctype = GSS_KRB5_ENC_AES256_SHA1, .ge_keylen = 32,
	  .ge_seedlen = 32, .ge_block = GK_AES_BLOCK, .ge_maclen = 12,
	  .ge_kclen = 32, .ge_kelen = 32, .ge_kilen = 32,
	  .ge_hash = GK_HASH_SHA1 },
	/* RFC 8009 s5: Kc, Ke, Ki of 128, 128, 128 and 192, 256, 192. */
	{ .ge_enctype = GSS_KRB5_ENC_AES128_SHA256, .ge_keylen = 16,
	  .ge_block = GK_AES_BLOCK, .ge_maclen = 16,
	  .ge_kclen = 16, .ge_kelen = 16, .ge_kilen = 16,
	  .ge_hash = GK_HASH_SHA256, .ge_kdf2 = true },
	{ .ge_enctype = GSS_KRB5_ENC_AES256_SHA384, .ge_keylen = 32,
	  .ge_block = GK_AES_BLOCK, .ge_maclen = 24,
	  .ge_kclen = 24, .ge_kelen = 32, .ge_kilen = 24,
	  .ge_hash = GK_HASH_SHA384, .ge_kdf2 = true },
};

const struct gk_etype *
gk_etype_lookup(uint32_t enctype)
{
	size_t i;

	for (i = 0; i < sizeof(gk_etypes) / sizeof(gk_etypes[0]); i++)
		if (gk_etypes[i].ge_enctype == enctype)
			return &gk_etypes[i];
	return NULL;
}

union gk_hctx {
	MD5_CTX		md5;
	SHA1_CTX	sha1;
	SHA256_CTX	sha256;
	SHA384_CTX	sha384;
};

static size_t
gk_hash_block(int h)
{

	return h == GK_HASH_SHA384 ? SHA384_BLOCK_LENGTH : SHA1_BLOCK_LENGTH;
}

static size_t
gk_hash_len(int h)
{

	switch (h) {
	case GK_HASH_MD5:
		return 16;
	case GK_HASH_SHA1:
		return 20;
	case GK_HASH_SHA256:
		return 32;
	default:
		return GK_MAXHASH;
	}
}

static void
gk_hash_init(int h, union gk_hctx *c)
{

	switch (h) {
	case GK_HASH_MD5:
		MD5Init(&c->md5);
		break;
	case GK_HASH_SHA1:
		SHA1Init(&c->sha1);
		break;
	case GK_HASH_SHA256:
		SHA256_Init(&c->sha256);
		break;
	default:
		SHA384_Init(&c->sha384);
		break;
	}
}

static void
gk_hash_update(int h, union gk_hctx *c, const void *p, size_t len)
{
	const uint8_t *q = p;
	unsigned int n;

	/* MD5Update() and SHA1Update() count in an unsigned int. */
	while (len > 0) {
		n = len > 0x40000000 ? 0x40000000 : (unsigned int)len;
		switch (h) {
		case GK_HASH_MD5:
			MD5Update(&c->md5, q, n);
			break;
		case GK_HASH_SHA1:
			SHA1Update(&c->sha1, q, n);
			break;
		case GK_HASH_SHA256:
			SHA256_Update(&c->sha256, q, n);
			break;
		default:
			SHA384_Update(&c->sha384, q, n);
			break;
		}
		q += n;
		len -= n;
	}
}

static void
gk_hash_final(int h, union gk_hctx *c, uint8_t *out)
{

	switch (h) {
	case GK_HASH_MD5:
		MD5Final(out, &c->md5);
		break;
	case GK_HASH_SHA1:
		SHA1Final(out, &c->sha1);
		break;
	case GK_HASH_SHA256:
		SHA256_Final(out, &c->sha256);
		break;
	default:
		SHA384_Final(out, &c->sha384);
		break;
	}
}

/*
 * RFC 2104 s2, in full; the callers truncate.  Every key here is shorter
 * than the block, so the step that hashes a long key is not needed.  out
 * has GK_MAXHASH bytes.
 */
void
gk_hmac(int h, const void *key, size_t keylen, const struct gk_iov *iov,
    int niov, uint8_t *out)
{
	uint8_t pad[GK_MAXHBLOCK], inner[GK_MAXHASH];
	union gk_hctx c;
	size_t i, block = gk_hash_block(h);
	int v;

	KASSERT(keylen <= block);

	memset(pad, 0x36, block);	/* RFC 2104 s2, ipad */
	for (i = 0; i < keylen; i++)
		pad[i] ^= ((const uint8_t *)key)[i];
	gk_hash_init(h, &c);
	gk_hash_update(h, &c, pad, block);
	for (v = 0; v < niov; v++)
		gk_hash_update(h, &c, iov[v].gv_base, iov[v].gv_len);
	gk_hash_final(h, &c, inner);

	for (i = 0; i < block; i++)	/* RFC 2104 s2, opad */
		pad[i] ^= 0x36 ^ 0x5c;
	gk_hash_init(h, &c);
	gk_hash_update(h, &c, pad, block);
	gk_hash_update(h, &c, inner, gk_hash_len(h));
	gk_hash_final(h, &c, out);

	explicit_memset(pad, 0, sizeof(pad));
	explicit_memset(inner, 0, sizeof(inner));
	explicit_memset(&c, 0, sizeof(c));
}

static size_t
gk_gcd(size_t a, size_t b)
{
	size_t t;

	while (b != 0) {
		t = a % b;
		a = b;
		b = t;
	}
	return a;
}

/*
 * RFC 3961 s5.1.  The stream is the input repeated to the least common
 * multiple of the two lengths, each repetition 13 bits further right of
 * the one before, cut in chunks of the output's length; those are summed
 * in 1's complement.  In octets, big-endian.  It runs when a context is
 * made, so it reads the stream a bit at a time and keeps none of it.
 */
void
gk_nfold(const void *in, size_t inlen, void *outp, size_t outlen)
{
	const uint8_t *x = in;
	uint8_t *out = outp;
	size_t lcm, total, inbits, c, j, k, p, pos, r, s;
	unsigned int sum, carry, b;
	int bit;

	lcm = inlen / gk_gcd(inlen, outlen) * outlen;
	inbits = inlen * 8;
	memset(out, 0, outlen);
	total = lcm / outlen;
	for (c = 0; c < total; c++) {
		carry = 0;
		for (j = outlen; j-- > 0;) {
			k = c * outlen + j;
			r = k / inlen;
			s = (r * 13) % inbits;
			pos = (k % inlen) * 8;
			b = 0;
			for (bit = 0; bit < 8; bit++) {
				/* Right by s: from s bits earlier. */
				p = (pos + bit + inbits - s) % inbits;
				b = (b << 1) |
				    ((x[p / 8] >> (7 - p % 8)) & 1);
			}
			sum = out[j] + b + carry;
			out[j] = sum & 0xff;
			carry = sum >> 8;
		}
		for (j = outlen; carry != 0 && j-- > 0;) {
			sum = out[j] + carry;
			out[j] = sum & 0xff;
			carry = sum >> 8;
		}
	}
}

static uint32_t
gk_aes_setenc(struct aesenc *enc, const void *key, size_t keylen)
{

	return keylen == 16 ? aes_setenckey128(enc, key) :
	    aes_setenckey256(enc, key);
}

static void
gk_des3_sched(const uint8_t *key, des_key_schedule ks1, des_key_schedule ks2,
    des_key_schedule ks3)
{
	des_cblock k;

	memcpy(k, key, 8);
	des_set_key_unchecked(&k, ks1);
	memcpy(k, key + 8, 8);
	des_set_key_unchecked(&k, ks2);
	memcpy(k, key + 16, 8);
	des_set_key_unchecked(&k, ks3);
	explicit_memset(k, 0, sizeof(k));
}

/*
 * DR of RFC 3961 s5.1, for the enctypes of the simplified profile, into
 * ge_seedlen bytes.  E of one block with the initial cipher state is the
 * block cipher alone: for AES-CTS by RFC 3962 s5, and for outer CBC since
 * the IV is zero.
 */
void
gk_dr(const struct gk_etype *et, const void *key, const void *constant,
    size_t len, void *out)
{
	uint8_t block[GK_AES_BLOCK], *o = out;
	struct aesenc enc;
	des_key_schedule ks1, ks2, ks3;
	des_cblock iv;
	size_t c = et->ge_block, n, left;
	uint32_t nrounds = 0;

	KASSERT(len <= c);

	if (c == GK_AES_BLOCK)
		nrounds = gk_aes_setenc(&enc, key, et->ge_keylen);
	else
		gk_des3_sched(key, ks1, ks2, ks3);

	gk_nfold(constant, len, block, c);
	for (left = et->ge_seedlen; left > 0; left -= n) {
		if (c == GK_AES_BLOCK)
			aes_enc(&enc, block, block, nrounds);
		else {
			memset(iv, 0, sizeof(iv));
			des_ede3_cbc_encrypt(block, block, GK_DES_BLOCK, ks1,
			    ks2, ks3, &iv, DES_ENCRYPT);
		}
		n = left < c ? left : c;
		memcpy(o, block, n);
		o += n;
	}

	explicit_memset(block, 0, sizeof(block));
	if (c == GK_AES_BLOCK)
		explicit_memset(&enc, 0, sizeof(enc));
	else {
		explicit_memset(ks1, 0, sizeof(des_key_schedule));
		explicit_memset(ks2, 0, sizeof(des_key_schedule));
		explicit_memset(ks3, 0, sizeof(des_key_schedule));
	}
}

/*
 * RFC 3961 s6.3.1, DES3random-to-key: each 7 octets become 8, the eighth
 * collecting the low bits of the seven, the first one's the highest but
 * for the parity bit; then odd parity, and s6.2's correction of weak keys.
 */
void
gk_des3_random_to_key(const uint8_t *in, uint8_t *out)
{
	des_cblock k;
	int i, j;

	for (i = 0; i < 3; i++) {
		memcpy(k, in + i * 7, 7);
		k[7] = 0;
		/* Bits 8, 16, .. 56 of the table: the first goes right. */
		for (j = 0; j < 7; j++)
			k[7] |= (k[j] & 1) << (j + 1);
		des_set_odd_parity(&k);
		if (des_is_weak_key(&k))
			k[7] ^= 0xf0;	/* RFC 3961 s6.2 */
		memcpy(out + i * 8, k, 8);
	}
	explicit_memset(k, 0, sizeof(k));
}

/*
 * KDF-HMAC-SHA2 of RFC 8009 s3, kbits at most the hash's length.  context
 * may be absent.
 */
void
gk_kdf2(int h, const void *key, size_t keylen, const void *label,
    size_t labellen, const void *context, size_t contextlen, uint32_t kbits,
    void *out)
{
	static const uint8_t one[4] = { 0, 0, 0, 1 };	/* RFC 8009 s3, i */
	static const uint8_t zero[1] = { 0 };
	uint8_t l[4], k1[GK_MAXHASH];
	struct gk_iov iov[5];

	KASSERT(kbits / 8 <= gk_hash_len(h));

	l[0] = (uint8_t)(kbits >> 24);
	l[1] = (uint8_t)(kbits >> 16);
	l[2] = (uint8_t)(kbits >> 8);
	l[3] = (uint8_t)kbits;
	iov[0] = (struct gk_iov){ one, sizeof(one) };
	iov[1] = (struct gk_iov){ label, labellen };
	iov[2] = (struct gk_iov){ zero, sizeof(zero) };
	iov[3] = (struct gk_iov){ context, contextlen };
	iov[4] = (struct gk_iov){ l, sizeof(l) };
	gk_hmac(h, key, keylen, iov, 5, k1);
	memcpy(out, k1, kbits / 8);
	explicit_memset(k1, 0, sizeof(k1));
}

/*
 * The key of a usage and tag; usage and tag make the 5-octet constant of
 * RFC 3961 s5.3 and the label of RFC 8009 s5.
 */
void
gk_derive(const struct gk_etype *et, const void *key, uint32_t usage,
    uint8_t tag, void *out)
{
	uint8_t c[5], seed[GK_MAXSEED];
	uint32_t len;

	c[0] = (uint8_t)(usage >> 24);
	c[1] = (uint8_t)(usage >> 16);
	c[2] = (uint8_t)(usage >> 8);
	c[3] = (uint8_t)usage;
	c[4] = tag;
	if (et->ge_kdf2) {
		len = tag == GK_TAG_KC ? et->ge_kclen :
		    tag == GK_TAG_KE ? et->ge_kelen : et->ge_kilen;
		gk_kdf2(et->ge_hash, key, et->ge_keylen, c, sizeof(c), NULL,
		    0, len * 8, out);
	} else if (et->ge_block == GK_AES_BLOCK)
		gk_dr(et, key, c, sizeof(c), out);	/* identity, RFC 3962 s6 */
	else {
		gk_dr(et, key, c, sizeof(c), seed);
		gk_des3_random_to_key(seed, out);
		explicit_memset(seed, 0, sizeof(seed));
	}
}

/* Not for DES3, which uses none of these; see gss_krb5.c. */
void
gk_dk_init(const struct gk_etype *et, const void *key, uint32_t usage,
    struct gk_dk *dk)
{
	uint8_t ke[GSS_KRB5_MAXKEY];

	gk_derive(et, key, usage, GK_TAG_KC, dk->gd_kc);
	gk_derive(et, key, usage, GK_TAG_KI, dk->gd_ki);
	gk_derive(et, key, usage, GK_TAG_KE, ke);
	dk->gd_nrounds = gk_aes_setenc(&dk->gd_enc, ke, et->ge_kelen);
	if (et->ge_kelen == 16)
		(void)aes_setdeckey128(&dk->gd_dec, ke);
	else
		(void)aes_setdeckey256(&dk->gd_dec, ke);
	explicit_memset(ke, 0, sizeof(ke));
}

/*
 * RFC 3962 s5 in place, IV zero, at least one block.  One block is the
 * cipher alone; otherwise the last two go as RFC 2040 s8 with the errata
 * of RFC 3962 App. A.  A multiple of the block is then CBC with the last
 * two swapped.  Shorter input cannot occur, there being a confounder.
 */
void
gk_cts_encrypt(struct aesenc *enc, uint32_t nrounds, uint8_t *buf, size_t len)
{
	uint8_t iv[GK_AES_BLOCK], x[GK_AES_BLOCK], last[GK_AES_BLOCK];
	size_t head, tail;

	KASSERT(len >= GK_AES_BLOCK);

	memset(iv, 0, sizeof(iv));
	if (len == GK_AES_BLOCK) {
		aes_cbc_enc(enc, buf, buf, GK_AES_BLOCK, iv, nrounds);
		return;
	}
	tail = (len - 1) % GK_AES_BLOCK + 1;
	head = len - tail - GK_AES_BLOCK;
	if (head != 0)
		aes_cbc_enc(enc, buf, buf, head, iv, nrounds);
	aes_cbc_enc(enc, buf + head, x, GK_AES_BLOCK, iv, nrounds);
	memset(last, 0, sizeof(last));
	memcpy(last, buf + head + GK_AES_BLOCK, tail);
	aes_cbc_enc(enc, last, last, GK_AES_BLOCK, iv, nrounds);
	memcpy(buf + head, last, GK_AES_BLOCK);
	memcpy(buf + head + GK_AES_BLOCK, x, tail);
	explicit_memset(x, 0, sizeof(x));
	explicit_memset(last, 0, sizeof(last));
}

void
gk_cts_decrypt(struct aesdec *dec, uint32_t nrounds, uint8_t *buf, size_t len)
{
	uint8_t iv[GK_AES_BLOCK], d[GK_AES_BLOCK], x[GK_AES_BLOCK];
	size_t head, tail, i;

	KASSERT(len >= GK_AES_BLOCK);

	memset(iv, 0, sizeof(iv));
	if (len == GK_AES_BLOCK) {
		aes_cbc_dec(dec, buf, buf, GK_AES_BLOCK, iv, nrounds);
		return;
	}
	tail = (len - 1) % GK_AES_BLOCK + 1;
	head = len - tail - GK_AES_BLOCK;
	if (head != 0)
		aes_cbc_dec(dec, buf, buf, head, iv, nrounds);
	aes_dec(dec, buf + head, d, nrounds);
	/* The stolen part of the next-to-last block completes it. */
	memcpy(x, d, sizeof(x));
	memcpy(x, buf + head + GK_AES_BLOCK, tail);
	for (i = 0; i < tail; i++)
		d[i] ^= x[i];
	memcpy(buf + head + GK_AES_BLOCK, d, tail);
	aes_cbc_dec(dec, x, buf + head, GK_AES_BLOCK, iv, nrounds);
	explicit_memset(d, 0, sizeof(d));
	explicit_memset(x, 0, sizeof(x));
}

/*
 * buf has the confounder and then ptlen octets, with room after them for
 * the MAC; in its place comes the ciphertext.  RFC 3961 s5.3 takes the MAC
 * of the plaintext, RFC 8009 s5 that of the IV and the AES output.
 */
void
gk_encrypt(const struct gk_etype *et, struct gk_dk *dk, uint8_t *buf,
    size_t ptlen)
{
	static const uint8_t zeroiv[GK_AES_BLOCK];
	uint8_t mac[GK_MAXHASH];
	struct gk_iov iov[2];
	size_t len = et->ge_block + ptlen;

	if (et->ge_kdf2) {
		gk_cts_encrypt(&dk->gd_enc, dk->gd_nrounds, buf, len);
		iov[0] = (struct gk_iov){ zeroiv, sizeof(zeroiv) };
		iov[1] = (struct gk_iov){ buf, len };
		gk_hmac(et->ge_hash, dk->gd_ki, et->ge_kilen, iov, 2, mac);
	} else {
		iov[0] = (struct gk_iov){ buf, len };
		gk_hmac(et->ge_hash, dk->gd_ki, et->ge_kilen, iov, 1, mac);
		gk_cts_encrypt(&dk->gd_enc, dk->gd_nrounds, buf, len);
	}
	memcpy(buf + len, mac, et->ge_maclen);
	explicit_memset(mac, 0, sizeof(mac));
}

/*
 * The reverse, in place, of len octets which the caller has seen to be at
 * least the block and the MAC.  buf + ge_block is then the plaintext.
 */
bool
gk_decrypt(const struct gk_etype *et, struct gk_dk *dk, uint8_t *buf,
    size_t len)
{
	static const uint8_t zeroiv[GK_AES_BLOCK];
	uint8_t mac[GK_MAXHASH];
	struct gk_iov iov[2];
	size_t clen = len - et->ge_maclen;
	bool ok;

	KASSERT(len >= et->ge_block + et->ge_maclen);

	if (et->ge_kdf2) {
		/* RFC 8009 s5: the MAC first, then the decryption. */
		iov[0] = (struct gk_iov){ zeroiv, sizeof(zeroiv) };
		iov[1] = (struct gk_iov){ buf, clen };
		gk_hmac(et->ge_hash, dk->gd_ki, et->ge_kilen, iov, 2, mac);
		ok = consttime_memequal(mac, buf + clen, et->ge_maclen) != 0;
		if (ok)
			gk_cts_decrypt(&dk->gd_dec, dk->gd_nrounds, buf, clen);
	} else {
		gk_cts_decrypt(&dk->gd_dec, dk->gd_nrounds, buf, clen);
		iov[0] = (struct gk_iov){ buf, clen };
		gk_hmac(et->ge_hash, dk->gd_ki, et->ge_kilen, iov, 1, mac);
		ok = consttime_memequal(mac, buf + clen, et->ge_maclen) != 0;
	}
	explicit_memset(mac, 0, sizeof(mac));
	return ok;
}

/* RFC 3961 s5.4 and RFC 8009 s6, over the two pieces, into ge_maclen. */
void
gk_checksum(const struct gk_etype *et, const uint8_t *kc, const void *a,
    size_t alen, const void *b, size_t blen, uint8_t *out)
{
	uint8_t mac[GK_MAXHASH];
	struct gk_iov iov[2];

	iov[0] = (struct gk_iov){ a, alen };
	iov[1] = (struct gk_iov){ b, blen };
	gk_hmac(et->ge_hash, kc, et->ge_kclen, iov, 2, mac);
	memcpy(out, mac, et->ge_maclen);
	explicit_memset(mac, 0, sizeof(mac));
}
