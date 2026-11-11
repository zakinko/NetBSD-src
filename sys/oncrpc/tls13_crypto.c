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
 * AES-128-GCM after NIST SP 800-38D, and the record protection and
 * traffic keys of TLS 1.3 for TLS_AES_128_GCM_SHA256, RFC 8446 s5 and s7.
 * The GHASH multiplication is Algorithm 1 bit by bit, with masks in place
 * of branches so that its time does not depend on H or on the data; a
 * table-driven one is a matter of speed only.
 */

#include <sys/cdefs.h>
#ifdef _KERNEL
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/sha2.h>

#include <crypto/aes/aes.h>

#include <oncrpc/tls13_crypto.h>
#else
#include "gss_krb5_shim.h"
#include "tls13_crypto.h"
#endif

#define	GCM_BLOCK	16

/* SP 800-38D s6.3: R = 11100001 || 0^120, as the high word. */
#define	GCM_R		0xe100000000000000ULL

static inline uint64_t
ld64(const uint8_t *p)
{

	return (uint64_t)p[0] << 56 | (uint64_t)p[1] << 48 |
	    (uint64_t)p[2] << 40 | (uint64_t)p[3] << 32 |
	    (uint64_t)p[4] << 24 | (uint64_t)p[5] << 16 |
	    (uint64_t)p[6] << 8 | (uint64_t)p[7];
}

static inline void
st64(uint8_t *p, uint64_t v)
{
	int i;

	for (i = 7; i >= 0; i--, v >>= 8)
		p[i] = (uint8_t)v;
}

/*
 * SP 800-38D s6.3, Algorithm 1: x = x * h.  Bit x_0 is the most
 * significant bit of x[0]; "V >> 1" moves every bit to the next index.
 */
static void
gcm_mul(uint8_t x[GCM_BLOCK], const uint8_t h[GCM_BLOCK])
{
	uint64_t zh = 0, zl = 0, vh = ld64(h), vl = ld64(h + 8), m;
	int i;

	for (i = 0; i < 128; i++) {
		m = -(uint64_t)((x[i >> 3] >> (7 - (i & 7))) & 1);
		zh ^= vh & m;
		zl ^= vl & m;
		m = -(vl & 1);			/* LSB_1(V_i) */
		vl = vl >> 1 | vh << 63;
		vh = vh >> 1 ^ (GCM_R & m);
	}
	st64(x, zh);
	st64(x + 8, zl);
}

/*
 * SP 800-38D s6.4, Algorithm 2, carried on in y over a string padded with
 * zeros to whole blocks, as s7.1 step 5 pads A and C.
 */
static void
gcm_ghash(uint8_t y[GCM_BLOCK], const uint8_t h[GCM_BLOCK], const uint8_t *x,
    size_t len)
{
	size_t i, n;

	while (len > 0) {
		n = MIN(len, GCM_BLOCK);
		for (i = 0; i < n; i++)
			y[i] ^= x[i];
		gcm_mul(y, h);
		x += n;
		len -= n;
	}
}

/* SP 800-38D s6.2, inc_32 */
static inline void
gcm_inc32(uint8_t cb[GCM_BLOCK])
{
	int i;

	for (i = GCM_BLOCK - 1; i >= GCM_BLOCK - 4; i--)
		if (++cb[i] != 0)
			break;
}

/* SP 800-38D s6.5, Algorithm 3, in place. */
static void
gcm_gctr(const struct tls13_gcm *g, const uint8_t icb[GCM_BLOCK], uint8_t *x,
    size_t len)
{
	uint8_t cb[GCM_BLOCK], ks[GCM_BLOCK];
	size_t i, n;

	memcpy(cb, icb, GCM_BLOCK);
	while (len > 0) {
		aes_enc(&g->g_enc, cb, ks, g->g_nrounds);
		n = MIN(len, GCM_BLOCK);
		for (i = 0; i < n; i++)
			x[i] ^= ks[i];
		gcm_inc32(cb);
		x += n;
		len -= n;
	}
	explicit_memset(ks, 0, sizeof(ks));
}

void
tls13_gcm_init(struct tls13_gcm *g, const uint8_t *key)
{
	static const uint8_t zero[GCM_BLOCK];

	g->g_nrounds = aes_setenckey128(&g->g_enc, key);
	aes_enc(&g->g_enc, zero, g->g_h, g->g_nrounds);	/* s7.1 step 1 */
}

/*
 * s7.1 steps 2, 5 and 6 for a 96-bit IV: J_0 and the tag of A and C.
 */
static void
gcm_j0_tag(const struct tls13_gcm *g, const uint8_t *iv, uint8_t j0[GCM_BLOCK],
    const uint8_t *a, size_t alen, const uint8_t *c, size_t clen,
    uint8_t tag[GCM_BLOCK])
{
	uint8_t s[GCM_BLOCK], lens[GCM_BLOCK];

	/* step 2: J_0 = IV || 0^31 || 1 */
	memcpy(j0, iv, TLS13_IVLEN);
	j0[12] = j0[13] = j0[14] = 0;
	j0[15] = 1;

	/* step 5: S = GHASH(A || 0^v || C || 0^u || [len(A)]_64 || [len(C)]_64) */
	memset(s, 0, sizeof(s));
	gcm_ghash(s, g->g_h, a, alen);
	gcm_ghash(s, g->g_h, c, clen);
	st64(lens, (uint64_t)alen * 8);
	st64(lens + 8, (uint64_t)clen * 8);
	gcm_ghash(s, g->g_h, lens, sizeof(lens));

	/* step 6: T = MSB_t(GCTR(J_0, S)), t = 128 */
	gcm_gctr(g, j0, s, sizeof(s));
	memcpy(tag, s, GCM_BLOCK);
	explicit_memset(s, 0, sizeof(s));
}

/* SP 800-38D s7.1, Algorithm 4, with a 96-bit IV, in place. */
void
tls13_gcm_seal(const struct tls13_gcm *g, const uint8_t *iv, const uint8_t *a,
    size_t alen, uint8_t *p, size_t len, uint8_t *tag)
{
	uint8_t j0[GCM_BLOCK], icb[GCM_BLOCK];

	memcpy(icb, iv, TLS13_IVLEN);
	icb[12] = icb[13] = icb[14] = 0;
	icb[15] = 1;
	gcm_inc32(icb);
	gcm_gctr(g, icb, p, len);			/* step 3 */
	gcm_j0_tag(g, iv, j0, a, alen, p, len, tag);
}

/*
 * SP 800-38D s7.2, Algorithm 5, in place.  The tag is checked first, as
 * s7 allows, so that nothing is decrypted under a forged one.
 */
int
tls13_gcm_open(const struct tls13_gcm *g, const uint8_t *iv, const uint8_t *a,
    size_t alen, uint8_t *c, size_t len, const uint8_t *tag)
{
	uint8_t j0[GCM_BLOCK], icb[GCM_BLOCK], t[GCM_BLOCK];
	int ok;

	gcm_j0_tag(g, iv, j0, a, alen, c, len, t);
	ok = consttime_memequal(t, tag, GCM_BLOCK);
	explicit_memset(t, 0, sizeof(t));
	if (!ok)
		return EBADMSG;				/* step 8: FAIL */
	memcpy(icb, j0, GCM_BLOCK);
	gcm_inc32(icb);
	gcm_gctr(g, icb, c, len);			/* step 4 */
	return 0;
}

/* RFC 2104 with SHA-256, over two pieces. */
static void
hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *m1, size_t l1,
    const uint8_t *m2, size_t l2, uint8_t out[TLS13_SECRETLEN])
{
	uint8_t k[64], h[TLS13_SECRETLEN];
	SHA256_CTX c;
	int i;

	KASSERT(keylen <= sizeof(k));
	memset(k, 0, sizeof(k));
	memcpy(k, key, keylen);
	for (i = 0; i < 64; i++)
		k[i] ^= 0x36;
	SHA256_Init(&c);
	SHA256_Update(&c, k, sizeof(k));
	SHA256_Update(&c, m1, l1);
	SHA256_Update(&c, m2, l2);
	SHA256_Final(h, &c);
	for (i = 0; i < 64; i++)
		k[i] ^= 0x36 ^ 0x5c;
	SHA256_Init(&c);
	SHA256_Update(&c, k, sizeof(k));
	SHA256_Update(&c, h, sizeof(h));
	SHA256_Final(out, &c);
	explicit_memset(k, 0, sizeof(k));
	explicit_memset(h, 0, sizeof(h));
	explicit_memset(&c, 0, sizeof(c));
}

/*
 * RFC 8446 s7.1, HKDF-Expand-Label, by HKDF-Expand of RFC 5869 s2.3 with
 * SHA-256.  Labels and contexts here are short; the bounds hold them.
 * prefix is the six bytes put before the label: "tls13 " for TLS 1.3,
 * "dtls13" for DTLS 1.3 (RFC 9147 s5.9).
 */
static void
expand_label(const char *prefix, const uint8_t *secret, const char *label,
    const uint8_t *ctx, size_t ctxlen, uint8_t *out, size_t outlen)
{
	uint8_t info[2 + 1 + 255 + 1 + 255 + 1], t[TLS13_SECRETLEN];
	size_t llen = strlen(label), ilen, done, n;
	uint8_t ctr;

	KASSERT(6 + llen <= 255 && ctxlen <= 255);
	KASSERT(outlen <= 255 * TLS13_SECRETLEN);
	ilen = 0;
	info[ilen++] = (uint8_t)(outlen >> 8);		/* uint16 length */
	info[ilen++] = (uint8_t)outlen;
	info[ilen++] = (uint8_t)(6 + llen);		/* label<7..255> */
	memcpy(info + ilen, prefix, 6);
	ilen += 6;
	memcpy(info + ilen, label, llen);
	ilen += llen;
	info[ilen++] = (uint8_t)ctxlen;			/* context<0..255> */
	if (ctxlen != 0)
		memcpy(info + ilen, ctx, ctxlen);
	ilen += ctxlen;

	/* T(i) = HMAC(PRK, T(i-1) | info | i), T(0) empty */
	for (done = 0, ctr = 1; done < outlen; done += n, ctr++) {
		info[ilen] = ctr;
		hmac_sha256(secret, TLS13_SECRETLEN, done == 0 ? NULL : t,
		    done == 0 ? 0 : sizeof(t), info, ilen + 1, t);
		n = MIN(outlen - done, sizeof(t));
		memcpy(out + done, t, n);
	}
	explicit_memset(t, 0, sizeof(t));
}

void
tls13_expand_label(const uint8_t *secret, const char *label,
    const uint8_t *ctx, size_t ctxlen, uint8_t *out, size_t outlen)
{

	expand_label("tls13 ", secret, label, ctx, ctxlen, out, outlen);
}

void
dtls13_expand_label(const uint8_t *secret, const char *label,
    const uint8_t *ctx, size_t ctxlen, uint8_t *out, size_t outlen)
{

	expand_label("dtls13", secret, label, ctx, ctxlen, out, outlen);	/* RFC 9147 s5.9 */
}

/* RFC 8446 s7.3: the write key and IV of a traffic secret. */
static void
dir_keys(struct tls13_dir *d)
{
	uint8_t key[TLS13_KEYLEN];

	tls13_expand_label(d->d_secret, "key", NULL, 0, key, sizeof(key));
	tls13_expand_label(d->d_secret, "iv", NULL, 0, d->d_iv,
	    sizeof(d->d_iv));
	tls13_gcm_init(&d->d_gcm, key);
	explicit_memset(key, 0, sizeof(key));
}

void
tls13_dir_init(struct tls13_dir *d, const uint8_t *secret, uint64_t seq)
{

	memcpy(d->d_secret, secret, TLS13_SECRETLEN);
	dir_keys(d);
	d->d_seq = seq;
}

/*
 * RFC 8446 s7.2: application_traffic_secret_N+1, and s5.3: the sequence
 * number starts again at 0 with the new keys.
 */
void
tls13_dir_update(struct tls13_dir *d)
{
	uint8_t next[TLS13_SECRETLEN];

	tls13_expand_label(d->d_secret, "traffic upd", NULL, 0, next,
	    sizeof(next));
	memcpy(d->d_secret, next, sizeof(next));
	explicit_memset(next, 0, sizeof(next));
	dir_keys(d);
	d->d_seq = 0;
}

void
tls13_dir_fini(struct tls13_dir *d)
{

	explicit_memset(d, 0, sizeof(*d));
}

/* RFC 8446 s5.3: the IV XOR the sequence number, left-padded. */
static void
dir_nonce(const struct tls13_dir *d, uint8_t nonce[TLS13_IVLEN])
{
	int i;

	memcpy(nonce, d->d_iv, TLS13_IVLEN);
	for (i = 0; i < 8; i++)
		nonce[TLS13_IVLEN - 1 - i] ^= (uint8_t)(d->d_seq >> (8 * i));
}

/*
 * Protect a record, RFC 8446 s5.2.  rec holds len bytes of content at
 * TLS13_HDRLEN, with room for one byte and the tag after; the whole
 * record is TLS13_HDRLEN + len + 1 + TLS13_TAGLEN.  No padding.
 */
int
tls13_seal(struct tls13_dir *d, uint8_t type, uint8_t *rec, size_t len)
{
	uint8_t nonce[TLS13_IVLEN];
	size_t clen = len + 1;

	if (len > TLS13_MAXPLAIN)
		return EMSGSIZE;
	/* s5.3: the sequence number MUST NOT wrap. */
	if (d->d_seq == UINT64_MAX)
		return EOVERFLOW;
	rec[TLS13_HDRLEN + len] = type;			/* TLSInnerPlaintext.type */
	rec[0] = TLS13_CT_APPDATA;			/* opaque_type */
	rec[1] = 0x03;					/* legacy_record_version */
	rec[2] = 0x03;
	rec[3] = (uint8_t)((clen + TLS13_TAGLEN) >> 8);
	rec[4] = (uint8_t)(clen + TLS13_TAGLEN);
	dir_nonce(d, nonce);
	/* s5.2: additional_data is the record header. */
	tls13_gcm_seal(&d->d_gcm, nonce, rec, TLS13_HDRLEN,
	    rec + TLS13_HDRLEN, clen, rec + TLS13_HDRLEN + clen);
	d->d_seq++;
	return 0;
}

/*
 * Deprotect a whole record of reclen bytes in place, RFC 8446 s5.2.  On
 * success the content is at TLS13_HDRLEN, *lenp bytes of it, of type
 * *typep.  The errors stand for the alerts the RFC has sent: EBADMSG for
 * bad_record_mac, EMSGSIZE for record_overflow, EPROTO for
 * unexpected_message.
 */
int
tls13_open(struct tls13_dir *d, uint8_t *rec, size_t reclen, uint8_t *typep,
    size_t *lenp)
{
	uint8_t nonce[TLS13_IVLEN];
	size_t clen, n;
	int error;

	if (reclen < TLS13_HDRLEN)
		return EPROTO;
	clen = (size_t)rec[3] << 8 | rec[4];
	/* s5.2: length MUST NOT exceed 2^14 + 256, record_overflow */
	if (clen > TLS13_MAXCIPHER)
		return EMSGSIZE;
	if (clen + TLS13_HDRLEN != reclen || clen < 1 + TLS13_TAGLEN)
		return EBADMSG;
	/*
	 * s5: after the handshake every record is protected and its outer
	 * type is application_data; anything else is unexpected_message.
	 */
	if (rec[0] != TLS13_CT_APPDATA)
		return EPROTO;
	if (d->d_seq == UINT64_MAX)
		return EOVERFLOW;
	dir_nonce(d, nonce);
	clen -= TLS13_TAGLEN;
	error = tls13_gcm_open(&d->d_gcm, nonce, rec, TLS13_HDRLEN,
	    rec + TLS13_HDRLEN, clen, rec + TLS13_HDRLEN + clen);
	if (error != 0)
		return error;
	d->d_seq++;
	/* s5.4: the type is the last non-zero byte; none at all is unexpected. */
	for (n = clen; n > 0 && rec[TLS13_HDRLEN + n - 1] == 0; n--)
		continue;
	if (n == 0)
		return EPROTO;
	n--;
	/* s5.2: TLSInnerPlaintext.content beyond 2^14 is record_overflow. */
	if (n > TLS13_MAXPLAIN)
		return EMSGSIZE;
	*typep = rec[TLS13_HDRLEN + n];
	*lenp = n;
	return 0;
}

/*
 * At module load: the client's application_data record of the simple
 * 1-RTT trace, RFC 8448 s3, sealed and opened again.
 */
int
tls13_selftest(void)
{
	static const uint8_t secret[TLS13_SECRETLEN] = {
		0x9e, 0x40, 0x64, 0x6c, 0xe7, 0x9a, 0x7f, 0x9d,
		0xc0, 0x5a, 0xf8, 0x88, 0x9b, 0xce, 0x65, 0x52,
		0x87, 0x5a, 0xfa, 0x0b, 0x06, 0xdf, 0x00, 0x87,
		0xf7, 0x92, 0xeb, 0xb7, 0xc1, 0x75, 0x04, 0xa5,
	};
	static const uint8_t record[TLS13_HDRLEN + 50 + 1 + TLS13_TAGLEN] = {
		0x17, 0x03, 0x03, 0x00, 0x43, 0xa2, 0x3f, 0x70,
		0x54, 0xb6, 0x2c, 0x94, 0xd0, 0xaf, 0xfa, 0xfe,
		0x82, 0x28, 0xba, 0x55, 0xcb, 0xef, 0xac, 0xea,
		0x42, 0xf9, 0x14, 0xaa, 0x66, 0xbc, 0xab, 0x3f,
		0x2b, 0x98, 0x19, 0xa8, 0xa5, 0xb4, 0x6b, 0x39,
		0x5b, 0xd5, 0x4a, 0x9a, 0x20, 0x44, 0x1e, 0x2b,
		0x62, 0x97, 0x4e, 0x1f, 0x5a, 0x62, 0x92, 0xa2,
		0x97, 0x70, 0x14, 0xbd, 0x1e, 0x3d, 0xea, 0xe6,
		0x3a, 0xee, 0xbb, 0x21, 0x69, 0x49, 0x15, 0xe4,
	};
	uint8_t buf[sizeof(record)], type;
	struct tls13_dir d;
	size_t i, len;
	int error = 0;

	tls13_dir_init(&d, secret, 0);
	for (i = 0; i < 50; i++)
		buf[TLS13_HDRLEN + i] = (uint8_t)i;
	if (tls13_seal(&d, TLS13_CT_APPDATA, buf, 50) != 0 ||
	    memcmp(buf, record, sizeof(record)) != 0)
		error = EIO;
	tls13_dir_init(&d, secret, 0);
	if (error == 0 &&
	    (tls13_open(&d, buf, sizeof(buf), &type, &len) != 0 ||
	    type != TLS13_CT_APPDATA || len != 50 ||
	    buf[TLS13_HDRLEN + 49] != 49))
		error = EIO;
	tls13_dir_fini(&d);
	return error;
}

/*
 * DTLS 1.3, RFC 9147.  The AEAD is that of TLS 1.3 with the 64-bit
 * sequence number of the epoch for the nonce, s4; the keys are derived
 * with the "dtls13" prefix, s5.9; the sequence number on the wire is
 * encrypted, s4.2.3; and every record carries a unified header, s4.
 */

/* RFC 9147 s4, the first byte of the unified header */
#define	DTLS13_FIXED		0x20	/* 001 in the top three bits */
#define	DTLS13_FIXEDMASK	0xe0
#define	DTLS13_C		0x10	/* a connection ID */
#define	DTLS13_S		0x08	/* a 16-bit sequence number */
#define	DTLS13_L		0x04	/* a length */
#define	DTLS13_E		0x03	/* the low bits of the epoch */

/*
 * RFC 9147 s4.1, Figure 5: alert, handshake and ack are DTLSPlaintext,
 * 001 in the top bits is DTLSCiphertext, and anything else MUST be
 * rejected as a record failing deprotection, s4.5.2.  The DTLS 1.2
 * types of the figure are rejected too: only 1.3 is spoken here.
 */
int
dtls13_demux(uint8_t b0)
{

	if (b0 == TLS13_CT_ALERT || b0 == TLS13_CT_HANDSHAKE ||
	    b0 == TLS13_CT_ACK)
		return DTLS13_PLAINTEXT;
	if ((b0 & DTLS13_FIXEDMASK) == DTLS13_FIXED)
		return DTLS13_CIPHERTEXT;
	return DTLS13_REJECT;
}

static void
dtls_keys(struct dtls13_dir *d)
{
	uint8_t key[TLS13_KEYLEN];

	dtls13_expand_label(d->dd_secret, "key", NULL, 0, key, sizeof(key));
	dtls13_expand_label(d->dd_secret, "iv", NULL, 0, d->dd_iv,
	    sizeof(d->dd_iv));
	tls13_gcm_init(&d->dd_gcm, key);
	/* s4.2.3: [sender]_sn_key */
	dtls13_expand_label(d->dd_secret, "sn", NULL, 0, key, sizeof(key));
	d->dd_snrounds = aes_setenckey128(&d->dd_sn, key);
	explicit_memset(key, 0, sizeof(key));
}

void
dtls13_dir_init(struct dtls13_dir *d, const uint8_t *secret, uint64_t epoch)
{

	memset(d, 0, sizeof(*d));
	memcpy(d->dd_secret, secret, TLS13_SECRETLEN);
	d->dd_epoch = epoch;
	dtls_keys(d);
}

/*
 * The next epoch after a KeyUpdate, RFC 9147 s8 and RFC 8446 s7.2: the
 * sequence numbers and the replay window start again.
 */
void
dtls13_dir_update(struct dtls13_dir *d)
{
	uint8_t next[TLS13_SECRETLEN];

	dtls13_expand_label(d->dd_secret, "traffic upd", NULL, 0, next,
	    sizeof(next));
	memcpy(d->dd_secret, next, sizeof(next));
	explicit_memset(next, 0, sizeof(next));
	d->dd_epoch++;
	d->dd_seq = 0;
	d->dd_top = 0;
	d->dd_window = 0;
	d->dd_any = false;
	dtls_keys(d);
}

void
dtls13_dir_fini(struct dtls13_dir *d)
{

	explicit_memset(d, 0, sizeof(*d));
}

static void
dtls_nonce(const struct dtls13_dir *d, uint64_t seq, uint8_t nonce[TLS13_IVLEN])
{
	int i;

	/* RFC 9147 s4: the 64-bit sequence number, not the epoch. */
	memcpy(nonce, d->dd_iv, TLS13_IVLEN);
	for (i = 0; i < 8; i++)
		nonce[TLS13_IVLEN - 1 - i] ^= (uint8_t)(seq >> (8 * i));
}

/* RFC 9147 s4.2.3: Mask = AES-ECB(sn_key, Ciphertext[0..15]). */
static void
dtls_snmask(const struct dtls13_dir *d, const uint8_t *ct, uint8_t mask[16])
{

	aes_enc(&d->dd_sn, ct, mask, d->dd_snrounds);
}

/*
 * Protect a record into rec, with a connection ID of cidlen bytes when
 * cidlen is not 0, a 16-bit sequence number and a length: the header is
 * 1 + cidlen + 2 + 2 bytes, then len bytes of content are taken from in,
 * one byte of type and the tag follow.  The whole record's length is
 * returned in *reclenp.
 */
int
dtls13_seal(struct dtls13_dir *d, uint8_t type, const uint8_t *cid,
    size_t cidlen, const uint8_t *in, size_t len, uint8_t *rec,
    size_t *reclenp)
{
	uint8_t nonce[TLS13_IVLEN], mask[16], *ct;
	size_t hlen, clen = len + 1;

	if (len > TLS13_MAXPLAIN || cidlen > DTLS13_MAXCID)
		return EMSGSIZE;
	/* s4.2.1: a sequence number never wraps; 2^48 is s4's limit. */
	if (d->dd_seq >= (1ULL << 48))
		return EOVERFLOW;
	hlen = 0;
	rec[hlen++] = DTLS13_FIXED | (cidlen != 0 ? DTLS13_C : 0) | DTLS13_S |
	    DTLS13_L | (d->dd_epoch & DTLS13_E);
	if (cidlen != 0)
		memcpy(rec + hlen, cid, cidlen);
	hlen += cidlen;
	rec[hlen++] = (uint8_t)(d->dd_seq >> 8);
	rec[hlen++] = (uint8_t)d->dd_seq;
	rec[hlen++] = (uint8_t)((clen + TLS13_TAGLEN) >> 8);
	rec[hlen++] = (uint8_t)(clen + TLS13_TAGLEN);
	ct = rec + hlen;
	memmove(ct, in, len);
	ct[len] = type;
	dtls_nonce(d, d->dd_seq, nonce);
	/* s4: the header before record number encryption is the AD. */
	tls13_gcm_seal(&d->dd_gcm, nonce, rec, hlen, ct, clen, ct + clen);
	/* s4.2.3; the ciphertext is never shorter than 16 bytes here. */
	dtls_snmask(d, ct, mask);
	rec[hlen - 4] ^= mask[0];
	rec[hlen - 3] ^= mask[1];
	d->dd_seq++;
	*reclenp = hlen + clen + TLS13_TAGLEN;
	return 0;
}

/*
 * RFC 9147 s4.2.2: the full sequence number closest to one past the
 * highest deprotected, from its low bits.
 */
static uint64_t
dtls_seqfull(const struct dtls13_dir *d, uint32_t low, u_int bits)
{
	uint64_t next = d->dd_any ? d->dd_top + 1 : 0;
	uint64_t span = 1ULL << bits, cand;

	cand = (next & ~(span - 1)) | low;
	if (cand + span / 2 < next && cand + span < (1ULL << 48))
		cand += span;
	else if (cand > next + span / 2 && cand >= span)
		cand -= span;
	return cand;
}

/*
 * RFC 9147 s4.5.1, the anti-replay window RFC 9289 s5.1.2 REQUIRES: the
 * bitmap of RFC 4303 s3.4.3, DTLS13_WINDOW records behind the highest.
 */
static bool
dtls_replayed(const struct dtls13_dir *d, uint64_t seq)
{

	if (!d->dd_any || seq > d->dd_top)
		return false;
	if (d->dd_top - seq >= DTLS13_WINDOW)
		return true;		/* too old to tell: rejected */
	return (d->dd_window >> (d->dd_top - seq)) & 1;
}

static void
dtls_seen(struct dtls13_dir *d, uint64_t seq)
{
	uint64_t shift;

	if (!d->dd_any) {
		d->dd_any = true;
		d->dd_top = seq;
		d->dd_window = 1;
		return;
	}
	if (seq > d->dd_top) {
		shift = seq - d->dd_top;
		d->dd_window = shift >= DTLS13_WINDOW ? 0 :
		    d->dd_window << shift;
		d->dd_window |= 1;
		d->dd_top = seq;
	} else
		d->dd_window |= 1ULL << (d->dd_top - seq);
}

/*
 * Deprotect the record at the start of the len bytes at p, in place.  A
 * connection ID, when the header says there is one, is cidlen bytes:
 * the header does not carry its length, the association does.  *usedp is
 * the record's length within the datagram; the content is at *contentp,
 * *clenp bytes of type *typep.  Any error means the record is to be
 * dropped without an answer, s4.5.2; EALREADY is a replay, EAGAIN an
 * epoch other than this direction's.  On an error *usedp is still the
 * record's length once the header could be read, so that the records
 * behind it in the datagram, s4.3, are not lost with it, and 0 if not.
 */
int
dtls13_open(struct dtls13_dir *d, size_t cidlen, uint8_t *p, size_t len,
    size_t *usedp, uint8_t *typep, uint8_t **contentp, size_t *clenp)
{
	uint8_t nonce[TLS13_IVLEN], mask[16], b0, *ct;
	size_t hlen, clen, n;
	u_int seqbits;
	uint32_t low;
	uint64_t seq;
	int error;

	*usedp = 0;
	if (len < 1)
		return EBADMSG;
	b0 = p[0];
	/* s4.1 */
	if ((b0 & DTLS13_FIXEDMASK) != DTLS13_FIXED)
		return EBADMSG;
	hlen = 1;
	if ((b0 & DTLS13_C) != 0) {
		if (cidlen == 0)
			return EBADMSG;
		hlen += cidlen;
	} else if (cidlen != 0)
		return EBADMSG;	/* s4: then in every datagram */
	seqbits = (b0 & DTLS13_S) != 0 ? 16 : 8;
	hlen += seqbits / 8;
	if ((b0 & DTLS13_L) != 0)
		hlen += 2;
	if (len < hlen)
		return EBADMSG;
	if ((b0 & DTLS13_L) != 0) {
		clen = (size_t)p[hlen - 2] << 8 | p[hlen - 1];
		if (clen > len - hlen)
			return EBADMSG;
	} else
		clen = len - hlen;	/* the rest of the datagram, s4 */
	*usedp = hlen + clen;
	if (clen > TLS13_MAXCIPHER)
		return EMSGSIZE;
	if (clen < 16 + 1)	/* s4.2.3 needs 16; content type and tag */
		return EBADMSG;
	if ((b0 & DTLS13_E) != (d->dd_epoch & DTLS13_E))
		return EAGAIN;
	ct = p + hlen;
	n = (b0 & DTLS13_L) != 0 ? hlen - 2 : hlen;	/* past the seq */

	dtls_snmask(d, ct, mask);
	if (seqbits == 16) {
		p[n - 2] ^= mask[0];
		p[n - 1] ^= mask[1];
		low = (uint32_t)p[n - 2] << 8 | p[n - 1];
	} else {
		p[n - 1] ^= mask[0];
		low = p[n - 1];
	}
	seq = dtls_seqfull(d, low, seqbits);
	dtls_nonce(d, seq, nonce);
	clen -= TLS13_TAGLEN;
	error = tls13_gcm_open(&d->dd_gcm, nonce, p, hlen, ct, clen,
	    ct + clen);
	if (error != 0)
		return error;
	/*
	 * s4.5.1 SHOULD: the replay check after deprotection, so that a
	 * discard does not tell the record number.
	 */
	if (dtls_replayed(d, seq))
		return EALREADY;
	dtls_seen(d, seq);
	/* RFC 8446 s5.4, as in DTLSInnerPlaintext */
	for (n = clen; n > 0 && ct[n - 1] == 0; n--)
		continue;
	if (n == 0)
		return EPROTO;
	*typep = ct[n - 1];
	*contentp = ct;
	*clenp = n - 1;
	*usedp = hlen + clen + TLS13_TAGLEN;
	return 0;
}
