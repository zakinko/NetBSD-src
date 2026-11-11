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

#ifndef _ONCRPC_TLS13_CRYPTO_H_
#define _ONCRPC_TLS13_CRYPTO_H_

/*
 * The cryptography of the TLS 1.3 record layer for RPC-with-TLS: AES-GCM
 * (NIST SP 800-38D) and the traffic keys of TLS_AES_128_GCM_SHA256 (RFC
 * 8446 s7), on linear buffers.
 */

#define	TLS13_AES_128_GCM_SHA256 0x1301	/* RFC 8446 App. B.4 */
#define	TLS13_KEYLEN		16	/* AES-128 */
#define	TLS13_IVLEN		12	/* RFC 8446 s5.3, iv_length */
#define	TLS13_TAGLEN		16	/* RFC 5116 s5.1, AEAD_AES_128_GCM */
#define	TLS13_SECRETLEN		32	/* SHA-256, Hash.length */
#define	TLS13_HDRLEN		5	/* RFC 8446 s5.2, TLSCiphertext header */

/* RFC 8446 s5.1, ContentType */
#define	TLS13_CT_ALERT		21
#define	TLS13_CT_HANDSHAKE	22
#define	TLS13_CT_APPDATA	23

/* RFC 8446 s5.1 and s5.2 */
#define	TLS13_MAXPLAIN		(1U << 14)
#define	TLS13_MAXCIPHER		(TLS13_MAXPLAIN + 256)

struct tls13_gcm {
	struct aesenc	g_enc;
	uint32_t	g_nrounds;
	uint8_t		g_h[16];	/* SP 800-38D s7.1 step 1 */
};

/* One direction of a connection. */
struct tls13_dir {
	struct tls13_gcm d_gcm;
	uint8_t		d_secret[TLS13_SECRETLEN];
	uint8_t		d_iv[TLS13_IVLEN];
	uint64_t	d_seq;		/* RFC 8446 s5.3 */
};

void	tls13_gcm_init(struct tls13_gcm *, const uint8_t *);
void	tls13_gcm_seal(const struct tls13_gcm *, const uint8_t *,
	    const uint8_t *, size_t, uint8_t *, size_t, uint8_t *);
int	tls13_gcm_open(const struct tls13_gcm *, const uint8_t *,
	    const uint8_t *, size_t, uint8_t *, size_t, const uint8_t *);

void	tls13_expand_label(const uint8_t *, const char *, const uint8_t *,
	    size_t, uint8_t *, size_t);
void	tls13_dir_init(struct tls13_dir *, const uint8_t *, uint64_t);
void	tls13_dir_update(struct tls13_dir *);
void	tls13_dir_fini(struct tls13_dir *);

int	tls13_seal(struct tls13_dir *, uint8_t, uint8_t *, size_t);
int	tls13_open(struct tls13_dir *, uint8_t *, size_t, uint8_t *, size_t *);

int	tls13_selftest(void);

#endif /* !_ONCRPC_TLS13_CRYPTO_H_ */
