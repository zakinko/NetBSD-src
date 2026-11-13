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

#ifdef _KERNEL
#include <crypto/aes/aes.h>
#endif

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
#define	TLS13_CT_ACK		26	/* RFC 9147 s7 */

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

/* DTLS 1.3, RFC 9147 */
#define	DTLS13_MAXCID	20	/* ours; RFC 9146 s3 allows cid<0..2^8-1> */
#define	DTLS13_WINDOW	64	/* RFC 9147 s4.5.1 leaves it local; ours */

struct dtls13_dir {
	struct tls13_gcm dd_gcm;
	struct aesenc	dd_sn;		/* RFC 9147 s4.2.3 */
	uint32_t	dd_snrounds;
	uint8_t		dd_secret[TLS13_SECRETLEN];
	uint8_t		dd_iv[TLS13_IVLEN];
	uint64_t	dd_epoch;	/* RFC 9147 s4, the 8-byte counter */
	uint64_t	dd_seq;		/* the next to send */
	uint64_t	dd_top;		/* the highest received */
	uint64_t	dd_window;	/* bit i: dd_top - i received */
	uint64_t	dd_last;	/* of the record last opened */
	bool		dd_any;
};

void	dtls13_expand_label(const uint8_t *, const char *, const uint8_t *,
	    size_t, uint8_t *, size_t);
void	dtls13_dir_init(struct dtls13_dir *, const uint8_t *, uint64_t);
void	dtls13_dir_update(struct dtls13_dir *);
void	dtls13_dir_fini(struct dtls13_dir *);
int	dtls13_seal(struct dtls13_dir *, uint8_t, const uint8_t *, size_t,
	    const uint8_t *, size_t, uint8_t *, size_t *);
int	dtls13_open(struct dtls13_dir *, size_t, uint8_t *, size_t, size_t *,
	    uint8_t *, uint8_t **, size_t *);

/* RFC 9147 s4, the first byte of the unified header */
#define	DTLS13_FIXED		0x20	/* 001 in the top three bits */
#define	DTLS13_FIXEDMASK	0xe0
#define	DTLS13_C		0x10	/* a connection ID */
#define	DTLS13_S		0x08	/* a 16-bit sequence number */
#define	DTLS13_L		0x04	/* a length */
#define	DTLS13_E		0x03	/* the low bits of the epoch */

/* What dtls13_demux() makes of the first byte of a record, s4.1. */
#define	DTLS13_PLAINTEXT	1
#define	DTLS13_CIPHERTEXT	2
#define	DTLS13_REJECT		3
int	dtls13_demux(uint8_t);

/* RFC 9147 s5.2, DTLSHandshake, and the types used after the handshake */
#define	DTLS13_HS_HDRLEN	12
#define	DTLS13_HS_REQUEST_CID	9
#define	DTLS13_HS_NEW_CID	10
#define	DTLS13_HS_KEY_UPDATE	24
/* RFC 9147 s4, RecordNumber, in an ACK, s7 */
#define	DTLS13_RECNUMLEN	16

int	dtls13_hs_parse(const uint8_t *, size_t, uint8_t *, uint16_t *,
	    const uint8_t **, size_t *, size_t *);
size_t	dtls13_hs_build(uint8_t *, uint8_t, uint16_t, const uint8_t *, size_t);
size_t	dtls13_ack_build(uint8_t *, size_t, const uint64_t *, size_t);
int	dtls13_ack_has(const uint8_t *, size_t, uint64_t, uint64_t);

#endif /* !_ONCRPC_TLS13_CRYPTO_H_ */
