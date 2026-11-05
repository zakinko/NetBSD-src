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

#ifndef _ONCRPC_GSS_KRB5_H_
#define _ONCRPC_GSS_KRB5_H_

#include <sys/types.h>

/* GSS-API major status, RFC 2744 s3.9.1 */
#define	GSS_S_COMPLETE		0U
#define	GSS_S_BAD_SIG		(6U << 16)
#define	GSS_S_NO_CONTEXT	(8U << 16)
#define	GSS_S_DEFECTIVE_TOKEN	(9U << 16)
#define	GSS_S_FAILURE		(13U << 16)

/* RFC 3961 s8 and RFC 8009 s3 */
#define	GSS_KRB5_ENC_DES_CBC_CRC	1
#define	GSS_KRB5_ENC_DES_CBC_MD5	3
#define	GSS_KRB5_ENC_DES3_CBC_SHA1	16
#define	GSS_KRB5_ENC_AES128_SHA1	17
#define	GSS_KRB5_ENC_AES256_SHA1	18
#define	GSS_KRB5_ENC_AES128_SHA256	19
#define	GSS_KRB5_ENC_AES256_SHA384	20

#define	GSS_KRB5_MAXKEY		32

/* What the daemon got from the established context. */
struct gss_krb5_import {
	uint32_t	gi_enctype;
	uint32_t	gi_keylen;
	uint8_t		gi_key[GSS_KRB5_MAXKEY];
	bool		gi_cfx;		/* RFC 4121 tokens, else RFC 1964 */
	bool		gi_initiator;	/* we started the context */
	bool		gi_acceptor_subkey; /* gi_key is the acceptor's */
	uint64_t	gi_send_seq;	/* the first SND_SEQ we send */
};

struct gss_krb5_ctx;

/* Sleeps for memory.  0, or EINVAL for what this cannot do. */
int	gss_krb5_ctx_create(const struct gss_krb5_import *,
	    struct gss_krb5_ctx **);
void	gss_krb5_ctx_destroy(struct gss_krb5_ctx *);	/* zeroes the keys */

/* The longest MIC token of any mechanism here. */
#define	GSS_KRB5_MAXMIC		64

/* The results are GSS-API major status. */
uint32_t gss_krb5_get_mic(struct gss_krb5_ctx *, const void *, size_t,
	    void *, size_t, size_t *);
uint32_t gss_krb5_verify_mic(struct gss_krb5_ctx *, const void *, size_t,
	    const void *, size_t);

/* The most gss_krb5_wrap() can write for a message of this length. */
size_t	gss_krb5_wrap_size(const struct gss_krb5_ctx *, size_t);
/* Always with confidentiality.  in and out must not overlap. */
uint32_t gss_krb5_wrap(struct gss_krb5_ctx *, const void *, size_t,
	    void *, size_t, size_t *);
/*
 * in is changed.  *outp and *outlen name the message inside in, or out
 * if it had to move; out has room for inlen bytes.  *confp says if it
 * was encrypted.
 */
uint32_t gss_krb5_unwrap(struct gss_krb5_ctx *, void *, size_t, void *,
	    void **, size_t *, bool *);

int	gss_krb5_selftest(void);

#ifdef GSS_KRB5_PRIVATE
/*
 * Between gss_krb5.c and gss_krb5_crypto.c, and for the test, which has
 * vectors for these steps.  The includer has <crypto/aes/aes.h> or the
 * test's shim.
 */

#define	GK_HASH_MD5		0
#define	GK_HASH_SHA1		1
#define	GK_HASH_SHA256		2
#define	GK_HASH_SHA384		3

#define	GK_MAXHASH		48	/* SHA-384 */

struct gk_iov {
	const void	*gv_base;
	size_t		gv_len;
};

struct gk_etype {
	uint32_t	ge_enctype;
	uint32_t	ge_keylen;	/* protocol key */
	uint32_t	ge_seedlen;	/* k of RFC 3961 s5.1 */
	uint32_t	ge_block;	/* c, also the confounder */
	uint32_t	ge_maclen;	/* h */
	uint32_t	ge_kclen;
	uint32_t	ge_kelen;
	uint32_t	ge_kilen;
	int		ge_hash;
	bool		ge_kdf2;	/* RFC 8009: KDF, MAC over C */
};

/* The keys of one usage, RFC 3961 s5.3 and RFC 8009 s5. */
struct gk_dk {
	uint8_t		gd_kc[GSS_KRB5_MAXKEY];
	uint8_t		gd_ki[GSS_KRB5_MAXKEY];
	struct aesenc	gd_enc;
	struct aesdec	gd_dec;
	uint32_t	gd_nrounds;
};

const struct gk_etype *gk_etype_lookup(uint32_t);
void	gk_hmac(int, const void *, size_t, const struct gk_iov *, int,
	    uint8_t *);
void	gk_nfold(const void *, size_t, void *, size_t);
void	gk_dr(const struct gk_etype *, const void *, const void *, size_t,
	    void *);
void	gk_des3_random_to_key(const uint8_t *, uint8_t *);
void	gk_kdf2(int, const void *, size_t, const void *, size_t,
	    const void *, size_t, uint32_t, void *);
void	gk_derive(const struct gk_etype *, const void *, uint32_t, uint8_t,
	    void *);
void	gk_dk_init(const struct gk_etype *, const void *, uint32_t,
	    struct gk_dk *);
void	gk_cts_encrypt(struct aesenc *, uint32_t, uint8_t *, size_t);
void	gk_cts_decrypt(struct aesdec *, uint32_t, uint8_t *, size_t);
void	gk_encrypt(const struct gk_etype *, struct gk_dk *, uint8_t *, size_t);
bool	gk_decrypt(const struct gk_etype *, struct gk_dk *, uint8_t *, size_t);
void	gk_checksum(const struct gk_etype *, const uint8_t *, const void *,
	    size_t, const void *, size_t, uint8_t *);
#endif /* GSS_KRB5_PRIVATE */

#endif /* !_ONCRPC_GSS_KRB5_H_ */
