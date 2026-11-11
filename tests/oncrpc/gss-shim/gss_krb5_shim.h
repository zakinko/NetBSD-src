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
 * What gss_krb5*.c takes from the kernel, for the test in userland, by
 * OpenSSL's low-level interfaces.  Only the calls used are here.
 */

#ifndef _GSS_KRB5_SHIM_H_
#define _GSS_KRB5_SHIM_H_

#define	OPENSSL_SUPPRESS_DEPRECATED

#include <sys/types.h>
#include <sys/param.h>		/* MIN */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define	KASSERT(x)	assert(x)
/* <sys/cdefs.h> has these on NetBSD; glibc does not. */
#ifndef __UNCONST
#define	__UNCONST(p)	((void *)(uintptr_t)(const void *)(p))
#endif
#ifndef __unused
#define	__unused	__attribute__((__unused__))
#endif

#define	KM_SLEEP	0
static inline void *
kmem_zalloc(size_t n, int f __unused)
{

	return calloc(1, n);
}

static inline void
kmem_free(void *p, size_t n __unused)
{

	free(p);
}

static inline uint64_t
atomic_inc_64_nv(volatile uint64_t *p)
{

	return __atomic_add_fetch(p, 1, __ATOMIC_RELAXED);
}
#define	__HAVE_ATOMIC64_OPS

static inline size_t
cprng_fast(void *p, size_t n)
{

	if (RAND_bytes(p, (int)n) != 1)
		abort();
	return n;
}

#ifndef __NetBSD__
static inline void *
explicit_memset(void *p, int c, size_t n)
{
	volatile unsigned char *q = p;

	while (n-- > 0)
		*q++ = (unsigned char)c;
	return p;
}

static inline int
consttime_memequal(const void *a, const void *b, size_t n)
{
	const unsigned char *x = a, *y = b;
	unsigned int r = 0;

	while (n-- > 0)
		r |= *x++ ^ *y++;
	return r == 0;
}
#endif

/* AES */
struct aesenc {
	AES_KEY	k;
};
struct aesdec {
	AES_KEY	k;
};

static inline uint32_t
aes_setenckey128(struct aesenc *e, const uint8_t *key)
{

	AES_set_encrypt_key(key, 128, &e->k);
	return 10;
}

static inline uint32_t
aes_setenckey256(struct aesenc *e, const uint8_t *key)
{

	AES_set_encrypt_key(key, 256, &e->k);
	return 14;
}

static inline uint32_t
aes_setdeckey128(struct aesdec *d, const uint8_t *key)
{

	AES_set_decrypt_key(key, 128, &d->k);
	return 10;
}

static inline uint32_t
aes_setdeckey256(struct aesdec *d, const uint8_t *key)
{

	AES_set_decrypt_key(key, 256, &d->k);
	return 14;
}

static inline void
aes_enc(const struct aesenc *e, const uint8_t *in, uint8_t *out,
    uint32_t n __unused)
{

	AES_encrypt(in, out, &e->k);
}

static inline void
aes_dec(const struct aesdec *d, const uint8_t *in, uint8_t *out,
    uint32_t n __unused)
{

	AES_decrypt(in, out, &d->k);
}

static inline void
aes_cbc_enc(struct aesenc *e, const uint8_t *in, uint8_t *out, size_t n,
    uint8_t *iv, uint32_t r __unused)
{

	assert(n % 16 == 0);
	AES_cbc_encrypt(in, out, n, &e->k, iv, AES_ENCRYPT);
}

static inline void
aes_cbc_dec(struct aesdec *d, const uint8_t *in, uint8_t *out, size_t n,
    uint8_t *iv, uint32_t r __unused)
{

	assert(n % 16 == 0);
	AES_cbc_encrypt(in, out, n, &d->k, iv, AES_DECRYPT);
}

/* DES.  An array, so that the schedule is passed as in the kernel. */
typedef unsigned char des_cblock[8];
typedef struct {
	DES_key_schedule ks;
} des_key_schedule[1];

static inline void
des_set_key_unchecked(des_cblock *k, des_key_schedule s)
{

	DES_set_key_unchecked((const_DES_cblock *)k, &s->ks);
}

static inline void
des_set_odd_parity(des_cblock *k)
{

	DES_set_odd_parity((DES_cblock *)k);
}

static inline int
des_is_weak_key(des_cblock *k)
{

	return DES_is_weak_key((const_DES_cblock *)k);
}

static inline void
des_ncbc_encrypt(const unsigned char *in, unsigned char *out, long n,
    des_key_schedule s, des_cblock *iv, int enc)
{

	DES_ncbc_encrypt(in, out, n, &s->ks, (DES_cblock *)iv, enc);
}

static inline void
des_ede3_cbc_encrypt(const unsigned char *in, unsigned char *out, long n,
    des_key_schedule a, des_key_schedule b, des_key_schedule c,
    des_cblock *iv, int enc)
{

	DES_ede3_cbc_encrypt(in, out, n, &a->ks, &b->ks, &c->ks,
	    (DES_cblock *)iv, enc);
}

/* The hashes.  SHA-2 has the kernel's names already. */
typedef SHA_CTX SHA1_CTX;
typedef SHA512_CTX SHA384_CTX;
#define	SHA1Init(c)		SHA1_Init(c)
#define	SHA1Update(c, p, n)	SHA1_Update((c), (p), (n))
#define	SHA1Final(d, c)		SHA1_Final((d), (c))
#define	MD5Init(c)		MD5_Init(c)
#define	MD5Update(c, p, n)	MD5_Update((c), (p), (n))
#define	MD5Final(d, c)		MD5_Final((d), (c))
#ifndef SHA1_DIGEST_LENGTH
#define	SHA1_DIGEST_LENGTH	20
#endif
#define	SHA1_BLOCK_LENGTH	64
#define	SHA256_BLOCK_LENGTH	64
#define	SHA384_BLOCK_LENGTH	128
#define	MD5_BLOCK_LENGTH	64

#endif /* !_GSS_KRB5_SHIM_H_ */
