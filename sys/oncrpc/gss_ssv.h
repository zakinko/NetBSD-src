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

#ifndef _ONCRPC_GSS_SSV_H_
#define _ONCRPC_GSS_SSV_H_

/* RFC 8881 s18.35.3: the hash and encryption algorithms, by our index. */
#define	GSS_SSV_SHA1		0
#define	GSS_SSV_SHA224		1
#define	GSS_SSV_SHA256		2
#define	GSS_SSV_SHA384		3
#define	GSS_SSV_SHA512		4
#define	GSS_SSV_NHASH		5

#define	GSS_SSV_AES128		0
#define	GSS_SSV_AES192		1
#define	GSS_SSV_AES256		2
#define	GSS_SSV_NENCR		3

#define	GSS_SSV_MAXHASH		64	/* SHA-512 */
#define	GSS_SSV_MAXWINDOW	8	/* versions kept; chosen */

struct gss_ssv;

int	gss_ssv_hash_byoid(const void *, size_t);
int	gss_ssv_encr_byoid(const void *, size_t);
int	gss_ssv_pair_ok(int, int, bool);
size_t	gss_ssv_hashlen(int);

int	gss_ssv_create(int, int, uint32_t, struct gss_ssv **);
void	gss_ssv_hold(struct gss_ssv *);
void	gss_ssv_rele(struct gss_ssv *);
void	gss_ssv_confirm(struct gss_ssv *);
size_t	gss_ssv_len(const struct gss_ssv *);
int	gss_ssv_set(struct gss_ssv *, const void *, size_t, const void *,
	    size_t, const void *, size_t, const void *, size_t, void *,
	    size_t *);

extern const struct oncrpc_gss_mech oncrpc_gss_ssv_mech;

#endif /* !_ONCRPC_GSS_SSV_H_ */
