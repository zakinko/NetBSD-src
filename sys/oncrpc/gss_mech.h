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

#ifndef _ONCRPC_GSS_MECH_H_
#define _ONCRPC_GSS_MECH_H_

/*
 * The GSS mechanisms of the per-message work, RFC 2743 s2.3: Kerberos V5
 * from a context gssd(8) built, and the SSV mechanism of RFC 8881 s2.10.9,
 * whose contexts come from EXCHANGE_ID.  The results are GSS-API major
 * status, as gss_krb5.h has them.
 */
struct oncrpc_gss_mech {
	uint32_t	(*gm_get_mic)(void *, const void *, size_t, void *,
			    size_t, size_t *);
	uint32_t	(*gm_verify_mic)(void *, const void *, size_t,
			    const void *, size_t);
	size_t		(*gm_wrap_size)(const void *, size_t);
	uint32_t	(*gm_wrap)(void *, const void *, size_t, void *, size_t,
			    size_t *);
	uint32_t	(*gm_unwrap)(void *, void *, size_t, void *, void **,
			    size_t *, bool *);
	void		(*gm_destroy)(void *);
};

/* A context of one mechanism. */
struct oncrpc_gss_key {
	const struct oncrpc_gss_mech *k_mech;
	void		*k_ctx;
};

extern const struct oncrpc_gss_mech oncrpc_gss_krb5_mech;

static __inline uint32_t
oncrpc_gssk_get_mic(const struct oncrpc_gss_key *k, const void *m, size_t ml,
    void *t, size_t tmax, size_t *tl)
{

	return (*k->k_mech->gm_get_mic)(k->k_ctx, m, ml, t, tmax, tl);
}

static __inline uint32_t
oncrpc_gssk_verify_mic(const struct oncrpc_gss_key *k, const void *m,
    size_t ml, const void *t, size_t tl)
{

	return (*k->k_mech->gm_verify_mic)(k->k_ctx, m, ml, t, tl);
}

static __inline size_t
oncrpc_gssk_wrap_size(const struct oncrpc_gss_key *k, size_t len)
{

	return (*k->k_mech->gm_wrap_size)(k->k_ctx, len);
}

static __inline uint32_t
oncrpc_gssk_wrap(const struct oncrpc_gss_key *k, const void *m, size_t ml,
    void *t, size_t tmax, size_t *tl)
{

	return (*k->k_mech->gm_wrap)(k->k_ctx, m, ml, t, tmax, tl);
}

static __inline uint32_t
oncrpc_gssk_unwrap(const struct oncrpc_gss_key *k, void *t, size_t tl,
    void *out, void **mp, size_t *mlp, bool *confp)
{

	return (*k->k_mech->gm_unwrap)(k->k_ctx, t, tl, out, mp, mlp, confp);
}

static __inline void
oncrpc_gssk_destroy(struct oncrpc_gss_key *k)
{

	if (k->k_mech != NULL)
		(*k->k_mech->gm_destroy)(k->k_ctx);
	k->k_mech = NULL;
	k->k_ctx = NULL;
}

#endif /* !_ONCRPC_GSS_MECH_H_ */
