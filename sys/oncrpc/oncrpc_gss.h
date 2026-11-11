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

#ifndef _ONCRPC_ONCRPC_GSS_H_
#define _ONCRPC_ONCRPC_GSS_H_

#include <rpc/types.h>
#include <rpc/xdr.h>

#define	RPCSEC_GSS		6	/* RFC 2203 s3, the flavor */
#define	RPCSEC_GSS_VERS_1	1	/* RFC 2203 s5 */
#define	RPCSEC_GSS_VERS_2	2	/* RFC 5403 s3.2 */
#define	RPCSEC_GSS_MAXSEQ	0x80000000U	/* RFC 2203 s5, MAXSEQ */

/* RFC 2203 s5, enum rpc_gss_proc_t */
#define	RPCSEC_GSS_DATA		0
#define	RPCSEC_GSS_INIT		1
#define	RPCSEC_GSS_CONTINUE_INIT 2
#define	RPCSEC_GSS_DESTROY	3
#define	RPCSEC_GSS_BIND_CHANNEL	4	/* RFC 5403 s3.2 */

/* RFC 2203 s5, enum rpc_gss_service_t; RFC 5403 s3.2 */
#define	RPCSEC_GSS_SVC_NONE	1
#define	RPCSEC_GSS_SVC_INTEGRITY 2
#define	RPCSEC_GSS_SVC_PRIVACY	3
#define	RPCSEC_GSS_SVC_CHANNEL	4

/* RFC 2623 s4.2, the pseudo flavors */
#define	RPCSEC_GSS_KRB5		390003
#define	RPCSEC_GSS_KRB5I	390004
#define	RPCSEC_GSS_KRB5P	390005

/* RFC 2203 App. A */
#define	RPCSEC_GSS_S_CONTINUE_NEEDED 1

/* RFC 2203 s4, the auth_stat values it adds */
#define	RPCSEC_GSS_CREDPROBLEM	13
#define	RPCSEC_GSS_CTXPROBLEM	14

/* Chosen, RFC 2203 s5.3.3.1 suggesting about the number of threads. */
#define	RPCSEC_GSS_WINDOW	128

/* A verifier: GSS_KRB5_MAXMIC, or an rgss2_bind_chan_verf_res with one. */
#define	ONCRPC_GSS_MAXVERF	128

struct oncrpc_gss_cred {
	uint32_t	gc_vers;
	uint32_t	gc_proc;
	uint32_t	gc_seq;
	uint32_t	gc_service;
	uint32_t	gc_handlelen;
	uint8_t		gc_handle[64];	/* a server's own, so ours to bound */
};

struct oncrpc_gss_seq {
	uint32_t	gs_seen[RPCSEC_GSS_WINDOW / 32];
	uint32_t	gs_last;
	bool		gs_any;
};

uint32_t oncrpc_gss_cred_decode(XDR *, struct oncrpc_gss_cred *);
void	oncrpc_gss_seq_init(struct oncrpc_gss_seq *);
bool	oncrpc_gss_seq_accept(struct oncrpc_gss_seq *, uint32_t);

#ifdef _KERNEL
struct mbuf;
struct oncrpc_call;
struct oncrpc_gss_ctx;
struct oncrpc_req;
struct oncrpc_xdrmbuf;

/* What a request under RPCSEC_GSS is to get. */
enum oncrpc_gss_verdict {
	ONCRPC_GSS_DISPATCH,	/* on to the program */
	ONCRPC_GSS_REPLY,	/* a control message; *resp is the result */
	ONCRPC_GSS_GARBAGE,	/* GARBAGE_ARGS, with a verifier */
	ONCRPC_GSS_DROP,	/* no reply at all */
	ONCRPC_GSS_DENY		/* MSG_DENIED, for the auth_stat */
};

/* One call, from oncrpc_gss_accept() until oncrpc_gss_done(). */
struct oncrpc_gss_call {
	struct oncrpc_gss_ctx	*gg_ctx;	/* NULL if there is none */
	struct oncrpc_gss_cred	gg_cred;
	uint32_t		gg_verf;	/* the flavor of the reply's */
	uint32_t		gg_verflen;
	uint8_t			gg_verfbody[ONCRPC_GSS_MAXVERF];
};

struct oncrpc_gss_key;
struct oncrpc_gssc;
struct oncrpc_opaque_auth;
struct sockaddr;

int	oncrpc_gssc_create(const struct sockaddr *, uint32_t, uint32_t,
	    const char *, uint32_t, int, struct oncrpc_gssc **);
void	oncrpc_gssc_destroy(struct oncrpc_gssc *);
void	oncrpc_gssc_hold(struct oncrpc_gssc *);
int	oncrpc_gssc_back(const uint8_t *, uint32_t, const uint8_t *, uint32_t,
	    uint32_t, struct oncrpc_gssc **);
struct oncrpc_gss_ctx *
	oncrpc_gss_ctx_hold(const uint8_t *, uint32_t, struct oncrpc_gss_key **);
void	oncrpc_gss_ctx_rele(struct oncrpc_gss_ctx *);
void	oncrpc_gssc_close(const struct sockaddr *, uint32_t, uint32_t,
	    struct oncrpc_gssc *, int);
bool	oncrpc_gssc_header(struct oncrpc_gssc *, uint32_t, uint32_t, uint32_t,
	    uint32_t, uint8_t *, uint32_t *, uint8_t *, uint32_t *, uint32_t *);
struct mbuf *
	oncrpc_gssc_seal(struct oncrpc_gssc *, uint32_t, struct mbuf *);
int	oncrpc_gssc_open(struct oncrpc_gssc *, uint32_t,
	    const struct oncrpc_opaque_auth *, struct mbuf *, u_int,
	    struct mbuf **);

void	oncrpc_gss_init(void);
void	oncrpc_gss_fini(void);
enum oncrpc_gss_verdict
	oncrpc_gss_accept(struct oncrpc_gss_call *, const struct oncrpc_call *,
	    struct oncrpc_xdrmbuf *, struct mbuf **, struct oncrpc_req *,
	    struct mbuf **, uint32_t *);
bool	oncrpc_gss_verifier(struct oncrpc_gss_call *);
bool	oncrpc_gss_wrap_results(struct oncrpc_gss_call *, struct mbuf **);
void	oncrpc_gss_done(struct oncrpc_gss_call *);
#endif

#endif /* !_ONCRPC_ONCRPC_GSS_H_ */
