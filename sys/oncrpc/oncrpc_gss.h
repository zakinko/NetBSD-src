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

#define	RPCSEC_GSS		6	/* RFC 2203 s3, the flavor */
#define	RPCSEC_GSS_VERS_1	1	/* RFC 2203 s5 */
#define	RPCSEC_GSS_MAXSEQ	0x80000000U	/* RFC 2203 s5, MAXSEQ */

/* RFC 2203 s5, enum rpc_gss_proc_t */
#define	RPCSEC_GSS_DATA		0
#define	RPCSEC_GSS_INIT		1
#define	RPCSEC_GSS_CONTINUE_INIT 2
#define	RPCSEC_GSS_DESTROY	3

/* RFC 2203 s4, the auth_stat values it adds */
#define	RPCSEC_GSS_CREDPROBLEM	13
#define	RPCSEC_GSS_CTXPROBLEM	14

/* Chosen, RFC 2203 s5.3.3.1 suggesting about the number of threads. */
#define	RPCSEC_GSS_WINDOW	128

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

bool	oncrpc_gss_cred_decode(XDR *, struct oncrpc_gss_cred *);
void	oncrpc_gss_seq_init(struct oncrpc_gss_seq *);
bool	oncrpc_gss_seq_accept(struct oncrpc_gss_seq *, uint32_t);

#endif /* !_ONCRPC_ONCRPC_GSS_H_ */
