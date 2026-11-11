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

#ifndef _ONCRPC_ONCRPC_DTLS_H_
#define _ONCRPC_ONCRPC_DTLS_H_

/*
 * RPC-with-TLS on UDP, RFC 9289 s5.1.2: the DTLS 1.3 associations of
 * one UDP socket, RFC 9147, told apart by the peer's address.
 */

struct mbuf;
struct socket;
struct sockaddr;
struct oncrpc_dtls;
struct oncrpc_dtlspeer;

struct oncrpc_tls_dgram;
struct oncrpc_tls_params;

void	oncrpc_dtls_init(void (*)(void));
void	oncrpc_dtls_fini(void);
struct oncrpc_dtls *oncrpc_dtls_create(struct socket *, void (*)(void *),
	    void *);
void	oncrpc_dtls_destroy(struct oncrpc_dtls *);
int	oncrpc_dtls_input(struct mbuf **, int, struct socket *,
	    struct sockaddr *, void *);
struct mbuf *oncrpc_dtls_getmsg(struct oncrpc_dtls *, struct mbuf **,
	    struct oncrpc_dtlspeer **);
int	oncrpc_dtls_probed(struct oncrpc_dtls *, const struct sockaddr *);
int	oncrpc_dtls_take(uint64_t *, int *, struct oncrpc_tls_dgram *);
bool	oncrpc_dtls_cookie(uint64_t);
int	oncrpc_dtls_done(uint64_t, int, const struct oncrpc_tls_params *);
int	oncrpc_dtls_output(struct oncrpc_dtlspeer *, struct mbuf *,
	    struct mbuf **);
void	oncrpc_dtls_exporter(const struct oncrpc_dtlspeer *, uint8_t *);
void	oncrpc_dtls_rele(struct oncrpc_dtlspeer *);

#endif /* !_ONCRPC_ONCRPC_DTLS_H_ */
