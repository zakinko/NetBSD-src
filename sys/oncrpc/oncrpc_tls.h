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

#ifndef _ONCRPC_ONCRPC_TLS_H_
#define _ONCRPC_ONCRPC_TLS_H_

#include <sys/socket.h>	/* struct sockaddr_storage */

/* RPC-with-TLS, RFC 9289: the record layer of a connection. */

#define	ONCRPC_TLS_SECRETMAX	48	/* SHA-384, RFC 8446 s7.1 */
#define	ONCRPC_TLS_EXPORTERLEN	32	/* "tls-exporter", RFC 9266 s2 */
#define	ONCRPC_TLS_MAXCID	20	/* DTLS, ours; see DTLS13_MAXCID */

/* RFC 8446 s6, AlertLevel and AlertDescription; those used here */
#define	ONCRPC_TLS_WARNING		1
#define	ONCRPC_TLS_FATAL		2
#define	ONCRPC_TLS_CLOSE_NOTIFY		0
#define	ONCRPC_TLS_UNEXPECTED_MESSAGE	10
#define	ONCRPC_TLS_BAD_RECORD_MAC	20
#define	ONCRPC_TLS_RECORD_OVERFLOW	22
#define	ONCRPC_TLS_ILLEGAL_PARAMETER	47
#define	ONCRPC_TLS_DECODE_ERROR		50
#define	ONCRPC_TLS_INTERNAL_ERROR	80
#define	ONCRPC_TLS_USER_CANCELED	90
#define	ONCRPC_TLS_NOALERT		256	/* none to send */

/* What rpc.tlsservd hands over at the end of a handshake. */
struct oncrpc_tls_params {
	uint16_t	tp_suite;	/* RFC 8446 App. B.4 */
	uint8_t		tp_flags;	/* ONCRPC_TLS_PEERCERT */
	uint8_t		tp_secretlen;
	uint8_t		tp_csecret[ONCRPC_TLS_SECRETMAX];
	uint8_t		tp_ssecret[ONCRPC_TLS_SECRETMAX];
	uint8_t		tp_exporter[ONCRPC_TLS_EXPORTERLEN];
	/* DTLS, RFC 9147 s9: ours, on what the peer sends, and its. */
	uint8_t		tp_rcidlen;
	uint8_t		tp_tcidlen;
	uint8_t		tp_rcid[ONCRPC_TLS_MAXCID];
	uint8_t		tp_tcid[ONCRPC_TLS_MAXCID];
};
#define	ONCRPC_TLS_PEERCERT	0x01

/*
 * A datagram association for the daemon, RFC 9289 s5.1.2: td_accept
 * says the daemon can do DTLS; the rest says what it was given, the
 * peer's address and the largest datagram payload toward it.
 */
struct oncrpc_tls_dgram {
	bool		td_accept;
	bool		td_is;
	uint32_t	td_pmtu;
	struct sockaddr_storage td_peer;
};

/* An alert, for rpc.tlsservd to hear of. */
struct oncrpc_tls_event {
	uint64_t	te_cookie;	/* the connection, as TLSWAIT named it */
	bool		te_sent;	/* by us, or received */
	uint8_t		te_level;
	uint8_t		te_desc;
};

/* What oncrpc_tlsconn_input() found. */
struct oncrpc_tls_in {
	struct mbuf	*ti_data;	/* application data */
	u_int		 ti_alert;	/* to send, or ONCRPC_TLS_NOALERT */
	bool		 ti_keyupdate;	/* the peer asked for ours, s4.6.3 */
	bool		 ti_ralert;	/* an alert received: */
	uint8_t		 ti_rlevel;
	uint8_t		 ti_rdesc;
};

struct oncrpc_tlsconn;

struct oncrpc_tlsconn *oncrpc_tlsconn_create(const struct oncrpc_tls_params *,
	    int *);
void	oncrpc_tlsconn_destroy(struct oncrpc_tlsconn *);
void	oncrpc_tlsconn_exporter(const struct oncrpc_tlsconn *, uint8_t *);
int	oncrpc_tlsconn_input(struct oncrpc_tlsconn *, struct mbuf *,
	    struct oncrpc_tls_in *);
int	oncrpc_tlsconn_output(struct oncrpc_tlsconn *, struct mbuf *,
	    struct mbuf **);
int	oncrpc_tlsconn_keyupdate(struct oncrpc_tlsconn *, struct mbuf **);
int	oncrpc_tlsconn_alert(struct oncrpc_tlsconn *, uint8_t, uint8_t,
	    struct mbuf **);

#endif /* !_ONCRPC_ONCRPC_TLS_H_ */
