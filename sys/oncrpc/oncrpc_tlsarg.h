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

#ifndef _ONCRPC_ONCRPC_TLSARG_H_
#define _ONCRPC_ONCRPC_TLSARG_H_

/*
 * The hand-off of RPC-with-TLS connections to rpc.tlsservd, RFC 9289,
 * through nfssvc(2).  Here and not in <nfs/nfs.h>, which with
 * NFSSERVER_ONCRPC off stays as before, as <oncrpc/oncrpc_sec.h> does.
 */
#define	NFSSVC_TLSWAIT	0x800	/* take a connection to handshake */
#define	NFSSVC_TLSDONE	0x1000	/* the handshake's verdict */

/*
 * For NFSSVC_TLSWAIT and NFSSVC_TLSDONE.  TLSWAIT fills in nt_cookie and
 * nt_fd, a new descriptor of the connection; TLSDONE names the connection
 * by nt_cookie and gives nt_error, 0 when the handshake succeeded, and
 * then what the record layer and channel bindings need of it.
 */
#define	NFSD_TLS_SECRETMAX	48	/* SHA-384, RFC 8446 s7.1 */
#define	NFSD_TLS_EXPORTERLEN	32	/* "tls-exporter", RFC 9266 s2 */
#define	NFSD_TLS_MAXCID		255	/* DTLS connection ID, RFC 9146 s3 */
#define	NFSD_TLS_PEERLEN	128	/* sizeof(struct sockaddr_storage) */

struct nfsd_tlsarg {
	uint64_t nt_cookie;
	int	nt_fd;
	int	nt_error;
	uint16_t nt_suite;		/* cipher suite, RFC 8446 App. B.4 */
	uint8_t	nt_flags;
	uint8_t	nt_secretlen;
	/* [sender]_application_traffic_secret_0, RFC 8446 s7.1 */
	uint8_t	nt_csecret[NFSD_TLS_SECRETMAX];
	uint8_t	nt_ssecret[NFSD_TLS_SECRETMAX];
	uint8_t	nt_exporter[NFSD_TLS_EXPORTERLEN];
	uint8_t	nt_alertlevel;		/* NFSD_TLS_EVENT, RFC 8446 s6 */
	uint8_t	nt_alertdesc;
	/* NFSD_TLS_DGRAM, RFC 9289 s5.1.2: nt_fd is an AF_LOCAL datagram
	 * socket carrying the peer's DTLS datagrams; nt_peer is where they
	 * come from and nt_pmtu the largest payload toward it. */
	uint32_t nt_pmtu;
	uint8_t	nt_peer[NFSD_TLS_PEERLEN];	/* a struct sockaddr */
	/* TLSDONE of a datagram association, RFC 9147 s9 */
	uint8_t	nt_rcidlen;		/* ours, on what the peer sends */
	uint8_t	nt_tcidlen;		/* the peer's, on what we send */
	uint8_t	nt_rcid[NFSD_TLS_MAXCID];
	uint8_t	nt_tcid[NFSD_TLS_MAXCID];
	/* RFC 9147 s5.2: the next message_seq the server sends, and the
	 * next it expects, for the messages after the handshake */
	uint16_t nt_hstxseq;
	uint16_t nt_hsrxseq;
	/* RFC 9147 s4: the records of epoch 3 the daemon sent (an ACK of the
	 * client's Finished, s7) and read; the kernel goes on from there */
	uint64_t nt_txseq;
	uint64_t nt_rxseq;
};

/* nt_flags */
#define	NFSD_TLS_PEERCERT	0x01	/* the client's certificate verified */
#define	NFSD_TLS_EVENT		0x02	/* TLSWAIT: an alert, nt_fd is -1 */
#define	NFSD_TLS_ALERTSENT	0x04	/* the alert was ours */
#define	NFSD_TLS_DGRAMOK	0x08	/* TLSWAIT in: the daemon does DTLS */
#define	NFSD_TLS_DGRAM		0x10	/* TLSWAIT out: a DTLS association */

#endif /* !_ONCRPC_ONCRPC_TLSARG_H_ */
