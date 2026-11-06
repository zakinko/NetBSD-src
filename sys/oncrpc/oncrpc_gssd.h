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

#ifndef _ONCRPC_ONCRPC_GSSD_H_
#define _ONCRPC_ONCRPC_GSSD_H_

/*
 * Between the kernel and gssd(8): ONC RPC over a local socket, with the
 * kernel as the client.  The program number is in the transient range
 * of RFC 5531 s8.3, as the protocol goes no further than this machine.
 * Both ends are built together, so it has one version.
 */
#define	ONCRPC_GSSD_PATH	"/var/run/gssd.sock"
#define	ONCRPC_GSSD_PROG	0x40475353
#define	ONCRPC_GSSD_VERS	1

#define	ONCRPC_GSSD_ACCEPT	1
#define	ONCRPC_GSSD_INIT	2	/* the initiator, RFC 7530 s3.3.3 */

#define	ONCRPC_GSSD_MAXGROUPS	16	/* as AUTH_SYS, RFC 5531 App. A */
#define	ONCRPC_GSSD_MAXTOKEN	(60 * 1024)
#define	ONCRPC_GSSD_MAXNAME	128	/* chosen */

#ifdef _KERNEL
#include <oncrpc/gss_krb5.h>

/*
 * The results of ACCEPT:
 *	major, minor, dh, token<>, and if major is 0:
 *	enctype, key<32>, cfx, acceptor_subkey, send_seq (hi, lo), lifetime,
 *	uid, gid, name<128>, groups<16>
 */
struct oncrpc_gssd_accept_res {
	uint32_t	ar_major;
	uint32_t	ar_minor;
	uint64_t	ar_dh;		/* for CONTINUE_INIT */
	uint32_t	ar_tokenlen;
	uint8_t		ar_token[ONCRPC_GSSD_MAXTOKEN];
	struct gss_krb5_import ar_import;
	uint32_t	ar_lifetime;	/* seconds from now */
	uint32_t	ar_uid;
	uint32_t	ar_gid;
	uint32_t	ar_namelen;
	char		ar_name[ONCRPC_GSSD_MAXNAME];
	uint32_t	ar_ngroups;
	uint32_t	ar_groups[ONCRPC_GSSD_MAXGROUPS];
};

int	oncrpc_gssd_accept(uint64_t, const void *, uint32_t,
	    struct oncrpc_gssd_accept_res *);
int	oncrpc_gssd_init(uint64_t, const char *, const void *, uint32_t,
	    struct oncrpc_gssd_accept_res *);
#endif

#endif /* !_ONCRPC_ONCRPC_GSSD_H_ */
