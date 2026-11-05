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

#ifndef _ONCRPC_ONCRPC_VAR_H_
#define _ONCRPC_ONCRPC_VAR_H_

#include <sys/queue.h>

#include <oncrpc/oncrpc.h>

/* RFC 5531 s8.2, struct opaque_auth */
struct oncrpc_opaque_auth {
	uint32_t	oa_flavor;
	uint32_t	oa_len;
	char		oa_body[ONCRPC_MAX_AUTH_BYTES];
};

/* RFC 5531 s9, struct call_body with the xid */
struct oncrpc_call {
	uint32_t	c_xid;
	uint32_t	c_prog;
	uint32_t	c_vers;
	uint32_t	c_proc;
	struct oncrpc_opaque_auth c_cred;
	struct oncrpc_opaque_auth c_verf;
};

/* What oncrpc_msg_decode_call() made of a message. */
enum oncrpc_decoded {
	ONCRPC_DEC_OK,
	ONCRPC_DEC_DROP,	/* nothing can be said in reply */
	ONCRPC_DEC_RPCVERS,	/* c_xid is good; RPC_MISMATCH */
	ONCRPC_DEC_BADCRED,	/* c_xid is good; AUTH_ERROR */
	ONCRPC_DEC_BADVERF	/* c_xid is good; AUTH_ERROR */
};

enum oncrpc_decoded
	oncrpc_msg_decode_call(XDR *, struct oncrpc_call *);
bool	oncrpc_msg_encode_accepted(XDR *, uint32_t, uint32_t, uint32_t,
	    uint32_t);
bool	oncrpc_msg_encode_denied_vers(XDR *, uint32_t);
bool	oncrpc_msg_encode_denied_auth(XDR *, uint32_t, uint32_t);

/*
 * An authentication flavor, server side.  Returns an auth_stat, and on
 * ONCRPC_AUTH_OK a held credential, or NULL for no identity.
 */
struct oncrpc_auth_ops {
	uint32_t	ao_flavor;
	uint32_t	(*ao_svc_verify)(const struct oncrpc_call *,
			    kauth_cred_t *);
};

const struct oncrpc_auth_ops *
	oncrpc_auth_lookup(uint32_t);

/*
 * Record marking state for one connection.
 */
struct oncrpc_rm {
	struct mbuf	*rm_raw;	/* stream not yet looked at */
	struct mbuf	*rm_rawend;
	u_int		rm_cc;		/* bytes in rm_raw */
	struct mbuf	*rm_frag;	/* fragments of this record */
	u_int		rm_need;	/* rest of this fragment */
	u_int		rm_total;	/* of this record, for the limit */
	u_int		rm_nfrag;	/* of this record, for the limit */
	u_int		rm_max;		/* limit on a record */
	bool		rm_inframe;	/* header seen, rm_need is good */
	bool		rm_last;	/* this fragment ends the record */
};

void	oncrpc_rm_init(struct oncrpc_rm *, u_int);
void	oncrpc_rm_fini(struct oncrpc_rm *);
void	oncrpc_rm_input(struct oncrpc_rm *, struct mbuf *, u_int);
int	oncrpc_rm_next(struct oncrpc_rm *, struct mbuf **);

#endif /* !_ONCRPC_ONCRPC_VAR_H_ */
