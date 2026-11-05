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
 * RPC messages, RFC 5531 s9.  Only XDR is touched here: no sockets and
 * no request state.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/systm.h>

#include <oncrpc/oncrpc_var.h>

/*
 * An opaque_auth, with the length tested against the buffer before any
 * of the body is read.  *toolong says the failure is the length, which
 * unlike a short message can be answered.
 */
static bool
msg_decode_auth(XDR *xdrs, struct oncrpc_opaque_auth *oa, bool *toolong)
{

	if (!xdr_u_int32_t(xdrs, &oa->oa_flavor) ||
	    !xdr_u_int32_t(xdrs, &oa->oa_len))
		return false;
	if (oa->oa_len > sizeof(oa->oa_body)) {
		*toolong = true;
		return false;
	}
	return xdr_opaque(xdrs, oa->oa_body, oa->oa_len);
}

enum oncrpc_decoded
oncrpc_msg_decode_call(XDR *xdrs, struct oncrpc_call *c)
{
	uint32_t mtype, rpcvers;
	bool toolong = false;

	if (!xdr_u_int32_t(xdrs, &c->c_xid) ||
	    !xdr_u_int32_t(xdrs, &mtype) ||
	    mtype != ONCRPC_CALL)
		return ONCRPC_DEC_DROP;
	if (!xdr_u_int32_t(xdrs, &rpcvers))
		return ONCRPC_DEC_DROP;
	/* The rest of the header is version 2's, so stop here. */
	if (rpcvers != ONCRPC_VERS)
		return ONCRPC_DEC_RPCVERS;
	if (!xdr_u_int32_t(xdrs, &c->c_prog) ||
	    !xdr_u_int32_t(xdrs, &c->c_vers) ||
	    !xdr_u_int32_t(xdrs, &c->c_proc))
		return ONCRPC_DEC_DROP;
	if (!msg_decode_auth(xdrs, &c->c_cred, &toolong))
		return toolong ? ONCRPC_DEC_BADCRED : ONCRPC_DEC_DROP;
	if (!msg_decode_auth(xdrs, &c->c_verf, &toolong))
		return toolong ? ONCRPC_DEC_BADVERF : ONCRPC_DEC_DROP;
	return ONCRPC_DEC_OK;
}

static bool
msg_encode_head(XDR *xdrs, uint32_t xid, uint32_t stat)
{
	uint32_t mtype = ONCRPC_REPLY;

	return xdr_u_int32_t(xdrs, &xid) &&
	    xdr_u_int32_t(xdrs, &mtype) &&
	    xdr_u_int32_t(xdrs, &stat);
}

/*
 * accepted_reply up to the results.  The verifier is always an empty
 * AUTH_NONE, one of the two RFC 5531 App. A allows; this server never
 * issues AUTH_SHORT.  low and high are for PROG_MISMATCH.
 */
bool
oncrpc_msg_encode_accepted(XDR *xdrs, uint32_t xid, uint32_t stat,
    uint32_t low, uint32_t high)
{
	uint32_t flavor = ONCRPC_AUTH_NONE, len = 0;

	if (!msg_encode_head(xdrs, xid, ONCRPC_MSG_ACCEPTED) ||
	    !xdr_u_int32_t(xdrs, &flavor) ||
	    !xdr_u_int32_t(xdrs, &len) ||
	    !xdr_u_int32_t(xdrs, &stat))
		return false;
	if (stat == ONCRPC_PROG_MISMATCH)
		return xdr_u_int32_t(xdrs, &low) &&
		    xdr_u_int32_t(xdrs, &high);
	return true;
}

bool
oncrpc_msg_encode_denied_vers(XDR *xdrs, uint32_t xid)
{
	uint32_t stat = ONCRPC_RPC_MISMATCH, vers = ONCRPC_VERS;

	return msg_encode_head(xdrs, xid, ONCRPC_MSG_DENIED) &&
	    xdr_u_int32_t(xdrs, &stat) &&
	    xdr_u_int32_t(xdrs, &vers) &&
	    xdr_u_int32_t(xdrs, &vers);
}

bool
oncrpc_msg_encode_denied_auth(XDR *xdrs, uint32_t xid, uint32_t why)
{
	uint32_t stat = ONCRPC_AUTH_ERROR;

	return msg_encode_head(xdrs, xid, ONCRPC_MSG_DENIED) &&
	    xdr_u_int32_t(xdrs, &stat) &&
	    xdr_u_int32_t(xdrs, &why);
}
