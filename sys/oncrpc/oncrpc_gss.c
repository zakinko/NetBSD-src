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
 * The pieces of RPCSEC_GSS, RFC 2203, that need no GSS-API: the credential
 * and the sequence window.  The kernel has no Kerberos and no way yet to
 * reach one in userland, so no context can come to exist, and flavor 6
 * still gets AUTH_REJECTEDCRED from oncrpc_auth_lookup().  Nothing here
 * sleeps or allocates, and tests/oncrpc runs it in userland.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <stdbool.h>
#include <string.h>
#endif

#include <rpc/types.h>
#include <rpc/xdr.h>

#include <oncrpc/oncrpc_gss.h>

/* RFC 2203 s5, rpc_gss_cred_t.  False if it is not version 1 or is bad. */
bool
oncrpc_gss_cred_decode(XDR *x, struct oncrpc_gss_cred *gc)
{

	if (!xdr_u_int32_t(x, &gc->gc_vers) ||
	    gc->gc_vers != RPCSEC_GSS_VERS_1 ||
	    !xdr_u_int32_t(x, &gc->gc_proc) ||
	    !xdr_u_int32_t(x, &gc->gc_seq) ||
	    !xdr_u_int32_t(x, &gc->gc_service) ||
	    !xdr_u_int32_t(x, &gc->gc_handlelen) ||
	    gc->gc_handlelen > sizeof(gc->gc_handle))
		return false;
	if (gc->gc_proc > RPCSEC_GSS_DESTROY)
		return false;
	return xdr_opaque(x, (char *)gc->gc_handle, gc->gc_handlelen) != 0;
}

void
oncrpc_gss_seq_init(struct oncrpc_gss_seq *gs)
{

	memset(gs, 0, sizeof(*gs));
}

/*
 * RFC 2203 s5.3.3.1, to be called once GSS_VerifyMIC() has passed: the
 * window moves only for a request that proved itself.  False means that
 * the request is to be dropped without a word.
 */
bool
oncrpc_gss_seq_accept(struct oncrpc_gss_seq *gs, uint32_t seq)
{
	uint32_t d, i, bit;

	if (seq >= RPCSEC_GSS_MAXSEQ)
		return false;
	if (!gs->gs_any || seq > gs->gs_last) {
		d = gs->gs_any ? seq - gs->gs_last : RPCSEC_GSS_WINDOW;
		if (d >= RPCSEC_GSS_WINDOW)
			memset(gs->gs_seen, 0, sizeof(gs->gs_seen));
		else {
			for (i = gs->gs_last + 1; i <= seq; i++) {
				bit = i % RPCSEC_GSS_WINDOW;
				gs->gs_seen[bit / 32] &= ~(1U << (bit % 32));
			}
		}
		gs->gs_last = seq;
		gs->gs_any = true;
	} else if (gs->gs_last - seq >= RPCSEC_GSS_WINDOW)
		return false;
	bit = seq % RPCSEC_GSS_WINDOW;
	if ((gs->gs_seen[bit / 32] & (1U << (bit % 32))) != 0)
		return false;
	gs->gs_seen[bit / 32] |= 1U << (bit % 32);
	return true;
}
