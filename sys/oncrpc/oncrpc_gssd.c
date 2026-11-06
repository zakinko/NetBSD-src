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
 * The kernel's end of gssd(8); see oncrpc_gssd.h.  Each call opens the
 * socket, as a callback does, so that a daemon restarted is simply
 * found again, and a daemon not there is an error to the one call.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/systm.h>

#include <oncrpc/oncrpc_gssd.h>
#include <oncrpc/oncrpc_var.h>

#define	GSSD_TIMEO	30	/* chosen; a KDC may have to be asked */

struct gssd_accept_arg {
	uint64_t	aa_dh;
	const void	*aa_token;
	uint32_t	aa_len;
};

static bool
gssd_accept_enc(XDR *x, void *arg)
{
	struct gssd_accept_arg *aa = arg;
	uint32_t hi = aa->aa_dh >> 32, lo = (uint32_t)aa->aa_dh;

	return xdr_u_int32_t(x, &hi) && xdr_u_int32_t(x, &lo) &&
	    xdr_u_int32_t(x, &aa->aa_len) &&
	    (aa->aa_len == 0 ||
	    xdr_opaque(x, __UNCONST(aa->aa_token), aa->aa_len));
}

static bool
gssd_accept_dec(XDR *x, void *arg)
{
	struct oncrpc_gssd_accept_res *ar = arg;
	struct gss_krb5_import *gi = &ar->ar_import;
	uint32_t hi, lo, cfx, subkey;
	uint32_t i;

	if (!xdr_u_int32_t(x, &ar->ar_major) ||
	    !xdr_u_int32_t(x, &ar->ar_minor) ||
	    !xdr_u_int32_t(x, &hi) || !xdr_u_int32_t(x, &lo) ||
	    !xdr_u_int32_t(x, &ar->ar_tokenlen) ||
	    ar->ar_tokenlen > sizeof(ar->ar_token) ||
	    (ar->ar_tokenlen != 0 &&
	    !xdr_opaque(x, (char *)ar->ar_token, ar->ar_tokenlen)))
		return false;
	ar->ar_dh = (uint64_t)hi << 32 | lo;
	if (ar->ar_major != 0)
		return true;
	if (!xdr_u_int32_t(x, &gi->gi_enctype) ||
	    !xdr_u_int32_t(x, &gi->gi_keylen) ||
	    gi->gi_keylen > sizeof(gi->gi_key) ||
	    !xdr_opaque(x, (char *)gi->gi_key, gi->gi_keylen) ||
	    !xdr_u_int32_t(x, &cfx) || !xdr_u_int32_t(x, &subkey) ||
	    !xdr_u_int32_t(x, &hi) || !xdr_u_int32_t(x, &lo) ||
	    !xdr_u_int32_t(x, &ar->ar_lifetime) ||
	    !xdr_u_int32_t(x, &ar->ar_uid) ||
	    !xdr_u_int32_t(x, &ar->ar_gid) ||
	    !xdr_u_int32_t(x, &ar->ar_ngroups) ||
	    ar->ar_ngroups > ONCRPC_GSSD_MAXGROUPS)
		return false;
	gi->gi_cfx = cfx != 0;
	gi->gi_acceptor_subkey = subkey != 0;
	gi->gi_initiator = false;
	gi->gi_send_seq = (uint64_t)hi << 32 | lo;
	for (i = 0; i < ar->ar_ngroups; i++)
		if (!xdr_u_int32_t(x, &ar->ar_groups[i]))
			return false;
	return true;
}

static int
gssd_call(uint32_t proc, bool (*enc)(XDR *, void *), void *arg,
    bool (*dec)(XDR *, void *), void *res)
{
	struct oncrpc_clnt_call cc;

	memset(&cc, 0, sizeof(cc));
	cc.cc_prog = ONCRPC_GSSD_PROG;
	cc.cc_vers = ONCRPC_GSSD_VERS;
	cc.cc_proc = proc;
	cc.cc_flavor = ONCRPC_AUTH_NONE;
	cc.cc_encode = enc;
	cc.cc_arg = arg;
	cc.cc_decode = dec;
	cc.cc_res = res;
	return oncrpc_clnt_call_unix(ONCRPC_GSSD_PATH, &cc, GSSD_TIMEO);
}

int
oncrpc_gssd_accept(uint64_t dh, const void *token, uint32_t len,
    struct oncrpc_gssd_accept_res *ar)
{
	struct gssd_accept_arg aa = { dh, token, len };

	return gssd_call(ONCRPC_GSSD_ACCEPT, gssd_accept_enc, &aa,
	    gssd_accept_dec, ar);
}
