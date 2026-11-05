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
 * Authentication flavors, server side.  AUTH_NONE is required of every
 * implementation and AUTH_SYS is optional, RFC 5531 s10.  The incoming
 * verifier of AUTH_SYS should be AUTH_NONE (App. A); it proves nothing
 * either way, so it is not looked at.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/kauth.h>
#include <sys/systm.h>
#include <sys/uio.h>

#include <oncrpc/oncrpc_var.h>

static uint32_t
auth_none_verify(const struct oncrpc_call *c, kauth_cred_t *credp)
{

	/* RFC 5531 s10.1: the body means nothing, whatever its length. */
	*credp = NULL;
	return ONCRPC_AUTH_OK;
}

/*
 * RFC 5531 App. A, struct authsys_parms.  The name is read into a local
 * array rather than with xdr_string(), which would allocate it and,
 * given a NUL in it, later free it with the wrong size (RFC 4506 s8).
 * It is not used for anything.
 */
static uint32_t
auth_sys_verify(const struct oncrpc_call *c, kauth_cred_t *credp)
{
	char name[ONCRPC_MAX_MACHINENAME];
	gid_t gids[ONCRPC_MAX_AUTHSYS_GIDS];
	uint32_t stamp, namelen, uid, gid, ngids, g, i;
	kauth_cred_t cred;
	XDR xdrs;

	CTASSERT(ONCRPC_MAX_AUTHSYS_GIDS <= NGROUPS);

	xdrmem_create(&xdrs, __UNCONST(c->c_cred.oa_body), c->c_cred.oa_len,
	    XDR_DECODE);
	if (!xdr_u_int32_t(&xdrs, &stamp) ||
	    !xdr_u_int32_t(&xdrs, &namelen) ||
	    namelen > sizeof(name) ||
	    !xdr_opaque(&xdrs, name, namelen) ||
	    !xdr_u_int32_t(&xdrs, &uid) ||
	    !xdr_u_int32_t(&xdrs, &gid) ||
	    !xdr_u_int32_t(&xdrs, &ngids) ||
	    ngids > __arraycount(gids))
		return ONCRPC_AUTH_BADCRED;
	for (i = 0; i < ngids; i++) {
		if (!xdr_u_int32_t(&xdrs, &g))
			return ONCRPC_AUTH_BADCRED;
		gids[i] = g;
	}
	if (XDR_GETPOS(&xdrs) != c->c_cred.oa_len)
		return ONCRPC_AUTH_BADCRED;

	cred = kauth_cred_alloc();
	kauth_cred_setuid(cred, uid);
	kauth_cred_seteuid(cred, uid);
	kauth_cred_setsvuid(cred, uid);
	kauth_cred_setgid(cred, gid);
	kauth_cred_setegid(cred, gid);
	kauth_cred_setsvgid(cred, gid);
	if (ngids > 0)
		kauth_cred_setgroups(cred, gids, ngids, -1, UIO_SYSSPACE);
	*credp = cred;
	return ONCRPC_AUTH_OK;
}

static const struct oncrpc_auth_ops auth_flavors[] = {
	{ ONCRPC_AUTH_NONE,	auth_none_verify },
	{ ONCRPC_AUTH_SYS,	auth_sys_verify },
};

const struct oncrpc_auth_ops *
oncrpc_auth_lookup(uint32_t flavor)
{
	u_int i;

	for (i = 0; i < __arraycount(auth_flavors); i++) {
		if (auth_flavors[i].ao_flavor == flavor)
			return &auth_flavors[i];
	}
	return NULL;
}
