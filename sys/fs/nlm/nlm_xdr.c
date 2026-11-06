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
 * XDR of the Network Lock Manager and the Network Status Monitor, by
 * hand as in nfsv4_xdr.c.  Versions 1 and 3 differ from version 4 only
 * in the width of offsets and lengths: C702 ch. 10 nlm_lock, and ch. 14
 * or RFC 1813 s6.1.4 nlm4_lock.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/systm.h>

#include <fs/nlm/nlm_var.h>

#define	U32(x, p)	xdr_u_int32_t((x), (p))
#define	I32(x, p)	xdr_int32_t((x), (p))
#define	U64(x, p)	xdr_u_int64_t((x), (p))

static bool
opaque_decode(XDR *x, void *buf, uint32_t *lenp, uint32_t max)
{

	/* The length first: buf is no larger than the limit. */
	if (!U32(x, lenp) || *lenp > max)
		return false;
	return *lenp == 0 || xdr_opaque(x, buf, *lenp) != 0;
}

static bool
opaque_encode(XDR *x, const void *buf, uint32_t len)
{

	return U32(x, &len) &&
	    (len == 0 || xdr_opaque(x, __UNCONST(buf), len) != 0);
}

/* A name, which RFC-wise may be any bytes but is a C string here. */
static bool
name_decode(XDR *x, char *buf, uint32_t *lenp)
{

	if (!opaque_decode(x, buf, lenp, LM_MAXSTRLEN))
		return false;
	buf[*lenp] = '\0';
	return memchr(buf, '\0', *lenp) == NULL;
}

static bool
bool_decode(XDR *x, bool *bp)
{
	uint32_t v;

	if (!U32(x, &v))
		return false;
	*bp = v != 0;
	return true;
}

static bool
xdr_cookie(XDR *x, struct nlm_args *a)
{

	return opaque_decode(x, a->a_cookie, &a->a_cookielen, MAXNETOBJ_SZ);
}

static bool
xdr_alock(XDR *x, uint32_t vers, struct nlm_args *a)
{
	struct nlm_xlock *l = &a->a_lock;
	uint32_t off, len;

	if (!name_decode(x, l->xl_name, &l->xl_namelen) ||
	    !opaque_decode(x, l->xl_fh, &l->xl_fhlen, MAXNETOBJ_SZ) ||
	    !opaque_decode(x, l->xl_oh, &l->xl_ohlen, MAXNETOBJ_SZ) ||
	    !I32(x, &l->xl_svid))
		return false;
	if (vers == NLM_VERS4)
		return U64(x, &l->xl_offset) && U64(x, &l->xl_len);
	if (!U32(x, &off) || !U32(x, &len))
		return false;
	l->xl_offset = off;
	l->xl_len = len;
	return true;
}

bool
nlm_xdr_testargs(XDR *x, uint32_t vers, struct nlm_args *a)
{

	return xdr_cookie(x, a) && bool_decode(x, &a->a_exclusive) &&
	    xdr_alock(x, vers, a);
}

bool
nlm_xdr_lockargs(XDR *x, uint32_t vers, struct nlm_args *a)
{

	return xdr_cookie(x, a) && bool_decode(x, &a->a_block) &&
	    bool_decode(x, &a->a_exclusive) && xdr_alock(x, vers, a) &&
	    bool_decode(x, &a->a_reclaim) && U32(x, &a->a_state);
}

bool
nlm_xdr_cancargs(XDR *x, uint32_t vers, struct nlm_args *a)
{

	return xdr_cookie(x, a) && bool_decode(x, &a->a_block) &&
	    bool_decode(x, &a->a_exclusive) && xdr_alock(x, vers, a);
}

bool
nlm_xdr_unlockargs(XDR *x, uint32_t vers, struct nlm_args *a)
{

	return xdr_cookie(x, a) && xdr_alock(x, vers, a);
}

bool
nlm_xdr_shareargs(XDR *x, struct nlm_args *a)
{
	struct nlm_xlock *l = &a->a_lock;

	return xdr_cookie(x, a) &&
	    name_decode(x, l->xl_name, &l->xl_namelen) &&
	    opaque_decode(x, l->xl_fh, &l->xl_fhlen, MAXNETOBJ_SZ) &&
	    opaque_decode(x, l->xl_oh, &l->xl_ohlen, MAXNETOBJ_SZ) &&
	    U32(x, &l->xl_mode) && U32(x, &l->xl_access) &&
	    l->xl_mode <= NLM_FSM_MAX && l->xl_access <= NLM_FSA_MAX &&
	    bool_decode(x, &a->a_reclaim);
}

/*
 * nlm_notify.  Its name is LM_MAXSTRLEN + 1 long in C702 ch. 10, where
 * every name it could match is LM_MAXSTRLEN at most.
 */
bool
nlm_xdr_notify(XDR *x, struct nlm_args *a)
{
	struct nlm_xlock *l = &a->a_lock;

	return name_decode(x, l->xl_name, &l->xl_namelen) &&
	    U32(x, &a->a_state);
}

/* struct status, C702 SM_NOTIFY */
bool
nlm_xdr_status(XDR *x, char *name, uint32_t *lenp, uint32_t *statep,
    uint8_t *priv)
{

	return name_decode(x, name, lenp) && U32(x, statep) &&
	    xdr_opaque(x, (char *)priv, SM_PRIVLEN) != 0;
}

/*
 * What versions 1 and 3 can say.  C702 ch. 10 has only the first five;
 * "failed" is what the rest come to, and LCK_DENIED is the only such
 * status the procedures all have.
 */
static uint32_t
stat_for(uint32_t vers, uint32_t stat)
{

	if (vers == NLM_VERS4 || stat <= NLM4_DENIED_GRACE_PERIOD)
		return stat;
	return NLM4_DENIED;
}

bool
nlm_xdr_res(XDR *x, uint32_t vers, const void *cookie, uint32_t cookielen,
    uint32_t stat)
{

	stat = stat_for(vers, stat);
	return opaque_encode(x, cookie, cookielen) && U32(x, &stat);
}

bool
nlm_xdr_testres(XDR *x, uint32_t vers, const void *cookie, uint32_t cookielen,
    uint32_t stat, const struct nlm_xholder *h)
{
	uint32_t ex, off, len;

	if (!nlm_xdr_res(x, vers, cookie, cookielen, stat))
		return false;
	if (stat != NLM4_DENIED)
		return true;
	ex = h->xh_exclusive;
	if (!U32(x, &ex) || !I32(x, __UNCONST(&h->xh_svid)) ||
	    !opaque_encode(x, h->xh_oh, h->xh_ohlen))
		return false;
	if (vers == NLM_VERS4)
		return U64(x, __UNCONST(&h->xh_offset)) &&
		    U64(x, __UNCONST(&h->xh_len));
	/*
	 * A lock that a 32-bit client cannot name.  C702 says nothing; the
	 * nearest it can be told is to the end of what it can see.
	 */
	off = MIN(h->xh_offset, UINT32_MAX);
	len = h->xh_len > UINT32_MAX ? 0 : (uint32_t)h->xh_len;
	return U32(x, &off) && U32(x, &len);
}

/* C702 nlm_shareres: "sequence" is only there for compatibility. */
bool
nlm_xdr_shareres(XDR *x, uint32_t vers, const void *cookie, uint32_t cookielen,
    uint32_t stat)
{
	uint32_t seq = 0;

	return nlm_xdr_res(x, vers, cookie, cookielen, stat) && U32(x, &seq);
}

/* nlm_testargs as a client gets it in NLM_GRANTED */
bool
nlm_xdr_granted(XDR *x, uint32_t vers, const void *cookie, uint32_t cookielen,
    bool exclusive, const char *name, const void *fh, uint32_t fhlen,
    const void *oh, uint32_t ohlen, int32_t svid, uint64_t offset,
    uint64_t length)
{
	uint32_t ex = exclusive, off, len;

	if (!opaque_encode(x, cookie, cookielen) || !U32(x, &ex) ||
	    !opaque_encode(x, name, strlen(name)) ||
	    !opaque_encode(x, fh, fhlen) || !opaque_encode(x, oh, ohlen) ||
	    !I32(x, &svid))
		return false;
	if (vers == NLM_VERS4)
		return U64(x, &offset) && U64(x, &length);
	off = (uint32_t)offset;
	len = (uint32_t)length;
	return U32(x, &off) && U32(x, &len);
}

/* sm_name, C702 ch. 11 */
bool
nlm_xdr_name(XDR *x, const char *name)
{

	return opaque_encode(x, name, strlen(name));
}

/* my_id, C702 ch. 11: NLM on this host. */
static bool
nlm_xdr_myid(XDR *x)
{
	static const char me[] = "127.0.0.1";
	uint32_t prog = NLM_PROG, vers = NLM_VERS_SM, proc = NLM_SM_NOTIFY;

	return opaque_encode(x, me, sizeof(me) - 1) && U32(x, &prog) &&
	    U32(x, &vers) && U32(x, &proc);
}

/* mon_id */
bool
nlm_xdr_unmon(XDR *x, const char *name)
{

	return opaque_encode(x, name, strlen(name)) && nlm_xdr_myid(x);
}

/* struct mon */
bool
nlm_xdr_mon(XDR *x, const char *name, const uint8_t *priv)
{

	return nlm_xdr_unmon(x, name) &&
	    xdr_opaque(x, __UNCONST(priv), SM_PRIVLEN) != 0;
}

/*
 * The client's side of the same structures.  The arguments of the calls
 * here always carry a cookie of a few bytes, which it never looks at
 * again: C702 nlm_res says it need not come back the same.
 */
static bool
c_alock(XDR *x, const struct nlm_cargs *ca)
{
	uint32_t off, len;
	int32_t svid = ca->ca_svid;
	uint64_t off64 = ca->ca_offset, len64 = ca->ca_len;

	if (!opaque_encode(x, ca->ca_name, strlen(ca->ca_name)) ||
	    !opaque_encode(x, ca->ca_fh, ca->ca_fhlen) ||
	    !opaque_encode(x, ca->ca_oh, ca->ca_ohlen) || !I32(x, &svid))
		return false;
	if (ca->ca_vers == NLM_VERS4)
		return U64(x, &off64) && U64(x, &len64);
	off = (uint32_t)ca->ca_offset;
	len = (uint32_t)ca->ca_len;
	return U32(x, &off) && U32(x, &len);
}

static bool
c_cookie(XDR *x)
{
	uint32_t zero = 0;

	return U32(x, &zero);
}

bool_t
nlm_xdr_c_lock(XDR *x, const void *arg)
{
	const struct nlm_cargs *ca = arg;
	uint32_t block = ca->ca_block, ex = ca->ca_exclusive;
	uint32_t reclaim = ca->ca_reclaim, state = ca->ca_state;

	return c_cookie(x) && U32(x, &block) && U32(x, &ex) &&
	    c_alock(x, ca) && U32(x, &reclaim) && U32(x, &state);
}

bool_t
nlm_xdr_c_test(XDR *x, const void *arg)
{
	const struct nlm_cargs *ca = arg;
	uint32_t ex = ca->ca_exclusive;

	return c_cookie(x) && U32(x, &ex) && c_alock(x, ca);
}

bool_t
nlm_xdr_c_cancel(XDR *x, const void *arg)
{
	const struct nlm_cargs *ca = arg;
	uint32_t block = ca->ca_block, ex = ca->ca_exclusive;

	return c_cookie(x) && U32(x, &block) && U32(x, &ex) && c_alock(x, ca);
}

bool_t
nlm_xdr_c_unlock(XDR *x, const void *arg)
{
	const struct nlm_cargs *ca = arg;

	return c_cookie(x) && c_alock(x, ca);
}

static bool
c_skipobj(XDR *x)
{
	uint32_t len;

	return U32(x, &len) && len <= MAXNETOBJ_SZ &&
	    xdr_setpos(x, xdr_getpos(x) + RNDUP(len));
}

bool_t
nlm_xdr_c_res(XDR *x, const void *arg)
{
	struct nlm_cres *cr = __UNCONST(arg);

	return c_skipobj(x) && U32(x, &cr->cr_stat);
}

bool_t
nlm_xdr_c_testres(XDR *x, const void *arg)
{
	struct nlm_cres *cr = __UNCONST(arg);
	uint32_t ex, off, len;

	if (!nlm_xdr_c_res(x, arg))
		return false;
	if (cr->cr_stat != NLM4_DENIED)
		return true;
	if (!U32(x, &ex) || !I32(x, &cr->cr_svid) || !c_skipobj(x))
		return false;
	cr->cr_exclusive = ex != 0;
	if (cr->cr_vers == NLM_VERS4)
		return U64(x, &cr->cr_offset) && U64(x, &cr->cr_len);
	if (!U32(x, &off) || !U32(x, &len))
		return false;
	cr->cr_offset = off;
	cr->cr_len = len;
	return true;
}
