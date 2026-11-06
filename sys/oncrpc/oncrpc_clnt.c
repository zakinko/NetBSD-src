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
 * The client side of the RPC layer, as much of it as a server calling
 * back needs: one call at a time on a socket of its own.  A
 * caller here makes few calls, so nothing is kept between them, and the
 * reply is told by its xid alone.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/atomic.h>
#include <sys/errno.h>
#include <sys/cprng.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/uio.h>

#include <netinet/in.h>

#include <oncrpc/oncrpc_var.h>

#define	ONCRPC_CLNT_MAXMSG	8192	/* of a call; not from the RFC */
#define	ONCRPC_RCVALL		1000000000	/* as in oncrpc_svc.c */

#define	CLNT_NOTOURS	(-1)

#define	PMAP_PROG	100000		/* RFC 1833 s3, port mapper */
#define	PMAP_VERS	2
#define	PMAP_PORT	111
#define	PMAP_GETPORT	3
#define	RPCB_VERS	4
#define	RPCB_GETADDR	3

/*
 * The call, up to the arguments: RFC 5531 s9, with AUTH_SYS as cred, or
 * as root with none, and at most gids<16> of it, App. A.
 */
static bool
clnt_encode_head(XDR *x, uint32_t xid, uint32_t prog, uint32_t vers,
    uint32_t proc, kauth_cred_t cred)
{
	gid_t gids[ONCRPC_MAX_AUTHSYS_GIDS];
	uint32_t zero = 0, two = ONCRPC_VERS, mtype = ONCRPC_CALL;
	uint32_t sys = ONCRPC_AUTH_SYS, bodylen, uid = 0, gid = 0, ngids = 0, g;
	u_int i;

	if (cred != NULL) {
		uid = kauth_cred_geteuid(cred);
		gid = kauth_cred_getegid(cred);
		ngids = MIN(kauth_cred_ngroups(cred), __arraycount(gids));
		for (i = 0; i < ngids; i++)
			gids[i] = kauth_cred_group(cred, i);
	}
	bodylen = (5 + ngids) * BYTES_PER_XDR_UNIT;

	if (!(xdr_u_int32_t(x, &xid) && xdr_u_int32_t(x, &mtype) &&
	    xdr_u_int32_t(x, &two) && xdr_u_int32_t(x, &prog) &&
	    xdr_u_int32_t(x, &vers) && xdr_u_int32_t(x, &proc) &&
	    /* App. A, authsys_parms: stamp, "", uid, gid, gids */
	    xdr_u_int32_t(x, &sys) && xdr_u_int32_t(x, &bodylen) &&
	    xdr_u_int32_t(x, &zero) && xdr_u_int32_t(x, &zero) &&
	    xdr_u_int32_t(x, &uid) && xdr_u_int32_t(x, &gid) &&
	    xdr_u_int32_t(x, &ngids)))
		return false;
	for (i = 0; i < ngids; i++) {
		g = gids[i];
		if (!xdr_u_int32_t(x, &g))
			return false;
	}
	/* verifier, AUTH_NONE */
	return xdr_u_int32_t(x, &zero) && xdr_u_int32_t(x, &zero);
}

/*
 * The reply to xid.  CLNT_NOTOURS says it is not one, and to keep waiting;
 * no errno will do, as EAGAIN is what a timed out receive returns.
 */
static int
clnt_decode_reply(struct mbuf *m, uint32_t want, xdrproc_t xres, void *res)
{
	struct oncrpc_xdrmbuf xm;
	XDR *x = &xm.xm_xdr;
	uint32_t xid, mtype, rstat, flavor, len, stat;

	oncrpc_xdrmbuf_create(&xm, m, 0, XDR_DECODE);
	if (!xdr_u_int32_t(x, &xid) || !xdr_u_int32_t(x, &mtype) ||
	    xid != want || mtype != ONCRPC_REPLY)
		return CLNT_NOTOURS;
	if (!xdr_u_int32_t(x, &rstat) || rstat != ONCRPC_MSG_ACCEPTED)
		return EPROTO;
	if (!xdr_u_int32_t(x, &flavor) || !xdr_u_int32_t(x, &len) ||
	    len > ONCRPC_MAX_AUTH_BYTES ||
	    !xdr_setpos(x, xdr_getpos(x) + RNDUP(len)))
		return EPROTO;
	if (!xdr_u_int32_t(x, &stat) || stat != ONCRPC_SUCCESS)
		return EPROTO;
	if (xres != NULL && !(*xres)(x, res))
		return EPROTO;
	return 0;
}

static int
clnt_socket(int family, int type, struct socket **sop)
{
	struct socket *so;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	int error, val;

	error = socreate(family, &so, type, 0, curlwp, NULL);
	if (error != 0)
		return error;
	/* As nfs_connect() does. */
	if (family == AF_INET6) {
		val = IPV6_PORTRANGE_LOW;
		error = so_setsockopt(NULL, so, IPPROTO_IPV6, IPV6_PORTRANGE,
		    &val, sizeof(val));
		if (error == 0) {
			memset(&sin6, 0, sizeof(sin6));
			sin6.sin6_len = sizeof(sin6);
			sin6.sin6_family = AF_INET6;
			error = sobind(so, (struct sockaddr *)&sin6, &lwp0);
		}
	} else {
		val = IP_PORTRANGE_LOW;
		error = so_setsockopt(NULL, so, IPPROTO_IP, IP_PORTRANGE,
		    &val, sizeof(val));
		if (error == 0) {
			memset(&sin, 0, sizeof(sin));
			sin.sin_len = sizeof(sin);
			sin.sin_family = AF_INET;
			error = sobind(so, (struct sockaddr *)&sin, &lwp0);
		}
	}
	if (error != 0) {
		soclose(so);
		return error;
	}
	*sop = so;
	return 0;
}

int
oncrpc_clnt_call(const struct sockaddr *to, uint32_t prog, uint32_t vers,
    uint32_t proc, xdrproc_t xargs, void *args, xdrproc_t xres, void *res,
    u_int tries, u_int timo, kauth_cred_t cred)
{
	struct oncrpc_xdrmbuf xm;
	struct socket *so;
	struct mbuf *call, *m, *nam;
	struct timeval tv;
	struct uio auio;
	uint32_t xid;
	int error, flags;
	u_int i;

	error = clnt_socket(to->sa_family, SOCK_DGRAM, &so);
	if (error != 0)
		return error;

	xid = cprng_fast32();
	oncrpc_xdrmbuf_create(&xm, NULL, ONCRPC_CLNT_MAXMSG, XDR_ENCODE);
	if (!clnt_encode_head(&xm.xm_xdr, xid, prog, vers, proc, cred) ||
	    (xargs != NULL && !(*xargs)(&xm.xm_xdr, args))) {
		XDR_DESTROY(&xm.xm_xdr);
		soclose(so);
		return EMSGSIZE;
	}
	call = oncrpc_xdrmbuf_detach(&xm);

	if (tries == 0) {
		error = (*so->so_send)(so, __UNCONST(to), NULL, call, NULL, 0,
		    curlwp);
		soclose(so);
		return error;
	}

	tv.tv_sec = timo;
	tv.tv_usec = 0;
	error = so_setsockopt(NULL, so, SOL_SOCKET, SO_RCVTIMEO, &tv,
	    sizeof(tv));
	if (error != 0)
		goto out;

	error = ETIMEDOUT;
	for (i = 0; i < tries; i++) {
		m = m_copypacket(call, M_WAIT);
		error = (*so->so_send)(so, __UNCONST(to), NULL, m, NULL, 0,
		    curlwp);
		if (error != 0)
			break;
		do {
			m = nam = NULL;
			auio.uio_resid = ONCRPC_RCVALL;
			/* not need to setup uio_vmspace */
			flags = 0;
			error = (*so->so_receive)(so, &nam, &auio, &m, NULL,
			    &flags);
			m_freem(nam);
			if (m != NULL) {
				error = clnt_decode_reply(m, xid, xres, res);
				m_freem(m);
			} else if (error == 0)
				error = EWOULDBLOCK;
		} while (error == CLNT_NOTOURS);
		if (error != EWOULDBLOCK)
			break;
		error = ETIMEDOUT;
	}
out:
	m_freem(call);
	soclose(so);
	return error;
}

/*
 * The same over TCP, RFC 5531 s11, for a host that UDP does not reach.
 * timo is for connecting and again for the reply.
 */
int
oncrpc_clnt_call_tcp(const struct sockaddr *to, uint32_t prog, uint32_t vers,
    uint32_t proc, xdrproc_t xargs, void *args, xdrproc_t xres, void *res,
    u_int timo, kauth_cred_t cred)
{
	struct oncrpc_xdrmbuf xm;
	struct oncrpc_rm rm;
	struct socket *so;
	struct mbuf *m, *nam;
	struct timeval tv;
	struct uio auio;
	uint32_t xid, *hdr, len;
	u_int cc, waited;
	int error, flags;

	error = clnt_socket(to->sa_family, SOCK_STREAM, &so);
	if (error != 0)
		return error;

	solock(so);
	error = soconnect(so, __UNCONST(to), curlwp);
	for (waited = 0; error == 0 && (so->so_state & SS_ISCONNECTING) != 0 &&
	    so->so_error == 0 && waited < timo; waited++)
		(void)sowait(so, false, hz);
	if (error == 0) {
		if (so->so_error != 0)
			error = so->so_error;
		else if ((so->so_state & SS_ISCONNECTED) == 0)
			error = ETIMEDOUT;
	}
	sounlock(so);
	if (error != 0) {
		soclose(so);
		return error;
	}

	xid = cprng_fast32();
	oncrpc_xdrmbuf_create(&xm, NULL, ONCRPC_CLNT_MAXMSG, XDR_ENCODE);
	if (!clnt_encode_head(&xm.xm_xdr, xid, prog, vers, proc, cred) ||
	    (xargs != NULL && !(*xargs)(&xm.xm_xdr, args))) {
		XDR_DESTROY(&xm.xm_xdr);
		soclose(so);
		return EMSGSIZE;
	}
	m = oncrpc_xdrmbuf_detach(&xm);
	len = m->m_pkthdr.len;
	M_PREPEND(m, ONCRPC_RM_HDRSIZE, M_WAIT);
	hdr = mtod(m, uint32_t *);
	*hdr = htonl(ONCRPC_RM_LAST | len);
	error = (*so->so_send)(so, NULL, NULL, m, NULL, 0, curlwp);
	if (error != 0) {
		soclose(so);
		return error;
	}

	tv.tv_sec = timo;
	tv.tv_usec = 0;
	error = so_setsockopt(NULL, so, SOL_SOCKET, SO_RCVTIMEO, &tv,
	    sizeof(tv));
	oncrpc_rm_init(&rm, ONCRPC_CLNT_MAXMSG);
	while (error == 0) {
		error = oncrpc_rm_next(&rm, &m);
		if (error == 0) {
			error = clnt_decode_reply(m, xid, xres, res);
			m_freem(m);
			if (error == CLNT_NOTOURS) {
				error = 0;
				continue;
			}
			break;
		}
		if (error != EAGAIN)
			break;
		m = nam = NULL;
		auio.uio_resid = ONCRPC_RCVALL;
		/* not need to setup uio_vmspace */
		flags = 0;
		error = (*so->so_receive)(so, &nam, &auio, &m, NULL, &flags);
		m_freem(nam);
		if (m == NULL) {
			error = error == EWOULDBLOCK ? ETIMEDOUT :
			    (error != 0 ? error : ECONNRESET);
			break;
		}
		cc = ONCRPC_RCVALL - auio.uio_resid;
		oncrpc_rm_input(&rm, m, cc);
		error = 0;
	}
	oncrpc_rm_fini(&rm);
	soclose(so);
	return error;
}

static bool_t
xdr_pmap_map(XDR *x, const void *arg)
{
	uint32_t *map = __UNCONST(arg);
	int i;

	for (i = 0; i < 4; i++)
		if (!xdr_u_int32_t(x, &map[i]))
			return FALSE;
	return TRUE;
}

static bool_t
xdr_pmap_port(XDR *x, const void *arg)
{

	return xdr_u_int32_t(x, __UNCONST(arg));
}

struct rpcb_args {
	uint32_t	 ra_prog;
	uint32_t	 ra_vers;
	const char	*ra_netid;
};

/* rpcb, RFC 1833 s2.2, with an empty r_addr and r_owner. */
static bool_t
xdr_rpcb(XDR *x, const void *arg)
{
	const struct rpcb_args *ra = arg;
	uint32_t prog = ra->ra_prog, vers = ra->ra_vers, zero = 0;
	uint32_t len = strlen(ra->ra_netid);

	return xdr_u_int32_t(x, &prog) && xdr_u_int32_t(x, &vers) &&
	    xdr_u_int32_t(x, &len) &&
	    xdr_opaque(x, __UNCONST(ra->ra_netid), len) &&
	    xdr_u_int32_t(x, &zero) && xdr_u_int32_t(x, &zero);
}

#define	RPCB_UADDRMAX	80	/* longer than any IPv6 universal address */

static bool_t
xdr_rpcb_res(XDR *x, const void *arg)
{
	char *uaddr = __UNCONST(arg);
	uint32_t len;

	if (!xdr_u_int32_t(x, &len) || len >= RPCB_UADDRMAX)
		return FALSE;
	if (len != 0 && !xdr_opaque(x, uaddr, len))
		return FALSE;
	uaddr[len] = '\0';
	return TRUE;
}

/* The port of a universal address, RFC 5665 s5.2.3.3: h.h.h.h.p1.p2 */
static int
rpcb_uaddr_port(const char *uaddr, uint16_t *portp)
{
	const char *lo, *hi;
	unsigned long p1, p2;

	lo = strrchr(uaddr, '.');
	if (lo == NULL || lo == uaddr)
		return ENOENT;
	for (hi = lo - 1; hi > uaddr && *hi != '.'; hi--)
		continue;
	if (*hi != '.')
		return ENOENT;
	p1 = strtoul(hi + 1, NULL, 10);
	p2 = strtoul(lo + 1, NULL, 10);
	if (p1 > 255 || p2 > 255 || (p1 == 0 && p2 == 0))
		return ENOENT;
	*portp = p1 << 8 | p2;
	return 0;
}

/*
 * The port of a program on a host.  Version 2 of the port mapper is for
 * IPv4, RFC 1833 s3.2; for IPv6 it takes GETADDR of version 4, s2.2.
 */
int
oncrpc_clnt_getport(const struct sockaddr *to, uint32_t prog, uint32_t vers,
    int proto, uint16_t *portp)
{
	struct sockaddr_storage ss;
	char uaddr[RPCB_UADDRMAX];
	struct rpcb_args ra;
	uint32_t map[4], port;
	int error;

	memcpy(&ss, to, to->sa_len);
	/* The port is at the same place in both families. */
	((struct sockaddr_in *)&ss)->sin_port = htons(PMAP_PORT);
	if (to->sa_family == AF_INET6) {
		ra.ra_prog = prog;
		ra.ra_vers = vers;
		ra.ra_netid = proto == IPPROTO_TCP ? "tcp6" : "udp6";
		error = oncrpc_clnt_call((struct sockaddr *)&ss, PMAP_PROG,
		    RPCB_VERS, RPCB_GETADDR, xdr_rpcb, &ra, xdr_rpcb_res,
		    uaddr, 2, 2, NULL);
		return error != 0 ? error : rpcb_uaddr_port(uaddr, portp);
	}
	map[0] = prog;
	map[1] = vers;
	map[2] = proto;
	map[3] = 0;
	port = 0;
	error = oncrpc_clnt_call((struct sockaddr *)&ss, PMAP_PROG, PMAP_VERS,
	    PMAP_GETPORT, xdr_pmap_map, map, xdr_pmap_port, &port,
	    2, 2, NULL);
	if (error != 0)
		return error;
	if (port == 0 || port > 65535)
		return ENOENT;
	*portp = port;
	return 0;
}

static oncrpc_share_fn oncrpc_share_fns[ONCRPC_SHARE_NSLOTS];

/* A server of share reservations says how to ask it, or takes that back. */
void
oncrpc_share_register(u_int slot, oncrpc_share_fn fn)
{

	atomic_store_release(&oncrpc_share_fns[slot], fn);
}

/* Does any other server hold something against this? */
bool
oncrpc_share_conflict(u_int self, struct vnode *vp, uint32_t access,
    uint32_t deny)
{
	oncrpc_share_fn fn;
	u_int i;

	for (i = 0; i < ONCRPC_SHARE_NSLOTS; i++) {
		if (i == self)
			continue;
		fn = atomic_load_acquire(&oncrpc_share_fns[i]);
		if (fn != NULL && (*fn)(vp, access, deny))
			return true;
	}
	return false;
}

static volatile time_t oncrpc_grace_end;

void
oncrpc_grace_start(u_int secs)
{

	oncrpc_grace_end = time_uptime + secs;
}

bool
oncrpc_grace_active(void)
{

	return time_uptime < oncrpc_grace_end;
}
