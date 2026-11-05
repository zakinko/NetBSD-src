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
 * The client side of the RPC layer, as little of it as a server needs
 * to call back: one call, on a connection of its own, on TCP, sleeping
 * in the calling thread until there is a reply or the time is up.
 * Nothing is resent, RFC 5531 s8 leaving reliability to the caller of
 * a stream transport, and a connection is not kept: calls of this kind
 * are rare, and a peer that has gone costs only the one call.
 *
 * The socket handling follows nfs_connect().
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/cprng.h>
#include <sys/errno.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/uio.h>

#include <netinet/in.h>

#include <oncrpc/oncrpc_var.h>

/* Not from the RFC: the largest reply taken, and the size of a call. */
#define	CLNT_MAXREPLY		(64 * 1024)
#define	CLNT_MAXCALL		(64 * 1024)
#define	CLNT_RCVALL		1000000000	/* as nfsrv_rcv() */

static int
clnt_connect(const struct sockaddr *to, struct socket **sop, time_t end)
{
	struct socket *so;
	int error;

	error = socreate(to->sa_family, &so, SOCK_STREAM, 0, curlwp, NULL);
	if (error != 0)
		return error;

	solock(so);
	error = soconnect(so, __UNCONST(to), curlwp);
	while (error == 0 && (so->so_state & SS_ISCONNECTING) != 0 &&
	    so->so_error == 0) {
		if (time_uptime >= end) {
			so->so_state &= ~SS_ISCONNECTING;
			error = ETIMEDOUT;
			break;
		}
		(void)sowait(so, false, hz);
	}
	if (error == 0 && so->so_error != 0) {
		error = so->so_error;
		so->so_error = 0;
	}
	if (error == 0) {
		so->so_rcv.sb_timeo = hz;
		so->so_snd.sb_timeo = hz;
	}
	sounlock(so);
	if (error != 0)
		soclose(so);
	else
		*sop = so;
	return error;
}

/* One record in one fragment, RFC 5531 s11, consuming m. */
static int
clnt_send(struct socket *so, struct mbuf *m)
{
	u_int len = m->m_pkthdr.len;
	uint32_t *rm;

	M_PREPEND(m, ONCRPC_RM_HDRSIZE, M_WAIT);
	rm = mtod(m, uint32_t *);
	*rm = htonl(ONCRPC_RM_LAST | len);
	return (*so->so_send)(so, NULL, NULL, m, NULL, 0, curlwp);
}

/* The next whole record, which is the caller's to free. */
static int
clnt_recv(struct socket *so, struct mbuf **recp, time_t end)
{
	struct oncrpc_rm rm;
	struct mbuf *m;
	struct uio auio;
	int error, flags;

	oncrpc_rm_init(&rm, CLNT_MAXREPLY);
	for (;;) {
		error = oncrpc_rm_next(&rm, recp);
		if (error != EAGAIN)
			break;
		if (time_uptime >= end) {
			error = ETIMEDOUT;
			break;
		}
		m = NULL;
		auio.uio_resid = CLNT_RCVALL;
		/* not need to setup uio_vmspace */
		flags = 0;
		error = (*so->so_receive)(so, NULL, &auio, &m, NULL, &flags);
		if (m != NULL)
			oncrpc_rm_input(&rm, m, CLNT_RCVALL - auio.uio_resid);
		else if (error == 0) {
			error = ECONNRESET;	/* end of the stream */
			break;
		} else if (error != EWOULDBLOCK) {
			break;
		}
	}
	oncrpc_rm_fini(&rm);
	return error;
}

/*
 * Call proc of (prog, vers) at to, within timeo seconds.  encode writes
 * the arguments and decode reads the results; either may be NULL for
 * none.  Returns an errno for the failure of the call, and EPROTO for
 * a reply saying that the call was refused.
 */
int
oncrpc_clnt_call(const struct sockaddr *to,
    const struct oncrpc_clnt_call *cc, int timeo)
{
	struct oncrpc_xdrmbuf ax, rx;
	struct socket *so = NULL;
	struct mbuf *m = NULL;
	uint32_t xid;
	time_t end;
	int error;

	end = time_uptime + timeo;
	xid = cprng_fast32();

	oncrpc_xdrmbuf_create(&ax, NULL, CLNT_MAXCALL, XDR_ENCODE);
	if (!oncrpc_msg_encode_call(&ax.xm_xdr, xid, cc) ||
	    (cc->cc_encode != NULL &&
	    !(*cc->cc_encode)(&ax.xm_xdr, cc->cc_arg))) {
		XDR_DESTROY(&ax.xm_xdr);
		return EMSGSIZE;
	}
	m = oncrpc_xdrmbuf_detach(&ax);

	error = clnt_connect(to, &so, end);
	if (error != 0) {
		m_freem(m);
		return error;
	}
	error = clnt_send(so, m);
	m = NULL;
	if (error == 0)
		error = clnt_recv(so, &m, end);
	if (error == 0) {
		oncrpc_xdrmbuf_create(&rx, m, 0, XDR_DECODE);
		error = oncrpc_msg_decode_reply(&rx.xm_xdr, xid);
		if (error == 0 && cc->cc_decode != NULL &&
		    !(*cc->cc_decode)(&rx.xm_xdr, cc->cc_res))
			error = EBADRPC;
		m_freem(m);
	}
	solock(so);
	soshutdown(so, SHUT_RDWR);
	sounlock(so);
	soclose(so);
	return error;
}
