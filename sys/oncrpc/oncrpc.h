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

#ifndef _ONCRPC_ONCRPC_H_
#define _ONCRPC_ONCRPC_H_

/*
 * ONC RPC version 2 (RFC 5531), independent of any one program.
 *
 * The names keep the ONCRPC_ prefix because sys/nfs/rpcv2.h has the
 * RFC's own names as macros and is included outside sys/nfs.
 */

#include <sys/types.h>
#include <sys/kauth.h>

#include <oncrpc/oncrpc_xdr.h>

#define	ONCRPC_VERS		2	/* RFC 5531 s9, rpcvers */

/* RFC 5531 s9, enum msg_type */
#define	ONCRPC_CALL		0
#define	ONCRPC_REPLY		1

/* RFC 5531 s9, enum reply_stat */
#define	ONCRPC_MSG_ACCEPTED	0
#define	ONCRPC_MSG_DENIED	1

/* RFC 5531 s9, enum accept_stat */
#define	ONCRPC_SUCCESS		0
#define	ONCRPC_PROG_UNAVAIL	1
#define	ONCRPC_PROG_MISMATCH	2
#define	ONCRPC_PROC_UNAVAIL	3
#define	ONCRPC_GARBAGE_ARGS	4
#define	ONCRPC_SYSTEM_ERR	5

/* RFC 5531 s9, enum reject_stat */
#define	ONCRPC_RPC_MISMATCH	0
#define	ONCRPC_AUTH_ERROR	1

/* RFC 5531 s9, enum auth_stat; only those a server here can return */
#define	ONCRPC_AUTH_OK		0
#define	ONCRPC_AUTH_BADCRED	1
#define	ONCRPC_AUTH_REJECTEDCRED 2
#define	ONCRPC_AUTH_BADVERF	3

/* RFC 5531 s8.2, enum auth_flavor */
#define	ONCRPC_AUTH_NONE	0
#define	ONCRPC_AUTH_SYS		1

#define	ONCRPC_MAX_AUTH_BYTES	400	/* RFC 5531 s8.2, opaque body<400> */
#define	ONCRPC_MAX_MACHINENAME	255	/* RFC 5531 App. A, machinename<255> */
#define	ONCRPC_MAX_AUTHSYS_GIDS	16	/* RFC 5531 App. A, gids<16> */

/* RFC 5531 s11 */
#define	ONCRPC_RM_LAST		0x80000000U
#define	ONCRPC_RM_LENMASK	0x7fffffffU
#define	ONCRPC_RM_HDRSIZE	4

struct file;
struct mbuf;
struct socket;
struct oncrpc_svc;
struct oncrpc_req;
struct sockaddr;

/* One call, for oncrpc_clnt_call(). */
struct oncrpc_clnt_call {
	uint32_t	cc_prog;
	uint32_t	cc_vers;
	uint32_t	cc_proc;
	uint32_t	cc_flavor;	/* of the credential below */
	const void	*cc_cred;	/* the body of an opaque_auth */
	uint32_t	cc_credlen;
	bool		(*cc_encode)(XDR *, void *);
	void		*cc_arg;
	bool		(*cc_decode)(XDR *, void *);
	void		*cc_res;
};

/* What a program's dispatch wants done with the request. */
enum oncrpc_dispatch {
	ONCRPC_DONE,		/* send SUCCESS and what is in rq_res */
	ONCRPC_NOREPLY,		/* no reply, RFC 5531 s8.4.1 */
	ONCRPC_ERR_PROC,	/* PROC_UNAVAIL */
	ONCRPC_ERR_ARGS,	/* GARBAGE_ARGS */
	ONCRPC_ERR_SYSTEM,	/* SYSTEM_ERR */
	ONCRPC_RAWREPLY,	/* rq_raw is the whole message, to send as is */
	ONCRPC_DEFERRED		/* oncrpc_req_finish() will end the call */
};

/*
 * A program, for a range of versions.  One program may be registered
 * several times with ranges that do not overlap, which is how NFS
 * versions 2 and 3 can share a socket with version 4.
 */
struct oncrpc_program {
	uint32_t	op_prog;
	uint32_t	op_vers_low;
	uint32_t	op_vers_high;
	uint32_t	op_nprocs;	/* PROC_UNAVAIL at or above; 0 for none */
	enum oncrpc_dispatch
			(*op_dispatch)(struct oncrpc_req *);
	void		*op_arg;
};

/*
 * A call being served.  dispatch reads its arguments from rq_args, at
 * the first byte of them, and writes results to rq_res.  It may sleep.
 */
struct oncrpc_req {
	uint32_t	rq_xid;
	uint32_t	rq_prog;
	uint32_t	rq_vers;
	uint32_t	rq_proc;
	uint32_t	rq_flavor;
	uint32_t	rq_secflavor;	/* rq_flavor, or the pseudo flavor */
	kauth_cred_t	rq_cred;	/* NULL for AUTH_NONE */
	struct mbuf	*rq_nam;	/* peer, as MT_SONAME; may be NULL */
	uint64_t	rq_connid;	/* the connection; none is used twice */
	void		*rq_arg;	/* op_arg */
	XDR		*rq_args;
	XDR		*rq_res;
	struct mbuf	*rq_raw;	/* for ONCRPC_RAWREPLY */
};

int	oncrpc_svc_create(const char *, u_int, struct oncrpc_svc **);
void	oncrpc_svc_destroy(struct oncrpc_svc *);
int	oncrpc_svc_register(struct oncrpc_svc *, const struct oncrpc_program *);
void	oncrpc_svc_unregister(struct oncrpc_svc *,
	    const struct oncrpc_program *);
int	oncrpc_svc_addsock(struct oncrpc_svc *, struct file *, struct mbuf *);
u_int	oncrpc_svc_nxprt(struct oncrpc_svc *);
int	oncrpc_clnt_call_unix(const char *,
	    const struct oncrpc_clnt_call *, int);
int	oncrpc_clnt_call(const struct sockaddr *,
	    const struct oncrpc_clnt_call *, int);

/*
 * A server shared by name, so that programs that know nothing of each
 * other can answer on the same sockets.  The pool only ever grows to
 * the largest nworkers asked for, which may be 0 for a holder whose
 * threads come through oncrpc_svc_run().
 */
int	oncrpc_svc_hold(const char *, u_int, struct oncrpc_svc **);
void	oncrpc_svc_rele(struct oncrpc_svc *);
int	oncrpc_svc_run(struct oncrpc_svc *);
int	oncrpc_svc_addsock_tag(struct oncrpc_svc *, struct file *,
	    struct mbuf *, const void *);
void	oncrpc_svc_closesocks(struct oncrpc_svc *, const void *);
void	oncrpc_svc_closesocks_for(struct oncrpc_svc *, const void *,
	    const struct oncrpc_program *);

/* For a program that parses the mbufs of a call itself. */
void	oncrpc_req_takemsg(struct oncrpc_req *, struct mbuf **, struct mbuf **,
	    char **);
void	*oncrpc_req_ctx(struct oncrpc_req *, void *(*)(struct socket *),
	    void (*)(void *));
void	oncrpc_req_finish(struct oncrpc_req *, struct mbuf *);

#endif /* !_ONCRPC_ONCRPC_H_ */
