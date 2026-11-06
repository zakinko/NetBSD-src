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

#ifndef _FS_NLM_NLM_VAR_H_
#define _FS_NLM_NLM_VAR_H_

/*
 * The Network Lock Manager, versions 1, 3 and 4, and what it asks of the
 * Network Status Monitor.  "C702" is Protocols for Interworking: XNFS,
 * Version 3W (The Open Group, 1998); version 4 is also RFC 1813 s6.
 *
 * Both 32-bit and 64-bit versions are held in the form of version 4, its
 * status included: a status with no equivalent in the earlier versions
 * is translated as the reply is encoded.
 */

#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/kauth.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <oncrpc/oncrpc.h>

#define	NLM_PROG	100021
#define	NLM_VERS_SM	0	/* NLM_SM_NOTIFY only; private to this host */
#define	NLM_VERS1	1
#define	NLM_VERS3	3
#define	NLM_VERS4	4

/* C702 ch. 10, NLM Procedures; RFC 1813 s6.2 for version 4 */
#define	NLM_NULL	0
#define	NLM_TEST	1
#define	NLM_LOCK	2
#define	NLM_CANCEL	3
#define	NLM_UNLOCK	4
#define	NLM_GRANTED	5
#define	NLM_TEST_MSG	6
#define	NLM_LOCK_MSG	7
#define	NLM_CANCEL_MSG	8
#define	NLM_UNLOCK_MSG	9
#define	NLM_GRANTED_MSG	10
#define	NLM_TEST_RES	11
#define	NLM_LOCK_RES	12
#define	NLM_CANCEL_RES	13
#define	NLM_UNLOCK_RES	14
#define	NLM_GRANTED_RES	15
#define	NLM_SHARE	20
#define	NLM_UNSHARE	21
#define	NLM_NM_LOCK	22
#define	NLM_FREE_ALL	23
#define	NLM_NPROCS	24

#define	NLM_SM_NOTIFY	1	/* version NLM_VERS_SM */

/* C702 ch. 10, Sizes of XDR Structures */
#define	LM_MAXSTRLEN	1024
#define	MAXNETOBJ_SZ	1024

/* RFC 1813 s6.1.3, nlm4_stats; 0 to 4 are C702 ch. 10, nlm_stats */
#define	NLM4_GRANTED		0
#define	NLM4_DENIED		1
#define	NLM4_DENIED_NOLOCKS	2
#define	NLM4_BLOCKED		3
#define	NLM4_DENIED_GRACE_PERIOD 4
#define	NLM4_DEADLCK		5
#define	NLM4_ROFS		6
#define	NLM4_STALE_FH		7
#define	NLM4_FBIG		8
#define	NLM4_FAILED		9

/* C702 ch. 10, fsh_mode and fsh_access */
#define	NLM_FSM_MAX	3
#define	NLM_FSA_MAX	3

/* C702 ch. 11 */
#define	SM_PROG		100024
#define	SM_VERS		1
#define	SM_STAT		1
#define	SM_MON		2
#define	SM_UNMON	3
#define	SM_MAXSTRLEN	1024
#define	SM_PRIVLEN	16
#define	SM_STAT_SUCC	0

/* C702 ch. 9, Grace period: "implementation-dependent", ch. 10: 45 common */
#define	NLM_GRACE_DEFAULT	45

/* The rest are this server's own limits on what a peer can make it hold. */
#define	NLM_MAXHOSTS	4096
#define	NLM_MAXWAITERS	256
#define	NLM_MAXRESCALLS	64

/* The lock and the share of the arguments, in one form. */
struct nlm_xlock {
	char		xl_name[LM_MAXSTRLEN + 1];
	uint32_t	xl_namelen;
	uint8_t		xl_fh[MAXNETOBJ_SZ];
	uint32_t	xl_fhlen;
	uint8_t		xl_oh[MAXNETOBJ_SZ];
	uint32_t	xl_ohlen;
	int32_t		xl_svid;
	uint64_t	xl_offset;
	uint64_t	xl_len;
	uint32_t	xl_mode;	/* shares */
	uint32_t	xl_access;
};

struct nlm_args {
	uint8_t		a_cookie[MAXNETOBJ_SZ];
	uint32_t	a_cookielen;
	bool		a_block;
	bool		a_exclusive;
	bool		a_reclaim;
	uint32_t	a_state;
	struct nlm_xlock a_lock;
};

/* nlm_holder */
struct nlm_xholder {
	bool		xh_exclusive;
	int32_t		xh_svid;
	const uint8_t	*xh_oh;
	uint32_t	xh_ohlen;
	uint64_t	xh_offset;
	uint64_t	xh_len;
};

/* Decoders; a false return is GARBAGE_ARGS. */
bool	nlm_xdr_testargs(XDR *, uint32_t, struct nlm_args *);
bool	nlm_xdr_lockargs(XDR *, uint32_t, struct nlm_args *);
bool	nlm_xdr_cancargs(XDR *, uint32_t, struct nlm_args *);
bool	nlm_xdr_unlockargs(XDR *, uint32_t, struct nlm_args *);
bool	nlm_xdr_shareargs(XDR *, struct nlm_args *);
bool	nlm_xdr_notify(XDR *, struct nlm_args *);
bool	nlm_xdr_status(XDR *, char *, uint32_t *, uint32_t *, uint8_t *);

/* Encoders */
bool	nlm_xdr_res(XDR *, uint32_t, const void *, uint32_t, uint32_t);
bool	nlm_xdr_testres(XDR *, uint32_t, const void *, uint32_t, uint32_t,
	    const struct nlm_xholder *);
bool	nlm_xdr_shareres(XDR *, uint32_t, const void *, uint32_t, uint32_t);
bool	nlm_xdr_granted(XDR *, uint32_t, const void *, uint32_t, bool,
	    const char *, const void *, uint32_t, const void *, uint32_t,
	    int32_t, uint64_t, uint64_t);

/* The client's calls */
struct nlm_cargs {
	const char	*ca_name;
	const void	*ca_fh;
	uint32_t	 ca_fhlen;
	const void	*ca_oh;
	uint32_t	 ca_ohlen;
	int32_t		 ca_svid;
	uint64_t	 ca_offset;
	uint64_t	 ca_len;
	bool		 ca_block;
	bool		 ca_exclusive;
	bool		 ca_reclaim;
	uint32_t	 ca_state;
	uint32_t	 ca_vers;
};
bool_t	nlm_xdr_c_lock(XDR *, const void *);
bool_t	nlm_xdr_c_test(XDR *, const void *);
bool_t	nlm_xdr_c_cancel(XDR *, const void *);
bool_t	nlm_xdr_c_unlock(XDR *, const void *);
struct nlm_cres {
	uint32_t	cr_stat;
	uint32_t	cr_vers;
	bool		cr_exclusive;
	int32_t		cr_svid;
	uint64_t	cr_offset;
	uint64_t	cr_len;
};
bool_t	nlm_xdr_c_res(XDR *, const void *);
bool_t	nlm_xdr_c_testres(XDR *, const void *);

/* NSM */
bool	nlm_xdr_mon(XDR *, const char *, const uint8_t *);
bool	nlm_xdr_unmon(XDR *, const char *);
bool	nlm_xdr_name(XDR *, const char *);

/* State, nlm_lock.c */
struct nlm_host;
struct vnode;

extern kmutex_t nlm_lock;
extern int nlm_monitor_required;
extern u_int nlm_nhosts, nlm_nowners, nlm_nholds, nlm_nwaiters, nlm_nshares;

void	nlm_state_init(void);
void	nlm_state_fini(void);
uint32_t nlm_do_lock(const struct nlm_args *, const struct sockaddr *,
	    struct vnode *, uint32_t, bool);
uint32_t nlm_do_cancel(const struct nlm_args *, const struct sockaddr *,
	    struct vnode *);
uint32_t nlm_do_unlock(const struct nlm_args *, const struct sockaddr *,
	    struct vnode *);
uint32_t nlm_do_test(const struct nlm_args *, const struct sockaddr *,
	    struct vnode *, struct nlm_xholder *, uint8_t *);
uint32_t nlm_do_share(const struct nlm_args *, const struct sockaddr *,
	    struct vnode *);
uint32_t nlm_do_unshare(const struct nlm_args *, const struct sockaddr *,
	    struct vnode *);
void	nlm_do_free_all(const char *, const struct sockaddr *);
void	nlm_do_notify(const uint8_t *, uint32_t);
bool	nlm_share_conflict(struct vnode *, uint32_t, uint32_t);
bool	nlm_owner_byid(const void *, struct nlm_xholder *, uint8_t *);
void	nlm_grants_run(void);
void	nlm_hosts_gc(void);

/* The client, nlm_client.c */
void	nlm_client_init(void);
void	nlm_client_fini(void);
int	nlm_client_enable(bool);
uint32_t nlm_client_granted(const struct nlm_args *, const struct sockaddr *);
void	nlm_client_notify(const uint8_t *);

/* Monitoring and calling back, nlm_nsm.c */
void	nlm_nsm_init(void);
void	nlm_nsm_fini(void);
void	nlm_nsm_kick(void);
void	nlm_nsm_start(void);
int	nlm_nsm_mon(const struct sockaddr *, uint32_t *);
void	nlm_nsm_unmon(const struct sockaddr *);
int	nlm_nsm_grant(const struct sockaddr *, uint32_t, const void *, uint32_t,
	    bool, const char *, const void *, uint32_t, const void *, uint32_t,
	    int32_t, uint64_t, uint64_t, uint32_t *);
void	nlm_nsm_res(const struct sockaddr *, uint32_t, uint32_t, void *, u_int);
void	nlm_nsm_priv(const struct sockaddr *, uint8_t *);
bool	nlm_addr_string(const struct sockaddr *, char *, size_t);

#endif /* !_FS_NLM_NLM_VAR_H_ */
