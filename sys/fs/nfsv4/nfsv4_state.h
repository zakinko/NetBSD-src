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

#ifndef _FS_NFSV4_NFSV4_STATE_H_
#define _FS_NFSV4_NFSV4_STATE_H_

/*
 * Client, owner and open and lock state, RFC 7530 s9.
 *
 * nfsv4_state_lock covers all of it.  It is never held across a VOP or
 * an allocation that sleeps, and it is taken outside vnode locks.  What
 * must hold still across a VOP is held by marking the owner busy:
 * RFC 7530 s9.1.7 allows an owner one request at a time, so this only
 * enforces what a client must do anyway, and a state or owner is not
 * freed while an owner it belongs to is busy.  Taken together, an open
 * owner is made busy before a lock owner.
 */

#include <sys/condvar.h>
#include <sys/mutex.h>
#include <sys/queue.h>

struct nfsv4_owner_s;
struct nfsv4_state;
struct vnode;

/* What is known of a client's callback path, s10.2. */
#define	NFSV4_CB_UNKNOWN	0
#define	NFSV4_CB_UP		1
#define	NFSV4_CB_DOWN		2

/* RFC 7530 s16.33.5, a record { v, x, c, k, s } */
struct nfsv4_client {
	LIST_ENTRY(nfsv4_client) cl_list;
	TAILQ_ENTRY(nfsv4_client) cl_cbq;	/* to be probed */
	LIST_HEAD(, nfsv4_owner_s) cl_owners;
	uint64_t	cl_id;		/* c */
	struct nfsv4_verifier cl_verf;	/* v */
	struct nfsv4_verifier cl_confirm; /* s */
	struct nfsv4_clientaddr cl_cb;	/* k, and cl_cbprog, cl_cbident */
	uint32_t	cl_cbprog;
	uint32_t	cl_cbident;
	uid_t		cl_uid;		/* the principal */
	gid_t		cl_gid;		/* and for callbacks, s3.3.3 */
	uint32_t	cl_flavor;
	uint64_t	cl_connid;	/* last connection known to be its */
	u_int		cl_cbstate;
	uint32_t	cl_cbgen;	/* of cl_cb, for a call that returns */
	bool		cl_cbqueued;	/* on cl_cbq */
	time_t		cl_cbnext;	/* time to probe a dead path again */
	time_t		cl_prevend;	/* end of s10.2.1's reclaims, or 0 */
	bool		cl_purged;	/* DELEGPURGE was done */
	bool		cl_stable;	/* stable storage has it */
	bool		cl_revoked;	/* and must hear of a revocation */
	bool		cl_confirmed;
	bool		cl_expired;	/* state gone; stateids still known */
	time_t		cl_expire;	/* lease, in time_uptime */
	uint32_t	cl_idlen;	/* x */
	uint8_t		cl_idstr[NFS4_OPAQUE_LIMIT];
};

#define	NFSV4_OWNER_OPEN	1
#define	NFSV4_OWNER_LOCK	2
#define	NFSV4_OWNER_DELEG	3	/* the client's delegations */

/* An open-owner or lock-owner, RFC 7530 s9.1.1. */
struct nfsv4_owner_s {
	LIST_ENTRY(nfsv4_owner_s) sw_list;
	LIST_HEAD(, nfsv4_state) sw_states;
	struct nfsv4_client *sw_client;
	u_int		sw_type;
	bool		sw_busy;
	u_int		sw_waiters;
	bool		sw_confirmed;	/* open-owner, s9.1.11 */
	uint32_t	sw_seqid;	/* L, s9.1.7 */
	uint32_t	sw_lastop;	/* of the reply below */
	uint32_t	sw_laststat;
	u_int		sw_rlen;
	char		*sw_rbuf;
	struct nfsv4_fh	sw_rfh;		/* the file, to replay an OPEN */
	struct nfsv4_state *sw_closed;	/* last CLOSE, s9.10.1 */
	uint32_t	sw_len;
	uint8_t		sw_data[NFS4_OPAQUE_LIMIT];
};

/* All the state on one vnode. */
struct nfsv4_file {
	LIST_ENTRY(nfsv4_file) f_list;
	LIST_HEAD(, nfsv4_state) f_states;
	struct vnode	*f_vp;		/* a reference */
	struct nfsv4_fh	f_fh;		/* unless f_isattr, of an open file */
	bool		f_isattr;	/* opens of a named attribute */
	char		f_aname[NFSV4_ANAME_MAX + 1];
};

#define	NFSV4_ST_OPEN		1
#define	NFSV4_ST_LOCK		2
#define	NFSV4_ST_DELEG		3

struct nfsv4_state {
	LIST_ENTRY(nfsv4_state) st_hash;
	LIST_ENTRY(nfsv4_state) st_olist;	/* on the owner */
	LIST_ENTRY(nfsv4_state) st_flist;	/* on the file */
	LIST_ENTRY(nfsv4_state) st_plist;	/* lock, on its open */
	LIST_HEAD(, nfsv4_state) st_locks;	/* open */
	SLIST_ENTRY(nfsv4_state) st_reap;
	uint64_t	st_other;	/* stateid "other", with nfsv4_boot */
	uint32_t	st_seqid;
	u_int		st_type;
	struct nfsv4_owner_s *st_owner;
	struct nfsv4_file *st_file;	/* NULL once released */
	struct nfsv4_state *st_open;	/* lock, the open it came under */
	uint32_t	st_access;	/* open */
	uint32_t	st_deny;
	uint32_t	st_accbits;	/* each access ever opened with */
	uint32_t	st_denybits;
	bool		st_asked;	/* lock, by lock_owner_held() */
	struct vnode	*st_reapvp;	/* a reference, while reaping */
	bool		st_free;	/* reaping ends it */
	bool		st_closed;	/* kept for a resent CLOSE */
	/* delegation */
	TAILQ_ENTRY(nfsv4_state) st_cbq;	/* to be called back */
	LIST_ENTRY(nfsv4_state) st_rlist;	/* recalled */
	uint32_t	st_dtype;	/* OPEN_DELEGATE_* */
	bool		st_cbqueued;	/* on st_cbq */
	bool		st_recalled;	/* on st_rlist */
	bool		st_prev;	/* of a client now restarted, s10.2.1 */
	time_t		st_recall_end;	/* when it is revoked */
	time_t		st_cbnext;	/* when to call again, if not 0 */
};

SLIST_HEAD(nfsv4_reap, nfsv4_state);

/* Allocated beforehand for a delegation that may come of an OPEN. */
struct nfsv4_deleg_spare {
	struct nfsv4_state *ds_st;
	struct nfsv4_owner_s *ds_sw;
	struct nfsv4_file *ds_f;
};

/* nfsv4_deleg_conflict() */
#define	NFSV4_DC_READ		1
#define	NFSV4_DC_WRITE		2

extern kmutex_t nfsv4_state_lock;
extern kcondvar_t nfsv4_state_cv;
extern uint32_t nfsv4_boot;

/* What to do with a request after looking at its seqid, s9.1.7. */
enum nfsv4_seq {
	NFSV4_SEQ_GO,
	NFSV4_SEQ_REPLAY,
	NFSV4_SEQ_BAD
};

void	nfsv4_state_init(void);
void	nfsv4_state_fini(void);
void	nfsv4_cb_init(void);
void	nfsv4_cb_fini(void);
void	nfsv4_deleg_init(void);
void	nfsv4_stable_init(void);
void	nfsv4_stable_fini(void);
void	nfsv4_grace_scan(void);
int	nfsv4_stable_open(const char *);
void	nfsv4_stable_good(const uint8_t *, uint32_t);
void	nfsv4_stable_gone(const uint8_t *, uint32_t);
bool	nfsv4_grace_active(void);
uint32_t nfsv4_reclaim_check(const struct nfsv4_client *);

/* These want nfsv4_state_lock held. */
uint32_t nfsv4_client_get(uint64_t, struct nfsv4_client **);
struct nfsv4_owner_s *
	nfsv4_owner_find(struct nfsv4_client *, u_int, const uint8_t *,
	    uint32_t);
struct nfsv4_owner_s *
	nfsv4_owner_add(struct nfsv4_client *, struct nfsv4_owner_s **, u_int,
	    const uint8_t *, uint32_t);
void	nfsv4_owner_busy(struct nfsv4_owner_s *);
void	nfsv4_owner_idle(struct nfsv4_owner_s *);
struct nfsv4_owner_s *
	nfsv4_owner_byid(const void *);
enum nfsv4_seq
	nfsv4_seq_check(const struct nfsv4_owner_s *, uint32_t, uint32_t);
struct nfsv4_state *
	nfsv4_state_add(struct nfsv4_state **, struct nfsv4_owner_s *,
	    struct nfsv4_file **, struct vnode *, u_int);
struct nfsv4_state *
	nfsv4_state_add_attr(struct nfsv4_state **, struct nfsv4_owner_s *,
	    struct nfsv4_file **, struct vnode *, u_int, const char *);
void	nfsv4_state_unlink(struct nfsv4_state *, struct nfsv4_reap *, bool);
void	nfsv4_owner_free(struct nfsv4_owner_s *, struct nfsv4_reap *);
uint32_t nfsv4_stateid_lookup(const struct nfsv4_stateid *,
	    struct nfsv4_state **);
uint32_t nfsv4_stateid_check(const struct nfsv4_stateid *,
	    const struct nfsv4_state *, struct vnode *, u_int);
bool	nfsv4_stateid_special(const struct nfsv4_stateid *);
void	nfsv4_stateid_out(const struct nfsv4_state *, struct nfsv4_stateid *);
struct nfsv4_file *
	nfsv4_file_find(struct vnode *);
struct nfsv4_file *
	nfsv4_file_find_attr(struct vnode *, const char *);
struct nfsv4_client *
	nfsv4_client_byid(uint64_t);
void	nfsv4_client_renew(struct nfsv4_client *);
struct nfsv4_state *
	nfsv4_state_byother(uint64_t);
void	nfsv4_cb_probe(struct nfsv4_client *);
void	nfsv4_cb_reset(struct nfsv4_client *);
void	nfsv4_cb_recall(struct nfsv4_state *);
void	nfsv4_cb_forget_client(struct nfsv4_client *);
void	nfsv4_cb_forget_state(struct nfsv4_state *);
uint32_t nfsv4_deleg_conflict(struct vnode *, const struct nfsv4_client *,
	    uint64_t, u_int);
void	nfsv4_deleg_offer(struct nfsv4_owner_s *, struct vnode *,
	    const struct nfsv4_fh *, uint32_t, struct nfsv4_deleg_spare *,
	    struct nfsv4_open_deleg *);
void	nfsv4_deleg_add(struct nfsv4_client *, struct vnode *,
	    const struct nfsv4_fh *, uint32_t, struct nfsv4_deleg_spare *,
	    struct nfsv4_open_deleg *);
void	nfsv4_deleg_gone(struct nfsv4_state *);
uint32_t nfsv4_deleg_claim_cur(struct nfsv4_client *,
	    const struct nfsv4_stateid *, struct vnode *);
uint32_t nfsv4_deleg_claim_prev(struct nfsv4_client *, struct vnode *,
	    struct nfsv4_open_deleg *);
void	nfsv4_deleg_carry(struct nfsv4_client *, struct nfsv4_client *,
	    struct nfsv4_owner_s **);
void	nfsv4_deleg_drop_prev(struct nfsv4_client *, struct nfsv4_reap *);
void	nfsv4_deleg_scan(struct nfsv4_reap *);
bool	nfsv4_deleg_path_down(struct nfsv4_client *);

/* These do not. */
struct vnode *nfsv4_file_vp_byfh(const struct nfsv4_fh *);
uint32_t nfsv4_seq_stateid(const struct nfsv4_stateid *, uint32_t, uint32_t,
	    struct nfsv4_state **, enum nfsv4_seq *);
uint32_t nfsv4_seq_reply(struct nfsv4_compound *, struct nfsv4_owner_s *,
	    uint32_t, uint32_t, uint32_t, u_int);
uint32_t nfsv4_seq_replay(struct nfsv4_compound *, struct nfsv4_owner_s *,
	    bool);
void	nfsv4_seq_cancel(struct nfsv4_owner_s *);
void	nfsv4_reap_finish(struct nfsv4_reap *);
void	nfsv4_owner_replay_save(struct nfsv4_owner_s *, uint32_t, uint32_t,
	    uint32_t, const char *, u_int);
uint32_t nfsv4_deleg_break(struct vnode *, const struct nfsv4_client *,
	    uint64_t, u_int);
uint32_t nfsv4_deleg_break_name(const struct nfsv4_cfh *, const char *);

#endif /* !_FS_NFSV4_NFSV4_STATE_H_ */
