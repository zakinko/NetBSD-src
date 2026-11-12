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
 * Client, owner and open and lock state, RFC 7530 s9, and the sessions of
 * RFC 8881 s2.10.
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

struct flock;
struct nfsv4_owner_s;
struct nfsv4_state;
struct vnode;

/* What is known of a client's callback path, s10.2. */
#define	NFSV4_CB_UNKNOWN	0
#define	NFSV4_CB_UP		1
#define	NFSV4_CB_DOWN		2

/*
 * How many connections a session remembers, a choice: the oldest goes
 * first, and nothing tells a session that one has closed.  A connection
 * forgotten that way is bound again by its next SEQUENCE, s2.10.3.1.
 */
#define	NFSV4_SES_CONNS		8

struct nfsv4_sesconn {
	uint64_t	sc_id;
	uint32_t	sc_dir;		/* CDFS4_* */
};

/* s2.10.6.1.  sl_seq is what the last request carried. */
struct nfsv4_slot {
	uint32_t	sl_seq;
	bool		sl_used;	/* no request yet: nothing to retry */
	bool		sl_busy;	/* that request is still running */
	uint32_t	sl_sum;		/* c_argsum of that request */
	uid_t		sl_uid;		/* whose it was, s2.10.6.1.3.1 */
	char		*sl_reply;	/* its whole reply, if kept */
	u_int		sl_len;
};

/* s2.10.  se_refs is one for the table and one for each COMPOUND on it. */
struct nfsv4_session {
	LIST_ENTRY(nfsv4_session) se_hash;
	LIST_ENTRY(nfsv4_session) se_list;	/* on the client */
	struct nfsv4_client *se_client;
	struct nfsv4_sessionid se_id;
	u_int		se_refs;
	bool		se_gone;	/* out of the table */
	uint32_t	se_maxreq;
	uint32_t	se_maxresp;
	uint32_t	se_maxcached;
	uint32_t	se_maxops;
	uint32_t	se_nslots;
	uint32_t	se_cbprog;
	struct nfsv4_cbsec se_cbsec;
	uint32_t	se_cbvers;	/* RPC version of calls on it */
	uint32_t	se_cbseq;	/* of the one slot of the backchannel */
	bool		se_cbbusy;	/* a call is out on it */
	size_t		se_cost;	/* of the reply cache budget */
	size_t		se_size;
	u_int		se_nconn;
	struct nfsv4_sesconn se_conns[NFSV4_SES_CONNS];
	struct nfsv4_slot se_slots[];
};

/* What the replay of a CREATE_SESSION needs, s18.36.4. */
#define	NFSV4_CSREPLY_MAX	128

/*
 * RFC 8881 s18.40.3: the device ID notifications asked of one device ID,
 * as bits 1 << NOTIFY_DEVICEID4_*.  Two layout types, each with a device
 * and one retired, nfsv4_layout.c.
 */
struct nfsv4_devnote {
	uint32_t	dn_type;	/* LAYOUT4_* */
	uint32_t	dn_gen;		/* of the device ID */
	uint32_t	dn_mask;	/* 0 for a free one */
};
#define	NFSV4_DEVNOTES	(2 * 2)

/*
 * RFC 7530 s16.33.5, a record { v, x, c, k, s }, or the 5-tuple of
 * RFC 8881 s18.35.4 if cl_minor is not 0.  The two never match each
 * other by name.
 */
struct nfsv4_client {
	LIST_ENTRY(nfsv4_client) cl_list;
	TAILQ_ENTRY(nfsv4_client) cl_cbq;	/* to be probed */
	LIST_HEAD(, nfsv4_owner_s) cl_owners;
	LIST_HEAD(, nfsv4_session) cl_sessions;
	uint32_t	cl_minor;
	u_int		cl_refs;	/* COMPOUNDs; the lease scan waits */
	bool		cl_retired;	/* being forgotten; no name finds it */
	bool		cl_reclaimed;	/* RECLAIM_COMPLETE was done, s18.51 */
	bool		cl_pnfs;	/* USE_PNFS_MDS and _DS, RFC 8881 s13.1 */
	u_int		cl_nrevoked;	/* of st_revoked */
	uint32_t	cl_csseq;	/* the CREATE_SESSION slot, s18.36.4 */
	uint32_t	cl_csstatus;
	u_int		cl_cslen;
	char		cl_csreply[NFSV4_CSREPLY_MAX];
	uint64_t	cl_id;		/* c */
	struct nfsv4_verifier cl_verf;	/* v */
	struct nfsv4_verifier cl_confirm; /* s */
	struct nfsv4_clientaddr cl_cb;	/* k, and cl_cbprog, cl_cbident */
	uint32_t	cl_cbprog;
	uint32_t	cl_cbident;
	uid_t		cl_uid;		/* the principal */
	uint32_t	cl_pflavor;	/* and its flavour, 4.1 */
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
	uint32_t	cl_movedack;	/* moved generation it has heard of */
	bool		cl_confirmed;
	bool		cl_expired;	/* state gone; stateids still known */
	time_t		cl_expire;	/* lease, in time_uptime */
	uint32_t	cl_idlen;	/* x */
	uint8_t		cl_idstr[NFS4_OPAQUE_LIMIT];
	struct nfsv4_devnote cl_devnote[NFSV4_DEVNOTES];
	uint32_t	cl_lwant;	/* RCA4_TYPE_MASK_* bits, s18.43.3 */
};

#define	NFSV4_OWNER_OPEN	1
#define	NFSV4_OWNER_LOCK	2
#define	NFSV4_OWNER_DELEG	3	/* the client's delegations */
#define	NFSV4_OWNER_LAYOUT	4	/* the client's layouts */

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
	uint64_t	sw_gen;		/* to be known by, never reused */
	uint32_t	sw_lastop;	/* of the reply below */
	uint32_t	sw_laststat;
	u_int		sw_rlen;
	char		*sw_rbuf;
	struct nfsv4_fh	sw_rfh;		/* the file, to replay an OPEN */
	struct nfsv4_state *sw_closed;	/* last CLOSE, s9.10.1 */
	uint32_t	sw_len;
	uint8_t		sw_data[NFS4_OPAQUE_LIMIT];
};

/* A blocking lock denied, in order, s9.4. */
struct nfsv4_lockwait {
	TAILQ_ENTRY(nfsv4_lockwait) lw_list;
	uint64_t	lw_gen;		/* sw_gen */
	off_t		lw_start;
	off_t		lw_end;		/* -1 for EOF */
	bool		lw_write;
	time_t		lw_expire;
	/* lock_owner4, for CB_NOTIFY_LOCK, RFC 8881 s20.11 */
	uint64_t	lw_clientid;
	uint32_t	lw_olen;
	uint8_t		lw_owner[NFS4_OPAQUE_LIMIT];
};

/* All the state on one vnode. */
struct nfsv4_file {
	LIST_ENTRY(nfsv4_file) f_list;
	LIST_HEAD(, nfsv4_state) f_states;
	struct vnode	*f_vp;		/* a reference */
	struct nfsv4_fh	f_fh;		/* unless f_isattr, of an open file */
	TAILQ_HEAD(, nfsv4_lockwait) f_waits;
	u_int		f_nwaits;
	bool		f_isattr;	/* opens of a named attribute */
	char		f_aname[NFSV4_ANAME_MAX + 1];
};

#define	NFSV4_ST_OPEN		1
#define	NFSV4_ST_LOCK		2
#define	NFSV4_ST_DELEG		3
#define	NFSV4_ST_LAYOUT		4	/* RFC 8881 s12.5.3 */

/* What of a file a lock state has locked, s9.5.  lr_end is past the last. */
struct nfsv4_lrange {
	LIST_ENTRY(nfsv4_lrange) lr_list;
	off_t		lr_start;
	off_t		lr_end;
};

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
	LIST_HEAD(, nfsv4_lrange) st_ranges;	/* lock, unless st_allfile */
	u_int		st_nranges;
	bool		st_allfile;	/* too many: taken to be all of it */
	struct vnode	*st_reapvp;	/* a reference, while reaping */
	bool		st_free;	/* reaping ends it */
	bool		st_closed;	/* kept for a resent CLOSE */
	bool		st_revoked;	/* RFC 8881 s8.2.4: until FREE_STATEID */
	/* delegation */
	TAILQ_ENTRY(nfsv4_state) st_cbq;	/* to be called back */
	LIST_ENTRY(nfsv4_state) st_rlist;	/* recalled */
	uint32_t	st_dtype;	/* OPEN_DELEGATE_* */
	uint64_t	st_sc;		/* s10.4.3 */
	bool		st_modified;
	bool		st_cbqueued;	/* on st_cbq */
	bool		st_recalled;	/* on st_rlist */
	bool		st_prev;	/* of a client now restarted, s10.2.1 */
	bool		st_refset;	/* the request granting it, s2.10.6.3 */
	struct nfsv4_sessionid st_refsid;
	uint32_t	st_refslot;
	uint32_t	st_refseq;
	time_t		st_recall_end;	/* when it is revoked */
	time_t		st_cbnext;	/* when to call again, if not 0 */
	/* layout, of nfsv4_layout.c: all of the file, in these modes */
	uint32_t	st_liomode;	/* bits 1 << LAYOUTIOMODE4_* */
	uint32_t	st_ltype;	/* LAYOUT4_*, s3.3.13 */
	uint32_t	st_lgen;	/* of the device it refers to */
	bool		st_lfence;	/* not returned in time, RFC 8435 s2.2 */
	bool		st_lrecall;	/* CB_LAYOUTRECALL sent, s12.5.5.2 */
	bool		st_lanswered;	/* and the client has answered it */
	time_t		st_lrend;	/* when it is let go regardless */
};

SLIST_HEAD(nfsv4_reap, nfsv4_state);

/* Allocated beforehand for a delegation that may come of an OPEN. */
struct nfsv4_deleg_spare {
	bool		ds_locked;	/* locks on the file, of whoever */
	uint64_t	ds_change;	/* s10.4.3, sc */
	bool		ds_refset;	/* st_refset and the rest */
	struct nfsv4_sessionid ds_refsid;
	uint32_t	ds_refslot;
	uint32_t	ds_refseq;
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
extern int nfsv4_deleg_mode;
extern int nfsv4_dirdeleg;
extern int nfsv4_gdd_unavail_ok;
extern int nfsv4_remove_past_deny;
extern int nfsv4_cb_vers1;
extern int nfsv4_cb_trace;

/* What to do with a request after looking at its seqid, s9.1.7. */
enum nfsv4_seq {
	NFSV4_SEQ_GO,
	NFSV4_SEQ_REPLAY,
	NFSV4_SEQ_BAD
};

extern const uint64_t nfsv4_attr_exclcreat;

void	nfsv4_state_init(void);
void	nfsv4_state_fini(void);
void	nfsv4_cb_init(void);
void	nfsv4_cb_fini(void);
void	nfsv4_deleg_init(void);
void	nfsv4_deleg_fini(void);
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
uint32_t nfsv4_client_cur(struct nfsv4_compound *, uint64_t,
	    struct nfsv4_client **);
struct nfsv4_client *
	nfsv4_client_find(const uint8_t *, uint32_t, bool, uint32_t);
struct nfsv4_client *
	nfsv4_client_byid(uint64_t);
struct nfsv4_client *
	nfsv4_client_next(struct nfsv4_client *);
struct nfsv4_client *
	nfsv4_client_insert(struct nfsv4_client *);
void	nfsv4_client_retire(struct nfsv4_client *);
struct nfsv4_session *
	nfsv4_session_cbget(struct nfsv4_client *, uint64_t *);
bool	nfsv4_session_cbany(struct nfsv4_client *);
void	nfsv4_session_cbdone(struct nfsv4_session *, bool);
bool	nfsv4_client_has_state(const struct nfsv4_client *);
uint64_t nfsv4_clientid_new(void);
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
uint32_t nfsv4_stateid_lookup(const struct nfsv4_compound *,
	    const struct nfsv4_stateid *, struct nfsv4_state **);
uint32_t nfsv4_stateid_check(const struct nfsv4_stateid *,
	    const struct nfsv4_state *, struct vnode *, u_int);
bool	nfsv4_stateid_special(const struct nfsv4_stateid *);
void	nfsv4_stateid_out(const struct nfsv4_state *, struct nfsv4_stateid *);
struct nfsv4_file *
	nfsv4_file_find(struct vnode *);
struct nfsv4_file *
	nfsv4_file_find_attr(struct vnode *, const char *);
struct nfsv4_client *
	nfsv4_client_byid41(uint64_t);
void	nfsv4_client_renew(struct nfsv4_client *);
bool	nfsv4_lease_moved(const struct nfsv4_client *);
struct nfsv4_state *
	nfsv4_state_byother(uint64_t);
void	nfsv4_cb_probe(struct nfsv4_client *);
void	nfsv4_cb_reset(struct nfsv4_client *);
void	nfsv4_cb_recall(struct nfsv4_state *);
void	nfsv4_cb_forget_client(struct nfsv4_client *);
void	nfsv4_cb_forget_state(struct nfsv4_state *);
void	nfsv4_cb_notify_lock(const struct nfsv4_lockwait *,
	    const struct nfsv4_fh *);
uint32_t nfsv4_deleg_conflict(struct vnode *, const struct nfsv4_client *,
	    uint64_t, u_int);
void	nfsv4_deleg_offer(struct nfsv4_owner_s *, struct vnode *,
	    const struct nfsv4_fh *, uint32_t, struct nfsv4_deleg_spare *,
	    struct nfsv4_open_deleg *);
void	nfsv4_deleg_add(struct nfsv4_client *, struct vnode *,
	    const struct nfsv4_fh *, uint32_t, struct nfsv4_deleg_spare *,
	    struct nfsv4_open_deleg *);
void	nfsv4_deleg_gone(struct nfsv4_state *);
void	nfsv4_deleg_look(struct vnode *, kauth_cred_t,
	    struct nfsv4_deleg_spare *);
void	nfsv4_deleg_refer(const struct nfsv4_compound *,
	    struct nfsv4_deleg_spare *);
uint32_t nfsv4_deleg_claim_cur(const struct nfsv4_compound *,
	    struct nfsv4_client *,
	    const struct nfsv4_stateid *, struct vnode *);
uint32_t nfsv4_deleg_claim_prev(struct nfsv4_client *, struct vnode *,
	    struct nfsv4_open_deleg *);
void	nfsv4_deleg_carry(struct nfsv4_client *, struct nfsv4_client *,
	    struct nfsv4_owner_s **);
void	nfsv4_deleg_drop_prev(struct nfsv4_client *, struct nfsv4_reap *);
void	nfsv4_deleg_scan(struct nfsv4_reap *);
bool	nfsv4_deleg_path_down(struct nfsv4_client *);
bool	nfsv4_cb_layoutrecall(struct nfsv4_state *);
void	nfsv4_cb_notify_deviceid(const struct nfsv4_client *, uint32_t,
	    const uint8_t *);
void	nfsv4_cb_recall_any(const struct nfsv4_client *, uint32_t, uint32_t,
	    uint32_t);
void	nfsv4_layout_recalled(uint64_t, int, uint32_t, struct nfsv4_reap *);
void	nfsv4_layout_scan(struct nfsv4_reap *);
void	nfsv4_layout_gone(struct nfsv4_state *);
void	nfsv4_ff_reap(void);
uint32_t nfsv4_layout_ff_conflict(struct vnode *);

/* These do not. */
void	nfsv4_layout_recall_all(void);
void	nfsv4_layout_recall_vp(struct vnode *, bool);
void	nfsv4_layout_recall_name(const struct nfsv4_cfh *, const char *);
struct vnode *nfsv4_file_vp_byfh(const struct nfsv4_fh *);
uint32_t nfsv4_seq_stateid(const struct nfsv4_compound *,
	    const struct nfsv4_stateid *, uint32_t, uint32_t,
	    struct nfsv4_state **, enum nfsv4_seq *);
uint32_t nfsv4_seq_reply(struct nfsv4_compound *, struct nfsv4_owner_s *,
	    uint32_t, uint32_t, uint32_t, u_int);
uint32_t nfsv4_seq_replay(struct nfsv4_compound *, struct nfsv4_owner_s *,
	    bool);
void	nfsv4_seq_cancel(struct nfsv4_owner_s *);
void	nfsv4_reap_finish(struct nfsv4_reap *);
void	nfsv4_client_stable(struct nfsv4_client *);
void	nfsv4_lock_assign(struct nfsv4_owner_s *, struct nfsv4_file *,
	    struct nfsv4_state *, const struct flock *);
void	nfsv4_lock_drop(struct nfsv4_state *, struct vnode *);
uid_t	nfsv4_client_principal(const struct nfsv4_compound *);
void	nfsv4_owner_replay_save(struct nfsv4_owner_s *, uint32_t, uint32_t,
	    uint32_t, const char *, u_int);
bool	nfsv4_lock_fair(struct nfsv4_owner_s *, struct vnode *,
	    const struct flock *);
void	nfsv4_lock_waited(struct nfsv4_owner_s *, struct vnode *,
	    const struct flock *, bool, bool);
uint32_t nfsv4_deleg_getattr(struct nfsv4_compound *);
int	nfsv4_cb_getattr(const struct nfsv4_client *, const struct nfsv4_fh *,
	    uint64_t *, uint64_t *);
uint32_t nfsv4_deleg_break(struct vnode *, const struct nfsv4_client *,
	    uint64_t, u_int);
uint32_t nfsv4_deleg_break_name(const struct nfsv4_cfh *, const char *);
uint32_t nfsv4_deleg_break_dir(const struct nfsv4_compound *,
	    const struct nfsv4_cfh *);
uint32_t nfsv4_open_denies_remove(const struct nfsv4_cfh *, const char *);

#endif /* !_FS_NFSV4_NFSV4_STATE_H_ */
