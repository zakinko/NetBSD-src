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

#ifndef _FS_NFSV4_NFSV4_VAR_H_
#define _FS_NFSV4_NFSV4_VAR_H_

#include <sys/fstypes.h>
#include <sys/queue.h>

#include <oncrpc/oncrpc.h>

#include <fs/nfsv4/nfsv4_xdr.h>

struct mount;
struct nameidata;
struct nfsv4_client;
struct nfsv4_session;
struct nfsv4_slot;
struct vattr;
struct vnode;

/*
 * A named attribute.  RFC 7530 s5.3 asks for all the names a directory
 * could have, and the handle has room only for a hash of one.
 */
#define	NFSV4_ATTR_DIR		1
#define	NFSV4_ATTR_FILE		2
#define	NFSV4_ANAME_MAX		255
#define	NFSV4_ANAME_HASH	16	/* of the name, in the handle */

/* An owner string at its longest; see nfsv4_idmap.c. */
#define	NFSV4_IDSTR_MAX		128

/* See nfsv4_referral.c. */
struct nfsv4_referral {
	SLIST_ENTRY(nfsv4_referral) rf_list;
	struct vnode	*rf_vp;
	u_int		rf_index;
	bool		rf_moved;	/* the whole file system, s9.14 */
	char		rf_path[256];
	char		rf_locs[512];
};

/*
 * A current or saved filehandle.  A real one holds a reference to its
 * vnode, unlocked, and the credential to use on it: which credential
 * that is depends on the export, so on the file system of the handle.
 * A node of the pseudo file system has neither, RFC 7530 s7.3.
 */
struct nfsv4_cfh {
	bool		cf_set;
	struct nfsv4_fh	cf_fh;
	struct vnode	*cf_vp;		/* NULL in the pseudo file system */
	kauth_cred_t	cf_cred;
	int		cf_exflags;
	u_int		cf_attr;	/* NFSV4_ATTR_*; see nfsv4_xattr.c */
	char		cf_aname[NFSV4_ANAME_MAX + 1];
	const struct nfsv4_referral *cf_ref;	/* absent, s8.2 */
	bool		cf_wrongsec;	/* the export refuses this request */
};

/* What SETATTR asked of the attributes of nfsv4_xattr.c. */
#define	NFSV4_MIME_MAX		128	/* chosen */
struct nfsv4_xstore {
	uint64_t	xs_set;
	uint32_t	xs_archive, xs_hidden, xs_system;
	uint32_t	xs_mimelen;
	char		xs_mime[NFSV4_MIME_MAX];
	struct timespec	xs_backup;
	/* retention_set, retentevt_set and retention_hold, RFC 8881 s5.13 */
	uint32_t	xs_set2;	/* of the third word */
	uint32_t	xs_did2;	/* what was set of it */
	struct {
		bool		rs_enable;
		bool		rs_hasdur;
		uint64_t	rs_duration;
	}		xs_ret[2];	/* NFSV4_RET_* */
	uint64_t	xs_hold;
	/*
	 * mode_set_masked, RFC 8881 s6.2.5: given, the value, the mask.
	 * Not in xs_set2, which says what nfsv4_xstore_apply() keeps.
	 */
	bool		xs_masked;
	uint32_t	xs_mmode, xs_mmask;
	/* dacl, RFC 8881 s6.2.2: given, and its aclflag4 */
	bool		xs_dacl;
	uint32_t	xs_daclflags;
};
#define	NFSV4_RET		0	/* retention_set */
#define	NFSV4_RETEVT		1	/* retentevt_set */

/* What CB_GETATTR said, s10.4.3. */
struct nfsv4_attrov {
	bool		ao_valid;
	uint64_t	ao_size;
	uint64_t	ao_change;
	struct timespec	ao_time;
};

/*
 * What is being done for one COMPOUND.  Its operations run in order in
 * one thread, so nothing here needs a lock.  c_sess and c_client are
 * held from SEQUENCE until the COMPOUND ends.
 */
struct nfsv4_compound {
	struct oncrpc_req *c_rq;
	XDR		*c_ax;		/* arguments */
	XDR		*c_rx;		/* results */
	struct nfsv4_cfh c_cur;		/* RFC 7530 s15.2.4.1 */
	struct nfsv4_cfh c_saved;
	struct nfsv4_cfh c_scratch;	/* for a lookup that is thrown away */
	char		*c_rbuf;	/* NFSV4_REPLAY_MAX, for seqid replies */
	bool		c_drc;		/* an operation that the DRC keeps ran */
	struct acl	*c_setacl;	/* parsed, not set yet; nfsv4_acl_set */
	struct nfsv4_xstore c_xs;
	struct nfsv4_attrov c_ov;	/* for the GETATTR going on */
	bool		c_probed;	/* fs_locations of an absent fs, s9.14.3 */
	uint32_t	c_minor;
	uint32_t	c_numops;
	uint32_t	c_opi;		/* index of the current operation */
	struct nfsv4_session *c_sess;
	struct nfsv4_client *c_client;
	struct nfsv4_slot *c_slot;	/* NULL for a retry, or no SEQUENCE */
	bool		c_seqdone;	/* nfsv4_seq_begin() ran */
	uint32_t	c_seqstatus;	/* and said this */
	bool		c_cachethis;
	bool		c_uncached;	/* a retry with no reply kept */
	uint32_t	c_seqflags;	/* sr_status_flags */
	uint32_t	c_argsum;	/* of what follows SEQUENCE */
	uint32_t	c_maxslot;	/* sr_highest_slotid */
	uint32_t	c_resmax;	/* size of reply allowed, or 0 */
	uint32_t	c_cachemax;	/* and to be cached, if c_cachethis */
	struct nfsv4_stateid c_curst;	/* RFC 8881 s16.2.3.1.2 */
	struct nfsv4_stateid c_savest;
};

/* A COMPOUND in the duplicate request cache's hands; see nfsv4_drc.c. */
struct nfsv4_drc {
	bool		d_on;		/* the cache knows of it */
	uint32_t	d_xid;
	uint32_t	d_sum;
	uint32_t	d_uid;
	uint32_t	d_hash;
	uint8_t		d_addr[16];
	char		*d_buf;		/* the reply to replay */
	u_int		d_len;
};

/*
 * An operation.  It gets its decoded arguments and returns its status,
 * having written to c_rx what follows the status in its result: that is
 * nothing for an error, unless the error has an arm of its own in the
 * result's union, because the COMPOUND cannot take bytes back.
 */
typedef uint32_t (*nfsv4_op_t)(struct nfsv4_compound *, union nfsv4_args *);

/*
 * Limits chosen here, none from the RFC.  NFSV4_MAXIO is the maxread
 * and maxwrite attributes and bounds what one READ can ask to hold in
 * memory.  NFSV4_LEASE is the lease_time attribute, in seconds.
 */
#define	NFSV4_MAXIO		(128 * 1024)
#define	NFSV4_LEASE		90

/* The largest result of an operation with a seqid: LOCK4denied. */
#define	NFSV4_REPLAY_MAX	(64 + NFS4_OPAQUE_LIMIT)

/*
 * Room for one object's attributes, not counting the bitmap.  An ACL
 * has the most of them: ACL_MAX_ENTRIES of 28 bytes at the longest.
 */
#define	NFSV4_ATTRBUF		8192

#define	NFSV4_IMPL_MAX		64
extern char nfsv4_impl_domain[], nfsv4_impl_name[];
bool	nfsv4_conn_alive(uint64_t);
int	nfsv4_conn_call(uint64_t, const struct oncrpc_clnt_call *, int);
void	nfsv4_session_init(void);
void	nfsv4_session_fini(void);
void	nfsv4_session_drop_all(struct nfsv4_client *);
uint32_t nfsv4_seq_begin(struct nfsv4_compound *,
	    const struct nfsv4_args_sequence *, char **, u_int *);
void	nfsv4_seq_end(struct nfsv4_compound *, bool);

void	nfsv4_drc_init(void);
void	nfsv4_drc_fini(void);
bool	nfsv4_drc_start(struct oncrpc_req *, struct nfsv4_drc *);
bool	nfsv4_drc_replay(struct oncrpc_req *, struct nfsv4_drc *);
void	nfsv4_drc_end(struct nfsv4_drc *, struct oncrpc_req *);

uint32_t nfsv4_attr_fill(struct nfsv4_compound *, const struct nfsv4_cfh *,
	    const struct nfsv4_bitmap *, uint32_t, char *, size_t,
	    struct nfsv4_bitmap *, u_int *);
uint64_t nfsv4_attr_change(const struct vnode *, const struct vattr *);
bool	nfsv4_attr_getonly_ok(const struct nfsv4_bitmap *, uint32_t);
uint32_t nfsv4_attr_create_ok(const struct nfsv4_compound *);
bool	nfsv4_attr_mode_masked(struct nfsv4_compound *, struct vnode *,
	    struct vattr *);
bool	nfsv4_attr_supported(const struct nfsv4_compound *,
	    const struct nfsv4_bitmap *, struct vnode *);
int	nfsv4_access_vp(const struct nfsv4_cfh *, int);

uint32_t nfsv4_attr_parse(struct nfsv4_compound *,
	    const struct nfsv4_fattr *, struct vattr *, uint64_t *);
bool	nfsv4_attr_put_mask(XDR *, uint64_t, uint32_t);

uint32_t nfsv4_file_check(const struct nfsv4_compound *,
	    const struct nfsv4_cfh *);
int	nfsv4_dir_change(struct vnode *, kauth_cred_t, uint64_t *);
uint32_t nfsv4_io_check(struct nfsv4_compound *, const struct nfsv4_stateid *,
	    bool);
uint32_t nfsv4_setattr_stateid(struct nfsv4_compound *,
	    const struct nfsv4_stateid *);

uint32_t nfsv4_errno(int);
void	nfsv4_write_verf(struct nfsv4_verifier *);

bool	nfsv4_xstore_ok(struct vnode *);
uint32_t nfsv4_xstore_apply(struct nfsv4_compound *, struct vnode *,
	    kauth_cred_t);
bool	nfsv4_xstore_bool(struct vnode *, const char *);
uint32_t nfsv4_xstore_u32(struct vnode *, const char *);
int	nfsv4_xstore_set_u32(struct vnode *, const char *, uint32_t);
u_int	nfsv4_xstore_mime(struct vnode *, char *);
void	nfsv4_xstore_time(struct vnode *, struct timespec *);
uint32_t nfsv4_retention_check(struct nfsv4_compound *, struct vnode *,
	    kauth_cred_t);
bool	nfsv4_retained(struct vnode *, bool);
void	nfsv4_retention_scan(void);
void	nfsv4_retention_init(void);
void	nfsv4_retention_fini(void);
void	nfsv4_retention_get(struct vnode *, u_int, uint64_t *,
	    struct timespec *);
uint64_t nfsv4_retention_hold(struct vnode *);

void	nfsv4_idmap_init(void);
void	nfsv4_idmap_fini(void);
int	nfsv4_idmap_line(const char *);
int	nfsv4_idmap_setdomain(const char *);
u_int	nfsv4_idmap_out(bool, uint32_t, char *);
bool	nfsv4_idmap_has(bool, uint32_t);
uint32_t nfsv4_idmap_in(bool, const char *, u_int, u_int, uint32_t *);

void	nfsv4_referral_init(void);
void	nfsv4_referral_fini(void);
int	nfsv4_referral_line(const char *);
const struct nfsv4_referral *
	nfsv4_referral_find(const struct vnode *);
bool	nfsv4_referral_allowed(uint32_t, const union nfsv4_args *);
int	nfsv4_moved_line(const char *);
int	nfsv4_arrived_line(const char *);
void	nfsv4_arrived_in(fsid_t *);
void	nfsv4_arrived_out(const struct mount *, fsid_t *);
bool	nfsv4_moved_mount(const struct mount *);
uint32_t nfsv4_moved_gen(void);
bool	nfsv4_moved_grace(void);
bool	nfsv4_attr_absent_ok(const struct nfsv4_bitmap *);
uint32_t nfsv4_xattr_byhash(struct nfsv4_cfh *, const uint8_t *);
void	nfsv4_xattr_hash(const char *, size_t, uint8_t *);

int	nfsv4_xattr_size(const struct nfsv4_cfh *, uint64_t *);
int	nfsv4_xattr_list(const struct nfsv4_cfh *, char **, size_t *, size_t *);
bool	nfsv4_xattr_any(const struct nfsv4_cfh *);
uint32_t nfsv4_xattr_lookup(struct nfsv4_compound *, struct nfsv4_cfh *,
	    const char *, struct nfsv4_cfh *);
uint32_t nfsv4_xattr_prepare(struct nfsv4_cfh *, const char *, bool, bool,
	    bool);
uint32_t nfsv4_xattr_op(struct nfsv4_compound *, uint32_t, union nfsv4_args *,
	    nfsv4_op_t);

bool	nfsv4_acl_supported(struct vnode *);
uint32_t nfsv4_acl_get(struct vnode *, kauth_cred_t, struct acl **);
bool	nfsv4_acl_put(XDR *, const struct acl *);
bool	nfsv4_dacl_put(XDR *, const struct acl *, uint32_t);
uint32_t nfsv4_acl_parse(XDR *, uint32_t, struct acl **);
uint32_t nfsv4_dacl_parse(XDR *, uint32_t, struct acl **, uint32_t *);
bool	nfsv4_dacl_supported(struct vnode *);
uint32_t nfsv4_dacl_flags(struct vnode *);
uint32_t nfsv4_acl_set(struct nfsv4_compound *, struct vnode *, kauth_cred_t);
uint32_t nfsv4_acl_noattr(struct vnode *, struct vnode *, bool, kauth_cred_t);
uint32_t nfsv4_acl_create(struct nfsv4_compound *, struct vnode *,
	    struct vnode *, bool, bool, kauth_cred_t);
extern int nfsv4_excl_inherit;
extern int nfsv4_create_mode_mask;
uint32_t nfsv4_attr_strid(bool, const char *, u_int, uint32_t, uint32_t *);
uint32_t nfsv4_name_check(const struct nfsv4_compound *,
	    const struct nfsv4_name *);
extern int nfsv4_utf8_only;
extern u_int nfsv4_fault_getattr;
extern u_int nfsv4_fault_renew;
bool	nfsv4_fault(volatile u_int *);
bool	nfsv4_pnfs_on(void);
uint32_t nfsv4_pnfs_flags(uint32_t, bool *);
int	nfsv4_layout_setds(const char *);
extern u_int nfsv4_layouts_given;
uint32_t nfsv4_layout_types(struct vnode *);
uint32_t nfsv4_layout_blksize(void);
extern int nfsv4_numeric_owner_sys;

void	nfsv4_cfh_clear(struct nfsv4_cfh *);
uint32_t nfsv4_cfh_put(struct nfsv4_compound *, const struct nfsv4_fh *);
uint32_t nfsv4_cfh_setvp(struct nfsv4_compound *, struct nfsv4_cfh *,
	    struct vnode *);
void	nfsv4_cfh_copy(struct nfsv4_cfh *, const struct nfsv4_cfh *);
uint32_t nfsv4_cfh_setattr(struct nfsv4_cfh *, u_int, const char *, size_t);
int	nfsv4_namei(struct nameidata *, struct vnode *, const char *, uint32_t,
	    uint32_t, kauth_cred_t);
uint32_t nfsv4_cfh_lookup(struct nfsv4_compound *, struct nfsv4_cfh *,
	    const char *, size_t, struct nfsv4_cfh *);
const char *nfsv4_cfh_path(const struct nfsv4_cfh *, size_t *);
int	nfsv4_lookup_vp(struct vnode *, const char *, kauth_cred_t,
	    struct vnode **);
int	nfsv4_pseudo_walk(struct nfsv4_compound *, const char *, size_t,
	    int (*)(struct mount *, const char *, size_t, void *), void *);

uint32_t nfsv4_op_backchannel_ctl(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_bind_conn(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_create_session(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_destroy_clientid(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_destroy_session(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_exchange_id(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_free_stateid(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_reclaim_complete(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_secinfo_no_name(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_sequence(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_set_ssv(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_get_dir_delegation(struct nfsv4_compound *,
	    union nfsv4_args *);
uint32_t nfsv4_op_want_delegation(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_test_stateid(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_getdeviceinfo(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_getdevicelist(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_layoutcommit(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_layoutget(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_layoutreturn(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_access(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_getattr(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_readdir(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_readlink(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_secinfo(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_close(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_commit(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_delegpurge(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_delegreturn(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_open(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_openattr(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_open_confirm(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_open_downgrade(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_read(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_write(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_create(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_link(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_lock(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_lockt(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_locku(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_nverify(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_release_lockowner(struct nfsv4_compound *,
	    union nfsv4_args *);
uint32_t nfsv4_op_remove(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_rename(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_setattr(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_verify(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_renew(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_setclientid(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_setclientid_confirm(struct nfsv4_compound *,
	    union nfsv4_args *);
uint32_t nfsv4_op_getfh(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_lookup(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_lookupp(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_lookupp(struct nfsv4_compound *);
uint32_t nfsv4_op_putfh(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_putpubfh(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_putrootfh(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_restorefh(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_savefh(struct nfsv4_compound *, union nfsv4_args *);

#endif /* !_FS_NFSV4_NFSV4_VAR_H_ */
