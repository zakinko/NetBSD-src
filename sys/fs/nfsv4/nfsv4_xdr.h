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

#ifndef _FS_NFSV4_NFSV4_XDR_H_
#define _FS_NFSV4_NFSV4_XDR_H_

/*
 * The types of RFC 7531 that have a use here, and their XDR filters.
 * The callback program has its encoding where the calls are made, in
 * nfsv4_cb.c.
 *
 * An operation's arguments decode into a structure of fixed size with
 * no allocation: every variable field has a bound, either the RFC's or
 * one chosen below.  The two that may be large, attrlist4 and the data
 * of WRITE, are not copied at all; the decoder steps over them and
 * leaves their position in the stream.  Each filter works in both
 * directions like rpcgen's, except that the encoder of a positional
 * field writes only its length and leaves the body to the caller.
 *
 * A name too long for this server is not malformed, and NFS4ERR_BADXDR
 * would be wrong for it (RFC 7530 s13.1.7.3 has NFS4ERR_NAMETOOLONG),
 * so it is read and marked.
 */

#include <sys/types.h>
#ifdef _KERNEL
#include <sys/stdbool.h>
#else
#include <stdbool.h>
#endif

#include <rpc/types.h>
#include <rpc/xdr.h>

#include <fs/nfsv4/nfsv4_proto.h>

/*
 * Attributes run to 75 (RFC 8881 s5.8.1.14), so three words hold them.  The
 * RFC does not bound bitmap4; NFSV4_BITMAP_READ is a choice, to keep a
 * length from the wire from driving a long loop.  Words past
 * NFSV4_BITMAP_WORDS are remembered only as being nonzero or not, for
 * they name attributes that do not exist here.
 */
#define	NFSV4_BITMAP_WORDS	3
#define	NFSV4_BITMAP_READ	64

/*
 * Bounds not given by the RFC, all chosen.  255 is what FFS and ZFS
 * have, and 1024 is MAXPATHLEN.  The two strings of clientaddr4 are
 * kept only to be given back in NFS4ERR_CLID_INUSE, and a client giving
 * more does not decode.
 */
#define	NFSV4_NAME_MAX		255
#define	NFSV4_LINK_MAX		1024
#define	NFSV4_NETADDR_MAX	64
#define	NFSV4_NETID_MAX		16

struct nfsv4_bitmap {
	uint32_t	bm_n;		/* words in bm_w that are good */
	uint32_t	bm_w[NFSV4_BITMAP_WORDS];
	bool		bm_more;	/* a nonzero word beyond bm_w */
};

/* component4; RFC 7530 s12.7 has the rules for what may be in one */
struct nfsv4_name {
	uint32_t	nm_len;
	bool		nm_toolong;
	char		nm_str[NFSV4_NAME_MAX + 1];	/* NUL terminated */
};

/* linktext4 */
struct nfsv4_link {
	uint32_t	ln_len;
	bool		ln_toolong;
	char		ln_str[NFSV4_LINK_MAX + 1];
};

/* nfs_fh4 */
struct nfsv4_fh {
	uint32_t	fh_len;
	uint8_t		fh_data[NFS4_FHSIZE];
};

struct nfsv4_stateid {
	uint32_t	si_seqid;
	uint8_t		si_other[NFS4_OTHER_SIZE];
};

struct nfsv4_verifier {
	uint8_t		v_data[NFS4_VERIFIER_SIZE];
};

/* fattr4, with attr_vals left in the stream */
struct nfsv4_fattr {
	struct nfsv4_bitmap fa_mask;
	uint32_t	fa_len;
	u_int		fa_pos;
};

struct nfsv4_owner {
	uint64_t	ow_clientid;
	uint32_t	ow_len;
	uint8_t		ow_data[NFS4_OPAQUE_LIMIT];
};

struct nfsv4_change_info {
	uint32_t	ci_atomic;
	uint64_t	ci_before;
	uint64_t	ci_after;
};

struct nfsv4_clientaddr {
	uint32_t	ca_netidlen;
	uint32_t	ca_addrlen;
	char		ca_netid[NFSV4_NETID_MAX];
	char		ca_addr[NFSV4_NETADDR_MAX];
};

struct nfsv4_lock_denied {
	uint64_t	ld_offset;
	uint64_t	ld_length;
	uint32_t	ld_type;
	uint64_t	ld_clientid;
	uint32_t	ld_ownerlen;
	const uint8_t	*ld_owner;	/* encode only */
};

/* open_delegation4, s16.16.3; encode only */
struct nfsv4_open_deleg {
	uint32_t	od_type;
	uint32_t	od_recall;
	uint32_t	od_why;		/* OPEN_DELEGATE_NONE_EXT */
	struct nfsv4_stateid od_stateid;
};

struct nfsv4_args_access {
	uint32_t	access;
};

struct nfsv4_args_close {
	uint32_t	seqid;
	struct nfsv4_stateid stateid;
};

struct nfsv4_args_commit {
	uint64_t	offset;
	uint32_t	count;
};

struct nfsv4_args_create {
	uint32_t	type;
	struct nfsv4_link link;		/* NF4LNK */
	uint32_t	spec1, spec2;	/* NF4BLK, NF4CHR */
	struct nfsv4_name name;
	struct nfsv4_fattr attrs;
};

struct nfsv4_args_clientid {		/* DELEGPURGE, RENEW */
	uint64_t	clientid;
};

struct nfsv4_args_stateid {		/* DELEGRETURN */
	struct nfsv4_stateid stateid;
};

struct nfsv4_args_getattr {
	struct nfsv4_bitmap mask;
};

struct nfsv4_args_name {		/* LINK, LOOKUP, REMOVE, SECINFO */
	struct nfsv4_name name;
};

struct nfsv4_args_lock {
	uint32_t	type;
	uint32_t	reclaim;
	uint64_t	offset;
	uint64_t	length;
	uint32_t	newowner;
	/* newowner */
	uint32_t	open_seqid;
	struct nfsv4_stateid open_stateid;
	struct nfsv4_owner owner;
	/* !newowner */
	struct nfsv4_stateid lock_stateid;
	/* both */
	uint32_t	lock_seqid;
};

struct nfsv4_args_lockt {
	uint32_t	type;
	uint64_t	offset;
	uint64_t	length;
	struct nfsv4_owner owner;
};

struct nfsv4_args_locku {
	uint32_t	type;
	uint32_t	seqid;
	struct nfsv4_stateid stateid;
	uint64_t	offset;
	uint64_t	length;
};

struct nfsv4_args_verify {		/* VERIFY, NVERIFY */
	struct nfsv4_fattr attrs;
};

struct nfsv4_args_open {
	uint32_t	seqid;
	uint32_t	share_access;
	uint32_t	share_deny;
	uint32_t	want;		/* RFC 8881 s18.16.1, from share_access */
	bool		wanted;		/* it has any of those flags */
	struct nfsv4_owner owner;
	uint32_t	opentype;
	uint32_t	createmode;		/* OPEN4_CREATE */
	struct nfsv4_fattr createattrs;		/* all but EXCLUSIVE4 */
	struct nfsv4_verifier createverf;	/* EXCLUSIVE4, EXCLUSIVE4_1 */
	uint32_t	claim;
	struct nfsv4_name file;			/* all but CLAIM_PREVIOUS */
	uint32_t	delegate_type;		/* CLAIM_PREVIOUS */
	struct nfsv4_stateid delegate_stateid;	/* CLAIM_DELEGATE_CUR */
};

struct nfsv4_args_openattr {
	uint32_t	createdir;
};

struct nfsv4_args_open_confirm {
	struct nfsv4_stateid stateid;
	uint32_t	seqid;
};

struct nfsv4_args_open_downgrade {
	struct nfsv4_stateid stateid;
	uint32_t	seqid;
	uint32_t	share_access;
	uint32_t	share_deny;
};

struct nfsv4_args_putfh {
	struct nfsv4_fh	fh;
};

struct nfsv4_args_read {
	struct nfsv4_stateid stateid;
	uint64_t	offset;
	uint32_t	count;
};

struct nfsv4_args_readdir {
	uint64_t	cookie;
	struct nfsv4_verifier cookieverf;
	uint32_t	dircount;
	uint32_t	maxcount;
	struct nfsv4_bitmap mask;
};

struct nfsv4_args_rename {
	struct nfsv4_name oldname;
	struct nfsv4_name newname;
};

struct nfsv4_args_setattr {
	struct nfsv4_stateid stateid;
	struct nfsv4_fattr attrs;
};

struct nfsv4_args_setclientid {
	struct nfsv4_verifier verifier;
	uint32_t	idlen;
	uint8_t		id[NFS4_OPAQUE_LIMIT];
	uint32_t	cb_program;
	struct nfsv4_clientaddr cb_location;
	uint32_t	cb_ident;
};

struct nfsv4_args_setclientid_confirm {
	uint64_t	clientid;
	struct nfsv4_verifier verifier;
};

struct nfsv4_args_write {
	struct nfsv4_stateid stateid;
	uint64_t	offset;
	uint32_t	stable;
	uint32_t	len;
	u_int		pos;		/* of the data, in the stream */
};

struct nfsv4_args_release_lockowner {
	struct nfsv4_owner owner;
};

/* RFC 8881 s18.35.1; what is not kept is decoded only to be passed. */
struct nfsv4_args_exchange_id {
	struct nfsv4_verifier verifier;
	uint32_t	idlen;
	uint8_t		id[NFS4_OPAQUE_LIMIT];
	uint32_t	flags;
	uint32_t	how;
};

/* channel_attrs4, RFC 8881 s18.36.1 */
struct nfsv4_chanattrs {
	uint32_t	ca_headerpad;
	uint32_t	ca_maxreq;
	uint32_t	ca_maxresp;
	uint32_t	ca_maxcached;
	uint32_t	ca_maxops;
	uint32_t	ca_maxreqs;
	uint32_t	ca_nird;	/* 0 or 1 */
	uint32_t	ca_ird;
};

/* What is kept of callback_sec_parms4<>, RFC 8881 s18.33.1. */
struct nfsv4_cbsec {
	bool		cs_gss;		/* one is RPCSEC_GSS */
	bool		cs_any;		/* one can be used */
	uint32_t	cs_flavor;	/* the first of the others */
	uint32_t	cs_uid;		/* of AUTH_SYS */
	uint32_t	cs_gid;
};

struct nfsv4_args_create_session {
	uint64_t	clientid;
	uint32_t	sequence;
	uint32_t	flags;
	struct nfsv4_chanattrs fore;
	struct nfsv4_chanattrs back;
	uint32_t	cb_program;
	struct nfsv4_cbsec sec;
};

struct nfsv4_args_backchannel_ctl {
	uint32_t	cb_program;
	struct nfsv4_cbsec sec;
};

struct nfsv4_sessionid {
	uint8_t		sid_data[NFS4_SESSIONID_SIZE];
};

struct nfsv4_args_sessionid {		/* DESTROY_SESSION */
	struct nfsv4_sessionid sessionid;
};

struct nfsv4_args_bind_conn {
	struct nfsv4_sessionid sessionid;
	uint32_t	dir;
	uint32_t	rdma;
};

struct nfsv4_args_sequence {
	struct nfsv4_sessionid sessionid;
	uint32_t	sequenceid;
	uint32_t	slotid;
	uint32_t	highest_slotid;
	uint32_t	cachethis;
};

struct nfsv4_args_test_stateid {
	uint32_t	count;
	u_int		pos;		/* of the first, in the stream */
};

struct nfsv4_args_u32 {			/* RECLAIM_COMPLETE, SECINFO_NO_NAME */
	uint32_t	value;
};

struct nfsv4_args_get_dir_delegation {
	uint32_t	signal;		/* gdda_signal_deleg_avail */
};

struct nfsv4_args_want_delegation {
	uint32_t	want;
	uint32_t	delegate_type;	/* CLAIM_PREVIOUS */
	uint32_t	claim;		/* deleg_claim4 */
};

/* ALLOCATE and DEALLOCATE, RFC 7862 s15.1.1, s15.4.1 */
struct nfsv4_args_range {
	struct nfsv4_stateid stateid;
	uint64_t	offset;
	uint64_t	length;
};

/* COPY, RFC 7862 s15.2.1, and CLONE, s15.13.1 */
struct nfsv4_args_copy {
	struct nfsv4_stateid src_stateid;
	struct nfsv4_stateid dst_stateid;
	uint64_t	src_offset;
	uint64_t	dst_offset;
	uint64_t	count;
	uint32_t	consecutive;
	uint32_t	synchronous;
	uint32_t	nsources;	/* of ca_source_server<>, not kept */
};

/* RFC 7862 s15.5.1 */
struct nfsv4_args_io_advise {
	struct nfsv4_stateid stateid;
	uint64_t	offset;
	uint64_t	count;
	struct nfsv4_bitmap hints;
};

/* RFC 7862 s15.11.1 */
struct nfsv4_args_seek {
	struct nfsv4_stateid stateid;
	uint64_t	offset;
	uint32_t	what;
};

/* RFC 7862 s15.12.1, with adb_pattern left in the stream */
struct nfsv4_args_write_same {
	struct nfsv4_stateid stateid;
	uint32_t	stable;
	uint64_t	offset;
	uint64_t	block_size;
	uint64_t	block_count;
	uint64_t	reloff_blocknum;
	uint32_t	block_num;
	uint64_t	reloff_pattern;
	uint32_t	pattern_len;
	u_int		pattern_pos;
};

/* RFC 8276 s8.4.2.1, with sxa_value left in the stream */
struct nfsv4_args_setxattr {
	uint32_t	option;
	struct nfsv4_name key;
	uint32_t	len;
	u_int		pos;
};

/* RFC 8276 s8.4.3.1 */
struct nfsv4_args_listxattrs {
	uint64_t	cookie;
	uint32_t	maxcount;
};

union nfsv4_args {
	struct nfsv4_args_want_delegation want_delegation;
	struct nfsv4_args_get_dir_delegation get_dir_delegation;
	struct nfsv4_args_exchange_id	exchange_id;
	struct nfsv4_args_create_session create_session;
	struct nfsv4_args_backchannel_ctl backchannel_ctl;
	struct nfsv4_args_sessionid	sessionid;
	struct nfsv4_args_bind_conn	bind_conn;
	struct nfsv4_args_sequence	sequence;
	struct nfsv4_args_test_stateid	test_stateid;
	struct nfsv4_args_u32		u32;
	struct nfsv4_args_access	access;
	struct nfsv4_args_close		close;
	struct nfsv4_args_commit	commit;
	struct nfsv4_args_create	create;
	struct nfsv4_args_clientid	clientid;
	struct nfsv4_args_stateid	stateid;
	struct nfsv4_args_getattr	getattr;
	struct nfsv4_args_name		name;
	struct nfsv4_args_lock		lock;
	struct nfsv4_args_lockt		lockt;
	struct nfsv4_args_locku		locku;
	struct nfsv4_args_verify	verify;
	struct nfsv4_args_open		open;
	struct nfsv4_args_openattr	openattr;
	struct nfsv4_args_open_confirm	open_confirm;
	struct nfsv4_args_open_downgrade open_downgrade;
	struct nfsv4_args_putfh		putfh;
	struct nfsv4_args_read		read;
	struct nfsv4_args_readdir	readdir;
	struct nfsv4_args_rename	rename;
	struct nfsv4_args_setattr	setattr;
	struct nfsv4_args_setclientid	setclientid;
	struct nfsv4_args_setclientid_confirm setclientid_confirm;
	struct nfsv4_args_write		write;
	struct nfsv4_args_release_lockowner release_lockowner;
	struct nfsv4_args_range		range;
	struct nfsv4_args_copy		copy;
	struct nfsv4_args_io_advise	io_advise;
	struct nfsv4_args_seek		seek;
	struct nfsv4_args_write_same	write_same;
	struct nfsv4_args_setxattr	setxattr;
	struct nfsv4_args_listxattrs	listxattrs;
};

/* Pieces shared by several operations, or by the results. */
bool	nfsv4_xdr_bitmap(XDR *, struct nfsv4_bitmap *);
bool	nfsv4_xdr_u32(XDR *, uint32_t);
bool	nfsv4_xdr_name(XDR *, struct nfsv4_name *);
bool	nfsv4_xdr_link(XDR *, struct nfsv4_link *);
bool	nfsv4_xdr_fh(XDR *, struct nfsv4_fh *);
bool	nfsv4_xdr_stateid(XDR *, struct nfsv4_stateid *);
bool	nfsv4_xdr_verifier(XDR *, struct nfsv4_verifier *);
bool	nfsv4_xdr_fattr(XDR *, struct nfsv4_fattr *);
bool	nfsv4_xdr_owner(XDR *, struct nfsv4_owner *);
bool	nfsv4_xdr_change_info(XDR *, struct nfsv4_change_info *);
bool	nfsv4_xdr_clientaddr(XDR *, struct nfsv4_clientaddr *);
bool	nfsv4_xdr_lock_denied(XDR *, struct nfsv4_lock_denied *);
bool	nfsv4_xdr_open_deleg(XDR *, struct nfsv4_open_deleg *);
bool	nfsv4_xdr_chanattrs(XDR *, struct nfsv4_chanattrs *);
bool	nfsv4_xdr_sessionid(XDR *, struct nfsv4_sessionid *);
bool	nfsv4_xdr_skip(XDR *, u_int);
bool	nfsv4_xdr_pad(XDR *, u_int);

/*
 * The arguments of operation op in a minor version.  False means they did not decode,
 * and is NFS4ERR_BADXDR: RFC 7530 s15.2.4 for a server decoding each
 * operation as it comes to it.
 */
bool	nfsv4_xdr_args(XDR *, uint32_t, uint32_t, union nfsv4_args *);

#endif /* !_FS_NFSV4_NFSV4_XDR_H_ */
