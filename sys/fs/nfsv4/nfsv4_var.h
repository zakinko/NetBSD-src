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

#include <oncrpc/oncrpc.h>

#include <fs/nfsv4/nfsv4_xdr.h>

struct mount;
struct vattr;
struct vnode;

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
};

/*
 * What is being done for one COMPOUND.  Its operations run in order in
 * one thread, so nothing here needs a lock.
 */
struct nfsv4_compound {
	struct oncrpc_req *c_rq;
	XDR		*c_ax;		/* arguments */
	XDR		*c_rx;		/* results */
	struct nfsv4_cfh c_cur;		/* RFC 7530 s15.2.4.1 */
	struct nfsv4_cfh c_saved;
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

/* Room for one object's attributes, not counting the bitmap. */
#define	NFSV4_ATTRBUF		2048

uint32_t nfsv4_attr_fill(struct nfsv4_compound *, const struct nfsv4_cfh *,
	    const struct nfsv4_bitmap *, uint32_t, char *, size_t,
	    struct nfsv4_bitmap *, u_int *);
uint64_t nfsv4_attr_change(const struct vattr *);
bool	nfsv4_attr_getonly_ok(const struct nfsv4_bitmap *);
int	nfsv4_access_vp(const struct nfsv4_cfh *, int);

uint32_t nfsv4_errno(int);
uint32_t nfsv4_name_check(const struct nfsv4_name *);

void	nfsv4_cfh_clear(struct nfsv4_cfh *);
uint32_t nfsv4_cfh_lookup(struct nfsv4_compound *, struct nfsv4_cfh *,
	    const char *, size_t, struct nfsv4_cfh *);
const char *nfsv4_cfh_path(const struct nfsv4_cfh *, size_t *);
int	nfsv4_lookup_vp(struct vnode *, const char *, kauth_cred_t,
	    struct vnode **);
int	nfsv4_pseudo_walk(struct nfsv4_compound *, const char *, size_t,
	    int (*)(struct mount *, const char *, size_t, void *), void *);

uint32_t nfsv4_op_access(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_getattr(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_readdir(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_readlink(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_secinfo(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_getfh(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_lookup(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_lookupp(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_putfh(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_putpubfh(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_putrootfh(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_restorefh(struct nfsv4_compound *, union nfsv4_args *);
uint32_t nfsv4_op_savefh(struct nfsv4_compound *, union nfsv4_args *);

#endif /* !_FS_NFSV4_NFSV4_VAR_H_ */
