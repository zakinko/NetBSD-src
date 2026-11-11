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
 * The upper-layer binding of NFS version 4 on RPC-over-RDMA, RFC 8267
 * s6.  s6.1 makes the data of WRITE and the linkdata of CREATE of an
 * NF4LNK the only arguments that may be reduced.  An operation has to
 * be decoded to find where the next one starts, so the whole COMPOUND
 * up to the last Read chunk is walked before any of it runs: by the time
 * nfsv4_compound() got to a chunk that may not be there, it would have
 * done the operations before it, and RFC 8166 s6.1 says not to process
 * such a call at all.
 *
 * The results go the other way, in nfsv4_op_read() and
 * nfsv4_op_readlink(), by oncrpc_req_ddp_result().
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#ifdef _KERNEL
#include <sys/kmem.h>
#include <sys/systm.h>
#else
#include <stdlib.h>
#include <string.h>
#endif

#include <oncrpc/oncrpc_rdma.h>

#include <fs/nfsv4/nfsv4_xdr.h>

#define	U32(x, p)	(xdr_u_int32_t((x), (p)) != 0)
#define	U64(x, p)	(xdr_u_int64_t((x), (p)) != 0)

/* An eligible item, at its length word. */
static bool
scan_item(XDR *x, struct oncrpc_rdma_ddpscan *rd)
{
	uint32_t count, skip;
	uint64_t pos;

	if (!U32(x, &count) ||
	    !oncrpc_rdma_ddp_item(rd, XDR_GETPOS(x), count, &skip))
		return false;
	pos = (uint64_t)XDR_GETPOS(x) + skip;
	return pos <= UINT32_MAX && XDR_SETPOS(x, (u_int)pos);
}

static bool
scan_write(XDR *x, struct oncrpc_rdma_ddpscan *rd)
{
	struct nfsv4_stateid si;
	uint64_t offset;
	uint32_t stable;

	return nfsv4_xdr_stateid(x, &si) && U64(x, &offset) &&
	    U32(x, &stable) && scan_item(x, rd);
}

/* CREATE4args with an NF4LNK, at the name that follows the linkdata. */
static bool
scan_create(XDR *x, uint32_t minor, union nfsv4_args *a,
    struct oncrpc_rdma_ddpscan *rd)
{
	struct nfsv4_args_create *ac = &a->create;
	uint32_t type;
	u_int pos = XDR_GETPOS(x);

	if (!U32(x, &type))
		return false;
	if (type != NF4LNK)
		return XDR_SETPOS(x, pos) &&
		    nfsv4_xdr_args(x, NFSV4_OP_CREATE, minor, a);
	return scan_item(x, rd) && nfsv4_xdr_name(x, &ac->name) &&
	    nfsv4_xdr_fattr(x, &ac->attrs);
}

static bool
nfsv4_ulb_scan(const void *buf, u_int len, u_int off, uint32_t vers,
    uint32_t proc, struct oncrpc_rdma_ddpscan *rd)
{
	union nfsv4_args *a;
	uint32_t taglen, minor, numops, op, maxop, i;
	XDR x;
	bool ok;

	if (proc != NFSV4_PROC_COMPOUND)
		return true;		/* NULL: no chunk can match */

	xdrmem_create(&x, __UNCONST(buf), len, XDR_DECODE);
	if (!XDR_SETPOS(&x, off) || !U32(&x, &taglen) ||
	    !nfsv4_xdr_skip(&x, taglen) || !U32(&x, &minor) ||
	    !U32(&x, &numops))
		return false;
	/*
	 * s6.1 is the same for every minor version.  One the server does
	 * not have gets no further than NFS4ERR_MINOR_VERS_MISMATCH, so
	 * any chunk of it is one that nothing claims.
	 */
	if (minor > NFSV4_MINORMAX)
		return true;
	maxop = minor == 0 ? NFSV4_OP_RELEASE_LOCKOWNER :
	    NFSV4_OP_RECLAIM_COMPLETE;

#ifdef _KERNEL
	a = kmem_alloc(sizeof(*a), KM_SLEEP);
#else
	a = malloc(sizeof(*a));
#endif
	ok = true;
	for (i = 0; ok && i < numops && !oncrpc_rdma_ddp_done(rd); i++) {
		if (!U32(&x, &op) || op < NFSV4_OP_ACCESS ||
		    op > maxop) {
			ok = false;
			break;
		}
		switch (op) {
		case NFSV4_OP_WRITE:
			ok = scan_write(&x, rd);
			break;
		case NFSV4_OP_CREATE:
			ok = scan_create(&x, minor, a, rd);
			break;
		default:
			ok = nfsv4_xdr_args(&x, op, minor, a);
			break;
		}
	}
#ifdef _KERNEL
	kmem_free(a, sizeof(*a));
#else
	free(a);
#endif
	return ok;
}

const struct oncrpc_rdma_ulb nfsv4_ulb = {
	.ub_scan = nfsv4_ulb_scan,
};
