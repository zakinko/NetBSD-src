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

#ifndef _ONCRPC_ONCRPC_RDMA_H_
#define _ONCRPC_ONCRPC_RDMA_H_

/*
 * RPC-over-RDMA version 1, RFC 8166, as the Responder: the header, the
 * chunks, and what a program's upper-layer binding (ULB) has to say.
 * Nothing here knows about the kernel or about the RDMA provider, so
 * all of it also runs in userland under tests/modules/t_oncrpc_rdma.c.
 */

#include <sys/types.h>
#ifdef _KERNEL
#include <sys/stdbool.h>
#else
#include <stdbool.h>
#endif

#include <rpc/types.h>
#include <rpc/xdr.h>

#define	ONCRPC_RDMA_VERS	1	/* RFC 8166 s4.2.2 */
#define	ONCRPC_RDMA_MINHDR	28	/* RFC 8166 s4.5 */
#define	ONCRPC_RDMA_INLINE_MIN	1024	/* RFC 8166 s3.3.3 */
#define	ONCRPC_RDMA_PORT	20049	/* RFC 8267 s9 */

/* RFC 8166 s4.1.2, enum rdma_proc */
#define	ONCRPC_RDMA_MSG		0
#define	ONCRPC_RDMA_NOMSG	1
#define	ONCRPC_RDMA_MSGP	2	/* not to be used, s4.6.1 */
#define	ONCRPC_RDMA_DONE	3	/* not to be used, s4.6.2 */
#define	ONCRPC_RDMA_ERROR	4

/* RFC 8166 s4.1.2, enum rpc_rdma_errcode */
#define	ONCRPC_RDMA_ERR_VERS	1
#define	ONCRPC_RDMA_ERR_CHUNK	2

/* RFC 8797 s4, the CM Private Data of version 1 */
#define	ONCRPC_RDMA_CMP_MAGIC	0xf6ab0e18U
#define	ONCRPC_RDMA_CMP_VERS	1
#define	ONCRPC_RDMA_CMP_LEN	8
#define	ONCRPC_RDMA_CMP_R	0x01	/* s4.1, remote invalidation */

/* RFC 8166 s4.1.2, xdr_rdma_segment */
struct oncrpc_rdma_seg {
	uint32_t	rs_handle;
	uint32_t	rs_length;
	uint64_t	rs_offset;
};

/* RFC 8166 s4.1.2, xdr_read_chunk */
struct oncrpc_rdma_rseg {
	uint32_t	rr_position;
	struct oncrpc_rdma_seg rr_seg;
};

/* RFC 8166 s4.1.2, xdr_write_chunk */
struct oncrpc_rdma_wchunk {
	uint32_t	rw_nseg;
	struct oncrpc_rdma_seg *rw_segs;
};

/*
 * A Transport stream.  RFC 8166 sets no limit on the chunk lists, and
 * neither does this: the lists are as long as the header says, and the
 * header is as long as an inline message can be.
 */
struct oncrpc_rdma_hdr {
	uint32_t	rh_xid;
	uint32_t	rh_vers;
	uint32_t	rh_credit;
	uint32_t	rh_proc;
	u_int		rh_hdrlen;	/* of the Transport stream */
	u_int		rh_nread;
	struct oncrpc_rdma_rseg *rh_reads;
	u_int		rh_nwrite;
	struct oncrpc_rdma_wchunk *rh_writes;
	bool		rh_hasreply;
	struct oncrpc_rdma_wchunk rh_reply;
	void		*rh_mem;	/* holds the lists */
	size_t		rh_memlen;
};

/* What a Responder is to do with a message, RFC 8166 s4.5. */
enum oncrpc_rdma_dec {
	ONCRPC_RDMA_DEC_OK,
	ONCRPC_RDMA_DEC_DROP,		/* discard in silence */
	ONCRPC_RDMA_DEC_ERR_VERS,	/* RDMA_ERROR, ERR_VERS */
	ONCRPC_RDMA_DEC_ERR_CHUNK	/* RDMA_ERROR, ERR_CHUNK */
};

enum oncrpc_rdma_dec
	oncrpc_rdma_hdr_decode(const void *, u_int, struct oncrpc_rdma_hdr *);
void	oncrpc_rdma_hdr_fini(struct oncrpc_rdma_hdr *);
u_int	oncrpc_rdma_hdr_size(const struct oncrpc_rdma_hdr *);
bool	oncrpc_rdma_hdr_encode(XDR *, const struct oncrpc_rdma_hdr *);
bool	oncrpc_rdma_error_encode(XDR *, uint32_t, uint32_t, uint32_t, uint32_t);

/* One Read chunk: the rseg of one Position, RFC 8166 s3.4.5. */
struct oncrpc_rdma_rchunk {
	uint32_t	rc_pos;
	u_int		rc_first;	/* in rh_reads */
	u_int		rc_nseg;
	uint32_t	rc_len;
};

int	oncrpc_rdma_reads_group(struct oncrpc_rdma_hdr *,
	    struct oncrpc_rdma_rchunk *, u_int *, uint64_t);

/* One step in putting a reduced Payload stream back together. */
enum oncrpc_rdma_ptype { RDMA_P_BASE, RDMA_P_CHUNK, RDMA_P_PAD };

struct oncrpc_rdma_piece {
	enum oncrpc_rdma_ptype rp_type;
	u_int		rp_off;		/* RDMA_P_BASE */
	u_int		rp_len;		/* RDMA_P_BASE, RDMA_P_PAD */
	u_int		rp_chunk;	/* RDMA_P_CHUNK */
};

struct oncrpc_rdma_layout {
	const struct oncrpc_rdma_rchunk *rl_c;
	u_int		rl_n;
	u_int		rl_i;
	int		rl_state;
	u_int		rl_baselen;
	u_int		rl_off;		/* in the base */
	uint64_t	rl_grown;	/* chunk bytes before rl_off */
};

void	oncrpc_rdma_layout_init(struct oncrpc_rdma_layout *,
	    const struct oncrpc_rdma_rchunk *, u_int, u_int);
bool	oncrpc_rdma_layout_check(const struct oncrpc_rdma_layout *);
bool	oncrpc_rdma_layout_next(struct oncrpc_rdma_layout *,
	    struct oncrpc_rdma_piece *);

/* The fixed part of an RPC message at the head of a Payload stream. */
struct oncrpc_rdma_callinfo {
	uint32_t	ri_xid;
	uint32_t	ri_mtype;
	uint32_t	ri_rpcvers;
	uint32_t	ri_prog;
	uint32_t	ri_vers;
	uint32_t	ri_proc;
	u_int		ri_argoff;	/* in the reduced stream */
	uint32_t	ri_flavor;	/* of the credential */
	bool		ri_plain;	/* the arguments are not wrapped */
};

bool	oncrpc_rdma_call_peek(const void *, u_int,
	    struct oncrpc_rdma_callinfo *);
bool	oncrpc_rdma_reply_peek(const void *, u_int, u_int *);

/*
 * Going through the arguments of a call, looking for what the chunks
 * took out.  Binding code stops at each DDP-eligible item, its length
 * word read, and asks with oncrpc_rdma_ddp_item() how much of the base
 * stream to step over.  A chunk that no item claims is a data item
 * reduced that may not be, RFC 8166 s6.1.
 */
struct oncrpc_rdma_ddpscan {
	const struct oncrpc_rdma_rchunk *rd_c;
	u_int		rd_n;
	u_int		rd_next;
	uint64_t	rd_grown;
};

void	oncrpc_rdma_ddp_init(struct oncrpc_rdma_ddpscan *,
	    const struct oncrpc_rdma_rchunk *, u_int);
bool	oncrpc_rdma_ddp_item(struct oncrpc_rdma_ddpscan *, u_int, uint32_t,
	    uint32_t *);
bool	oncrpc_rdma_ddp_done(const struct oncrpc_rdma_ddpscan *);

/* A DDP-eligible result, in the unreduced Payload stream. */
struct oncrpc_rdma_mark {
	u_int		dm_pos;
	u_int		dm_len;
};

/*
 * An upper-layer binding, RFC 8166 s6.  ub_scan walks the arguments of
 * proc at off in the reduced stream, and returns false if they do not
 * parse.  The DDP-eligible results are told to the transport as they
 * are encoded, by oncrpc_req_ddp_result().
 *
 * A program that hands the transport whole replies it made itself has
 * no place to say that, and gives ub_reply instead: given the first len
 * bytes of a reply of total bytes, its results at off, it finds the one
 * eligible item there may be, and returns false for none.  Only the
 * bindings of RFC 8267 s4 need it, as no reply of theirs has two.
 */
struct oncrpc_rdma_ulb {
	bool	(*ub_scan)(const void *, u_int, u_int, uint32_t, uint32_t,
		    struct oncrpc_rdma_ddpscan *);
	bool	(*ub_reply)(const void *, u_int, u_int, u_int, uint32_t,
		    uint32_t, struct oncrpc_rdma_mark *);
};

/* Bytes of a reply ub_reply may need: the RPC header and a fattr3. */
#define	ONCRPC_RDMA_REPLY_PEEK	1024

extern const struct oncrpc_rdma_ulb oncrpc_rdma_ulb_nfs23;
extern const struct oncrpc_rdma_ulb oncrpc_rdma_ulb_nfsacl;

enum oncrpc_rdma_form {
	ONCRPC_RDMA_SHORT,	/* RDMA_MSG, the stream inline, s3.5.1 */
	ONCRPC_RDMA_LONG,	/* RDMA_NOMSG, by the Reply chunk, s3.5.3 */
	ONCRPC_RDMA_NOFIT	/* RDMA_ERROR, ERR_CHUNK */
};

struct oncrpc_rdma_plan {
	enum oncrpc_rdma_form rp_form;
	u_int		rp_reduced;	/* bytes left of the stream */
	u_int		rp_hdrlen;
};

#define	ONCRPC_RDMA_INLINE_ITEM	(-1)

void	oncrpc_rdma_reply_plan(const struct oncrpc_rdma_hdr *,
	    const struct oncrpc_rdma_mark *, u_int, u_int, u_int, int *,
	    struct oncrpc_rdma_plan *);
void	oncrpc_rdma_chunk_fill(struct oncrpc_rdma_wchunk *, uint32_t);
void	oncrpc_rdma_reply_hdr(const struct oncrpc_rdma_hdr *, uint32_t, bool,
	    struct oncrpc_rdma_hdr *);

/*
 * Reverse direction, RFC 8167: credits apart from those of the forward
 * direction, s4.1.  The ULP says when it may be used, s6.
 */
struct oncrpc_rdma_bc {
	uint32_t	rb_granted;
	uint32_t	rb_inflight;
};

void	oncrpc_rdma_bc_init(struct oncrpc_rdma_bc *);
bool	oncrpc_rdma_bc_start(struct oncrpc_rdma_bc *);
void	oncrpc_rdma_bc_done(struct oncrpc_rdma_bc *, uint32_t);

#endif /* !_ONCRPC_ONCRPC_RDMA_H_ */
