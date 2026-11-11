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
 * Chunks, RFC 8166 s3.4 and s3.5: how a reduced Payload stream goes
 * back together, and how a reply is cut up to fit what the Requester
 * offered.  This is all arithmetic on lengths.  Moving the bytes is the
 * caller's.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/errno.h>
#ifdef _KERNEL
#include <sys/endian.h>
#include <sys/systm.h>
#else
#include <errno.h>
#include <string.h>
#endif

#include <oncrpc/oncrpc_rdma.h>

#define	PADLEN(n)	((4 - ((n) & 3)) & 3)
#define	ROUNDUP4(n)	((uint64_t)(n) + PADLEN(n))

/*
 * Group the read segments by Position: rc is as long as rh_nread, and
 * gets the Read chunks in order of Position, the one at zero first.
 * RFC 8166 s3.4.5 keeps the segments of a chunk in list order and says
 * nothing of the order of chunks, so the sort must be a stable one; the
 * lists fit in a Receive buffer, so one this simple is cheap enough.
 * max is the most bytes this end will pull, s8.1.4: EFBIG beyond it.
 */
int
oncrpc_rdma_reads_group(struct oncrpc_rdma_hdr *h,
    struct oncrpc_rdma_rchunk *rc, u_int *nrcp, uint64_t max)
{
	struct oncrpc_rdma_rseg t;
	uint64_t total = 0, clen;
	u_int i, j, n;

	for (i = 0; i < h->rh_nread; i++) {
		/* s3.4.5: "MUST be a multiple of four" */
		if ((h->rh_reads[i].rr_position & 3) != 0)
			return EINVAL;
		t = h->rh_reads[i];
		for (j = i; j > 0 &&
		    h->rh_reads[j - 1].rr_position > t.rr_position; j--)
			h->rh_reads[j] = h->rh_reads[j - 1];
		h->rh_reads[j] = t;
	}

	n = 0;
	clen = 0;
	for (i = 0; i < h->rh_nread; i++) {
		t = h->rh_reads[i];
		if (i == 0 || t.rr_position != rc[n - 1].rc_pos) {
			rc[n].rc_pos = t.rr_position;
			rc[n].rc_first = i;
			rc[n].rc_nseg = 0;
			rc[n].rc_len = 0;
			clen = 0;
			n++;
		}
		/* No wrap in the Requester's memory. */
		if (t.rr_seg.rs_offset + t.rr_seg.rs_length <
		    t.rr_seg.rs_offset)
			return EINVAL;
		rc[n - 1].rc_nseg++;
		clen += t.rr_seg.rs_length;
		total += t.rr_seg.rs_length;
		if (total > max)
			return EFBIG;
		rc[n - 1].rc_len = (uint32_t)clen;
	}
	*nrcp = n;
	return 0;
}

enum { RL_BASE, RL_CHUNK, RL_PAD, RL_TAIL, RL_END };

/*
 * Walk the pieces of the unreduced stream: the base, which is what came
 * inline or by the Position Zero Read chunk, with the n Read chunks of
 * rc, none at Position zero, between its bytes.  The Position is
 * counted in the unreduced stream, s3.4.5, so the place in the base is
 * less by what earlier chunks put in.
 */
void
oncrpc_rdma_layout_init(struct oncrpc_rdma_layout *rl,
    const struct oncrpc_rdma_rchunk *rc, u_int n, u_int baselen)
{

	memset(rl, 0, sizeof(*rl));
	rl->rl_c = rc;
	rl->rl_n = n;
	rl->rl_baselen = baselen;
	rl->rl_state = RL_BASE;
}

/* Does every Position land inside the base? */
bool
oncrpc_rdma_layout_check(const struct oncrpc_rdma_layout *rl)
{
	uint64_t grown = 0, at;
	u_int i, off = 0;

	for (i = 0; i < rl->rl_n; i++) {
		if (rl->rl_c[i].rc_pos < grown)
			return false;
		at = rl->rl_c[i].rc_pos - grown;
		if (at < off || at > rl->rl_baselen)
			return false;
		off = (u_int)at;
		grown += ROUNDUP4(rl->rl_c[i].rc_len);
	}
	return true;
}

bool
oncrpc_rdma_layout_next(struct oncrpc_rdma_layout *rl,
    struct oncrpc_rdma_piece *p)
{
	const struct oncrpc_rdma_rchunk *c;
	uint64_t at;

	memset(p, 0, sizeof(*p));
	for (;;) {
		switch (rl->rl_state) {
		case RL_BASE:
			if (rl->rl_i == rl->rl_n) {
				rl->rl_state = RL_TAIL;
				continue;
			}
			c = &rl->rl_c[rl->rl_i];
			at = c->rc_pos - rl->rl_grown;
			rl->rl_state = RL_CHUNK;
			if (at == rl->rl_off)
				continue;
			p->rp_type = RDMA_P_BASE;
			p->rp_off = rl->rl_off;
			p->rp_len = (u_int)at - rl->rl_off;
			rl->rl_off = (u_int)at;
			return true;
		case RL_CHUNK:
			rl->rl_state = RL_PAD;
			p->rp_type = RDMA_P_CHUNK;
			p->rp_chunk = rl->rl_i;
			return true;
		case RL_PAD:
			c = &rl->rl_c[rl->rl_i];
			rl->rl_grown += ROUNDUP4(c->rc_len);
			rl->rl_i++;
			rl->rl_state = RL_BASE;
			/* s3.4.5.2: the chunk SHOULD NOT carry the padding. */
			if (PADLEN(c->rc_len) == 0)
				continue;
			p->rp_type = RDMA_P_PAD;
			p->rp_len = PADLEN(c->rc_len);
			return true;
		case RL_TAIL:
			rl->rl_state = RL_END;
			if (rl->rl_off == rl->rl_baselen)
				return false;
			p->rp_type = RDMA_P_BASE;
			p->rp_off = rl->rl_off;
			p->rp_len = rl->rl_baselen - rl->rl_off;
			return true;
		default:
			return false;
		}
	}
}

static uint32_t
get32(const uint8_t *p)
{

	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	    (uint32_t)p[2] << 8 | p[3];
}

/*
 * The head of an RPC message, RFC 5531 s9.  Only the first two words
 * need be there for a reply.  All false says this is too short to be
 * anything; a call that goes wrong later is for the RPC layer to answer.
 */
bool
oncrpc_rdma_call_peek(const void *buf, u_int len,
    struct oncrpc_rdma_callinfo *ri)
{
	const uint8_t *p = buf;
	uint32_t alen;
	u_int off, i;

	memset(ri, 0, sizeof(*ri));
	if (len < 8)
		return false;
	ri->ri_xid = get32(p);
	ri->ri_mtype = get32(p + 4);
	if (len < 24)
		return true;
	ri->ri_rpcvers = get32(p + 8);
	ri->ri_prog = get32(p + 12);
	ri->ri_vers = get32(p + 16);
	ri->ri_proc = get32(p + 20);
	off = 24;
	for (i = 0; i < 2; i++) {	/* cred, verf */
		if (len - off < 8)
			return true;
		alen = get32(p + off + 4);
		off += 8;
		if (alen > len - off || ROUNDUP4(alen) > len - off)
			return true;
		if (i == 0) {
			ri->ri_flavor = get32(p + off - 8);
			/*
			 * RFC 2203 s5: the body of an RPCSEC_GSS credential
			 * is the version, gss_proc, seq_num and service, and
			 * only rpc_gss_svc_none (1) of RPCSEC_GSS_DATA (0)
			 * leaves the arguments as the program has them.
			 */
			ri->ri_plain = ri->ri_flavor != 6 ||
			    (alen >= 16 && get32(p + off + 4) == 0 &&
			    get32(p + off + 12) == 1);
		}
		off += (u_int)ROUNDUP4(alen);
	}
	ri->ri_argoff = off;
	return true;
}

/*
 * Where the results of a reply begin, RFC 5531 s9: past the verifier of
 * an accepted reply whose accept_stat is SUCCESS.  False for any other.
 */
bool
oncrpc_rdma_reply_peek(const void *buf, u_int len, u_int *offp)
{
	const uint8_t *p = buf;
	uint32_t alen;
	u_int off;

	/* xid, REPLY (1), MSG_ACCEPTED (0), the verifier's flavor, length */
	if (len < 20 || get32(p + 4) != 1 || get32(p + 8) != 0)
		return false;
	alen = get32(p + 16);
	off = 20;
	if (alen > 400 || ROUNDUP4(alen) + 4 > len - off)	/* s8.2 */
		return false;
	off += (u_int)ROUNDUP4(alen);
	if (get32(p + off) != 0)		/* SUCCESS */
		return false;
	*offp = off + 4;
	return true;
}

void
oncrpc_rdma_ddp_init(struct oncrpc_rdma_ddpscan *rd,
    const struct oncrpc_rdma_rchunk *rc, u_int n)
{

	rd->rd_c = rc;
	rd->rd_n = n;
	rd->rd_next = 0;
	rd->rd_grown = 0;
}

/*
 * A DDP-eligible item of count bytes at pos in the reduced stream.  If
 * the next chunk is where this item would start, it is this item, and
 * nothing of it is in the base; else it came inline.  False is a chunk
 * of the wrong length: s3.4.5.2 allows exactly count, or that with the
 * roundup.
 */
bool
oncrpc_rdma_ddp_item(struct oncrpc_rdma_ddpscan *rd, u_int pos, uint32_t count,
    uint32_t *skipp)
{
	const struct oncrpc_rdma_rchunk *c;

	if (rd->rd_next < rd->rd_n) {
		c = &rd->rd_c[rd->rd_next];
		if (c->rc_pos == pos + rd->rd_grown) {
			if (c->rc_len != count && c->rc_len != ROUNDUP4(count))
				return false;
			rd->rd_grown += ROUNDUP4(count);
			rd->rd_next++;
			*skipp = 0;
			return true;
		}
	}
	/* The caller's stepping over this fails if it wraps. */
	*skipp = ROUNDUP4(count) > UINT32_MAX ? UINT32_MAX :
	    (uint32_t)ROUNDUP4(count);
	return true;
}

bool
oncrpc_rdma_ddp_done(const struct oncrpc_rdma_ddpscan *rd)
{

	return rd->rd_next == rd->rd_n;
}

static uint64_t
chunk_room(const struct oncrpc_rdma_wchunk *rw)
{
	uint64_t n = 0;
	u_int i;

	for (i = 0; i < rw->rw_nseg; i++)
		n += rw->rw_segs[i].rs_length;
	return n;
}

/*
 * Decide the form of a reply of paylen bytes with nmark DDP-eligible
 * items, marks in order.  chunkof[i] is the Write chunk of mark i, or
 * ONCRPC_RDMA_INLINE_ITEM.  thresh is the reply inline threshold, s3.3.2.
 *
 * Pairing is RFC 8267 s6.4.1, the first item with the first chunk.  An
 * item with an empty chunk, or with none, stays in the stream.  An item
 * too big for a chunk that was offered has no good answer: s4.3.2 has
 * it "MUST push", and RFC 8267 s3.1 says such a reply is an error.
 */
void
oncrpc_rdma_reply_plan(const struct oncrpc_rdma_hdr *call,
    const struct oncrpc_rdma_mark *marks, u_int nmark, u_int paylen,
    u_int thresh, int *chunkof, struct oncrpc_rdma_plan *rp)
{
	struct oncrpc_rdma_hdr h;
	uint64_t cut = 0;
	u_int i, reduced, total;

	memset(rp, 0, sizeof(*rp));
	rp->rp_form = ONCRPC_RDMA_NOFIT;
	for (i = 0; i < nmark; i++) {
		chunkof[i] = ONCRPC_RDMA_INLINE_ITEM;
		if (i >= call->rh_nwrite ||
		    call->rh_writes[i].rw_nseg == 0)
			continue;
		if (marks[i].dm_len > chunk_room(&call->rh_writes[i]))
			return;
		chunkof[i] = (int)i;
		cut += ROUNDUP4(marks[i].dm_len);
	}
	if (cut > paylen)
		return;
	reduced = paylen - (u_int)cut;
	rp->rp_reduced = reduced;

	h = *call;
	h.rh_nread = 0;		/* s4.3.1 */
	rp->rp_hdrlen = oncrpc_rdma_hdr_size(&h);

	total = rp->rp_hdrlen + reduced;
	if (total <= thresh) {
		rp->rp_form = ONCRPC_RDMA_SHORT;
		return;
	}
	/* s3.5.3 */
	if (call->rh_hasreply && reduced <= chunk_room(&call->rh_reply))
		rp->rp_form = ONCRPC_RDMA_LONG;
}

/*
 * Say how much of a chunk was used, s3.4.6: contiguously and in array
 * order.  A chunk with nothing in it keeps its segments, all empty.
 */
void
oncrpc_rdma_chunk_fill(struct oncrpc_rdma_wchunk *rw, uint32_t len)
{
	struct oncrpc_rdma_seg *s;
	u_int i;

	for (i = 0; i < rw->rw_nseg; i++) {
		s = &rw->rw_segs[i];
		if (s->rs_length > len)
			s->rs_length = len;
		len -= s->rs_length;
	}
}

/*
 * The header of a reply: the Requester's chunks, already filled, s4.3.2
 * and s4.3.3, and no Read list, s4.3.1.
 */
void
oncrpc_rdma_reply_hdr(const struct oncrpc_rdma_hdr *call, uint32_t credit,
    bool nomsg, struct oncrpc_rdma_hdr *h)
{

	*h = *call;
	h->rh_credit = credit;
	h->rh_proc = nomsg ? ONCRPC_RDMA_NOMSG : ONCRPC_RDMA_MSG;
	h->rh_nread = 0;
	h->rh_reads = NULL;
	h->rh_mem = NULL;
}

/* RFC 8166 s3.3.3: one credit until the peer has said otherwise. */
void
oncrpc_rdma_bc_init(struct oncrpc_rdma_bc *rb)
{

	rb->rb_granted = 1;
	rb->rb_inflight = 0;
}

/* May another reverse Call go?  If so it has been counted. */
bool
oncrpc_rdma_bc_start(struct oncrpc_rdma_bc *rb)
{

	if (rb->rb_inflight >= rb->rb_granted)
		return false;
	rb->rb_inflight++;
	return true;
}

/* A reverse Reply came, with this grant, RFC 8167 s5.2. */
void
oncrpc_rdma_bc_done(struct oncrpc_rdma_bc *rb, uint32_t credit)
{

	if (rb->rb_inflight > 0)
		rb->rb_inflight--;
	/* RFC 8166 s3.3.1: zero "MUST NOT" be granted; keep the last one. */
	if (credit != 0)
		rb->rb_granted = credit;
}
