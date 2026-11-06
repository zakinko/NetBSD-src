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
 * The Transport stream of RPC-over-RDMA version 1, RFC 8166 s4.  A
 * header is short and sits whole in one Receive buffer, so it is read
 * from memory with the XDR filters, and twice: the lengths of the lists
 * are not known until they have been walked, and walking first means
 * nothing from the wire says how much to allocate.
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

#define	WORD		4
#define	SEG_WORDS	4	/* RFC 8166 s4.7, HLOO */

#ifdef _KERNEL
#define	HDR_ALLOC(n)	kmem_alloc((n), KM_SLEEP)
#define	HDR_FREE(p, n)	kmem_free((p), (n))
#else
#define	HDR_ALLOC(n)	malloc(n)
#define	HDR_FREE(p, n)	free(p)
#endif

static bool
hdr_opt(XDR *x, bool *present)
{
	uint32_t v;

	/* A boolean is 0 or 1, RFC 4506 s4.4. */
	if (!xdr_u_int32_t(x, &v) || v > 1)
		return false;
	*present = v != 0;
	return true;
}

static bool
hdr_seg(XDR *x, struct oncrpc_rdma_seg *s)
{

	return xdr_u_int32_t(x, &s->rs_handle) &&
	    xdr_u_int32_t(x, &s->rs_length) &&
	    xdr_u_int64_t(x, &s->rs_offset);
}

/* A counted array of segments; segs NULL to step over it. */
static bool
hdr_wchunk(XDR *x, u_int len, struct oncrpc_rdma_wchunk *rw,
    struct oncrpc_rdma_seg *segs)
{
	struct oncrpc_rdma_seg s;
	uint32_t n, i;

	if (!xdr_u_int32_t(x, &n))
		return false;
	/* Subtract: the count is off the wire. */
	if (n > (len - XDR_GETPOS(x)) / (SEG_WORDS * WORD))
		return false;
	rw->rw_nseg = n;
	rw->rw_segs = segs;
	for (i = 0; i < n; i++) {
		if (!hdr_seg(x, segs != NULL ? &segs[i] : &s))
			return false;
	}
	return true;
}

/*
 * The three lists after the fixed fields.  With fill false, count them
 * in rh_nread, rh_nwrite and *nsegp; with it true, put them where
 * those pointers say.
 */
static bool
hdr_lists(XDR *x, u_int len, struct oncrpc_rdma_hdr *h, u_int *nsegp, bool fill)
{
	struct oncrpc_rdma_seg *segs = fill ? h->rh_reply.rw_segs : NULL;
	struct oncrpc_rdma_rseg r;
	struct oncrpc_rdma_wchunk w;
	u_int nread = 0, nwrite = 0, nseg = 0;
	bool more;

	for (;;) {
		if (!hdr_opt(x, &more))
			return false;
		if (!more)
			break;
		if (!xdr_u_int32_t(x, &r.rr_position) ||
		    !hdr_seg(x, &r.rr_seg))
			return false;
		if (fill)
			h->rh_reads[nread] = r;
		nread++;
	}
	for (;;) {
		if (!hdr_opt(x, &more))
			return false;
		if (!more)
			break;
		if (!hdr_wchunk(x, len, &w, fill ? segs + nseg : NULL))
			return false;
		if (fill)
			h->rh_writes[nwrite] = w;
		nwrite++;
		nseg += w.rw_nseg;
	}
	if (!hdr_opt(x, &h->rh_hasreply))
		return false;
	if (h->rh_hasreply) {
		if (!hdr_wchunk(x, len, &w, fill ? segs + nseg : NULL))
			return false;
		if (fill)
			h->rh_reply = w;
		nseg += w.rw_nseg;
	}
	if (!fill) {
		h->rh_nread = nread;
		h->rh_nwrite = nwrite;
		*nsegp = nseg;
	}
	return true;
}

/*
 * Read a header as the Responder does: rh_mem is set only on
 * ONCRPC_RDMA_DEC_OK, and after anything but ONCRPC_RDMA_DEC_DROP the
 * fixed fields are good for making an RDMA_ERROR out of.
 */
enum oncrpc_rdma_dec
oncrpc_rdma_hdr_decode(const void *buf, u_int len, struct oncrpc_rdma_hdr *h)
{
	struct oncrpc_rdma_seg *segs;
	XDR x;
	char *mem;
	size_t msz, rsz, wsz, ssz;
	u_int start, nseg;

	memset(h, 0, sizeof(*h));

	/* s4.5: the XID of anything shorter cannot be trusted. */
	if (len < ONCRPC_RDMA_MINHDR)
		return ONCRPC_RDMA_DEC_DROP;

	xdrmem_create(&x, __UNCONST(buf), len, XDR_DECODE);
	if (!xdr_u_int32_t(&x, &h->rh_xid) ||
	    !xdr_u_int32_t(&x, &h->rh_vers) ||
	    !xdr_u_int32_t(&x, &h->rh_credit) ||
	    !xdr_u_int32_t(&x, &h->rh_proc))
		return ONCRPC_RDMA_DEC_DROP;

	if (h->rh_vers != ONCRPC_RDMA_VERS)	/* s4.5.1 */
		return ONCRPC_RDMA_DEC_ERR_VERS;

	switch (h->rh_proc) {
	case ONCRPC_RDMA_MSG:
	case ONCRPC_RDMA_NOMSG:
		break;
	case ONCRPC_RDMA_DONE:		/* s4.6.2 */
	case ONCRPC_RDMA_ERROR:		/* s4.2.4 */
		return ONCRPC_RDMA_DEC_DROP;
	case ONCRPC_RDMA_MSGP:		/* s4.6.1 */
	default:			/* s4.5.2 */
		return ONCRPC_RDMA_DEC_ERR_CHUNK;
	}

	start = XDR_GETPOS(&x);
	if (!hdr_lists(&x, len, h, &nseg, false))
		return ONCRPC_RDMA_DEC_ERR_CHUNK;
	h->rh_hdrlen = XDR_GETPOS(&x);

	rsz = h->rh_nread * sizeof(*h->rh_reads);
	wsz = h->rh_nwrite * sizeof(*h->rh_writes);
	ssz = nseg * sizeof(*segs);
	msz = rsz + wsz + ssz;
	if (msz != 0) {
		mem = HDR_ALLOC(msz);
		h->rh_mem = mem;
		h->rh_memlen = msz;
		h->rh_reads = (void *)mem;
		h->rh_writes = (void *)(mem + rsz);
		/* hdr_lists() finds the segments in rh_reply until it fills. */
		h->rh_reply.rw_segs = (void *)(mem + rsz + wsz);
	}
	if (!XDR_SETPOS(&x, start) || !hdr_lists(&x, len, h, &nseg, true)) {
		oncrpc_rdma_hdr_fini(h);
		return ONCRPC_RDMA_DEC_ERR_CHUNK;
	}
	return ONCRPC_RDMA_DEC_OK;
}

void
oncrpc_rdma_hdr_fini(struct oncrpc_rdma_hdr *h)
{

	if (h->rh_mem != NULL)
		HDR_FREE(h->rh_mem, h->rh_memlen);
	h->rh_mem = NULL;
}

/* Bytes that oncrpc_rdma_hdr_encode() will write. */
u_int
oncrpc_rdma_hdr_size(const struct oncrpc_rdma_hdr *h)
{
	u_int i, n;

	n = 4;				/* the fixed fields */
	n += h->rh_nread * (2 + SEG_WORDS) + 1;	/* 1 PHLOO, then 0, s4.7 */
	for (i = 0; i < h->rh_nwrite; i++)
		n += 2 + h->rh_writes[i].rw_nseg * SEG_WORDS;
	n += 1;				/* 0 to end the Write list */
	n += 1;				/* the Reply chunk's presence */
	if (h->rh_hasreply)
		n += 1 + h->rh_reply.rw_nseg * SEG_WORDS;
	return n * WORD;
}

static bool
hdr_put_wchunk(XDR *x, const struct oncrpc_rdma_wchunk *rw)
{
	struct oncrpc_rdma_seg s;
	uint32_t n = rw->rw_nseg;
	u_int i;

	if (!xdr_u_int32_t(x, &n))
		return false;
	for (i = 0; i < rw->rw_nseg; i++) {
		s = rw->rw_segs[i];
		if (!hdr_seg(x, &s))
			return false;
	}
	return true;
}

bool
oncrpc_rdma_hdr_encode(XDR *x, const struct oncrpc_rdma_hdr *h)
{
	struct oncrpc_rdma_rseg r;
	uint32_t v, one = 1, zero = 0;
	u_int i;

	v = h->rh_xid;
	if (!xdr_u_int32_t(x, &v))
		return false;
	v = h->rh_vers;
	if (!xdr_u_int32_t(x, &v))
		return false;
	v = h->rh_credit;
	if (!xdr_u_int32_t(x, &v))
		return false;
	v = h->rh_proc;
	if (!xdr_u_int32_t(x, &v))
		return false;
	for (i = 0; i < h->rh_nread; i++) {
		r = h->rh_reads[i];
		if (!xdr_u_int32_t(x, &one) ||
		    !xdr_u_int32_t(x, &r.rr_position) ||
		    !hdr_seg(x, &r.rr_seg))
			return false;
	}
	if (!xdr_u_int32_t(x, &zero))
		return false;
	for (i = 0; i < h->rh_nwrite; i++) {
		if (!xdr_u_int32_t(x, &one) ||
		    !hdr_put_wchunk(x, &h->rh_writes[i]))
			return false;
	}
	if (!xdr_u_int32_t(x, &zero))
		return false;
	if (!h->rh_hasreply)
		return xdr_u_int32_t(x, &zero);
	return xdr_u_int32_t(x, &one) && hdr_put_wchunk(x, &h->rh_reply);
}

/*
 * RDMA_ERROR, RFC 8166 s4.5: the XID and version of the failing message.
 * Of ERR_VERS the range is what this end speaks, s4.5.1.
 */
bool
oncrpc_rdma_error_encode(XDR *x, uint32_t xid, uint32_t vers, uint32_t credit,
    uint32_t err)
{
	uint32_t proc = ONCRPC_RDMA_ERROR, low = ONCRPC_RDMA_VERS;

	if (!xdr_u_int32_t(x, &xid) || !xdr_u_int32_t(x, &vers) ||
	    !xdr_u_int32_t(x, &credit) || !xdr_u_int32_t(x, &proc) ||
	    !xdr_u_int32_t(x, &err))
		return false;
	if (err == ONCRPC_RDMA_ERR_VERS)
		return xdr_u_int32_t(x, &low) && xdr_u_int32_t(x, &low);
	return true;
}
