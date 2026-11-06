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
 * Packing and unpacking of the frames in oncrpc_iwarp.h.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/errno.h>
#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <errno.h>
#include <string.h>
#endif

#include <oncrpc/oncrpc_iwarp.h>

static const char iw_key_req[IW_MPA_KEYLEN] = "MPA ID Req Frame";
static const char iw_key_rep[IW_MPA_KEYLEN] = "MPA ID Rep Frame";

static uint16_t
get16(const uint8_t *p)
{

	return (uint16_t)(p[0] << 8 | p[1]);
}

static uint32_t
get32(const uint8_t *p)
{

	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	    (uint32_t)p[2] << 8 | p[3];
}

static uint64_t
get64(const uint8_t *p)
{

	return (uint64_t)get32(p) << 32 | get32(p + 4);
}

static void
put16(uint8_t *p, uint16_t v)
{

	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static void
put32(uint8_t *p, uint32_t v)
{

	put16(p, (uint16_t)(v >> 16));
	put16(p + 2, (uint16_t)v);
}

static void
put64(uint8_t *p, uint64_t v)
{

	put32(p, (uint32_t)(v >> 32));
	put32(p + 4, (uint32_t)v);
}

/*
 * An MPA Request Frame, RFC 5044 s7.1.1 and RFC 6581 s6.  EAGAIN wants
 * more of the stream; any other error is s7.1.2 rule 2's "improperly
 * formatted".
 */
int
oncrpc_iw_mpa_parse(const void *buf, u_int len, struct oncrpc_iw_mpa *im)
{
	const uint8_t *p = buf;

	memset(im, 0, sizeof(*im));
	if (len < IW_MPA_HDRLEN)
		return EAGAIN;
	if (memcmp(p, iw_key_req, IW_MPA_KEYLEN) != 0)
		return EPROTO;
	im->im_flags = p[16];
	im->im_rev = p[17];
	im->im_pdlen = get16(p + 18);
	if (im->im_rev != IW_MPA_REV1 && im->im_rev != IW_MPA_REV2)
		return EPROTO;
	if (im->im_pdlen > IW_MPA_PDMAX)
		return EPROTO;
	im->im_len = IW_MPA_HDRLEN + im->im_pdlen;
	if (len < im->im_len)
		return EAGAIN;
	im->im_ulpoff = IW_MPA_HDRLEN;
	im->im_ulplen = im->im_pdlen;
	if (im->im_rev == IW_MPA_REV2 && (im->im_flags & IW_MPA_F_S) != 0) {
		if (im->im_pdlen < IW_MPA2_LEN)
			return EPROTO;
		im->im_ird = get16(p + IW_MPA_HDRLEN);
		im->im_ord = get16(p + IW_MPA_HDRLEN + 2);
		im->im_ulpoff += IW_MPA2_LEN;
		im->im_ulplen -= IW_MPA2_LEN;
	} else
		im->im_flags &= ~IW_MPA_F_S;
	return 0;
}

/*
 * The MPA Reply Frame to req.  flags are this end's M, C and R; the
 * revision and the S bit answer the request's, and if S then ird and
 * ord go first.  buf has room for a frame with IW_MPA_PDMAX of Private
 * Data.  Returns the length.
 */
u_int
oncrpc_iw_mpa_reply(void *buf, const struct oncrpc_iw_mpa *req, uint8_t flags,
    uint16_t ird, uint16_t ord, const void *ulp, u_int ulplen)
{
	uint8_t *p = buf;
	u_int pd = ulplen;

	memcpy(p, iw_key_rep, IW_MPA_KEYLEN);
	p[17] = req->im_rev;
	if ((req->im_flags & IW_MPA_F_S) != 0) {
		flags |= IW_MPA_F_S;
		put16(p + IW_MPA_HDRLEN, ird);
		put16(p + IW_MPA_HDRLEN + 2, ord);
		pd += IW_MPA2_LEN;
	}
	p[16] = flags;
	put16(p + 18, (uint16_t)pd);
	if (ulplen != 0)
		memcpy(p + IW_MPA_HDRLEN + pd - ulplen, ulp, ulplen);
	return IW_MPA_HDRLEN + pd;
}

/* RFC 5044 s4.1: pads to make the whole of the FPDU a multiple of four. */
u_int
oncrpc_iw_fpdu_pad(u_int ulpdu)
{

	return (4 - ((IW_FPDU_HDR + ulpdu) & 3)) & 3;
}

/* From the length word to the end of the CRC. */
u_int
oncrpc_iw_fpdu_len(u_int ulpdu)
{

	return IW_FPDU_HDR + ulpdu + oncrpc_iw_fpdu_pad(ulpdu) + IW_FPDU_CRC;
}

/*
 * The DDP header at the head of a ULPDU, with the RDMAP control in its
 * RsvdULP field.  The versions are checked here for it to be the one
 * place, RFC 5041 s4.1 and RFC 5040 s4.1.
 */
int
oncrpc_iw_seg_parse(const void *buf, u_int len, struct oncrpc_iw_seg *is)
{
	const uint8_t *p = buf;

	memset(is, 0, sizeof(*is));
	if (len < IW_DDP_TAGGED_HDR)
		return EPROTO;
	if ((p[0] & IW_DDP_DV_MASK) != IW_DDP_DV ||
	    (p[1] & IW_RDMAP_RV_MASK) != IW_RDMAP_RV)
		return EPROTO;
	is->is_tagged = (p[0] & IW_DDP_T) != 0;
	is->is_last = (p[0] & IW_DDP_L) != 0;
	is->is_op = p[1] & IW_RDMAP_OP_MASK;
	is->is_stag = get32(p + 2);
	if (is->is_tagged) {
		is->is_to = get64(p + 6);
		is->is_hdrlen = IW_DDP_TAGGED_HDR;
		return 0;
	}
	if (len < IW_DDP_UNTAGGED_HDR)
		return EPROTO;
	is->is_qn = get32(p + 6);
	is->is_msn = get32(p + 10);
	is->is_mo = get32(p + 14);
	is->is_hdrlen = IW_DDP_UNTAGGED_HDR;
	return 0;
}

/* The header for is, at most IW_DDP_UNTAGGED_HDR.  Returns its length. */
u_int
oncrpc_iw_seg_build(void *buf, const struct oncrpc_iw_seg *is)
{
	uint8_t *p = buf;

	p[0] = (is->is_tagged ? IW_DDP_T : 0) | (is->is_last ? IW_DDP_L : 0) |
	    IW_DDP_DV;
	p[1] = IW_RDMAP_RV | is->is_op;
	put32(p + 2, is->is_stag);
	if (is->is_tagged) {
		put64(p + 6, is->is_to);
		return IW_DDP_TAGGED_HDR;
	}
	put32(p + 6, is->is_qn);
	put32(p + 10, is->is_msn);
	put32(p + 14, is->is_mo);
	return IW_DDP_UNTAGGED_HDR;
}

void
oncrpc_iw_readreq_build(void *buf, const struct oncrpc_iw_readreq *ir)
{
	uint8_t *p = buf;

	put32(p, ir->ir_sinkstag);
	put64(p + 4, ir->ir_sinkto);
	put32(p + 12, ir->ir_size);
	put32(p + 16, ir->ir_srcstag);
	put64(p + 20, ir->ir_srcto);
}

/*
 * CRC32c as iSCSI has it, RFC 5044 s4.4 by way of RFC 7143: the
 * reflected polynomial 0x82f63b78, starting from all ones and ending
 * complemented.  Used only when the peer asks, so a table is not worth
 * having a copy of for one that is not; it is built at the first use,
 * idempotently.
 */
#define	IW_CRC_POLY	0x82f63b78U

static uint32_t iw_crc_tab[256];

uint32_t
oncrpc_iw_crc_init(void)
{
	uint32_t c;
	u_int i, j;

	if (iw_crc_tab[255] == 0) {
		for (i = 0; i < 256; i++) {
			c = i;
			for (j = 0; j < 8; j++)
				c = (c & 1) != 0 ? c >> 1 ^ IW_CRC_POLY : c >> 1;
			iw_crc_tab[i] = c;
		}
	}
	return 0xffffffffU;
}

uint32_t
oncrpc_iw_crc_update(uint32_t c, const void *buf, u_int len)
{
	const uint8_t *p = buf;

	while (len-- > 0)
		c = iw_crc_tab[(c ^ *p++) & 0xff] ^ c >> 8;
	return c;
}

/* The CRC in the order its octets go on the wire, as a big-endian word. */
uint32_t
oncrpc_iw_crc_final(uint32_t c)
{

	c = ~c;
	return (c & 0xff) << 24 | (c & 0xff00) << 8 | (c >> 8 & 0xff00) |
	    c >> 24;
}
