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

#ifndef _ONCRPC_ONCRPC_IWARP_H_
#define _ONCRPC_ONCRPC_IWARP_H_

/*
 * The wire of iWARP as a passive endpoint needs it: MPA (RFC 5044, with
 * the connection setup of RFC 6581), DDP (RFC 5041) and RDMAP (RFC
 * 5040).  Formats only; see oncrpc_rdma_svc.c for the protocol.
 */

#include <sys/types.h>
#ifdef _KERNEL
#include <sys/stdbool.h>
#else
#include <stdbool.h>
#endif

#define	IW_MPA_KEYLEN		16	/* RFC 5044 s7.1.1 */
#define	IW_MPA_HDRLEN		20	/* the key, then two more words */
#define	IW_MPA_PDMAX		512	/* RFC 5044 s7.1.1 */
#define	IW_MPA_REV1		1	/* RFC 5044 s7.1.1 */
#define	IW_MPA_REV2		2	/* RFC 6581 s9 has the data */

/* First octet of the third word; RFC 5044 s7.1.1. */
#define	IW_MPA_F_M		0x80
#define	IW_MPA_F_C		0x40
#define	IW_MPA_F_R		0x20
#define	IW_MPA_F_S		0x10	/* RFC 6581 s6 */

/* RFC 6581 s9, the first word of Private Data */
#define	IW_MPA2_LEN		4
#define	IW_MPA2_A		0x8000	/* on IRD: peer to peer */
#define	IW_MPA2_B		0x4000	/* on IRD: zero-length Send RTR */
#define	IW_MPA2_C		0x8000	/* on ORD: zero-length Write RTR */
#define	IW_MPA2_D		0x4000	/* on ORD: zero-length Read RTR */
#define	IW_MPA2_MASK		0x3fff

#define	IW_FPDU_HDR		2	/* RFC 5044 s4.1, ULPDU_Length */
#define	IW_FPDU_CRC		4	/* RFC 5044 s4.1 */
#define	IW_ULPDU_MAX		65535	/* RFC 5044 s4.1, 16 bits */

/* RFC 5041 s4.1 */
#define	IW_DDP_T		0x80
#define	IW_DDP_L		0x40
#define	IW_DDP_DV		0x01
#define	IW_DDP_DV_MASK		0x03

#define	IW_DDP_TAGGED_HDR	14	/* RFC 5041 s4.2, 5.2 */
#define	IW_DDP_UNTAGGED_HDR	18	/* RFC 5041 s4.3, 5.2 */

/* RFC 5040 s4.1: bits 24-25 of the word */
#define	IW_RDMAP_RV		0x40
#define	IW_RDMAP_RV_MASK	0xc0
#define	IW_RDMAP_OP_MASK	0x0f

/* RFC 5040 s4.1, Figure 4 */
#define	IW_OP_WRITE		0
#define	IW_OP_READ_REQ		1
#define	IW_OP_READ_RESP		2
#define	IW_OP_SEND		3
#define	IW_OP_SEND_INV		4
#define	IW_OP_SEND_SE		5
#define	IW_OP_SEND_SE_INV	6
#define	IW_OP_TERMINATE		7

/* RFC 5040 s4.1, Figure 4 */
#define	IW_QN_SEND		0
#define	IW_QN_READ		1
#define	IW_QN_TERM		2

#define	IW_READREQ_LEN		28	/* RFC 5040 s4.4, Figure 6 */
#define	IW_TERM_LEN		4	/* RFC 5040 s4.8, with no copies */

struct oncrpc_iw_mpa {
	uint8_t		im_flags;
	uint8_t		im_rev;
	uint16_t	im_pdlen;
	/* Of RFC 6581, if IW_MPA_F_ENH was there */
	uint16_t	im_ird;		/* with its flag bits */
	uint16_t	im_ord;
	u_int		im_ulpoff;	/* ULP Private Data in the frame */
	u_int		im_ulplen;
	u_int		im_len;		/* of the whole frame */
};

/* One DDP segment */
struct oncrpc_iw_seg {
	bool		is_tagged;
	bool		is_last;
	uint8_t		is_op;
	uint32_t	is_stag;	/* tagged, or the Invalidate STag */
	uint64_t	is_to;		/* tagged */
	uint32_t	is_qn;		/* untagged */
	uint32_t	is_msn;		/* untagged */
	uint32_t	is_mo;		/* untagged */
	u_int		is_hdrlen;
};

/* An RDMA Read Request's header, RFC 5040 s4.4 */
struct oncrpc_iw_readreq {
	uint32_t	ir_sinkstag;
	uint64_t	ir_sinkto;
	uint32_t	ir_size;
	uint32_t	ir_srcstag;
	uint64_t	ir_srcto;
};

int	oncrpc_iw_mpa_parse(const void *, u_int, struct oncrpc_iw_mpa *);
u_int	oncrpc_iw_mpa_reply(void *, const struct oncrpc_iw_mpa *, uint8_t,
	    uint16_t, uint16_t, const void *, u_int);
u_int	oncrpc_iw_fpdu_len(u_int);
u_int	oncrpc_iw_fpdu_pad(u_int);
int	oncrpc_iw_seg_parse(const void *, u_int, struct oncrpc_iw_seg *);
u_int	oncrpc_iw_seg_build(void *, const struct oncrpc_iw_seg *);
void	oncrpc_iw_readreq_build(void *, const struct oncrpc_iw_readreq *);
uint32_t oncrpc_iw_crc_init(void);
uint32_t oncrpc_iw_crc_update(uint32_t, const void *, u_int);
uint32_t oncrpc_iw_crc_final(uint32_t);

#endif /* !_ONCRPC_ONCRPC_IWARP_H_ */
