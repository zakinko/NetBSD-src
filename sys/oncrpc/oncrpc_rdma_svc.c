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
 * RPC-over-RDMA on a TCP socket: an iWARP Responder in software.
 *
 * NetBSD has no verbs and no RDMA driver.  What an RPC service needs of
 * RDMA is small, though, since it never advertises memory: it receives,
 * sends, and does RDMA Read and Write on what the Requester advertised.
 * iWARP is a protocol on top of TCP, so that much can be spoken from
 * here, to anything that speaks iWARP, such as the soft-iWARP of Linux.
 * No copy is avoided: this buys the protocol, not the speed.
 *
 * The four things that an RDMA device would do are the iw_*() here,
 * under what is the RPC-over-RDMA part, rdma_recv() and rdma_send(). A
 * provider on real verbs would replace the one and keep the other.
 *
 * The stream is read by whichever worker has XP_RECEIVING, in
 * rdma_recv().  An RDMA Read is done by that same worker, which sends
 * the request and goes on reading the stream until the response is
 * in: nothing else would read it, and if the read were left to another
 * worker they could all end up waiting for one that was not coming.
 * That costs a connection the parallelism of its Read chunks, and a
 * Send that arrives meanwhile waits on iw_msgs.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/condvar.h>
#include <sys/cprng.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <sys/uio.h>

#include <oncrpc/oncrpc_iwarp.h>
#include <oncrpc/oncrpc_rdma.h>
#include <oncrpc/oncrpc_var.h>

/*
 * None of these come from an RFC.  ONCRPC_RDMA_CREDITS stays under
 * ONCRPC_XPRT_MAXREQS so that a client within its credits is never made
 * to wait for that limit.  IW_RECVSIZE is what is offered by RFC 8797 s4.2,
 * and what Linux has as its default.  IW_MULPDU is a size to cut
 * messages at: RFC 5044 s5.1 has a sender on a layered TCP use the EMSS
 * if it can learn it, which here it cannot, and an FPDU over several TCP
 * segments is only slower to place, not wrong.  IW_ORD is how many RDMA
 * Reads this end has out at once, which is one.
 */
#define	ONCRPC_RDMA_CREDITS	32
#define	IW_RECVSIZE		4096
#define	IW_SENDSIZE		4096
#define	IW_MULPDU		16384
#define	IW_ORD			1
#define	IW_IRD			1

#define	IW_RCVALL		1000000000	/* as nfsrv_rcv() */
#define	IW_FPDU_BUF		(IW_FPDU_HDR + IW_ULPDU_MAX + 3 + IW_FPDU_CRC)

/* A whole Send, off the wire. */
struct iw_msg {
	SIMPLEQ_ENTRY(iw_msg)	 im_next;
	uint8_t			*im_buf;
	u_int			 im_len;
};

enum iw_state { IW_MPA_WAIT, IW_RUNNING };

struct iw_conn {
	enum iw_state		 iw_state;
	bool			 iw_crc;
	uint16_t		 iw_ord;	/* peer's IRD or less */
	u_int			 iw_sendthresh;	/* reply inline threshold */

	/* Of the receiver */
	struct mbuf		*iw_raw;
	u_int			 iw_rawlen;
	uint8_t			*iw_fpdu;
	uint8_t			*iw_cur;	/* the Send coming in */
	u_int			 iw_curlen;
	uint32_t		 iw_rmsn;	/* next Send */
	SIMPLEQ_HEAD(, iw_msg)	 iw_msgs;
	/* The RDMA Read in progress */
	bool			 iw_rdbusy;
	uint32_t		 iw_rdstag;
	uint64_t		 iw_rdto;
	uint32_t		 iw_rdleft;
	XDR			*iw_rdsink;

	/* Of the sender */
	kmutex_t		 iw_txlock;
	kcondvar_t		 iw_txcv;
	bool			 iw_txbusy;
	uint32_t		 iw_smsn[IW_QN_TERM + 1];
	struct oncrpc_rdma_bc	 iw_bc;
};

/* What one call brings along for its reply. */
struct rdma_ctx {
	struct oncrpc_rdma_hdr	 rc_hdr;
	struct oncrpc_rdma_mark	*rc_marks;	/* one per Write chunk */
	u_int			 rc_nmark;
	u_int			 rc_maxmark;
	struct oncrpc_rdma_callinfo rc_ri;
	const struct oncrpc_rdma_ulb *rc_ub;	/* for a whole reply */
	bool			 rc_fixed;	/* the program gave marks */
};

static struct iw_conn *
XPIW(struct oncrpc_xprt *xp)
{

	return xp->xp_priv;
}

static void
iw_tx_lock(struct iw_conn *iw)
{

	mutex_enter(&iw->iw_txlock);
	while (iw->iw_txbusy)
		cv_wait(&iw->iw_txcv, &iw->iw_txlock);
	iw->iw_txbusy = true;
	mutex_exit(&iw->iw_txlock);
}

static void
iw_tx_unlock(struct iw_conn *iw)
{

	mutex_enter(&iw->iw_txlock);
	iw->iw_txbusy = false;
	cv_signal(&iw->iw_txcv);
	mutex_exit(&iw->iw_txlock);
}

/* len bytes at off in m, to go on the end of some other chain. */
static struct mbuf *
iw_copy(struct mbuf *m, u_int off, u_int len)
{
	struct mbuf *n;

	n = m_copym(m, off, len, M_WAIT);
	if ((n->m_flags & M_PKTHDR) != 0)
		m_remove_pkthdr(n);
	return n;
}

static int
iw_crc_mbuf(void *arg, void *data, unsigned int len)
{
	uint32_t *c = arg;

	*c = oncrpc_iw_crc_update(*c, data, len);
	return 0;
}

/*
 * One FPDU: seg as header, then dlen bytes of data at off in src.  The
 * transmit lock is the caller's, as a message must not be broken up by
 * another's segments.
 */
static int
iw_tx_fpdu(struct oncrpc_xprt *xp, const struct iw_conn *iw,
    const struct oncrpc_iw_seg *seg, const void *extra, u_int extralen,
    struct mbuf *src, u_int off, u_int dlen)
{
	struct socket *so = xp->xp_so;
	static const uint8_t zero[3];
	struct mbuf *m, *n, *t;
	uint8_t *p;
	uint32_t crc, word;
	u_int hlen, ulpdu, pad;

	m = m_gethdr(M_WAIT, MT_DATA);
	m_reset_rcvif(m);
	p = mtod(m, uint8_t *);
	hlen = oncrpc_iw_seg_build(p + IW_FPDU_HDR, seg);
	ulpdu = hlen + extralen + dlen;
	KASSERT(ulpdu <= IW_ULPDU_MAX);
	p[0] = (uint8_t)(ulpdu >> 8);
	p[1] = (uint8_t)ulpdu;
	KASSERT(IW_FPDU_HDR + hlen + extralen <= MHLEN);
	if (extralen != 0)
		memcpy(p + IW_FPDU_HDR + hlen, extra, extralen);
	m->m_len = IW_FPDU_HDR + hlen + extralen;

	if (dlen != 0) {
		n = iw_copy(src, off, dlen);
		m_cat(m, n);
	}
	m->m_pkthdr.len = IW_FPDU_HDR + ulpdu;

	pad = oncrpc_iw_fpdu_pad(ulpdu);
	word = 0;
	if (iw->iw_crc) {
		crc = oncrpc_iw_crc_init();
		m_apply(m, 0, m->m_pkthdr.len, iw_crc_mbuf, &crc);
		crc = oncrpc_iw_crc_update(crc, zero, pad);
		word = htonl(oncrpc_iw_crc_final(crc));
	}
	/* All of it before m_cat(), which may copy t and free it. */
	t = m_get(M_WAIT, MT_DATA);
	memset(mtod(t, void *), 0, pad);
	memcpy(mtod(t, uint8_t *) + pad, &word, IW_FPDU_CRC);
	t->m_len = pad + IW_FPDU_CRC;
	m_cat(m, t);
	m->m_pkthdr.len += pad + IW_FPDU_CRC;

	return (*so->so_send)(so, NULL, NULL, m, NULL, 0, curlwp);
}

/* A Send of the first len bytes of m, RFC 5041 s5.2. */
static int
iw_send(struct oncrpc_xprt *xp, struct mbuf *m, u_int len)
{
	struct iw_conn *iw = XPIW(xp);
	struct oncrpc_iw_seg seg;
	u_int off, n, room = IW_MULPDU - IW_DDP_UNTAGGED_HDR;
	int error;

	memset(&seg, 0, sizeof(seg));
	seg.is_op = IW_OP_SEND;
	seg.is_qn = IW_QN_SEND;
	iw_tx_lock(iw);
	seg.is_msn = iw->iw_smsn[IW_QN_SEND]++;
	off = 0;
	do {
		n = MIN(len - off, room);
		seg.is_mo = off;
		seg.is_last = off + n == len;
		error = iw_tx_fpdu(xp, iw, &seg, NULL, 0, m, off, n);
		off += n;
	} while (error == 0 && off < len);
	iw_tx_unlock(iw);
	return error;
}

/* An RDMA Write of len bytes at off in m to one segment, RFC 5041 s4.2. */
static int
iw_write(struct oncrpc_xprt *xp, const struct oncrpc_rdma_seg *rs,
    struct mbuf *m, u_int off, u_int len)
{
	struct iw_conn *iw = XPIW(xp);
	struct oncrpc_iw_seg seg;
	u_int done, n, room = IW_MULPDU - IW_DDP_TAGGED_HDR;
	int error;

	memset(&seg, 0, sizeof(seg));
	seg.is_tagged = true;
	seg.is_op = IW_OP_WRITE;
	seg.is_stag = rs->rs_handle;
	iw_tx_lock(iw);
	done = 0;
	do {
		n = MIN(len - done, room);
		seg.is_to = rs->rs_offset + done;
		seg.is_last = done + n == len;
		error = iw_tx_fpdu(xp, iw, &seg, NULL, 0, m, off + done, n);
		done += n;
	} while (error == 0 && done < len);
	iw_tx_unlock(iw);
	return error;
}

/*
 * The STag for data coming back is this end's own, and for the peer to
 * guess one would be no use, as only an RDMA Read Response is taken and
 * only while one is expected.  It is random all the same, RFC 8166
 * s8.1.2; it costs nothing here.
 */
static int
iw_read_request(struct oncrpc_xprt *xp, const struct oncrpc_rdma_seg *rs)
{
	struct iw_conn *iw = XPIW(xp);
	struct oncrpc_iw_readreq rr;
	struct oncrpc_iw_seg seg;
	uint8_t hdr[IW_READREQ_LEN];
	int error;

	/* RFC 6581 s9.1: an ORD of zero, and there is a Read to do. */
	if (iw->iw_ord == 0)
		return EPROTO;

	iw->iw_rdstag = cprng_fast32();
	iw->iw_rdto = 0;
	iw->iw_rdleft = rs->rs_length;
	iw->iw_rdbusy = true;

	rr.ir_sinkstag = iw->iw_rdstag;
	rr.ir_sinkto = 0;
	rr.ir_size = rs->rs_length;
	rr.ir_srcstag = rs->rs_handle;
	rr.ir_srcto = rs->rs_offset;
	oncrpc_iw_readreq_build(hdr, &rr);

	memset(&seg, 0, sizeof(seg));
	seg.is_op = IW_OP_READ_REQ;
	seg.is_qn = IW_QN_READ;
	seg.is_last = true;
	iw_tx_lock(iw);
	seg.is_msn = iw->iw_smsn[IW_QN_READ]++;
	error = iw_tx_fpdu(xp, iw, &seg, hdr, sizeof(hdr), NULL, 0, 0);
	iw_tx_unlock(iw);
	return error;
}

/*
 * A Terminate, RFC 5040 s4.8, as a last word before closing: best
 * effort, with Layer RDMAP and the error left at unspecified, and no
 * copy of the headers at fault, which are only SHOULDs.
 */
static void
iw_terminate(struct oncrpc_xprt *xp)
{
	struct iw_conn *iw = XPIW(xp);
	struct oncrpc_iw_seg seg;
	uint8_t hdr[IW_TERM_LEN];

	memset(&seg, 0, sizeof(seg));
	memset(hdr, 0, sizeof(hdr));
	seg.is_op = IW_OP_TERMINATE;
	seg.is_qn = IW_QN_TERM;
	seg.is_last = true;
	iw_tx_lock(iw);
	seg.is_msn = iw->iw_smsn[IW_QN_TERM]++;
	(void)iw_tx_fpdu(xp, iw, &seg, hdr, sizeof(hdr), NULL, 0, 0);
	iw_tx_unlock(iw);
}

/* Bytes off the raw stream, which must have them. */
static void
iw_raw_take(struct iw_conn *iw, void *buf, u_int len)
{

	m_copydata(iw->iw_raw, 0, len, buf);
	if (len == iw->iw_rawlen) {
		m_freem(iw->iw_raw);
		iw->iw_raw = NULL;
	} else
		m_adj(iw->iw_raw, len);
	iw->iw_rawlen -= len;
}

/* RFC 5044 s7.1.2: the first thing on the stream. */
static int
iw_mpa_start(struct oncrpc_xprt *xp)
{
	struct iw_conn *iw = XPIW(xp);
	struct socket *so = xp->xp_so;
	struct oncrpc_iw_mpa im;
	const uint8_t *ulp;
	struct mbuf *m;
	uint8_t pd[ONCRPC_RDMA_CMP_LEN], *buf;
	uint32_t magic;
	uint16_t ird, ord;
	u_int avail, sendsize, len;
	int error;

	avail = MIN(iw->iw_rawlen, IW_MPA_HDRLEN + IW_MPA_PDMAX);
	if (avail == 0)
		return EAGAIN;
	buf = iw->iw_fpdu;
	m_copydata(iw->iw_raw, 0, avail, buf);
	error = oncrpc_iw_mpa_parse(buf, avail, &im);
	if (error != 0)
		return error;
	/* Markers are a stream of their own to weave in; siw refuses them too. */
	if ((im.im_flags & IW_MPA_F_M) != 0)
		return EPROTO;
	iw_raw_take(iw, buf, im.im_len);

	/* RFC 8166 s3.3.3: without RFC 8797, only this is known to fit. */
	sendsize = ONCRPC_RDMA_INLINE_MIN;
	ulp = buf + im.im_ulpoff;
	if (im.im_ulplen >= ONCRPC_RDMA_CMP_LEN) {
		magic = (uint32_t)ulp[0] << 24 | (uint32_t)ulp[1] << 16 |
		    (uint32_t)ulp[2] << 8 | ulp[3];
		if (magic == ONCRPC_RDMA_CMP_MAGIC &&
		    ulp[4] == ONCRPC_RDMA_CMP_VERS) {
			sendsize = MIN((ulp[7] + 1U) * 1024, IW_SENDSIZE);
		}
	}
	iw->iw_sendthresh = sendsize;

	/*
	 * RFC 6581 s9.1: the peer's ORD is what our IRD must cover.  A
	 * Requester never reads from a Responder (RFC 8166 s3.1 calls the
	 * model Read-Write) and a Read Request here ends the connection,
	 * so this is only agreeing to what will not be used.
	 */
	ird = MAX(im.im_ord & IW_MPA2_MASK, IW_IRD);
	ord = MIN(im.im_ird & IW_MPA2_MASK, IW_ORD);
	if ((im.im_flags & IW_MPA_F_S) == 0)
		ord = IW_ORD;
	iw->iw_ord = ord;

	/* An RTR is taken as it comes: see iw_tagged(). */
	if ((im.im_ird & IW_MPA2_A) != 0) {
		ird |= IW_MPA2_A;
		if ((im.im_ord & IW_MPA2_C) != 0)
			ord |= IW_MPA2_C;
		else if ((im.im_ord & IW_MPA2_D) != 0)
			ord |= IW_MPA2_D;
		else
			return EPROTO;	/* RFC 6581 s8, no matching RTR */
	}

	pd[0] = ONCRPC_RDMA_CMP_MAGIC >> 24;
	pd[1] = (ONCRPC_RDMA_CMP_MAGIC >> 16) & 0xff;
	pd[2] = (ONCRPC_RDMA_CMP_MAGIC >> 8) & 0xff;
	pd[3] = ONCRPC_RDMA_CMP_MAGIC & 0xff;
	pd[4] = ONCRPC_RDMA_CMP_VERS;
	pd[5] = 0;		/* R clear: only plain Send is used */
	pd[6] = IW_SENDSIZE / 1024 - 1;		/* RFC 8797 s4.2 */
	pd[7] = IW_RECVSIZE / 1024 - 1;

	iw->iw_crc = (im.im_flags & IW_MPA_F_C) != 0;
	len = oncrpc_iw_mpa_reply(buf, &im, iw->iw_crc ? IW_MPA_F_C : 0, ird,
	    ord, pd, sizeof(pd));

	m = m_gethdr(M_WAIT, MT_DATA);
	m_reset_rcvif(m);
	m_copyback(m, 0, len, buf);
	if (m->m_pkthdr.len != (int)len) {
		m_freem(m);
		return ENOBUFS;
	}
	error = (*so->so_send)(so, NULL, NULL, m, NULL, 0, curlwp);
	if (error != 0)
		return error;
	iw->iw_state = IW_RUNNING;
	return 0;
}

/*
 * Tagged data.  The only buffer here is the sink of the RDMA Read in
 * progress; a Write can only be zero-length, an RTR, for which RFC 5041
 * s5.2 says the STag is not to be checked.
 */
static int
iw_tagged(struct iw_conn *iw, const struct oncrpc_iw_seg *is, uint8_t *data,
    u_int len)
{

	if (is->is_op == IW_OP_WRITE && len == 0)
		return 0;
	if (is->is_op != IW_OP_READ_RESP || !iw->iw_rdbusy ||
	    is->is_stag != iw->iw_rdstag || is->is_to != iw->iw_rdto ||
	    len > iw->iw_rdleft)
		return EPROTO;
	if (len != 0 && !XDR_PUTBYTES(iw->iw_rdsink, (char *)data, len))
		return EPROTO;
	iw->iw_rdto += len;
	iw->iw_rdleft -= len;
	if (is->is_last) {
		/* RFC 5040 s5.2: what was asked for comes back whole. */
		if (iw->iw_rdleft != 0)
			return EPROTO;
		iw->iw_rdbusy = false;
	}
	return 0;
}

/* Untagged: only Sends are wanted of a client, RFC 8166 s2.3.2. */
static int
iw_untagged(struct iw_conn *iw, const struct oncrpc_iw_seg *is, uint8_t *data,
    u_int len)
{
	struct iw_msg *im;

	switch (is->is_op) {
	case IW_OP_SEND:
	case IW_OP_SEND_SE:
		break;
	case IW_OP_TERMINATE:
		return ECONNRESET;
	default:
		return EPROTO;
	}
	if (is->is_qn != IW_QN_SEND || is->is_msn != iw->iw_rmsn ||
	    is->is_mo != iw->iw_curlen)
		return EPROTO;
	/* RFC 8166 s3.3: a Send over what was posted ends the connection. */
	if (len > IW_RECVSIZE - iw->iw_curlen)
		return EMSGSIZE;
	if (iw->iw_cur == NULL)
		iw->iw_cur = kmem_alloc(IW_RECVSIZE, KM_SLEEP);
	memcpy(iw->iw_cur + iw->iw_curlen, data, len);
	iw->iw_curlen += len;
	if (!is->is_last)
		return 0;

	im = kmem_alloc(sizeof(*im), KM_SLEEP);
	im->im_buf = iw->iw_cur;
	im->im_len = iw->iw_curlen;
	SIMPLEQ_INSERT_TAIL(&iw->iw_msgs, im, im_next);
	iw->iw_cur = NULL;
	iw->iw_curlen = 0;
	iw->iw_rmsn++;
	return 0;
}

/* What is whole on the raw stream.  0 with no more to do yet. */
static int
iw_parse(struct oncrpc_xprt *xp)
{
	struct iw_conn *iw = XPIW(xp);
	struct oncrpc_iw_seg is;
	uint8_t lenb[IW_FPDU_HDR], *f;
	uint32_t crc, want;
	u_int ulpdu, total;
	int error;

	if (iw->iw_state == IW_MPA_WAIT) {
		error = iw_mpa_start(xp);
		if (error != 0)
			return error == EAGAIN ? 0 : error;
	}

	while (iw->iw_rawlen >= IW_FPDU_HDR) {
		m_copydata(iw->iw_raw, 0, IW_FPDU_HDR, lenb);
		ulpdu = (u_int)lenb[0] << 8 | lenb[1];
		total = oncrpc_iw_fpdu_len(ulpdu);
		if (iw->iw_rawlen < total)
			break;
		f = iw->iw_fpdu;
		iw_raw_take(iw, f, total);

		if (iw->iw_crc) {	/* RFC 5044 s4.4 */
			crc = oncrpc_iw_crc_init();
			crc = oncrpc_iw_crc_update(crc, f, total - IW_FPDU_CRC);
			memcpy(&want, f + total - IW_FPDU_CRC, IW_FPDU_CRC);
			if (oncrpc_iw_crc_final(crc) != ntohl(want))
				return EPROTO;	/* RFC 5044 s8 */
		}
		error = oncrpc_iw_seg_parse(f + IW_FPDU_HDR, ulpdu, &is);
		if (error != 0)
			return error;
		f += IW_FPDU_HDR + is.is_hdrlen;
		ulpdu -= is.is_hdrlen;
		error = is.is_tagged ? iw_tagged(iw, &is, f, ulpdu) :
		    iw_untagged(iw, &is, f, ulpdu);
		if (error != 0)
			return error;
	}
	return 0;
}

/*
 * Whatever the socket has, and what can be done with it.  EWOULDBLOCK
 * if it had nothing.  block is for going on only once there is more.
 */
static int
iw_pump(struct oncrpc_xprt *xp, bool block)
{
	struct iw_conn *iw = XPIW(xp);
	struct socket *so = xp->xp_so;
	struct mbuf *m, *nam, *n;
	struct uio auio;
	u_int cc;
	int error, flags;

	m = nam = NULL;
	auio.uio_resid = IW_RCVALL;
	/* not need to setup uio_vmspace */
	flags = block ? 0 : MSG_DONTWAIT;
	error = (*so->so_receive)(so, &nam, &auio, &m, NULL, &flags);
	m_freem(nam);
	if (m == NULL)
		return error != 0 ? error : EPIPE;	/* or the stream's end */
	cc = IW_RCVALL - auio.uio_resid;
	if (iw->iw_raw == NULL)
		iw->iw_raw = m;
	else {
		for (n = iw->iw_raw; n->m_next != NULL; n = n->m_next)
			continue;
		n->m_next = m;
	}
	iw->iw_rawlen += cc;
	return iw_parse(xp);
}

/*
 * RDMA Read a chunk's segments on to the end of sink, one at a time, in
 * list order, RFC 8166 s3.4.5.
 */
static int
iw_read(struct oncrpc_xprt *xp, const struct oncrpc_rdma_rseg *reads, u_int n,
    XDR *sink)
{
	struct iw_conn *iw = XPIW(xp);
	u_int i;
	int error;

	iw->iw_rdsink = sink;
	for (i = 0; i < n; i++) {
		if (reads[i].rr_seg.rs_length == 0)
			continue;
		error = iw_read_request(xp, &reads[i].rr_seg);
		if (error != 0)
			return error;
		while (iw->iw_rdbusy) {
			error = iw_pump(xp, true);
			if (error != 0)
				return error;
		}
	}
	return 0;
}

/* An RDMA_ERROR message, RFC 8166 s4.5. */
static int
rdma_send_error(struct oncrpc_xprt *xp, uint32_t xid, uint32_t vers,
    uint32_t err)
{
	struct oncrpc_xdrmbuf xm;
	struct mbuf *m;
	u_int len;
	int error;

	oncrpc_xdrmbuf_create(&xm, NULL, UINT_MAX, XDR_ENCODE);
	if (!oncrpc_rdma_error_encode(&xm.xm_xdr, xid, vers,
	    ONCRPC_RDMA_CREDITS, err)) {
		XDR_DESTROY(&xm.xm_xdr);
		return ENOBUFS;
	}
	len = XDR_GETPOS(&xm.xm_xdr);
	m = oncrpc_xdrmbuf_detach(&xm);
	error = iw_send(xp, m, len);
	m_freem(m);
	return error;
}

/*
 * Put a call's Payload stream together, RFC 8166 s3.5, on an encoder
 * that will be a chain to decode.  The Position Zero Read chunk, if
 * there is one, is the base, and is pulled before anything else so that
 * the arguments can be looked at; only when the binding has passed them
 * are the Read chunks asked for.  Returns an errno that loses the
 * connection, or 0 with *outp the stream, or NULL having sent the
 * RDMA_ERROR.
 */
static int
rdma_gather(struct oncrpc_xprt *xp, struct rdma_ctx *rc, const uint8_t *msg,
    u_int msglen, struct mbuf **outp)
{
	struct oncrpc_rdma_hdr *h = &rc->rc_hdr;
	struct oncrpc_rdma_rchunk *chunks = NULL, *c;
	struct oncrpc_xdrmbuf xm, pz;
	struct oncrpc_rdma_layout rl;
	struct oncrpc_rdma_piece p;
	struct oncrpc_rdma_callinfo ri;
	struct oncrpc_rdma_ddpscan rd;
	const struct oncrpc_rdma_ulb *ub;
	static const char zero[3];
	const uint8_t *base;
	uint8_t *flat = NULL;
	struct mbuf *m;
	u_int nc = 0, first, baselen = 0, ndata;
	int error;
	bool bad = true;

	*outp = NULL;
	oncrpc_xdrmbuf_create(&xm, NULL, ONCRPC_MAXMSG, XDR_ENCODE);
	if (h->rh_nread != 0) {
		chunks = kmem_alloc(h->rh_nread * sizeof(*chunks), KM_SLEEP);
		error = oncrpc_rdma_reads_group(h, chunks, &nc, ONCRPC_MAXMSG);
		if (error != 0)
			goto chunkerr;
	}
	ndata = nc;

	if (nc != 0 && chunks[0].rc_pos == 0) {
		/* s4.2.4, the stream comes in one place only */
		if (h->rh_proc != ONCRPC_RDMA_NOMSG)
			goto chunkerr;
		oncrpc_xdrmbuf_create(&pz, NULL, ONCRPC_MAXMSG, XDR_ENCODE);
		error = iw_read(xp, &h->rh_reads[chunks[0].rc_first],
		    chunks[0].rc_nseg, &pz.xm_xdr);
		if (error != 0) {
			XDR_DESTROY(&pz.xm_xdr);
			goto fail;
		}
		baselen = XDR_GETPOS(&pz.xm_xdr);
		m = oncrpc_xdrmbuf_detach(&pz);
		if (baselen == 0)
			goto chunkerr;
		flat = kmem_alloc(baselen, KM_SLEEP);
		m_copydata(m, 0, baselen, flat);
		m_freem(m);
		base = flat;
		ndata--;
	} else {
		/* s4.5.2, nothing would hold the stream of an RDMA_NOMSG */
		if (h->rh_proc != ONCRPC_RDMA_MSG)
			goto chunkerr;
		base = msg + h->rh_hdrlen;
		baselen = msglen - h->rh_hdrlen;
	}

	if (!oncrpc_rdma_call_peek(base, baselen, &ri) ||
	    ri.ri_xid != h->rh_xid)	/* s4.5.2 */
		goto chunkerr;
	rc->rc_ri = ri;

	first = nc - ndata;
	oncrpc_rdma_layout_init(&rl, chunks + first, ndata, baselen);
	if (!oncrpc_rdma_layout_check(&rl))
		goto chunkerr;

	/* s6.1: not processed if anything is reduced that may not be. */
	if (ndata != 0) {
		ub = ri.ri_mtype == ONCRPC_CALL ?
		    oncrpc_svc_ulb(xp->xp_svc, ri.ri_prog, ri.ri_vers) : NULL;
		if (ub == NULL || ri.ri_argoff == 0)
			goto chunkerr;
		oncrpc_rdma_ddp_init(&rd, chunks + first, ndata);
		if (!(*ub->ub_scan)(base, baselen, ri.ri_argoff, ri.ri_vers,
		    ri.ri_proc, &rd) || !oncrpc_rdma_ddp_done(&rd))
			goto chunkerr;
	}

	while (oncrpc_rdma_layout_next(&rl, &p)) {
		switch (p.rp_type) {
		case RDMA_P_BASE:
			if (!XDR_PUTBYTES(&xm.xm_xdr,
			    __UNCONST(base + p.rp_off), p.rp_len))
				goto chunkerr;
			break;
		case RDMA_P_CHUNK:
			c = &chunks[first + p.rp_chunk];
			error = iw_read(xp, &h->rh_reads[c->rc_first],
			    c->rc_nseg, &xm.xm_xdr);
			if (error != 0)
				goto fail;
			break;
		case RDMA_P_PAD:
			if (!XDR_PUTBYTES(&xm.xm_xdr, __UNCONST(zero),
			    p.rp_len))
				goto chunkerr;
			break;
		}
	}

	*outp = oncrpc_xdrmbuf_detach(&xm);
	bad = false;
	error = 0;
	goto out;

chunkerr:
	error = rdma_send_error(xp, h->rh_xid, h->rh_vers,
	    ONCRPC_RDMA_ERR_CHUNK);
fail:
out:
	if (bad)
		XDR_DESTROY(&xm.xm_xdr);
	if (flat != NULL)
		kmem_free(flat, baselen);
	if (chunks != NULL)
		kmem_free(chunks, h->rh_nread * sizeof(*chunks));
	return error;
}

static void
rdma_ctx_free(struct rdma_ctx *rc)
{

	oncrpc_rdma_hdr_fini(&rc->rc_hdr);
	if (rc->rc_marks != NULL)
		kmem_free(rc->rc_marks, rc->rc_maxmark * sizeof(*rc->rc_marks));
	kmem_free(rc, sizeof(*rc));
}

static void
rdma_xo_ctxfree(struct oncrpc_xprt *xp, void *ctx)
{

	rdma_ctx_free(ctx);
}

/*
 * One message off iw_msgs.  Returns an errno that loses the connection,
 * or 0 with a call in *mp, or with nothing there if it was dealt with.
 */
static int
rdma_message(struct oncrpc_xprt *xp, const struct iw_msg *im, struct mbuf **mp,
    void **ctxp)
{
	struct iw_conn *iw = XPIW(xp);
	struct oncrpc_rdma_callinfo ri;
	struct rdma_ctx *rc;
	int error;

	rc = kmem_zalloc(sizeof(*rc), KM_SLEEP);
	switch (oncrpc_rdma_hdr_decode(im->im_buf, im->im_len, &rc->rc_hdr)) {
	case ONCRPC_RDMA_DEC_OK:
		break;
	case ONCRPC_RDMA_DEC_ERR_VERS:
		error = rdma_send_error(xp, rc->rc_hdr.rh_xid,
		    rc->rc_hdr.rh_vers, ONCRPC_RDMA_ERR_VERS);
		rdma_ctx_free(rc);
		return error;
	case ONCRPC_RDMA_DEC_ERR_CHUNK:
		error = rdma_send_error(xp, rc->rc_hdr.rh_xid,
		    rc->rc_hdr.rh_vers, ONCRPC_RDMA_ERR_CHUNK);
		rdma_ctx_free(rc);
		return error;
	default:
		rdma_ctx_free(rc);
		return 0;
	}

	/*
	 * RFC 8167 s4.1: a Reply is the other direction's, and its credit
	 * value is a grant of those.  Nothing here makes reverse Calls yet
	 * but the count is kept right, and a Reply goes no further.
	 */
	if (rc->rc_hdr.rh_proc == ONCRPC_RDMA_MSG &&
	    oncrpc_rdma_call_peek(im->im_buf + rc->rc_hdr.rh_hdrlen,
	    im->im_len - rc->rc_hdr.rh_hdrlen, &ri) &&
	    ri.ri_mtype == ONCRPC_REPLY) {
		oncrpc_rdma_bc_done(&iw->iw_bc, rc->rc_hdr.rh_credit);
		rdma_ctx_free(rc);
		return 0;
	}

	error = rdma_gather(xp, rc, im->im_buf, im->im_len, mp);
	if (error != 0 || *mp == NULL) {
		rdma_ctx_free(rc);
		return error;
	}
	rc->rc_maxmark = rc->rc_hdr.rh_nwrite;
	if (rc->rc_maxmark != 0) {
		rc->rc_marks = kmem_alloc(rc->rc_maxmark *
		    sizeof(*rc->rc_marks), KM_SLEEP);
		if (rc->rc_ri.ri_mtype == ONCRPC_CALL)
			rc->rc_ub = oncrpc_svc_ulb(xp->xp_svc,
			    rc->rc_ri.ri_prog, rc->rc_ri.ri_vers);
	}
	*ctxp = rc;
	return 0;
}

static int
rdma_recv(struct oncrpc_xprt *xp, struct mbuf **mp, struct mbuf **namp,
    void **ctxp)
{
	struct iw_conn *iw = XPIW(xp);
	struct iw_msg *im;
	int error;

	for (;;) {
		if ((im = SIMPLEQ_FIRST(&iw->iw_msgs)) != NULL) {
			SIMPLEQ_REMOVE_HEAD(&iw->iw_msgs, im_next);
			error = rdma_message(xp, im, mp, ctxp);
			kmem_free(im->im_buf, IW_RECVSIZE);
			kmem_free(im, sizeof(*im));
			if (error != 0 || *mp != NULL)
				return error;
			continue;
		}
		error = iw_pump(xp, false);
		if (error == EWOULDBLOCK)
			return 0;
		if (error != 0) {
			/* RFC 5044 s7.1.2: before MPA is up, only a close. */
			if (iw->iw_state == IW_RUNNING &&
			    (error == EPROTO || error == EMSGSIZE))
				iw_terminate(xp);
			return error;
		}
	}
}

/*
 * Write one data item to the segments of a chunk, s3.4.6, whose lengths
 * have already been cut down to what it is using.
 */
static int
rdma_put_chunk(struct oncrpc_xprt *xp, const struct oncrpc_rdma_wchunk *rw,
    struct mbuf *m, u_int off)
{
	const struct oncrpc_rdma_seg *s;
	u_int i;
	int error;

	for (i = 0; i < rw->rw_nseg; i++) {
		s = &rw->rw_segs[i];
		if (s->rs_length == 0)
			continue;
		error = iw_write(xp, s, m, off, s->rs_length);
		if (error != 0)
			return error;
		off += s->rs_length;
	}
	return 0;
}

/*
 * A reply the program made whole, and so told nothing of: its binding
 * finds the eligible item, RFC 8267 s4.  Not when the results are
 * wrapped by RPCSEC_GSS, where the item is not as the binding has it;
 * the chunk then goes back unused, RFC 8166 s4.3.2.2.
 */
static void
rdma_reply_marks(struct rdma_ctx *rc, struct mbuf *m)
{
	const struct oncrpc_rdma_ulb *ub = rc->rc_ub;
	uint8_t *buf;
	u_int len, off;

	if (rc->rc_maxmark == 0 || ub == NULL || ub->ub_reply == NULL ||
	    !rc->rc_ri.ri_plain)
		return;
	len = MIN(m->m_pkthdr.len, ONCRPC_RDMA_REPLY_PEEK);
	buf = kmem_alloc(len, KM_SLEEP);
	m_copydata(m, 0, len, buf);
	if (oncrpc_rdma_reply_peek(buf, len, &off) &&
	    (*ub->ub_reply)(buf, len, off, m->m_pkthdr.len, rc->rc_ri.ri_vers,
	    rc->rc_ri.ri_proc, &rc->rc_marks[0]))
		rc->rc_nmark = 1;
	kmem_free(buf, len);
}

static int
rdma_send(struct oncrpc_xprt *xp, struct mbuf *m, struct mbuf *nam, void *ctx)
{
	struct iw_conn *iw = XPIW(xp);
	struct rdma_ctx *rc = ctx;
	struct oncrpc_rdma_hdr *call = &rc->rc_hdr;
	struct oncrpc_rdma_hdr rh;
	struct oncrpc_rdma_plan rp;
	struct oncrpc_xdrmbuf hx;
	struct mbuf *red, *n;
	u_int paylen, off, i, keep, hlen;
	int *chunkof = NULL, error;
	size_t ofsz = rc->rc_nmark * sizeof(int);

	paylen = m->m_pkthdr.len;
	if (!rc->rc_fixed)
		rdma_reply_marks(rc, m);
	if (rc->rc_nmark != 0)
		chunkof = kmem_alloc(ofsz, KM_SLEEP);
	oncrpc_rdma_reply_plan(call, rc->rc_marks, rc->rc_nmark, paylen,
	    iw->iw_sendthresh, chunkof, &rp);
	if (rp.rp_form == ONCRPC_RDMA_NOFIT) {
		error = rdma_send_error(xp, call->rh_xid, call->rh_vers,
		    ONCRPC_RDMA_ERR_CHUNK);
		goto out;
	}

	/* s3.5.2: the data before the Send that says it is there. */
	red = NULL;
	off = 0;
	for (i = 0; i < rc->rc_nmark; i++) {
		if (chunkof[i] == ONCRPC_RDMA_INLINE_ITEM)
			continue;
		oncrpc_rdma_chunk_fill(&call->rh_writes[i],
		    rc->rc_marks[i].dm_len);
		error = rdma_put_chunk(xp, &call->rh_writes[i], m,
		    rc->rc_marks[i].dm_pos);
		if (error != 0) {
			m_freem(red);
			goto out;
		}
		/* The reduced stream: all but the item and its roundup. */
		keep = rc->rc_marks[i].dm_pos - off;
		if (keep != 0) {
			n = iw_copy(m, off, keep);
			if (red == NULL)
				red = n;
			else
				m_cat(red, n);
		}
		off = rc->rc_marks[i].dm_pos + rc->rc_marks[i].dm_len;
		off += (4 - (off & 3)) & 3;
	}
	/* s4.3.2.2: what was not used goes back, its segments empty. */
	for (i = rc->rc_nmark; i < call->rh_nwrite; i++)
		oncrpc_rdma_chunk_fill(&call->rh_writes[i], 0);
	for (i = 0; i < rc->rc_nmark; i++) {
		if (chunkof[i] == ONCRPC_RDMA_INLINE_ITEM)
			oncrpc_rdma_chunk_fill(&call->rh_writes[i], 0);
	}
	if (off != paylen) {
		n = iw_copy(m, off, paylen - off);
		if (red == NULL)
			red = n;
		else
			m_cat(red, n);
	}
	m_freem(m);
	m = red;

	if (rp.rp_form == ONCRPC_RDMA_LONG) {
		oncrpc_rdma_chunk_fill(&call->rh_reply, rp.rp_reduced);
		error = rdma_put_chunk(xp, &call->rh_reply, m, 0);
		if (error != 0)
			goto out;
	} else if (call->rh_hasreply)
		oncrpc_rdma_chunk_fill(&call->rh_reply, 0);	/* s4.3.3 */

	oncrpc_rdma_reply_hdr(call, ONCRPC_RDMA_CREDITS,
	    rp.rp_form == ONCRPC_RDMA_LONG, &rh);
	oncrpc_xdrmbuf_create(&hx, NULL, UINT_MAX, XDR_ENCODE);
	if (!oncrpc_rdma_hdr_encode(&hx.xm_xdr, &rh)) {
		XDR_DESTROY(&hx.xm_xdr);
		error = ENOBUFS;
		goto out;
	}
	hlen = XDR_GETPOS(&hx.xm_xdr);
	n = oncrpc_xdrmbuf_detach(&hx);
	if (rp.rp_form == ONCRPC_RDMA_SHORT && m != NULL) {
		m_cat(n, m);
		hlen += rp.rp_reduced;
		m = NULL;
	}
	n->m_pkthdr.len = hlen;
	error = iw_send(xp, n, hlen);
	m_freem(n);
out:
	m_freem(m);
	if (chunkof != NULL)
		kmem_free(chunkof, ofsz);
	return error;
}

static void
rdma_ddp_result(void *ctx, u_int pos, u_int len)
{
	struct rdma_ctx *rc = ctx;

	/* RFC 8267 s6.4.1: past the last chunk, it goes inline anyway. */
	if (rc->rc_nmark == rc->rc_maxmark)
		return;
	rc->rc_marks[rc->rc_nmark].dm_pos = pos;
	rc->rc_marks[rc->rc_nmark].dm_len = len;
	rc->rc_nmark++;
}

/*
 * The marks are of rq_res, and the reply has the RPC header before
 * that; or the results were dropped for an error reply, and with them
 * all the marks, leaving every Write chunk unused.
 */
static void
rdma_ddp_fix(void *ctx, u_int hdrlen, bool kept)
{
	struct rdma_ctx *rc = ctx;
	u_int i;

	rc->rc_fixed = true;
	if (!kept)
		rc->rc_nmark = 0;
	for (i = 0; i < rc->rc_nmark; i++)
		rc->rc_marks[i].dm_pos += hdrlen;
}

static void
rdma_shutdown(struct oncrpc_xprt *xp)
{
	struct socket *so = xp->xp_so;

	solock(so);
	so->so_upcall = NULL;
	so->so_upcallarg = NULL;
	so->so_rcv.sb_flags &= ~SB_UPCALL;
	soshutdown(so, SHUT_RDWR);
	sounlock(so);
}

static void
rdma_destroy(struct oncrpc_xprt *xp)
{
	struct iw_conn *iw = XPIW(xp);
	struct iw_msg *im;

	while ((im = SIMPLEQ_FIRST(&iw->iw_msgs)) != NULL) {
		SIMPLEQ_REMOVE_HEAD(&iw->iw_msgs, im_next);
		kmem_free(im->im_buf, IW_RECVSIZE);
		kmem_free(im, sizeof(*im));
	}
	if (iw->iw_cur != NULL)
		kmem_free(iw->iw_cur, IW_RECVSIZE);
	m_freem(iw->iw_raw);
	kmem_free(iw->iw_fpdu, IW_FPDU_BUF);
	cv_destroy(&iw->iw_txcv);
	mutex_destroy(&iw->iw_txlock);
	kmem_free(iw, sizeof(*iw));
}

static const struct oncrpc_xprt_ops rdma_ops = {
	.xo_recv = rdma_recv,
	.xo_send = rdma_send,
	.xo_shutdown = rdma_shutdown,
	.xo_destroy = rdma_destroy,
	.xo_ctxfree = rdma_xo_ctxfree,
	.xo_ddp_result = rdma_ddp_result,
	.xo_ddp_fix = rdma_ddp_fix,
};

/*
 * Serve a connected TCP socket, accepted on the port of RFC 8267 s9 as
 * oncrpc_svc_addsock() would, as an iWARP passive endpoint.  The file
 * gets a reference of its own, and nam is consumed.
 */
int
oncrpc_svc_addrdma(struct oncrpc_svc *svc, struct file *fp, struct mbuf *nam)
{
	struct iw_conn *iw;
	int error;

	iw = kmem_zalloc(sizeof(*iw), KM_SLEEP);
	iw->iw_state = IW_MPA_WAIT;
	iw->iw_sendthresh = ONCRPC_RDMA_INLINE_MIN;
	iw->iw_fpdu = kmem_alloc(IW_FPDU_BUF, KM_SLEEP);
	/* RFC 5041 s4.3: "The initial value for MSN MUST be one." */
	iw->iw_rmsn = 1;
	iw->iw_smsn[IW_QN_SEND] = 1;
	iw->iw_smsn[IW_QN_READ] = 1;
	iw->iw_smsn[IW_QN_TERM] = 1;
	SIMPLEQ_INIT(&iw->iw_msgs);
	mutex_init(&iw->iw_txlock, MUTEX_DEFAULT, IPL_NONE);
	cv_init(&iw->iw_txcv, "oncrpcrd");
	oncrpc_rdma_bc_init(&iw->iw_bc);

	error = oncrpc_xprt_addsock(svc, fp, nam, &rdma_ops, iw);
	if (error != 0) {
		kmem_free(iw->iw_fpdu, IW_FPDU_BUF);
		cv_destroy(&iw->iw_txcv);
		mutex_destroy(&iw->iw_txlock);
		kmem_free(iw, sizeof(*iw));
	}
	return error;
}
