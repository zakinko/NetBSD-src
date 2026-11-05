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
 * XDR over mbuf chains.
 *
 * Nothing here looks at where the mbufs end: an item may start at any
 * offset and cross any number of them, because a chain from a socket
 * is cut wherever the network cut it.  So the fixed-size reads copy,
 * and only x_inline hands out a pointer, when it can.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/endian.h>
#include <sys/mbuf.h>

#include <oncrpc/oncrpc_xdr.h>

#define	XM(xdrs)	((struct oncrpc_xdrmbuf *)(xdrs))

static bool_t	xdrmbuf_getlong(XDR *, long *);
static bool_t	xdrmbuf_putlong(XDR *, const long *);
static bool_t	xdrmbuf_getbytes(XDR *, char *, u_int);
static bool_t	xdrmbuf_putbytes(XDR *, const char *, u_int);
static u_int	xdrmbuf_getpos(XDR *);
static bool_t	xdrmbuf_setpos(XDR *, u_int);
static int32_t	*xdrmbuf_inline(XDR *, u_int);
static void	xdrmbuf_destroy(XDR *);
static bool_t	xdrmbuf_control(XDR *, int, void *);

static const struct xdr_ops xdrmbuf_ops = {
	xdrmbuf_getlong,
	xdrmbuf_putlong,
	xdrmbuf_getbytes,
	xdrmbuf_putbytes,
	xdrmbuf_getpos,
	xdrmbuf_setpos,
	xdrmbuf_inline,
	xdrmbuf_destroy,
	xdrmbuf_control
};

/*
 * m is the chain to decode.  An encoder takes none, and writes at most
 * limit bytes; a decoder has no use for limit, stopping at the end of
 * the chain.
 */
void
oncrpc_xdrmbuf_create(struct oncrpc_xdrmbuf *xm, struct mbuf *m, u_int limit,
    enum xdr_op op)
{
	struct mbuf *n;
	u_int len;

	KASSERT(op == XDR_DECODE || m == NULL);

	len = 0;
	for (n = m; n != NULL; n = n->m_next)
		len += n->m_len;

	xm->xm_xdr.x_op = op;
	xm->xm_xdr.x_ops = &xdrmbuf_ops;
	xm->xm_head = xm->xm_cur = m;
	xm->xm_off = xm->xm_pos = 0;
	xm->xm_len = len;
	xm->xm_max = limit;
}

/*
 * Take the chain away from an encoder, which is then empty.
 */
struct mbuf *
oncrpc_xdrmbuf_detach(struct oncrpc_xdrmbuf *xm)
{
	struct mbuf *m;

	KASSERT(xm->xm_xdr.x_op == XDR_ENCODE);

	m = xm->xm_head;
	if (m != NULL)
		m->m_pkthdr.len = xm->xm_len;
	xm->xm_head = xm->xm_cur = NULL;
	xm->xm_off = xm->xm_pos = xm->xm_len = 0;
	return m;
}

/*
 * Where the cursor is, as the (nd_md, nd_dpos) pair the nfsm_* macros
 * use.  This is also how the body of a large opaque can be taken from
 * the chain without going through xdr_opaque(), which always copies.
 */
void
oncrpc_xdrmbuf_getcursor(struct oncrpc_xdrmbuf *xm, struct mbuf **mp,
    char **posp)
{

	*mp = xm->xm_cur;
	*posp = xm->xm_cur == NULL ? NULL :
	    mtod(xm->xm_cur, char *) + xm->xm_off;
}

static bool_t
xdrmbuf_getlong(XDR *xdrs, long *lp)
{
	uint32_t v;

	if (!xdrmbuf_getbytes(xdrs, (char *)&v, sizeof(v)))
		return FALSE;
	*lp = ntohl(v);
	return TRUE;
}

static bool_t
xdrmbuf_putlong(XDR *xdrs, const long *lp)
{
	uint32_t v;

	v = htonl((uint32_t)*lp);
	return xdrmbuf_putbytes(xdrs, (const char *)&v, sizeof(v));
}

static bool_t
xdrmbuf_getbytes(XDR *xdrs, char *addr, u_int len)
{
	struct oncrpc_xdrmbuf *xm = XM(xdrs);
	u_int n;

	/* Subtract: a length off the wire may be anything. */
	if (len > xm->xm_len - xm->xm_pos)
		return FALSE;

	xm->xm_pos += len;
	while (len > 0) {
		KASSERT(xm->xm_cur != NULL);
		n = xm->xm_cur->m_len - xm->xm_off;
		if (n == 0) {
			xm->xm_cur = xm->xm_cur->m_next;
			xm->xm_off = 0;
			continue;
		}
		if (n > len)
			n = len;
		memcpy(addr, mtod(xm->xm_cur, char *) + xm->xm_off, n);
		xm->xm_off += n;
		addr += n;
		len -= n;
	}
	return TRUE;
}

static struct mbuf *
xdrmbuf_more(struct oncrpc_xdrmbuf *xm, u_int want)
{
	struct mbuf *m;

	if (xm->xm_head == NULL) {
		m = m_gethdr(M_WAIT, MT_DATA);
		m_reset_rcvif(m);
		xm->xm_head = m;
	} else {
		m = m_get(M_WAIT, MT_DATA);
		xm->xm_cur->m_next = m;
	}
	m->m_len = 0;
	if (want >= MINCLSIZE)
		m_clget(m, M_WAIT);
	xm->xm_cur = m;
	xm->xm_off = 0;
	return m;
}

/*
 * Write at the cursor, over what is there after a setpos and then onto
 * the end of the chain.
 */
static bool_t
xdrmbuf_putbytes(XDR *xdrs, const char *addr, u_int len)
{
	struct oncrpc_xdrmbuf *xm = XM(xdrs);
	struct mbuf *m;
	u_int n;

	if (xm->xm_pos > xm->xm_max || len > xm->xm_max - xm->xm_pos)
		return FALSE;

	while (len > 0) {
		if ((m = xm->xm_cur) == NULL) {
			(void)xdrmbuf_more(xm, len);
			continue;
		}
		n = m->m_len - xm->xm_off;
		if (n == 0) {
			if (m->m_next != NULL) {
				xm->xm_cur = m->m_next;
				xm->xm_off = 0;
				continue;
			}
			n = M_TRAILINGSPACE(m);
			if (n == 0) {
				(void)xdrmbuf_more(xm, len);
				continue;
			}
			if (n > len)
				n = len;
			m->m_len += n;
		} else if (n > len)
			n = len;
		memcpy(mtod(m, char *) + xm->xm_off, addr, n);
		xm->xm_off += n;
		xm->xm_pos += n;
		addr += n;
		len -= n;
	}
	if (xm->xm_pos > xm->xm_len)
		xm->xm_len = xm->xm_pos;
	return TRUE;
}

static u_int
xdrmbuf_getpos(XDR *xdrs)
{

	return XM(xdrs)->xm_pos;
}

static bool_t
xdrmbuf_setpos(XDR *xdrs, u_int pos)
{
	struct oncrpc_xdrmbuf *xm = XM(xdrs);
	struct mbuf *m;
	u_int off;

	if (pos > xm->xm_len)
		return FALSE;

	off = pos;
	m = xm->xm_head;
	while (m != NULL && off > (u_int)m->m_len) {
		off -= m->m_len;
		m = m->m_next;
	}
	xm->xm_cur = m;
	xm->xm_off = off;
	xm->xm_pos = pos;
	return TRUE;
}

/*
 * A pointer, if len bytes at the cursor are contiguous and aligned for
 * the IXDR macros.  They may well not be, and NULL then says to use the
 * filters instead; it is not an error.
 */
static int32_t *
xdrmbuf_inline(XDR *xdrs, u_int len)
{
	struct oncrpc_xdrmbuf *xm = XM(xdrs);
	struct mbuf *m;
	char *p;
	u_int avail, grow;

	while ((m = xm->xm_cur) != NULL && xm->xm_off == (u_int)m->m_len &&
	    m->m_next != NULL) {
		xm->xm_cur = m->m_next;
		xm->xm_off = 0;
	}
	if (m == NULL)
		return NULL;

	avail = m->m_len - xm->xm_off;
	grow = 0;
	if (len > avail) {
		if (xdrs->x_op != XDR_ENCODE || m->m_next != NULL)
			return NULL;
		grow = len - avail;
		if (grow > (u_int)M_TRAILINGSPACE(m))
			return NULL;
	}
	if (xdrs->x_op == XDR_ENCODE ?
	    (xm->xm_pos > xm->xm_max || len > xm->xm_max - xm->xm_pos) :
	    len > xm->xm_len - xm->xm_pos)
		return NULL;

	p = mtod(m, char *) + xm->xm_off;
	if (((uintptr_t)p & (sizeof(int32_t) - 1)) != 0)
		return NULL;

	m->m_len += grow;
	xm->xm_off += len;
	xm->xm_pos += len;
	if (xm->xm_pos > xm->xm_len)
		xm->xm_len = xm->xm_pos;
	return (int32_t *)p;
}

static void
xdrmbuf_destroy(XDR *xdrs)
{
	struct oncrpc_xdrmbuf *xm = XM(xdrs);

	if (xdrs->x_op == XDR_ENCODE)
		m_freem(xm->xm_head);
	xm->xm_head = xm->xm_cur = NULL;
}

static bool_t
xdrmbuf_control(XDR *xdrs, int request, void *info)
{
	struct oncrpc_xdrmbuf *xm = XM(xdrs);
	xdr_bytesrec *xptr;

	switch (request) {
	case XDR_GET_BYTES_AVAIL:
		xptr = info;
		xptr->xc_is_last_record = TRUE;
		xptr->xc_num_avail = xm->xm_len - xm->xm_pos;
		return TRUE;
	}
	return FALSE;
}
