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

#ifndef _ONCRPC_ONCRPC_XDR_H_
#define _ONCRPC_ONCRPC_XDR_H_

#include <rpc/types.h>
#include <rpc/xdr.h>

struct mbuf;

/*
 * An XDR stream over an mbuf chain.  The filters in xdr.c work on it
 * unchanged; the XDR is first so that the ops can get back here from
 * the XDR * they are given.
 *
 * A decoder reads the chain it is given and leaves it to the caller.
 * An encoder starts empty and owns the chain it grows until
 * oncrpc_xdrmbuf_detach() takes it, or XDR_DESTROY() frees it.  It may
 * sleep for mbufs.
 */
struct oncrpc_xdrmbuf {
	XDR		xm_xdr;
	struct mbuf	*xm_head;	/* the chain */
	struct mbuf	*xm_cur;	/* mbuf the cursor is in */
	u_int		xm_off;		/* cursor within xm_cur */
	u_int		xm_pos;		/* cursor within the stream */
	u_int		xm_len;		/* bytes in the stream */
	u_int		xm_max;		/* limit on xm_len when encoding */
};

void	oncrpc_xdrmbuf_create(struct oncrpc_xdrmbuf *, struct mbuf *, u_int,
	    enum xdr_op);
struct mbuf *
	oncrpc_xdrmbuf_detach(struct oncrpc_xdrmbuf *);
void	oncrpc_xdrmbuf_getcursor(struct oncrpc_xdrmbuf *, struct mbuf **,
	    char **);

#endif /* !_ONCRPC_ONCRPC_XDR_H_ */
