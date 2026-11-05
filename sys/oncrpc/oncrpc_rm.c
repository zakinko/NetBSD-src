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
 * Record marking on a byte stream, RFC 5531 s11, in the manner of
 * nfsrv_getstream().  The RFC allows a record of any size in any number
 * of fragments; rm_max is what one peer may make this host hold on to,
 * and counts the headers of the fragments as well as their data.  Going
 * over it is treated as a broken stream, as there is no way to find the
 * next record but to read past this one.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/mbuf.h>
#include <sys/systm.h>

#include <oncrpc/oncrpc_var.h>

void
oncrpc_rm_init(struct oncrpc_rm *rm, u_int max)
{

	memset(rm, 0, sizeof(*rm));
	rm->rm_max = max;
}

void
oncrpc_rm_fini(struct oncrpc_rm *rm)
{

	m_freem(rm->rm_raw);
	m_freem(rm->rm_frag);
	memset(rm, 0, sizeof(*rm));
}

/* Take m, cc bytes more of the stream. */
void
oncrpc_rm_input(struct oncrpc_rm *rm, struct mbuf *m, u_int cc)
{

	if (rm->rm_raw != NULL)
		rm->rm_rawend->m_next = m;
	else
		rm->rm_raw = m;
	while (m->m_next != NULL)
		m = m->m_next;
	rm->rm_rawend = m;
	rm->rm_cc += cc;
}

/*
 * Return the next whole record in *recp: 0, or EAGAIN if it needs more
 * of the stream, or another error if the stream is no good.  A record
 * of no bytes is legal, a fragment being "0 to (2**31) - 1 bytes" and
 * Linux being known to send them (nfsrv_getstream), but holds no
 * message, so it is skipped.
 */
int
oncrpc_rm_next(struct oncrpc_rm *rm, struct mbuf **recp)
{
	struct mbuf *m, *rec;
	uint32_t hdr;

	for (;;) {
		if (!rm->rm_inframe) {
			if (rm->rm_cc < ONCRPC_RM_HDRSIZE)
				return EAGAIN;
			m_copydata(rm->rm_raw, 0, ONCRPC_RM_HDRSIZE, &hdr);
			m_adj(rm->rm_raw, ONCRPC_RM_HDRSIZE);
			rm->rm_cc -= ONCRPC_RM_HDRSIZE;
			hdr = ntohl(hdr);
			rm->rm_last = (hdr & ONCRPC_RM_LAST) != 0;
			rm->rm_need = hdr & ONCRPC_RM_LENMASK;

			/*
			 * A count of fragments would refuse a short record
			 * cut finely, which the RFC allows and which cost
			 * nothing: m_cat() below packs small ones.  Charging
			 * the header bounds them, and empty fragments too.
			 * rm_total passes rm_max by a header at most.
			 */
			if (rm->rm_total > rm->rm_max ||
			    rm->rm_need > rm->rm_max - rm->rm_total)
				return EMSGSIZE;
			rm->rm_total += rm->rm_need + ONCRPC_RM_HDRSIZE;
			rm->rm_inframe = true;
		}

		if (rm->rm_cc < rm->rm_need)
			return EAGAIN;

		if (rm->rm_need == rm->rm_cc && rm->rm_need > 0) {
			rec = rm->rm_raw;
			rm->rm_raw = rm->rm_rawend = NULL;
			rm->rm_cc = 0;
		} else if (rm->rm_need > 0) {
			rec = rm->rm_raw;
			m = m_split(rec, rm->rm_need, M_WAIT);
			if (m == NULL)
				return ENOBUFS;
			rm->rm_raw = m;
			while (m->m_next != NULL)
				m = m->m_next;
			rm->rm_rawend = m;
			rm->rm_cc -= rm->rm_need;
		} else
			rec = NULL;

		if (rm->rm_frag == NULL)
			rm->rm_frag = rec;
		else if (rec != NULL)
			m_cat(rm->rm_frag, rec);
		rm->rm_inframe = false;

		if (!rm->rm_last)
			continue;
		rec = rm->rm_frag;
		rm->rm_frag = NULL;
		rm->rm_total = 0;
		if (rec != NULL) {
			*recp = rec;
			return 0;
		}
	}
}
