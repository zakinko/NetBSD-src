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
 * The sequence window of RPCSEC_GSS, RFC 2203 s5.3.3.1, by a reference
 * model of it.  Exit status 0 is success.
 *
 *	cc -I../../sys -o t t_gss_seq.c
 */

#include <sys/types.h>
#include <sys/param.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef __KERNEL_RCSID
#define	__KERNEL_RCSID(a, b)
#endif

#include <oncrpc/oncrpc_gss.c>

static uint8_t seen[1 << 20];

int
main(void)
{
	struct oncrpc_gss_seq gs;
	uint32_t i, seq, last = 0, base = 1000;
	bool any = false, want, got;

	oncrpc_gss_seq_init(&gs);
	srandom(1);
	for (i = 0; i < 2000000; i++) {
		seq = base + random() % (sizeof(seen) - 1);
		/* Near the top of what was seen, mostly. */
		if (any && random() % 16 != 0) {
			seq = last + 40 - random() % 300;
			if (seq < base)
				seq = base;
			if (seq - base >= sizeof(seen))
				seq = base;
		}
		want = !seen[seq - base] &&
		    (!any || seq > last || last - seq < RPCSEC_GSS_WINDOW);
		got = oncrpc_gss_seq_accept(&gs, seq);
		if (got != want) {
			printf("step %u: %u, last %u: got %d, want %d\n", i,
			    seq, last, got, want);
			return 1;
		}
		if (got) {
			seen[seq - base] = 1;
			if (!any || seq > last)
				last = seq;
			any = true;
		}
		/* Start over before the space runs out. */
		if (last - base > sizeof(seen) - 4096) {
			oncrpc_gss_seq_init(&gs);
			memset(seen, 0, sizeof(seen));
			any = false;
		}
	}
	if (oncrpc_gss_seq_accept(&gs, RPCSEC_GSS_MAXSEQ)) {
		printf("MAXSEQ was taken\n");
		return 1;
	}
	printf("ok\n");
	return 0;
}
