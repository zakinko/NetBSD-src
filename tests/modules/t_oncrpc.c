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

#include <sys/cdefs.h>
__RCSID("$NetBSD$");

#include <sys/param.h>
#include <sys/sysctl.h>

#include <atf-c.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define	NODE	"vendor.k_oncrpc."

static void
load(const atf_tc_t *tc)
{
	char cmd[MAXPATHLEN];
	int v;
	size_t len = sizeof(v);

	if (sysctlbyname(NODE "pad", &v, &len, NULL, 0) == 0)
		return;
	snprintf(cmd, sizeof(cmd), "modload %s/k_oncrpc/k_oncrpc.kmod",
	    atf_tc_get_config_var(tc, "srcdir"));
	if (system(cmd) != 0)
		atf_tc_skip("cannot load k_oncrpc");
}

static void
kernel_test(const atf_tc_t *tc, const char *name)
{
	char node[64];
	int line;
	size_t len = sizeof(line);

	load(tc);
	snprintf(node, sizeof(node), NODE "%s", name);
	ATF_REQUIRE_MSG(sysctlbyname(node, &line, &len, NULL, 0) == 0,
	    "%s: %s", node, strerror(errno));
	ATF_CHECK_MSG(line == 0, "failed at k_oncrpc.c line %d", line);
}

#define	KERNEL_TC(name, descr)						\
	ATF_TC(name);							\
	ATF_TC_HEAD(name, tc)						\
	{								\
		atf_tc_set_md_var(tc, "descr", descr);			\
		atf_tc_set_md_var(tc, "require.user", "root");		\
	}								\
	ATF_TC_BODY(name, tc)						\
	{								\
		kernel_test(tc, #name);					\
	}

KERNEL_TC(pad, "RFC 4506 s3: items are padded to 4 with zeros")
KERNEL_TC(order, "RFC 4506 s4: big endian")
KERNEL_TC(boundary, "Values crossing every mbuf boundary")
KERNEL_TC(truncated, "Reads past the end of the chain fail")
KERNEL_TC(overlong, "RFC 4506 s8: lengths past the limit are refused")
KERNEL_TC(nonzero_pad, "A non-zero pad is accepted when decoding")
KERNEL_TC(encode_chain, "The encoder grows across mbufs")
KERNEL_TC(encode_limit, "The encoder limit and rewriting a length")
KERNEL_TC(inline, "x_inline only for contiguous aligned data")

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, pad);
	ATF_TP_ADD_TC(tp, order);
	ATF_TP_ADD_TC(tp, boundary);
	ATF_TP_ADD_TC(tp, truncated);
	ATF_TP_ADD_TC(tp, overlong);
	ATF_TP_ADD_TC(tp, nonzero_pad);
	ATF_TP_ADD_TC(tp, encode_chain);
	ATF_TP_ADD_TC(tp, encode_limit);
	ATF_TP_ADD_TC(tp, inline);

	return atf_no_error();
}
