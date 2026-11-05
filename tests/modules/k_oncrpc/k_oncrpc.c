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
 * Kernel half of t_oncrpc: the stream code needs real mbufs.  Each test
 * is a read-only sysctl under vendor.k_oncrpc, reading as 0 or as the
 * line that failed.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <oncrpc/oncrpc_xdr.h>

MODULE(MODULE_CLASS_MISC, k_oncrpc, "xdr");

#define	CHECK(e)	do { if (!(e)) return __LINE__; } while (0)

/*
 * A chain holding data, cut after a and then after b bytes.  Each
 * piece starts one byte into its mbuf, so nothing in it is aligned,
 * and a cut at the same place twice leaves an empty mbuf in the chain.
 */
static struct mbuf *
mkchain(const void *data, u_int len, u_int a, u_int b)
{
	const char *p = data;
	struct mbuf *head = NULL, **mp = &head, *m;
	u_int cut[3] = { a, b - a, len - b };
	u_int i;

	KASSERT(a <= b && b <= len && len <= MLEN - 1);
	for (i = 0; i < __arraycount(cut); i++) {
		m = m_get(M_WAIT, MT_DATA);
		m->m_data++;
		m->m_len = cut[i];
		memcpy(mtod(m, char *), p, cut[i]);
		p += cut[i];
		*mp = m;
		mp = &m->m_next;
	}
	return head;
}

static void
encoder(struct oncrpc_xdrmbuf *xm)
{

	oncrpc_xdrmbuf_create(xm, NULL, UINT_MAX, XDR_ENCODE);
}

/* RFC 4506 s3: every item is a multiple of 4, padded with zero bytes. */
static int
t_pad(void)
{
	static const u_char want[][8] = {
		{ 0, 0, 0, 0, 0, 0, 0, 0 },
		{ 0xff, 0, 0, 0, 0, 0, 0, 0 },
		{ 0xff, 0xff, 0, 0, 0, 0, 0, 0 },
		{ 0xff, 0xff, 0xff, 0, 0, 0, 0, 0 },
		{ 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0 },
		{ 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0 },
		{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0 },
		{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0 },
	};
	static const u_int total[] = { 0, 4, 4, 4, 4, 8, 8, 8 };
	struct oncrpc_xdrmbuf xm;
	char src[8], out[8];
	struct mbuf *m;
	u_int n;

	memset(src, 0xff, sizeof(src));
	for (n = 0; n < __arraycount(want); n++) {
		encoder(&xm);
		CHECK(xdr_opaque(&xm.xm_xdr, src, n));
		CHECK(XDR_GETPOS(&xm.xm_xdr) == total[n]);
		m = oncrpc_xdrmbuf_detach(&xm);
		if (total[n] == 0) {
			CHECK(m == NULL);
			continue;
		}
		CHECK(m->m_pkthdr.len == (int)total[n]);
		m_copydata(m, 0, total[n], out);
		m_freem(m);
		CHECK(memcmp(out, want[n], total[n]) == 0);
	}
	return 0;
}

/* RFC 4506 s4.1, s4.5: the most significant byte comes first. */
static int
t_order(void)
{
	static const u_char want[] = {
		0xde, 0xad, 0xbe, 0xef,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xff, 0xff, 0xff, 0xfe,		/* -2 */
		0x00, 0x00, 0x00, 0x01,		/* TRUE, s4.4 */
	};
	struct oncrpc_xdrmbuf xm;
	u_char out[sizeof(want)];
	uint32_t u = 0xdeadbeef;
	uint64_t h = 0x0123456789abcdefULL;
	int32_t i = -2;
	bool_t b = TRUE;
	struct mbuf *m;

	encoder(&xm);
	CHECK(xdr_u_int32_t(&xm.xm_xdr, &u));
	CHECK(xdr_u_int64_t(&xm.xm_xdr, &h));
	CHECK(xdr_int32_t(&xm.xm_xdr, &i));
	CHECK(xdr_bool(&xm.xm_xdr, &b));
	m = oncrpc_xdrmbuf_detach(&xm);
	m_copydata(m, 0, sizeof(out), out);
	m_freem(m);
	CHECK(memcmp(out, want, sizeof(want)) == 0);
	return 0;
}

/* Every value decodes the same wherever the chain is cut. */
static int
t_boundary(void)
{
	static const u_char wire[] = {
		0xde, 0xad, 0xbe, 0xef,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0x00, 0x00, 0x00, 0x05,
		'h', 'e', 'l', 'l', 'o', 0, 0, 0,
		0x00, 0x00, 0x00, 0x07,
	};
	u_int a, b;

	for (a = 0; a <= sizeof(wire); a++) {
		for (b = a; b <= sizeof(wire); b++) {
			struct oncrpc_xdrmbuf xm;
			struct mbuf *m;
			uint32_t u, last;
			uint64_t h;
			char buf[8], *bp = buf;
			u_int len;
			bool_t ok;

			memset(buf, 0, sizeof(buf));
			m = mkchain(wire, sizeof(wire), a, b);
			oncrpc_xdrmbuf_create(&xm, m, 0, XDR_DECODE);
			ok = xdr_u_int32_t(&xm.xm_xdr, &u) &&
			    xdr_u_int64_t(&xm.xm_xdr, &h) &&
			    xdr_bytes(&xm.xm_xdr, &bp, &len, sizeof(buf)) &&
			    xdr_u_int32_t(&xm.xm_xdr, &last);
			if (ok) {
				ok = XDR_GETPOS(&xm.xm_xdr) == sizeof(wire);
				XDR_DESTROY(&xm.xm_xdr);
			}
			m_freem(m);
			CHECK(ok);
			CHECK(u == 0xdeadbeef);
			CHECK(h == 0x0123456789abcdefULL);
			CHECK(len == 5 && memcmp(buf, "hello", 6) == 0);
			CHECK(last == 7);
		}
	}
	return 0;
}

/* Truncate at each length: the read fails, and only then. */
static int
t_truncated(void)
{
	static const u_char wire[] = {
		0x00, 0x00, 0x00, 0x05,
		'h', 'e', 'l', 'l', 'o', 0, 0, 0,
	};
	u_int n;

	for (n = 0; n <= sizeof(wire); n++) {
		struct oncrpc_xdrmbuf xm;
		struct mbuf *m;
		char buf[8], *bp = buf;
		u_int len;
		bool_t ok;

		m = mkchain(wire, n, n / 2, n / 2);
		oncrpc_xdrmbuf_create(&xm, m, 0, XDR_DECODE);
		ok = xdr_bytes(&xm.xm_xdr, &bp, &len, sizeof(buf));
		m_freem(m);
		CHECK(ok == (n == sizeof(wire)));
	}
	return 0;
}

/*
 * RFC 4506 s8: the length is not to be believed.  Each of these has to
 * be refused before a byte lands in the buffer behind the canary.
 */
static int
t_overlong(void)
{
	static const u_char big[][4] = {
		{ 0x00, 0x00, 0x00, 0x09 },	/* one more than the limit */
		{ 0x7f, 0xff, 0xff, 0xff },
		{ 0x80, 0x00, 0x00, 0x00 },
		{ 0xff, 0xff, 0xff, 0xff },	/* wraps if 3 is added */
		{ 0xff, 0xff, 0xff, 0xfd },
	};
	u_char wire[4 + 16];
	u_int i;

	memset(wire, 'x', sizeof(wire));
	for (i = 0; i < __arraycount(big); i++) {
		struct oncrpc_xdrmbuf xm;
		struct mbuf *m;
		char buf[8 + 4], *bp = buf;
		u_int len;
		bool_t ok;

		memcpy(wire, big[i], 4);
		memset(buf, 'c', sizeof(buf));
		m = mkchain(wire, sizeof(wire), 2, 3);
		oncrpc_xdrmbuf_create(&xm, m, 0, XDR_DECODE);
		ok = xdr_bytes(&xm.xm_xdr, &bp, &len, 8);
		CHECK(!ok);
		/* The same length with no limit: the stream must stop it. */
		CHECK(XDR_SETPOS(&xm.xm_xdr, 0));
		ok = len <= 16 ? FALSE :
		    xdr_u_int(&xm.xm_xdr, &len) &&
		    xdr_opaque(&xm.xm_xdr, buf, len);
		m_freem(m);
		CHECK(!ok);
		CHECK(bp == buf);
		CHECK(memcmp(buf, "cccccccccccc", sizeof(buf)) == 0);
	}
	return 0;
}

/* RFC 4506 does not say to reject a non-zero pad; we take it. */
static int
t_nonzero_pad(void)
{
	static const u_char wire[] = { 'a', 0xaa, 0xbb, 0xcc, 0, 0, 0, 1 };
	struct oncrpc_xdrmbuf xm;
	struct mbuf *m;
	uint32_t u;
	char c;
	bool_t ok;

	m = mkchain(wire, sizeof(wire), 1, 2);
	oncrpc_xdrmbuf_create(&xm, m, 0, XDR_DECODE);
	ok = xdr_opaque(&xm.xm_xdr, &c, 1) && xdr_u_int32_t(&xm.xm_xdr, &u);
	m_freem(m);
	CHECK(ok && c == 'a' && u == 1);
	return 0;
}

/* Grow across several mbufs and read it all back through a decoder. */
static int
t_encode_chain(void)
{
	const u_int n = 3 * MCLBYTES + 7;
	struct oncrpc_xdrmbuf xm;
	struct mbuf *m, *t;
	char *src, *dst;
	u_int i, nm, len;
	uint32_t u = 0x01020304;
	bool_t ok;

	src = kmem_alloc(n, KM_SLEEP);
	dst = kmem_alloc(n, KM_SLEEP);
	for (i = 0; i < n; i++)
		src[i] = (char)(i * 7);

	encoder(&xm);
	CHECK(xdr_u_int32_t(&xm.xm_xdr, &u));
	CHECK(xdr_opaque(&xm.xm_xdr, src, n));
	CHECK(xdr_u_int32_t(&xm.xm_xdr, &u));
	m = oncrpc_xdrmbuf_detach(&xm);
	CHECK(m->m_pkthdr.len == (int)(4 + roundup(n, 4) + 4));
	nm = len = 0;
	for (t = m; t != NULL; t = t->m_next) {
		nm++;
		len += t->m_len;
	}
	CHECK(nm > 1 && len == (u_int)m->m_pkthdr.len);

	oncrpc_xdrmbuf_create(&xm, m, 0, XDR_DECODE);
	u = 0;
	ok = xdr_u_int32_t(&xm.xm_xdr, &u) && u == 0x01020304 &&
	    xdr_opaque(&xm.xm_xdr, dst, n) &&
	    xdr_u_int32_t(&xm.xm_xdr, &u) && u == 0x01020304 &&
	    memcmp(src, dst, n) == 0;
	m_freem(m);
	kmem_free(src, n);
	kmem_free(dst, n);
	CHECK(ok);
	return 0;
}

/* The encoder's limit, and going back to fill in a length. */
static int
t_encode_limit(void)
{
	static const u_char want[] = {
		0, 0, 0, 2, 0, 0, 0, 9, 0, 0, 0, 8,
	};
	struct oncrpc_xdrmbuf xm;
	u_char out[sizeof(want)];
	uint32_t v;
	struct mbuf *m;

	oncrpc_xdrmbuf_create(&xm, NULL, 12, XDR_ENCODE);
	v = 1;
	CHECK(xdr_u_int32_t(&xm.xm_xdr, &v));
	v = 9;
	CHECK(xdr_u_int32_t(&xm.xm_xdr, &v));
	v = 8;
	CHECK(xdr_u_int32_t(&xm.xm_xdr, &v));
	CHECK(!xdr_u_int32_t(&xm.xm_xdr, &v));
	CHECK(XDR_GETPOS(&xm.xm_xdr) == 12);
	CHECK(!XDR_SETPOS(&xm.xm_xdr, 13));
	CHECK(XDR_SETPOS(&xm.xm_xdr, 0));
	v = 2;
	CHECK(xdr_u_int32_t(&xm.xm_xdr, &v));
	CHECK(XDR_GETPOS(&xm.xm_xdr) == 4);
	m = oncrpc_xdrmbuf_detach(&xm);
	CHECK(m->m_pkthdr.len == 12);
	m_copydata(m, 0, sizeof(out), out);
	m_freem(m);
	CHECK(memcmp(out, want, sizeof(want)) == 0);

	/* XDR_DESTROY frees what was not detached. */
	encoder(&xm);
	CHECK(xdr_u_int32_t(&xm.xm_xdr, &v));
	XDR_DESTROY(&xm.xm_xdr);
	return 0;
}

static int
t_inline(void)
{
	static const uint32_t wire[] = { 0, 1, 2, 3 };
	struct oncrpc_xdrmbuf xm;
	struct mbuf *m, *c;
	xdr_bytesrec rec;
	int32_t *p;
	char *pos;

	/* Not aligned, as mkchain makes it: fall back to the filters. */
	m = mkchain(wire, sizeof(wire), 16, 16);
	oncrpc_xdrmbuf_create(&xm, m, 0, XDR_DECODE);
	CHECK(XDR_INLINE(&xm.xm_xdr, 4) == NULL);
	CHECK(XDR_GETPOS(&xm.xm_xdr) == 0);
	m_freem(m);

	/* Aligned, and the end of the mbuf is the end of the answer. */
	m = m_get(M_WAIT, MT_DATA);
	m->m_len = sizeof(wire);
	memcpy(mtod(m, void *), wire, sizeof(wire));
	oncrpc_xdrmbuf_create(&xm, m, 0, XDR_DECODE);
	p = XDR_INLINE(&xm.xm_xdr, 12);
	CHECK(p == mtod(m, int32_t *));
	CHECK(XDR_GETPOS(&xm.xm_xdr) == 12);
	CHECK(XDR_CONTROL(&xm.xm_xdr, XDR_GET_BYTES_AVAIL, &rec));
	CHECK(rec.xc_num_avail == 4);
	CHECK(XDR_INLINE(&xm.xm_xdr, 8) == NULL);
	oncrpc_xdrmbuf_getcursor(&xm, &c, &pos);
	CHECK(c == m && pos == mtod(m, char *) + 12);
	CHECK(XDR_SETPOS(&xm.xm_xdr, 4));
	CHECK(XDR_INLINE(&xm.xm_xdr, 4) == mtod(m, int32_t *) + 1);
	m_freem(m);
	return 0;
}

static const struct {
	const char	*name;
	int		(*func)(void);
} tests[] = {
	{ "pad",		t_pad },
	{ "order",		t_order },
	{ "boundary",		t_boundary },
	{ "truncated",		t_truncated },
	{ "overlong",		t_overlong },
	{ "nonzero_pad",	t_nonzero_pad },
	{ "encode_chain",	t_encode_chain },
	{ "encode_limit",	t_encode_limit },
	{ "inline",		t_inline },
};

static int
sysctl_runtest(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	int (*func)(void) = rnode->sysctl_data;
	int result;

	result = (*func)();
	node.sysctl_data = &result;
	return sysctl_lookup(SYSCTLFN_CALL(&node));
}

static struct sysctllog *k_oncrpc_log;

static int
k_oncrpc_init(void)
{
	const struct sysctlnode *rnode;
	u_int i;
	int error;

	error = sysctl_createv(&k_oncrpc_log, 0, NULL, &rnode,
	    CTLFLAG_PERMANENT, CTLTYPE_NODE, "k_oncrpc", NULL,
	    NULL, 0, NULL, 0, CTL_VENDOR, CTL_CREATE, CTL_EOL);
	for (i = 0; error == 0 && i < __arraycount(tests); i++) {
		error = sysctl_createv(&k_oncrpc_log, 0, &rnode, NULL,
		    CTLFLAG_PERMANENT, CTLTYPE_INT, tests[i].name, NULL,
		    sysctl_runtest, 0, (void *)(uintptr_t)tests[i].func, 0,
		    CTL_CREATE, CTL_EOL);
	}
	if (error)
		sysctl_teardown(&k_oncrpc_log);
	return error;
}

static int
k_oncrpc_modcmd(modcmd_t cmd, void *arg)
{

	switch (cmd) {
	case MODULE_CMD_INIT:
		return k_oncrpc_init();
	case MODULE_CMD_FINI:
		sysctl_teardown(&k_oncrpc_log);
		return 0;
	default:
		return ENOTTY;
	}
}
