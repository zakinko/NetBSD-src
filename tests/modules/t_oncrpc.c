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
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>
#include <atf-c.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

KERNEL_TC(rm_frag, "RFC 5531 s11: fragments, empty ones, any cut")
KERNEL_TC(rm_limit, "Record and fragment count limits")
KERNEL_TC(register, "RFC 5531 s8.1: version 0 and overlaps are refused")

/*
 * The other half: messages built by hand here, so that the bytes on
 * the wire are what the test says, not what some RPC library sends.
 */
#define	PING_PROG	0x20000f00
#define	PING_NULL	0
#define	PING_ECHO	1
#define	PING_WHOAMI	2
#define	PING_SUM	3

#define	MAXWORDS	4096

/* RFC 5531 s9: words of a message. */
struct msg {
	uint32_t	w[MAXWORDS];
	size_t		n;
};

static void
put(struct msg *m, uint32_t v)
{

	ATF_REQUIRE(m->n < MAXWORDS);
	m->w[m->n++] = htonl(v);
}

static void
call_head(struct msg *m, uint32_t xid, uint32_t rpcvers, uint32_t prog,
    uint32_t vers, uint32_t proc)
{

	m->n = 0;
	put(m, xid);
	put(m, 0);		/* CALL */
	put(m, rpcvers);
	put(m, prog);
	put(m, vers);
	put(m, proc);
}

static void
auth_none(struct msg *m)
{

	put(m, 0);		/* AUTH_NONE */
	put(m, 0);
}

static void
call_none(struct msg *m, uint32_t xid, uint32_t vers, uint32_t proc)
{

	call_head(m, xid, 2, PING_PROG, vers, proc);
	auth_none(m);		/* cred */
	auth_none(m);		/* verf */
}

/* RFC 5531 App. A, machinename "abcde". */
static void
auth_sys(struct msg *m, uint32_t uid, uint32_t gid, uint32_t ngids)
{
	uint32_t i;

	put(m, 1);		/* AUTH_SYS */
	put(m, 4 + 4 + 8 + 4 + 4 + 4 + 4 * ngids);
	put(m, 12345);		/* stamp */
	put(m, 5);
	memcpy(&m->w[m->n], "abcde\0\0\0", 8);
	m->n += 2;
	put(m, uid);
	put(m, gid);
	put(m, ngids);
	for (i = 0; i < ngids; i++)
		put(m, 100 + i);
}

static int
tcp_connect(const atf_tc_t *tc)
{
	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);
	int ls, c, s, one = 1;

	load(tc);
	ATF_REQUIRE((ls = socket(AF_INET, SOCK_STREAM, 0)) != -1);
	memset(&sin, 0, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	ATF_REQUIRE(bind(ls, (void *)&sin, sizeof(sin)) == 0);
	ATF_REQUIRE(listen(ls, 1) == 0);
	ATF_REQUIRE(getsockname(ls, (void *)&sin, &len) == 0);
	ATF_REQUIRE((c = socket(AF_INET, SOCK_STREAM, 0)) != -1);
	ATF_REQUIRE(connect(c, (void *)&sin, sizeof(sin)) == 0);
	ATF_REQUIRE((s = accept(ls, NULL, NULL)) != -1);
	ATF_REQUIRE_MSG(sysctlbyname(NODE "addsock", NULL, NULL, &s,
	    sizeof(s)) == 0, "addsock: %s", strerror(errno));
	close(s);
	close(ls);
	(void)setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	return c;
}

static void
writeall(int fd, const void *buf, size_t len)
{
	const char *p = buf;
	ssize_t n;

	while (len > 0) {
		n = write(fd, p, len);
		ATF_REQUIRE_MSG(n > 0, "write: %s", strerror(errno));
		p += n;
		len -= n;
	}
}

/* len bytes, or false at the end of the stream.  Never hangs. */
static bool
readall(int fd, void *buf, size_t len)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	char *p = buf;
	ssize_t n;

	while (len > 0) {
		ATF_REQUIRE_MSG(poll(&pfd, 1, 20000) == 1, "no reply");
		n = read(fd, p, len);
		if (n == 0 || (n == -1 && errno == ECONNRESET))
			return false;
		ATF_REQUIRE_MSG(n > 0, "read: %s", strerror(errno));
		p += n;
		len -= n;
	}
	return true;
}

static void
tcp_send(int fd, const struct msg *m)
{
	uint32_t rm = htonl(0x80000000U | (uint32_t)(m->n * 4));

	writeall(fd, &rm, sizeof(rm));
	writeall(fd, m->w, m->n * 4);
}

/* One reply, in host order; returns the number of words. */
static size_t
tcp_recv(int fd, uint32_t *w, size_t max)
{
	uint32_t rm;
	size_t i, n;

	ATF_REQUIRE_MSG(readall(fd, &rm, sizeof(rm)), "connection closed");
	rm = ntohl(rm);
	ATF_REQUIRE_MSG(rm & 0x80000000U, "server split a reply");
	rm &= 0x7fffffffU;
	ATF_REQUIRE(rm % 4 == 0);
	n = rm / 4;
	ATF_REQUIRE(n <= max);
	ATF_REQUIRE(readall(fd, w, rm));
	for (i = 0; i < n; i++)
		w[i] = ntohl(w[i]);
	return n;
}

/* xid, REPLY, MSG_ACCEPTED, empty AUTH_NONE verifier, stat */
static void
check_accepted(const uint32_t *w, size_t n, uint32_t xid, uint32_t stat)
{

	ATF_REQUIRE_MSG(n >= 6, "short reply: %zu", n);
	ATF_CHECK_EQ(w[0], xid);
	ATF_CHECK_EQ(w[1], 1);
	ATF_CHECK_EQ(w[2], 0);
	ATF_CHECK_EQ(w[3], 0);
	ATF_CHECK_EQ(w[4], 0);
	ATF_CHECK_EQ(w[5], stat);
}

static void
check_auth_denied(const uint32_t *w, size_t n, uint32_t xid, uint32_t why)
{

	ATF_REQUIRE_EQ(n, 5);
	ATF_CHECK_EQ(w[0], xid);
	ATF_CHECK_EQ(w[1], 1);
	ATF_CHECK_EQ(w[2], 1);		/* MSG_DENIED */
	ATF_CHECK_EQ(w[3], 1);		/* AUTH_ERROR */
	ATF_CHECK_EQ(w[4], why);
}

#define	SOCK_TC(name, descr)						\
	ATF_TC(name);							\
	ATF_TC_HEAD(name, tc)						\
	{								\
		atf_tc_set_md_var(tc, "descr", descr);			\
		atf_tc_set_md_var(tc, "require.user", "root");		\
	}								\
	ATF_TC_BODY(name, tc)

static struct msg m;
static uint32_t r[MAXWORDS];

SOCK_TC(tcp_null, "A NULL call over TCP")
{
	int c = tcp_connect(tc);
	size_t n;

	call_none(&m, 0xdeadbeef, 2, PING_NULL);
	tcp_send(c, &m);
	n = tcp_recv(c, r, MAXWORDS);
	ATF_CHECK_EQ(n, 6);
	check_accepted(r, n, 0xdeadbeef, 0);
	close(c);
}

SOCK_TC(tcp_dribble, "A call a byte at a time, over three fragments")
{
	int c = tcp_connect(tc);
	uint8_t wire[256], *p = wire;
	uint32_t hdr, *b = m.w;
	size_t i, n, len;

	call_none(&m, 7, 3, PING_SUM);
	put(&m, 40);
	put(&m, 2);
	len = m.n * 4;

	hdr = htonl(5);			/* five bytes, more */
	memcpy(p, &hdr, 4); p += 4;
	memcpy(p, b, 5); p += 5;
	hdr = 0;			/* nothing, more */
	memcpy(p, &hdr, 4); p += 4;
	hdr = htonl(0x80000000U | (uint32_t)(len - 5));
	memcpy(p, &hdr, 4); p += 4;
	memcpy(p, (char *)b + 5, len - 5); p += len - 5;

	for (i = 0; i < (size_t)(p - wire); i++) {
		writeall(c, wire + i, 1);
		usleep(1000);
	}
	n = tcp_recv(c, r, MAXWORDS);
	ATF_REQUIRE_EQ(n, 7);
	check_accepted(r, n, 7, 0);
	ATF_CHECK_EQ(r[6], 42);
	close(c);
}

SOCK_TC(tcp_pipeline, "Several records in one write, all answered")
{
	int c = tcp_connect(tc);
	static uint32_t wire[32 * 13];
	uint32_t seen = 0, *p = wire;
	size_t n;
	int i;

	for (i = 0; i < 32; i++) {
		call_none(&m, i, 2, PING_SUM);
		put(&m, i);
		put(&m, 1000);
		*p++ = htonl(0x80000000U | (uint32_t)(m.n * 4));
		memcpy(p, m.w, m.n * 4);
		p += m.n;
	}
	writeall(c, wire, (char *)p - (char *)wire);
	for (i = 0; i < 32; i++) {
		n = tcp_recv(c, r, MAXWORDS);
		ATF_REQUIRE_EQ(n, 7);
		check_accepted(r, n, r[0], 0);
		ATF_REQUIRE(r[0] < 32);
		ATF_CHECK_EQ(r[6], r[0] + 1000);
		seen |= 1U << r[0];
	}
	ATF_CHECK_EQ(seen, 0xffffffffU);
	close(c);
}

SOCK_TC(tcp_large, "A message much larger than the socket buffer")
{
	int c = tcp_connect(tc);
	const size_t len = 200000;
	size_t wlen;
	uint8_t *out, *in;
	uint32_t *w, rm, hdr[7];
	pid_t pid;
	size_t i;
	int st;

	call_none(&m, 99, 2, PING_ECHO);
	put(&m, len);
	wlen = m.n * 4 + len;
	ATF_REQUIRE((out = malloc(wlen + 4)) != NULL);
	ATF_REQUIRE((in = malloc(len)) != NULL);
	w = (uint32_t *)out;
	w[0] = htonl(0x80000000U | (uint32_t)(wlen));
	memcpy(w + 1, m.w, m.n * 4);
	for (i = 0; i < len; i++)
		out[4 + m.n * 4 + i] = (uint8_t)(i * 13);

	/* Out of step with the read, or the two buffers fill and stick. */
	ATF_REQUIRE((pid = fork()) != -1);
	if (pid == 0) {
		writeall(c, out, 4 + wlen);
		_exit(0);
	}
	ATF_REQUIRE(readall(c, &rm, 4));
	ATF_CHECK_EQ(ntohl(rm), 0x80000000U | (uint32_t)(4 * 7 + len));
	ATF_REQUIRE(readall(c, hdr, sizeof(hdr)));
	ATF_CHECK_EQ(ntohl(hdr[0]), 99);
	ATF_CHECK_EQ(ntohl(hdr[5]), 0);
	ATF_CHECK_EQ(ntohl(hdr[6]), len);
	ATF_REQUIRE(readall(c, in, len));
	for (i = 0; i < len; i++)
		ATF_REQUIRE(in[i] == (uint8_t)(i * 13));
	ATF_REQUIRE(waitpid(pid, &st, 0) == pid);
	close(c);
}

SOCK_TC(stat_prog_unavail, "RFC 5531 s9: no such program")
{
	int c = tcp_connect(tc);
	size_t n;

	call_head(&m, 1, 2, 0x20000f01, 2, 0);
	auth_none(&m);
	auth_none(&m);
	tcp_send(c, &m);
	n = tcp_recv(c, r, MAXWORDS);
	ATF_CHECK_EQ(n, 6);
	check_accepted(r, n, 1, 1);
	close(c);
}

SOCK_TC(stat_prog_mismatch, "RFC 5531 s9: low and high of the versions")
{
	int c = tcp_connect(tc);
	size_t n;

	call_none(&m, 2, 4, PING_NULL);
	tcp_send(c, &m);
	n = tcp_recv(c, r, MAXWORDS);
	ATF_REQUIRE_EQ(n, 8);
	check_accepted(r, n, 2, 2);
	ATF_CHECK_EQ(r[6], 2);
	ATF_CHECK_EQ(r[7], 3);
	close(c);
}

SOCK_TC(stat_proc_unavail, "RFC 5531 s9: no such procedure")
{
	int c = tcp_connect(tc);
	size_t n;

	call_none(&m, 3, 2, 4);
	tcp_send(c, &m);
	n = tcp_recv(c, r, MAXWORDS);
	ATF_CHECK_EQ(n, 6);
	check_accepted(r, n, 3, 3);
	close(c);
}

SOCK_TC(stat_garbage_args, "RFC 5531 s9: arguments that do not decode")
{
	int c = tcp_connect(tc);
	size_t n;

	call_none(&m, 4, 2, PING_SUM);
	put(&m, 1);		/* one of the two */
	tcp_send(c, &m);
	n = tcp_recv(c, r, MAXWORDS);
	ATF_CHECK_EQ(n, 6);
	check_accepted(r, n, 4, 4);
	close(c);
}

SOCK_TC(stat_rpc_mismatch, "RFC 5531 s9: rpcvers must be 2")
{
	int c = tcp_connect(tc);
	size_t n;

	call_head(&m, 5, 3, PING_PROG, 2, 0);
	tcp_send(c, &m);
	n = tcp_recv(c, r, MAXWORDS);
	ATF_REQUIRE_EQ(n, 6);
	ATF_CHECK_EQ(r[0], 5);
	ATF_CHECK_EQ(r[1], 1);
	ATF_CHECK_EQ(r[2], 1);		/* MSG_DENIED */
	ATF_CHECK_EQ(r[3], 0);		/* RPC_MISMATCH */
	ATF_CHECK_EQ(r[4], 2);
	ATF_CHECK_EQ(r[5], 2);
	close(c);
}

SOCK_TC(auth_none_cred, "AUTH_NONE reaches the program with no identity")
{
	int c = tcp_connect(tc);
	size_t n;

	call_none(&m, 6, 2, PING_WHOAMI);
	tcp_send(c, &m);
	n = tcp_recv(c, r, MAXWORDS);
	ATF_REQUIRE_EQ(n, 8);
	check_accepted(r, n, 6, 0);
	ATF_CHECK_EQ(r[6], 0);
	ATF_CHECK_EQ(r[7], 0);
	close(c);
}

SOCK_TC(auth_sys_cred, "RFC 5531 App. A: the program sees the credential")
{
	int c = tcp_connect(tc);
	size_t n;

	call_head(&m, 8, 2, PING_PROG, 2, PING_WHOAMI);
	auth_sys(&m, 1001, 1002, 16);
	auth_none(&m);
	tcp_send(c, &m);
	n = tcp_recv(c, r, MAXWORDS);
	ATF_REQUIRE_EQ(n, 10);
	check_accepted(r, n, 8, 0);
	ATF_CHECK_EQ(r[6], 1);
	ATF_CHECK_EQ(r[7], 1001);
	ATF_CHECK_EQ(r[8], 1002);
	ATF_CHECK_EQ(r[9], 16);
	close(c);
}

SOCK_TC(auth_sys_bad, "Malformed AUTH_SYS gets AUTH_BADCRED, not a guess")
{
	int c = tcp_connect(tc);
	size_t n;

	/* gids<16> */
	call_head(&m, 9, 2, PING_PROG, 2, PING_WHOAMI);
	auth_sys(&m, 1, 1, 17);
	auth_none(&m);
	tcp_send(c, &m);
	n = tcp_recv(c, r, MAXWORDS);
	check_auth_denied(r, n, 9, 1);

	/* machinename<255> */
	call_head(&m, 10, 2, PING_PROG, 2, PING_WHOAMI);
	put(&m, 1);
	put(&m, 8);
	put(&m, 0);
	put(&m, 256);
	auth_none(&m);
	tcp_send(c, &m);
	n = tcp_recv(c, r, MAXWORDS);
	check_auth_denied(r, n, 10, 1);

	/* A length running off the credential. */
	call_head(&m, 11, 2, PING_PROG, 2, PING_WHOAMI);
	put(&m, 1);
	put(&m, 8);
	put(&m, 0);
	put(&m, 200);
	auth_none(&m);
	tcp_send(c, &m);
	n = tcp_recv(c, r, MAXWORDS);
	check_auth_denied(r, n, 11, 1);

	/* Procedure 0 goes through all the same, RFC 5531 s12.1. */
	call_head(&m, 12, 2, PING_PROG, 2, PING_NULL);
	auth_sys(&m, 1, 1, 17);
	auth_none(&m);
	tcp_send(c, &m);
	n = tcp_recv(c, r, MAXWORDS);
	ATF_CHECK_EQ(n, 6);
	check_accepted(r, n, 12, 0);
	close(c);
}

SOCK_TC(auth_flavor, "An unknown flavor, and a body over 400 bytes")
{
	int c = tcp_connect(tc);
	size_t n;
	int i;

	call_head(&m, 13, 2, PING_PROG, 2, PING_WHOAMI);
	put(&m, 99);
	put(&m, 0);
	auth_none(&m);
	tcp_send(c, &m);
	n = tcp_recv(c, r, MAXWORDS);
	check_auth_denied(r, n, 13, 2);	/* AUTH_REJECTEDCRED */

	call_head(&m, 14, 2, PING_PROG, 2, PING_WHOAMI);
	put(&m, 0);
	put(&m, 401);
	for (i = 0; i < 101; i++)
		put(&m, 0);
	auth_none(&m);
	tcp_send(c, &m);
	n = tcp_recv(c, r, MAXWORDS);
	check_auth_denied(r, n, 14, 1);	/* AUTH_BADCRED */

	call_head(&m, 15, 2, PING_PROG, 2, PING_NULL);
	auth_none(&m);
	put(&m, 0);
	put(&m, 401);
	tcp_send(c, &m);
	n = tcp_recv(c, r, MAXWORDS);
	check_auth_denied(r, n, 15, 3);	/* AUTH_BADVERF */
	close(c);
}

SOCK_TC(truncated_call, "A cut-short call is dropped; the stream lives on")
{
	int c = tcp_connect(tc);
	size_t n;

	call_none(&m, 16, 2, PING_NULL);
	m.n -= 1;		/* no length for the verifier */
	tcp_send(c, &m);
	call_none(&m, 17, 2, PING_NULL);
	tcp_send(c, &m);
	n = tcp_recv(c, r, MAXWORDS);
	check_accepted(r, n, 17, 0);	/* and no reply to 16 */
	close(c);
}

SOCK_TC(reply_ignored, "A REPLY sent to the server is dropped")
{
	int c = tcp_connect(tc);
	size_t n;

	m.n = 0;
	put(&m, 18);
	put(&m, 1);
	put(&m, 0);
	tcp_send(c, &m);
	call_none(&m, 19, 2, PING_NULL);
	tcp_send(c, &m);
	n = tcp_recv(c, r, MAXWORDS);
	check_accepted(r, n, 19, 0);
	close(c);
}

SOCK_TC(rm_overlong, "A record over the limit ends the connection")
{
	int c = tcp_connect(tc);
	uint32_t hdr = htonl(0xffffffffU);

	writeall(c, &hdr, sizeof(hdr));
	ATF_CHECK(!readall(c, r, 4));
	close(c);
}

SOCK_TC(xprt_close, "Connections that close leave nothing behind")
{
	int v, base, i, c;
	size_t len = sizeof(v);

	load(tc);
	ATF_REQUIRE(sysctlbyname(NODE "nxprt", &base, &len, NULL, 0) == 0);
	for (i = 0; i < 50; i++) {
		c = tcp_connect(tc);
		call_none(&m, i, 2, PING_NULL);
		tcp_send(c, &m);
		(void)tcp_recv(c, r, MAXWORDS);
		close(c);
	}
	for (i = 0; i < 100; i++) {
		ATF_REQUIRE(sysctlbyname(NODE "nxprt", &v, &len, NULL, 0) == 0);
		if (v <= base)
			break;
		usleep(100000);
	}
	ATF_CHECK_MSG(v <= base, "%d xprts, was %d", v, base);
}

static int
udp_server(const atf_tc_t *tc, struct sockaddr_in *sin)
{
	socklen_t len = sizeof(*sin);
	int s;

	load(tc);
	ATF_REQUIRE((s = socket(AF_INET, SOCK_DGRAM, 0)) != -1);
	memset(sin, 0, sizeof(*sin));
	sin->sin_len = sizeof(*sin);
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	ATF_REQUIRE(bind(s, (void *)sin, sizeof(*sin)) == 0);
	ATF_REQUIRE(getsockname(s, (void *)sin, &len) == 0);
	ATF_REQUIRE_MSG(sysctlbyname(NODE "addsock", NULL, NULL, &s,
	    sizeof(s)) == 0, "addsock: %s", strerror(errno));
	close(s);
	return s;
}

static size_t
udp_recv(int s, uint32_t *w)
{
	struct pollfd pfd = { .fd = s, .events = POLLIN };
	ssize_t n;
	size_t i;

	ATF_REQUIRE_MSG(poll(&pfd, 1, 20000) == 1, "no reply");
	n = recv(s, w, MAXWORDS * 4, 0);
	ATF_REQUIRE(n > 0 && n % 4 == 0);
	for (i = 0; i < (size_t)n / 4; i++)
		w[i] = ntohl(w[i]);
	return n / 4;
}

SOCK_TC(udp_two_peers, "One datagram socket serves two peers")
{
	struct sockaddr_in sin;
	int a, b;
	size_t n;

	(void)udp_server(tc, &sin);
	ATF_REQUIRE((a = socket(AF_INET, SOCK_DGRAM, 0)) != -1);
	ATF_REQUIRE((b = socket(AF_INET, SOCK_DGRAM, 0)) != -1);
	ATF_REQUIRE(connect(a, (void *)&sin, sizeof(sin)) == 0);
	ATF_REQUIRE(connect(b, (void *)&sin, sizeof(sin)) == 0);

	call_none(&m, 21, 2, PING_SUM);
	put(&m, 1);
	put(&m, 2);
	ATF_REQUIRE(send(a, m.w, m.n * 4, 0) == (ssize_t)(m.n * 4));
	call_none(&m, 22, 3, PING_SUM);
	put(&m, 3);
	put(&m, 4);
	ATF_REQUIRE(send(b, m.w, m.n * 4, 0) == (ssize_t)(m.n * 4));

	n = udp_recv(b, r);
	ATF_REQUIRE_EQ(n, 7);
	check_accepted(r, n, 22, 0);
	ATF_CHECK_EQ(r[6], 7);
	n = udp_recv(a, r);
	ATF_REQUIRE_EQ(n, 7);
	check_accepted(r, n, 21, 0);
	ATF_CHECK_EQ(r[6], 3);

	/* A runt gets nothing, and hurts nothing. */
	ATF_REQUIRE(send(a, m.w, 3, 0) == 3);
	call_none(&m, 23, 2, PING_NULL);
	ATF_REQUIRE(send(a, m.w, m.n * 4, 0) == (ssize_t)(m.n * 4));
	n = udp_recv(a, r);
	check_accepted(r, n, 23, 0);
	close(a);
	close(b);
}

SOCK_TC(stress, "Parallel clients, abrupt closes among them")
{
	pid_t pid[8];
	int i, j, st, c, bad = 0;
	size_t n;

	load(tc);
	for (i = 0; i < 8; i++) {
		ATF_REQUIRE((pid[i] = fork()) != -1);
		if (pid[i] != 0)
			continue;
		for (j = 0; j < 40; j++) {
			int k;

			c = tcp_connect(tc);
			for (k = 0; k < 50; k++) {
				uint32_t x = i * 100000 + j * 100 + k;

				call_none(&m, x, 3, PING_SUM);
				put(&m, x);
				put(&m, 1);
				tcp_send(c, &m);
				n = tcp_recv(c, r, MAXWORDS);
				if (n != 7 || r[0] != x || r[6] != x + 1)
					_exit(1);
			}
			/* Leave a call in the air now and then. */
			if (j % 4 == 0)
				tcp_send(c, &m);
			close(c);
		}
		_exit(0);
	}
	for (i = 0; i < 8; i++) {
		ATF_REQUIRE(waitpid(pid[i], &st, 0) == pid[i]);
		if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
			bad++;
	}
	ATF_CHECK_EQ(bad, 0);
}

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
	ATF_TP_ADD_TC(tp, rm_frag);
	ATF_TP_ADD_TC(tp, rm_limit);
	ATF_TP_ADD_TC(tp, register);
	ATF_TP_ADD_TC(tp, tcp_null);
	ATF_TP_ADD_TC(tp, tcp_dribble);
	ATF_TP_ADD_TC(tp, tcp_pipeline);
	ATF_TP_ADD_TC(tp, tcp_large);
	ATF_TP_ADD_TC(tp, stat_prog_unavail);
	ATF_TP_ADD_TC(tp, stat_prog_mismatch);
	ATF_TP_ADD_TC(tp, stat_proc_unavail);
	ATF_TP_ADD_TC(tp, stat_garbage_args);
	ATF_TP_ADD_TC(tp, stat_rpc_mismatch);
	ATF_TP_ADD_TC(tp, auth_none_cred);
	ATF_TP_ADD_TC(tp, auth_sys_cred);
	ATF_TP_ADD_TC(tp, auth_sys_bad);
	ATF_TP_ADD_TC(tp, auth_flavor);
	ATF_TP_ADD_TC(tp, truncated_call);
	ATF_TP_ADD_TC(tp, reply_ignored);
	ATF_TP_ADD_TC(tp, rm_overlong);
	ATF_TP_ADD_TC(tp, xprt_close);
	ATF_TP_ADD_TC(tp, udp_two_peers);
	ATF_TP_ADD_TC(tp, stress);

	return atf_no_error();
}
