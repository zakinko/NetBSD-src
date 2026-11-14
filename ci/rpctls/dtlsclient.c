/*	$NetBSD$	*/

/*
 * RPC-with-TLS over UDP, RFC 9289 s5.1.2, from the client's side, against
 * the kernel's DTLS 1.3 record layer and rpc.tlsservd.  OpenSSL 4.1 does
 * the handshake; records it cannot be made to send, a replay, garbage,
 * a NewConnectionId, are built with the kernel's own record code from
 * the client's traffic secret, which OpenSSL's key log gives.
 *
 *	dtlsclient host port cafile [nocid-ok]
 *	dtlsclient host port cafile bench NPROC NCALLS
 *
 * The second form times NCALLS NULL calls in each of NPROC processes,
 * first plain on UDP and then over DTLS, one association per process.
 *
 * With an OpenSSL that has the DTLS connection ID (SSL_set1_dtls_cid()),
 * the associations have IDs both ways, RFC 9289 s5.1.2, and the client
 * moves to another port, gives the server a new ID and asks it for some,
 * RFC 9146 s6 and RFC 9147 s9.  An association without IDs is then
 * expected to be refused, unless nocid-ok says the kernel has options
 * ONCRPC_DTLS_NOCID.  Each association prints "cid own HEX peer HEX" and
 * the new ID "cid new HEX", for a look at the packets.
 *
 * Prints "ok name" or "FAIL name" per check and "probe-dtls failures N".
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#ifdef SSL_DTLS_CID_MAX_LEN
#define	HAVE_DTLS_CID
#endif

#include "gss_krb5_shim.h"	/* struct aesenc, for tls13_crypto.h */
#include "tls13_crypto.h"

#define	NFS_PROG	100003
#define	NFS_VERS	3
#define	AUTH_NONE	0
#define	AUTH_TLS	7	/* RFC 9289 s7.1 */
#define	WAIT_MS		1500	/* ours: how long a reply may take */
#define	CID_LEN		8	/* ours, as rpc.tlsservd's */

static int failures;
static const char *host, *cafile;
static int port;
static uint32_t nextxid = 0x5a000001;

/* What OpenSSL's callbacks saw, per association. */
static uint8_t csecret[TLS13_SECRETLEN];
static bool have_csecret;
static int cw3;			/* records written under epoch 3 */
static int hsw;			/* next handshake message_seq of ours */
static int rx_keyupdate, rx_ack, rx_alert = -1;
static bool verbose;
static double tw, tr;		/* bench: in SSL_write, in SSL_read */
static int nslow;		/* bench: calls over 100 ms */

/* RFC 9147 s9: the IDs of the association, as OpenSSL agreed them. */
static uint8_t owncid[255], peercid[255], newcid[255];
static size_t owncidlen, peercidlen, newcidlen;
static int rx_newcid;		/* NewConnectionId messages received */
static size_t cidwant = CID_LEN;	/* the length of ours to ask for */

static void
check(bool ok, const char *what)
{

	printf("%s %s\n", ok ? "ok" : "FAIL", what);
	fflush(stdout);
	if (!ok)
		failures++;
}

static void
put32(uint8_t *p, uint32_t v)
{

	p[0] = v >> 24;
	p[1] = v >> 16;
	p[2] = v >> 8;
	p[3] = v;
}

static uint32_t
get32(const uint8_t *p)
{

	return (uint32_t)p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
}

/* RFC 5531 s9: a call of the NULL procedure, 40 bytes. */
static size_t
mkcall(uint8_t *p, uint32_t xid, uint32_t flavor)
{

	put32(p, xid);
	put32(p + 4, 0);		/* CALL */
	put32(p + 8, 2);		/* rpcvers */
	put32(p + 12, NFS_PROG);
	put32(p + 16, NFS_VERS);
	put32(p + 20, 0);		/* NULL */
	put32(p + 24, flavor);
	put32(p + 28, 0);
	put32(p + 32, AUTH_NONE);
	put32(p + 36, 0);
	return 40;
}

/* An accepted SUCCESS reply to xid; the verifier body in verf. */
static bool
isreply(const uint8_t *p, ssize_t n, uint32_t xid, char *verf, size_t vmax)
{
	uint32_t vlen;

	if (n < 24 || get32(p) != xid || get32(p + 4) != 1 ||
	    get32(p + 8) != 0)
		return false;
	vlen = get32(p + 16);
	if (vlen > 400 || n < 24 + (ssize_t)vlen)
		return false;
	if (verf != NULL) {
		memset(verf, 0, vmax);
		memcpy(verf, p + 20, vlen < vmax - 1 ? vlen : vmax - 1);
	}
	return get32(p + 20 + vlen) == 0;
}

static int
udpsock(void)
{
	struct sockaddr_in sin;
	int fd;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		err(1, "socket");
	memset(&sin, 0, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	if (inet_pton(AF_INET, host, &sin.sin_addr) != 1)
		errx(1, "%s: not an address", host);
	if (connect(fd, (void *)&sin, sizeof(sin)) == -1)
		err(1, "connect");
	return fd;
}

/* The next datagram within WAIT_MS, or -1. */
static ssize_t
recvwait(int fd, uint8_t *buf, size_t len)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };

	if (poll(&pfd, 1, WAIT_MS) != 1)
		return -1;
	return recv(fd, buf, len, 0);
}

/* A plain call; whether its reply came. */
static bool
plaincall(int fd, uint32_t flavor, char *verf, size_t vmax)
{
	uint8_t buf[2048];
	uint32_t xid = nextxid++;
	ssize_t n;

	n = (ssize_t)mkcall(buf, xid, flavor);
	if (send(fd, buf, n, 0) != n)
		return false;
	while ((n = recvwait(fd, buf, sizeof(buf))) > 0) {
		if (isreply(buf, n, xid, verf, vmax))
			return true;
	}
	return false;
}

static void
keylog(const SSL *ssl, const char *line)
{
	static const char cl[] = "CLIENT_TRAFFIC_SECRET_0 ";
	const char *p;
	unsigned v;
	size_t i;

	if (strncmp(line, cl, sizeof(cl) - 1) != 0 ||
	    (p = strchr(line + sizeof(cl) - 1, ' ')) == NULL)
		return;
	for (i = 0, p++; i < sizeof(csecret) && sscanf(p, "%2x", &v) == 1;
	    i++, p += 2)
		csecret[i] = v;
	have_csecret = i == sizeof(csecret);
}

static void
msgcb(int w, int version, int type, const void *buf, size_t len, SSL *ssl,
    void *arg)
{
	const uint8_t *p = buf;

	if (type == SSL3_RT_HANDSHAKE && len >= DTLS13_HS_HDRLEN + 3 &&
	    p[0] == DTLS13_HS_NEW_CID) {
		if (!w)
			rx_newcid++;
		else if (p[DTLS13_HS_HDRLEN + 2] <= sizeof(newcid) &&
		    len >= DTLS13_HS_HDRLEN + 3 + p[DTLS13_HS_HDRLEN + 2]) {
			/* s9: cids<0..2^16-1>, the first of ours */
			newcidlen = p[DTLS13_HS_HDRLEN + 2];
			memcpy(newcid, p + DTLS13_HS_HDRLEN + 3, newcidlen);
		}
	}
	if (type == SSL3_RT_HEADER && w && len >= 1 && (p[0] & 0xe3) == 0x23)
		cw3++;
	else if (type == SSL3_RT_HANDSHAKE && w && len >= 6 &&
	    (p[4] << 8 | p[5]) + 1 > hsw)
		hsw = (p[4] << 8 | p[5]) + 1;
	else if (type == SSL3_RT_HANDSHAKE && !w && len >= 1 &&
	    p[0] == DTLS13_HS_KEY_UPDATE)
		rx_keyupdate++;
	else if (type == TLS13_CT_ACK && !w)
		rx_ack++;
	if (verbose && type == SSL3_RT_HEADER && !w && len >= 1)
		printf("  # recv record b0 %02x\n", p[0]);
	if (verbose && type != SSL3_RT_HEADER && type != 257)
		printf("  # %s type %d len %zu first %02x\n", w ? "sent" : "recv",
		    type, len, len > 0 ? p[0] : 0);
	else if (type == SSL3_RT_ALERT && !w && len == 2)
		rx_alert = p[1];
}

static SSL_CTX *
mkctx(void)
{
	SSL_CTX *ctx;

	if ((ctx = SSL_CTX_new(DTLS_client_method())) == NULL ||
	    !SSL_CTX_set_min_proto_version(ctx, DTLS1_3_VERSION) ||
	    SSL_CTX_load_verify_locations(ctx, cafile, NULL) != 1)
		errx(1, "SSL_CTX");
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	/* RFC 9289 s5: "sunrpc" */
	SSL_CTX_set_alpn_protos(ctx, (const uint8_t *)"\x06sunrpc", 7);
	SSL_CTX_set_keylog_callback(ctx, keylog);
	SSL_CTX_set_msg_callback(ctx, msgcb);
	return ctx;
}

static void
hexline(const char *what, const uint8_t *p, size_t n)
{
	size_t i;

	printf("%s ", what);
	for (i = 0; i < n; i++)
		printf("%02x", p[i]);
	printf(n == 0 ? "-\n" : "\n");
}

static unsigned
lport(int fd)
{
	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);

	if (getsockname(fd, (void *)&sin, &len) == -1)
		return 0;
	return ntohs(sin.sin_port);
}

/* Put ssl on a datagram BIO of fd, which keeps fd open. */
static bool
setfd(SSL *ssl, int fd)
{
	struct timeval tv = { 3, 0 };
	BIO *bio;

	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if ((bio = BIO_new_dgram(fd, BIO_NOCLOSE)) == NULL)
		return false;
	SSL_set_bio(ssl, bio, bio);
	return true;
}

/*
 * Probe and shake hands on a new socket, with connection IDs when cid;
 * NULL if that failed.
 */
static SSL *
associate(SSL_CTX *ctx, int *fdp, bool spurious, bool cid)
{
	char verf[16];
	SSL *ssl;
	int fd;

	have_csecret = false;
	cw3 = hsw = rx_keyupdate = rx_ack = 0;
	rx_alert = -1;
	owncidlen = peercidlen = newcidlen = 0;
	rx_newcid = 0;
	fd = udpsock();
	*fdp = fd;
	/* RFC 9289 s4.1 */
	if (!plaincall(fd, AUTH_TLS, verf, sizeof(verf)) ||
	    strcmp(verf, "STARTTLS") != 0) {
		check(false, "UDP probe answered with STARTTLS, s4.1");
		return NULL;
	}
	check(true, "UDP probe answered with STARTTLS, s4.1");
	if (spurious)
		check(!plaincall(fd, AUTH_NONE, NULL, 0),
		    "a call between probe and handshake is discarded, s5.1.2");
	ssl = SSL_new(ctx);
	if (ssl == NULL || !setfd(ssl, fd))
		errx(1, "SSL_new");
#ifdef HAVE_DTLS_CID
	if (cid) {
		uint8_t c[255];

		if (RAND_bytes(c, (int)cidwant) != 1 ||
		    !SSL_set1_dtls_cid(ssl, c, cidwant))
			errx(1, "SSL_set1_dtls_cid");
	}
#endif
	if (SSL_connect(ssl) != 1) {
		ERR_print_errors_fp(stdout);
		check(false, "DTLS 1.3 handshake");
		SSL_free(ssl);
		return NULL;
	}
	check(SSL_version(ssl) == DTLS1_3_VERSION && have_csecret,
	    "DTLS 1.3 handshake");
	rx_ack = rx_keyupdate = 0;	/* those of the handshake are not ours */
#ifdef HAVE_DTLS_CID
	if (cid) {
		const unsigned char *o, *pe;
		size_t ol, pl;

		/* RFC 9289 s5.1.2: "a ConnectionID with a nonzero length" */
		check(SSL_get0_dtls_cid(ssl, &o, &ol, &pe, &pl) == 1 &&
		    ol == cidwant && pl != 0 && pl <= sizeof(peercid),
		    "connection IDs both ways, nonzero, s5.1.2");
		if (ol <= sizeof(owncid) && pl <= sizeof(peercid)) {
			memcpy(owncid, o, owncidlen = ol);
			memcpy(peercid, pe, peercidlen = pl);
		}
		hexline("cid own", owncid, owncidlen);
		hexline("cid peer", peercid, peercidlen);
		fflush(stdout);
	}
#endif
	return ssl;
}

static double now(void);

/* What OpenSSL said, for the log. */
static void
why(const char *what, SSL *ssl, int n)
{

	printf("  # %s: %d, SSL_get_error %d, alert received %d, "
	    "KeyUpdates %d, ACKs %d\n", what, n, SSL_get_error(ssl, n),
	    rx_alert, rx_keyupdate, rx_ack);
	ERR_print_errors_fp(stdout);
	fflush(stdout);
}

/*
 * A call over DTLS; whether its reply came.  Sent again on silence, as
 * RPC on UDP is: the first call may reach the server while the daemon
 * still holds the association, and is lost there.
 */
static bool
dtlsmsg(SSL *ssl, const uint8_t *call, int len, uint32_t xid,
    uint32_t *resp)
{
	uint8_t buf[2048];
	double t, t2;
	int n, i;

	for (i = 0; i < 8; i++) {
		/*
		 * After our KeyUpdate OpenSSL writes nothing until it has
		 * read the ACK, RFC 9147 s8, and says so with WANT_READ.
		 */
		t = now();
		if (i % 2 == 0 && (n = SSL_write(ssl, call, len)) != len &&
		    SSL_get_error(ssl, n) != SSL_ERROR_WANT_READ) {
			why("SSL_write", ssl, n);
			return false;
		}
		t2 = now();
		tw += t2 - t;
		n = SSL_read(ssl, buf, sizeof(buf));
		tr += now() - t2;
		if (n > 0 && isreply(buf, n, xid, NULL, 0)) {
			/* the first word of the results, past the verifier */
			if (resp != NULL && n >= 32 + (int)get32(buf + 16))
				*resp = get32(buf + 28 + get32(buf + 16));
			return true;
		}
		if (n <= 0 && SSL_get_error(ssl, n) != SSL_ERROR_WANT_READ &&
		    SSL_get_error(ssl, n) != SSL_ERROR_SYSCALL) {
			why("SSL_read", ssl, n);
			return false;
		}
	}
	printf("  # no reply to xid %#x after 4 sends\n", xid);
	return false;
}

static bool
dtlscall(SSL *ssl)
{
	uint8_t call[64];
	uint32_t xid = nextxid++;

	return dtlsmsg(ssl, call, (int)mkcall(call, xid, AUTH_NONE), xid,
	    NULL);
}

/* The root file handle of EXPORT, from mountd; see rootfh(). */
#define	EXPORT		"/export/pynfs"	/* ci/nfsv4/in-vm.sh exports it */
static uint8_t fh[64];
static uint32_t fhlen;

/* An AUTH_SYS root credential, RFC 5531 App. A, at call + 24. */
static void
authsys(uint8_t *call)
{

	put32(call + 24, 1);		/* AUTH_SYS */
	put32(call + 28, 20);		/* stamp, "", uid, gid, gids<> */
	memset(call + 32, 0, 20);
	put32(call + 52, AUTH_NONE);
	put32(call + 56, 0);
}

/*
 * A plain call on a new socket to port p of the server, from a reserved
 * port, as mountd wants; the reply's results in res, their length or -1.
 */
static ssize_t
plainto(int p, const uint8_t *call, size_t len, uint32_t xid, uint8_t *res,
    size_t rmax)
{
	struct sockaddr_in sin;
	uint8_t buf[2048];
	ssize_t n;
	int fd, rp;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		return -1;
	memset(&sin, 0, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	for (rp = 1023; rp > 600; rp--) {
		sin.sin_port = htons(rp);
		if (bind(fd, (void *)&sin, sizeof(sin)) == 0)
			break;
	}
	sin.sin_port = htons(p);
	(void)inet_pton(AF_INET, host, &sin.sin_addr);
	n = -1;
	if (connect(fd, (void *)&sin, sizeof(sin)) == 0 &&
	    send(fd, call, len, 0) == (ssize_t)len) {
		while ((n = recvwait(fd, buf, sizeof(buf))) > 0) {
			if (!isreply(buf, n, xid, NULL, 0))
				continue;
			n -= 24 + get32(buf + 16);
			if (n < 0 || (size_t)n > rmax)
				n = -1;
			else
				memcpy(res, buf + 24 + get32(buf + 16), n);
			break;
		}
	}
	close(fd);
	return n;
}

/*
 * The root file handle of EXPORT: rpcbind's PMAPPROC_GETPORT for mountd
 * (RFC 1833 s3.2), then MOUNTPROC3_MNT (RFC 1813 s5.2.1).
 */
static bool
rootfh(void)
{
	uint8_t call[128], res[256];
	uint32_t xid;
	ssize_t n;
	size_t len;
	int mport;

	xid = nextxid++;
	(void)mkcall(call, xid, AUTH_NONE);
	put32(call + 12, 100000);	/* PMAP_PROG */
	put32(call + 16, 2);
	put32(call + 20, 3);		/* PMAPPROC_GETPORT */
	put32(call + 40, 100005);	/* MOUNT */
	put32(call + 44, 3);
	put32(call + 48, 17);		/* IPPROTO_UDP */
	put32(call + 52, 0);
	if ((n = plainto(111, call, 56, xid, res, sizeof(res))) != 4 ||
	    (mport = (int)get32(res)) == 0)
		return false;
	xid = nextxid++;
	(void)mkcall(call, xid, AUTH_NONE);
	put32(call + 12, 100005);
	put32(call + 16, 3);
	put32(call + 20, 1);		/* MOUNTPROC3_MNT */
	authsys(call);
	len = sizeof(EXPORT) - 1;
	put32(call + 60, (uint32_t)len);
	memset(call + 64, 0, (len + 3) & ~3U);
	memcpy(call + 64, EXPORT, len);
	n = plainto(mport, call, 64 + ((len + 3) & ~3U), xid, res,
	    sizeof(res));
	/* mountres3: fhs_status, fhandle3 fhandle<64>, ... */
	if (n < 8 || get32(res) != 0 || (fhlen = get32(res + 4)) > 64 ||
	    (size_t)n < 8 + fhlen)
		return false;
	memcpy(fh, res + 8, fhlen);
	return true;
}

/* NFSv3 GETATTR, RFC 1813 s3.3.1, of the root of EXPORT. */
static size_t
mkgetattr(uint8_t *call, uint32_t xid)
{

	(void)mkcall(call, xid, AUTH_NONE);
	put32(call + 20, 1);		/* GETATTR */
	authsys(call);
	put32(call + 60, fhlen);	/* nfs_fh3 data<64> */
	memset(call + 64, 0, (fhlen + 3) & ~3U);
	memcpy(call + 64, fh, fhlen);
	return 64 + ((fhlen + 3) & ~3U);
}

static bool
dtlsgetattr(SSL *ssl, uint32_t *statp)
{
	uint8_t call[128];
	uint32_t xid = nextxid++;

	return dtlsmsg(ssl, call, (int)mkgetattr(call, xid), xid, statp);
}

/* The same in plain UDP, for comparison. */
static bool
plaingetattr(int fd, uint32_t *statp)
{
	uint8_t buf[2048];
	uint32_t xid = nextxid++;
	ssize_t n;

	n = (ssize_t)mkgetattr(buf, xid);
	if (send(fd, buf, n, 0) != n)
		return false;
	while ((n = recvwait(fd, buf, sizeof(buf))) > 0) {
		if (isreply(buf, n, xid, NULL, 0)) {
			*statp = get32(buf + 28 + get32(buf + 16));
			return true;
		}
	}
	return false;
}

/* Seal one record of ours by hand, sequence number seq of epoch 3. */
static size_t
handseal(uint8_t *rec, uint8_t type, const uint8_t *in, size_t len,
    uint64_t seq)
{
	struct dtls13_dir d;
	size_t reclen;

	dtls13_dir_init(&d, csecret, 3);
	d.dd_seq = seq;
	/* s4: with the server's ID, which is what we send with */
	if (dtls13_seal(&d, type, peercid, peercidlen, in, len, rec,
	    &reclen) != 0)
		errx(1, "dtls13_seal");
	dtls13_dir_fini(&d);
	return reclen;
}

/* A reply to xid read through OpenSSL, whatever record carried it. */
static bool
readreply(SSL *ssl, uint32_t xid)
{
	uint8_t buf[2048];
	int n, i;

	for (i = 0; i < 3; i++) {
		n = SSL_read(ssl, buf, sizeof(buf));
		if (n > 0 && isreply(buf, n, xid, NULL, 0))
			return true;
		if (n <= 0)
			return false;
	}
	return false;
}

static double
now(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return tv.tv_sec + tv.tv_usec / 1e6;
}

/*
 * NCALLS calls in each of nproc children; the calls answered and the
 * seconds the slowest child took.  Over DTLS each child associates
 * first, outside the timing.
 */
static void
bench(SSL_CTX *ctx, bool dtls, int nproc, int ncalls)
{
	int i, k, fd, pfd[2], st, ok, total = 0;
	double t0, t1, slow = 0;
	SSL *ssl = NULL;

	for (i = 0; i < nproc; i++) {
		if (pipe(pfd) == -1)
			err(1, "pipe");
		if (fork() == 0) {
			close(pfd[0]);
			if (dtls) {
				if ((ssl = associate(ctx, &fd, false, true)) == NULL)
					_exit(1);
			} else
				fd = udpsock();
			ok = 0;
			t0 = now();
			for (k = 0; k < ncalls; k++) {
				double c0 = now();

				ok += dtls ? dtlscall(ssl) :
				    plaincall(fd, AUTH_NONE, NULL, 0);
				if (now() - c0 > 0.1) {
					nslow++;
					printf("bench slow: call %d took %.3f s\n",
					    k, now() - c0);
				}
			}
			t1 = now() - t0;
			if (dtls)
				printf("bench child: per call %.0f us in SSL_write, "
				    "%.0f us in SSL_read; %d calls over 100 ms\n",
				    tw / ncalls * 1e6, tr / ncalls * 1e6, nslow);
			fflush(stdout);		/* _exit() would drop it */
			dprintf(pfd[1], "%d %f\n", ok, t1);
			_exit(0);
		}
		close(pfd[1]);
		/* the read end, kept per child in the low fds' order */
		if (dup2(pfd[0], 100 + i) == -1)
			err(1, "dup2");
		close(pfd[0]);
	}
	for (i = 0; i < nproc; i++) {
		char line[64] = "";
		FILE *f = fdopen(100 + i, "r");

		if (f != NULL && fgets(line, sizeof(line), f) != NULL) {
			double t;

			if (sscanf(line, "%d %lf", &ok, &t) == 2) {
				total += ok;
				if (t > slow)
					slow = t;
			}
		}
		if (f != NULL)
			fclose(f);
		(void)wait(&st);
	}
	printf("bench %s: %d processes, %d of %d calls answered, %.2f s, "
	    "%.0f calls/s\n", dtls ? "DTLS" : "plain UDP", nproc, total,
	    nproc * ncalls, slow, slow > 0 ? total / slow : 0);
	fflush(stdout);
}

#ifdef HAVE_DTLS_CID
/*
 * The connection IDs at work, RFC 9146 s6 and RFC 9147 s9, on the
 * association of ssl on *fdp; old is a record the server has seen.
 */
static void
cidchecks(SSL *ssl, int *fdp, const uint8_t *old, size_t oldlen)
{
	uint8_t junk[64];
	int fd2, fd3, before;
	int i;

	/*
	 * Which ID the server's records carry is read from a capture,
	 * ci/rpctls/cidcheck.sh: OpenSSL's message callback does not show
	 * it reliably.
	 */
	/* Another port, as after a NAT rebinding. */
	fd2 = udpsock();
	if (!setfd(ssl, fd2))
		errx(1, "BIO_new_dgram");
	before = rx_newcid;
	check(dtlscall(ssl), "a call from a new port is answered there, "
	    "RFC 9146 s6");
	check(rx_newcid > before, "the new port was probed with a "
	    "NewConnectionId before the move, RFC 9146 s6");
	printf("cid ports %u %u\n", lport(*fdp), lport(fd2));
	close(*fdp);
	*fdp = fd2;

	/* Neither a replay nor a forgery from a third port moves it. */
	fd3 = udpsock();
	(void)send(fd3, old, oldlen, 0);
	check(recvwait(fd3, junk, sizeof(junk)) < 0,
	    "a replayed record from a third port is not answered there");
	memset(junk, 0x5a, sizeof(junk));
	junk[0] = 0x3f;			/* 001, C, S, L, epoch 3; s4 */
	memcpy(junk + 1, peercid, peercidlen);
	junk[1 + peercidlen + 2] = 0;
	junk[1 + peercidlen + 3] = 40;
	(void)send(fd3, junk, 1 + peercidlen + 4 + 40, 0);
	check(recvwait(fd3, junk, sizeof(junk)) < 0,
	    "a forged record with the server's ID is not answered there");
	close(fd3);
	check(dtlscall(ssl), "the association stays where it moved");

	/* s9: cid_immediate "MUST be used immediately" */
	if (SSL_dtls_new_connection_id(ssl, SSL_DTLS_CID_IMMEDIATE) != 1)
		check(false, "SSL_dtls_new_connection_id");
	for (i = 0; i < 2; i++)
		(void)dtlscall(ssl);
	hexline("cid new", newcid, newcidlen);
	check(newcidlen == owncidlen && memcmp(newcid, owncid, owncidlen) &&
	    dtlscall(ssl), "a call after our NewConnectionId, s9");

	/* s9: "Endpoints SHOULD respond to RequestConnectionId" */
	before = rx_newcid;
	if (SSL_dtls_request_connection_id(ssl, 2) != 1)
		check(false, "SSL_dtls_request_connection_id");
	for (i = 0; i < 4 && rx_newcid == before; i++)
		(void)dtlscall(ssl);
	check(rx_newcid > before,
	    "RequestConnectionId answered with a NewConnectionId, s9");
	check(dtlscall(ssl), "a call after the connection ID messages");

	fflush(stdout);
}

/*
 * RFC 9147 s9, ConnectionId<0..2^8-1>, as RFC 9146 s3: an immediate
 * NewConnectionId of the longest, by hand, as OpenSSL gives out IDs
 * of the handshake's length only.  The server has to send with it,
 * the ACK first (s7); OpenSSL, which never gave it, cannot read
 * that, so it is read here off the socket.  The record is sealed under
 * epoch 3, so on an association that has not rekeyed.
 */
static void
longnewcid(int fd)
{
	uint8_t body[2 + 1 + 255 + 1], hs[512], rec[512], cid[255];
	uint8_t buf[2048];
	size_t len, n;
	ssize_t r;
	bool seen = false;
	int i;

	for (i = 0; i < 255; i++)
		cid[i] = (uint8_t)(i ^ 0x5c);
	body[0] = 0x01;		/* cids<0..2^16-1>: 256 bytes */
	body[1] = 0x00;
	body[2] = 255;
	memcpy(body + 3, cid, 255);
	body[3 + 255] = 0;	/* cid_immediate */
	len = dtls13_hs_build(hs, DTLS13_HS_NEW_CID,
	    (uint16_t)(hsw + 50), body, sizeof(body));
	n = handseal(rec, TLS13_CT_HANDSHAKE, hs, len,
	    (uint64_t)cw3 + 100);
	(void)send(fd, rec, n, 0);
	while (!seen && (r = recvwait(fd, buf, sizeof(buf))) > 0)
		seen = r > 1 + 255 && (buf[0] & 0xf0) == 0x30 &&
		    memcmp(buf + 1, cid, 255) == 0;
	check(seen, "after a NewConnectionId of a 255-byte ID the "
	    "server sends with it, s9");
}

#endif

int
main(int argc, char **argv)
{
	uint8_t call[64], rec[256], old[256], body[3] = { 0, 0, 0 }, hs[32];
	uint32_t pst = ~0U;
	SSL_CTX *ctx;
	SSL *ssl;
	size_t n, len;
	uint32_t xid;
	uint64_t seq;
	int fd, fd2, i;
	bool cid = false, nocidok = false, ok;

#ifdef HAVE_DTLS_CID
	cid = true;
#endif
	if (argc == 5 && strcmp(argv[4], "nocid-ok") == 0)
		nocidok = true;
	else if (argc != 4 && !(argc == 7 && strcmp(argv[4], "bench") == 0))
		errx(1, "usage: dtlsclient host port cafile [nocid-ok | "
		    "bench nproc ncalls]");
	host = argv[1];
	port = atoi(argv[2]);
	cafile = argv[3];
	ctx = mkctx();
	if (argc == 7) {
		bench(ctx, false, atoi(argv[5]), atoi(argv[6]));
		bench(ctx, true, atoi(argv[5]), atoi(argv[6]));
		return 0;
	}

	fd = udpsock();
	check(plaincall(fd, AUTH_NONE, NULL, 0),
	    "plain RPC on UDP from a peer without an association");
	{
		uint32_t st = 0;

		check(rootfh(), "the root file handle of " EXPORT
		    " from mountd");
		ok = plaingetattr(fd, &st);
		check(ok, "an NFSv3 GETATTR on plain UDP");
		printf("  # plain GETATTR nfsstat3 %u\n", st);
		pst = st;
	}
	close(fd);

	if ((ssl = associate(ctx, &fd, true, cid)) == NULL)
		goto out;
	check(dtlscall(ssl), "a call over DTLS");
	check(dtlscall(ssl), "a second call over DTLS");
	{
		uint32_t st = 0;

		ok = dtlsgetattr(ssl, &st);
		printf("  # GETATTR nfsstat3 %u\n", st);
		/* The server's answer, whatever it is, the same either way. */
		check(ok && st == pst, "an NFSv3 GETATTR over DTLS, answered "
		    "as on plain UDP");
	}

	/* A record of ours a little ahead of OpenSSL's, by hand. */
	seq = (uint64_t)cw3 + 10;
	xid = nextxid++;
	n = handseal(rec, TLS13_CT_APPDATA, call, mkcall(call, xid, AUTH_NONE),
	    seq);
	memcpy(old, rec, n);
	(void)send(fd, rec, n, 0);
	check(readreply(ssl, xid), "a call in a record sealed by hand");
	(void)send(fd, rec, n, 0);
	check(!readreply(ssl, xid), "its replay is dropped, s4.5.1");

	memset(rec, 0x5a, 64);
	rec[0] = 0x2f;			/* 001, S, L, epoch 3 */
	rec[3] = 0;
	rec[4] = 60;
	(void)send(fd, rec, 65, 0);
	check(dtlscall(ssl), "garbage dropped silently, s4.5.2");

	/* s8 and RFC 8446 s4.6.3, which the kernel MUST ACK */
	verbose = true;
	if (SSL_key_update(ssl, SSL_KEY_UPDATE_REQUESTED) != 1)
		check(false, "SSL_key_update");
	check(dtlscall(ssl), "a call after our KeyUpdate");
	for (i = 0; i < 6 && (rx_keyupdate == 0 || rx_ack == 0); i++)
		check(dtlscall(ssl), "a call while the KeyUpdate settles");
	check(rx_ack > 0, "the server ACKed our KeyUpdate, s7, s8");
	check(rx_keyupdate > 0, "the server's KeyUpdate, as requested");
	check(dtlscall(ssl), "a call under the new keys both ways");
	verbose = false;

#ifdef HAVE_DTLS_CID
	/* Run without IDs too, to count what fails then. */
	cidchecks(ssl, &fd, old, n);
#endif
	(void)SSL_shutdown(ssl);
	SSL_free(ssl);
	check(!plaincall(fd, AUTH_NONE, NULL, 0),
	    "after close_notify the 5-tuple is discarded, s5.1.2");
	close(fd);

#ifdef HAVE_DTLS_CID
	/*
	 * RFC 9146 s3: cid<0..2^8-1>.  64 bytes in the handshake, past
	 * the 20 the kernel once held; OpenSSL's own handshake failed with
	 * 180 bytes and more when measured, so not the longest here.
	 */
	cidwant = 64;
	if ((ssl = associate(ctx, &fd2, false, true)) != NULL) {
		check(dtlscall(ssl), "a call with a 64-byte connection ID "
		    "of ours, RFC 9146 s3");
		SSL_free(ssl);
		close(fd2);
	}
	cidwant = CID_LEN;
	if ((ssl = associate(ctx, &fd2, false, true)) != NULL) {
		check(dtlscall(ssl), "a call on a fresh association");
		longnewcid(fd2);
		SSL_free(ssl);
		close(fd2);
	}
#endif

	/*
	 * RFC 9289 s5.1.2: "each DTLS handshake MUST include the
	 * connection_id(54) extension".  A client that offers none gets
	 * its handshake, and then nothing; the kernel refused it.
	 */
	if ((ssl = associate(ctx, &fd2, false, false)) == NULL)
		goto out;
	ok = dtlscall(ssl);
	if (cid && !nocidok) {
		check(!ok, "an association without connection IDs is "
		    "refused, s5.1.2");
		SSL_free(ssl);
		close(fd2);
		goto out;
	}
	check(ok, "a call on an association without connection IDs");
	/* s9: NewConnectionId without negotiated IDs is fatal. */
	len = dtls13_hs_build(hs, DTLS13_HS_NEW_CID, (uint16_t)(hsw + 50),
	    body, sizeof(body));
	n = handseal(rec, TLS13_CT_HANDSHAKE, hs, len, (uint64_t)cw3 + 10);
	(void)send(fd2, rec, n, 0);
	(void)dtlscall(ssl);
	check(rx_alert == 10,
	    "NewConnectionId without IDs: unexpected_message, s9");
	check(!plaincall(fd2, AUTH_NONE, NULL, 0),
	    "after the fatal alert the 5-tuple is discarded, s5.1.2");
	SSL_free(ssl);
	close(fd2);
out:
	printf("probe-dtls failures %d\n", failures);
	return failures != 0;
}
