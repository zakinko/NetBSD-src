/*	$NetBSD$	*/

/*
 * RPC-with-TLS over UDP, RFC 9289 s5.1.2, from the client's side, against
 * the kernel's DTLS 1.3 record layer and rpc.tlsservd.  OpenSSL 4.1 does
 * the handshake; records it cannot be made to send, a replay, garbage,
 * a NewConnectionId, are built with the kernel's own record code from
 * the client's traffic secret, which OpenSSL's key log gives.
 *
 *	dtlsclient host port cafile
 *
 * Prints "ok name" or "FAIL name" per check and "probe-dtls failures N".
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

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
#include <openssl/ssl.h>

#include "gss_krb5_shim.h"	/* struct aesenc, for tls13_crypto.h */
#include "tls13_crypto.h"

#define	NFS_PROG	100003
#define	NFS_VERS	3
#define	AUTH_NONE	0
#define	AUTH_TLS	7	/* RFC 9289 s7.1 */
#define	WAIT_MS		1500	/* ours: how long a reply may take */

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

/* Probe and shake hands on a new socket; NULL if that failed. */
static SSL *
associate(SSL_CTX *ctx, int *fdp, bool spurious)
{
	struct timeval tv = { 3, 0 };
	char verf[16];
	BIO *bio;
	SSL *ssl;
	int fd;

	have_csecret = false;
	cw3 = hsw = rx_keyupdate = rx_ack = 0;
	rx_alert = -1;
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
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	ssl = SSL_new(ctx);
	bio = BIO_new_dgram(fd, BIO_NOCLOSE);
	SSL_set_bio(ssl, bio, bio);
	if (SSL_connect(ssl) != 1) {
		ERR_print_errors_fp(stdout);
		check(false, "DTLS 1.3 handshake");
		SSL_free(ssl);
		return NULL;
	}
	check(SSL_version(ssl) == DTLS1_3_VERSION && have_csecret,
	    "DTLS 1.3 handshake");
	rx_ack = rx_keyupdate = 0;	/* those of the handshake are not ours */
	return ssl;
}

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
dtlscall(SSL *ssl)
{
	uint8_t buf[2048], call[64];
	uint32_t xid = nextxid++;
	int n, i, len;

	len = (int)mkcall(call, xid, AUTH_NONE);
	for (i = 0; i < 8; i++) {
		/*
		 * After our KeyUpdate OpenSSL writes nothing until it has
		 * read the ACK, RFC 9147 s8, and says so with WANT_READ.
		 */
		if (i % 2 == 0 && (n = SSL_write(ssl, call, len)) != len &&
		    SSL_get_error(ssl, n) != SSL_ERROR_WANT_READ) {
			why("SSL_write", ssl, n);
			return false;
		}
		n = SSL_read(ssl, buf, sizeof(buf));
		if (n > 0 && isreply(buf, n, xid, NULL, 0))
			return true;
		if (n <= 0 && SSL_get_error(ssl, n) != SSL_ERROR_WANT_READ &&
		    SSL_get_error(ssl, n) != SSL_ERROR_SYSCALL) {
			why("SSL_read", ssl, n);
			return false;
		}
	}
	printf("  # no reply to xid %#x after 4 sends\n", xid);
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
	if (dtls13_seal(&d, type, NULL, 0, in, len, rec, &reclen) != 0)
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

int
main(int argc, char **argv)
{
	uint8_t call[64], rec[256], body[3] = { 0, 0, 0 }, hs[32];
	SSL_CTX *ctx;
	SSL *ssl;
	size_t n, len;
	uint32_t xid;
	uint64_t seq;
	int fd, fd2, i;

	if (argc != 4)
		errx(1, "usage: dtlsclient host port cafile");
	host = argv[1];
	port = atoi(argv[2]);
	cafile = argv[3];
	ctx = mkctx();

	fd = udpsock();
	check(plaincall(fd, AUTH_NONE, NULL, 0),
	    "plain RPC on UDP from a peer without an association");
	close(fd);

	if ((ssl = associate(ctx, &fd, true)) == NULL)
		goto out;
	check(dtlscall(ssl), "a call over DTLS");
	check(dtlscall(ssl), "a second call over DTLS");

	/* A record of ours a little ahead of OpenSSL's, by hand. */
	seq = (uint64_t)cw3 + 10;
	xid = nextxid++;
	n = handseal(rec, TLS13_CT_APPDATA, call, mkcall(call, xid, AUTH_NONE),
	    seq);
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
	(void)SSL_shutdown(ssl);
	SSL_free(ssl);
	check(!plaincall(fd, AUTH_NONE, NULL, 0),
	    "after close_notify the 5-tuple is discarded, s5.1.2");
	close(fd);

	/* s9: NewConnectionId without negotiated IDs is fatal. */
	if ((ssl = associate(ctx, &fd2, false)) == NULL)
		goto out;
	check(dtlscall(ssl), "a call on a second association");
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
