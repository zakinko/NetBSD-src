/*
 * RPC over the kernel's TLS 1.3 record layer, RFC 9289, from a client
 * written against OpenSSL, which can send what Python cannot: KeyUpdate,
 * a forged record.  probe3 HOST PORT CADIR
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fails;
static uint32_t xid = 0x9100;
static const char *host, *cadir;
static int port;

static void
ok(int cond, const char *what)
{
	printf("%s %s\n", cond ? "ok  " : "FAIL", what);
	if (!cond)
		fails++;
}

static size_t
put32(uint8_t *p, uint32_t v)
{
	v = htonl(v);
	memcpy(p, &v, 4);
	return 4;
}

static uint32_t
get32(const uint8_t *p)
{
	uint32_t v;

	memcpy(&v, p, 4);
	return ntohl(v);
}

/* A call record: prog 100003 vers 4, cred flavor with an empty body. */
static size_t
mkcall(uint8_t *b, uint32_t proc, uint32_t flavor, const uint8_t *args,
    size_t alen)
{
	size_t n = 4;

	n += put32(b + n, ++xid);
	n += put32(b + n, 0);		/* CALL */
	n += put32(b + n, 2);
	n += put32(b + n, 100003);
	n += put32(b + n, 4);
	n += put32(b + n, proc);
	n += put32(b + n, flavor);
	if (flavor == 1) {		/* AUTH_SYS, RFC 5531 App. A */
		n += put32(b + n, 20);
		n += put32(b + n, 0);	/* stamp */
		n += put32(b + n, 0);	/* machinename<> */
		n += put32(b + n, 0);	/* uid */
		n += put32(b + n, 0);	/* gid */
		n += put32(b + n, 0);	/* gids<> */
	} else
		n += put32(b + n, 0);
	n += put32(b + n, 0);		/* verf AUTH_NONE */
	n += put32(b + n, 0);
	memcpy(b + n, args, alen);
	n += alen;
	put32(b, 0x80000000U | (uint32_t)(n - 4));
	return n;
}

static int
readn(SSL *ssl, uint8_t *b, size_t n)
{
	size_t got = 0;
	int r;

	while (got < n) {
		r = SSL_read(ssl, b + got, (int)(n - got));
		if (r <= 0)
			return -1;
		got += r;
	}
	return 0;
}

/* One reply record into b; its length, or -1. */
static long
reply(SSL *ssl, uint8_t *b, size_t max)
{
	uint8_t h[4];
	uint32_t len;

	if (readn(ssl, h, 4) != 0)
		return -1;
	len = get32(h) & 0x7fffffff;
	if (len > max || readn(ssl, b, len) != 0)
		return -1;
	return len;
}

static int
connect_starttls(void)
{
	struct sockaddr_in sin;
	uint8_t b[256];
	size_t n;
	int s;

	s = socket(AF_INET, SOCK_STREAM, 0);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	inet_pton(AF_INET, host, &sin.sin_addr);
	if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		err(1, "connect");
	n = mkcall(b, 0, 7, NULL, 0);		/* AUTH_TLS, RFC 9289 s7.1 */
	write(s, b, n);
	if (read(s, b, sizeof(b)) < 36 || memcmp(b + 28, "STARTTLS", 8) != 0)
		errx(1, "no STARTTLS");
	return s;
}

static SSL *
shake(SSL_CTX *ctx, int *sp)
{
	SSL *ssl;

	*sp = connect_starttls();
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, *sp);
	SSL_set_tlsext_host_name(ssl, "localhost");
	SSL_set1_host(ssl, "localhost");
	if (SSL_connect(ssl) != 1) {
		ERR_print_errors_fp(stdout);
		errx(1, "handshake");
	}
	return ssl;
}

static int
nullcall(SSL *ssl, uint32_t flavor, uint32_t *rstat, uint32_t *x)
{
	uint8_t b[512];
	size_t n;
	long r;

	n = mkcall(b, 0, flavor, NULL, 0);
	if (SSL_write(ssl, b, (int)n) != (int)n)
		return -1;
	if ((r = reply(ssl, b, sizeof(b))) < 12)
		return -1;
	*rstat = get32(b + 8);
	*x = r >= 20 ? get32(b + 16) : 0;	/* reject_stat or verf flavor */
	return get32(b) == xid ? 0 : -1;
}

int
main(int argc, char **argv)
{
	static uint8_t big[600 * 1024];
	char path[512];
	uint32_t rstat, x;
	SSL_CTX *ctx;
	SSL *ssl;
	size_t n, i;
	long r;
	int s;

	if (argc != 4)
		errx(1, "usage: probe3 host port cadir");
	host = argv[1];
	port = atoi(argv[2]);
	cadir = argv[3];
	setvbuf(stdout, NULL, _IOLBF, 0);

	ctx = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	SSL_CTX_set_alpn_protos(ctx, (const uint8_t *)"\x06sunrpc", 7);
	snprintf(path, sizeof(path), "%s/ca.pem", cadir);
	SSL_CTX_load_verify_locations(ctx, path, NULL);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	/* 1. RPC in records, then the probe within TLS, s4.1. */
	ssl = shake(ctx, &s);
	ok(nullcall(ssl, 1, &rstat, &x) == 0 && rstat == 0,
	    "NULL under AUTH_SYS over TLS: MSG_ACCEPTED");
	ok(nullcall(ssl, 7, &rstat, &x) == 0 && rstat == 1 && x == 1,
	    "AUTH_TLS within TLS: MSG_DENIED AUTH_ERROR (s4.1 MUST)");
	ok(nullcall(ssl, 1, &rstat, &x) == 0 && rstat == 0,
	    "the connection goes on after the refusal");

	/*
	 * 2. Calls larger than a record, 2^14 (RFC 8446 s5.1): a NULL with
	 * arguments is refused or answered, either way in records the
	 * server split and the client put back together.
	 */
	for (i = 0; i < sizeof(big); i++)
		big[i] = (uint8_t)i;
	n = mkcall(big, 0, 1, big + 1024, 300 * 1024);
	ok(SSL_write(ssl, big, (int)n) == (int)n &&
	    (r = reply(ssl, big, sizeof(big))) >= 12 && get32(big) == xid,
	    "a 300 KB call over many records answered");

	/* 3. KeyUpdate both ways, s4.6.3. */
	ok(SSL_key_update(ssl, SSL_KEY_UPDATE_REQUESTED) == 1,
	    "client KeyUpdate, update_requested, queued");
	for (i = 0; i < 3; i++)
		if (nullcall(ssl, 1, &rstat, &x) != 0 || rstat != 0)
			break;
	ok(i == 3, "calls after the KeyUpdate, under the new keys both ways");
	ok(SSL_key_update(ssl, SSL_KEY_UPDATE_NOT_REQUESTED) == 1 &&
	    nullcall(ssl, 1, &rstat, &x) == 0 && rstat == 0,
	    "client KeyUpdate, update_not_requested");

	/* 4. close_notify is answered with close_notify, s6.1. */
	r = SSL_shutdown(ssl);
	if (r == 0)
		r = SSL_shutdown(ssl);
	ok(r == 1, "close_notify answered with close_notify (RFC 8446 s6.1)");
	SSL_free(ssl);
	close(s);

	/* 5. A forged record: bad_record_mac, s5.2. */
	ssl = shake(ctx, &s);
	ok(nullcall(ssl, 1, &rstat, &x) == 0, "second connection");
	{
		uint8_t junk[5 + 40] = { 0x17, 0x03, 0x03, 0x00, 40 };

		memset(junk + 5, 0xa5, 40);
		write(s, junk, sizeof(junk));
	}
	r = SSL_read(ssl, big, 16);
	n = ERR_peek_last_error();
	printf("     after the forged record: SSL_read %ld, %s\n", r,
	    ERR_reason_error_string(n) ? ERR_reason_error_string(n) : "-");
	ok(r <= 0 && n != 0 && strstr(ERR_reason_error_string(n),
	    "bad record mac") != NULL,
	    "forged record: bad_record_mac alert from the server (RFC 8446 s5.2)");
	ERR_clear_error();
	SSL_free(ssl);
	close(s);

	printf("probe3 failures %d\n", fails);
	return fails != 0;
}
