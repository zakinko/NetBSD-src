/*	$NetBSD$	*/

/*-
 * Copyright (c) 2026 The NetBSD Foundation, Inc.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * The server side of the TLS handshake of RPC-with-TLS, RFC 9289.  The
 * kernel answers the AUTH_TLS probe and hands each connection here with
 * NFSSVC_TLSWAIT; a child does the handshake with OpenSSL and gives the
 * kernel, with NFSSVC_TLSDONE, the traffic secrets for its record layer
 * and the "tls-exporter" channel binding.  OpenSSL never sees a byte of
 * application data, and the child leaves without closing the session.
 */

#include <sys/cdefs.h>
__RCSID("$NetBSD$");

#include <sys/types.h>
#include <sys/socket.h>

#include <nfs/nfs.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

/* Not from the RFC: how long a client may take over its handshake. */
#define	HANDSHAKE_TIMEOUT	30

/* RFC 9289 s7.2, as a TLS ALPN ProtocolNameList entry, RFC 7301 s3.1 */
static const unsigned char alpn_sunrpc[] = "\x06sunrpc";

/* RFC 9266 s2 */
static const char exporter_label[] = "EXPORTER-Channel-Binding";

static bool debug;
static struct nfsd_tlsarg nt;		/* the one connection of a child */
static bool have_csecret, have_ssecret;

static void
logssl(const char *what)
{
	unsigned long e;
	char buf[256];

	while ((e = ERR_get_error()) != 0) {
		ERR_error_string_n(e, buf, sizeof(buf));
		syslog(LOG_WARNING, "%s: %s", what, buf);
	}
}

static int
unhex(uint8_t *out, size_t max, const char *s)
{
	size_t n;
	unsigned v;

	for (n = 0; s[0] != '\0' && s[0] != '\n'; n++, s += 2) {
		if (n == max || sscanf(s, "%2x", &v) != 1)
			return -1;
		out[n] = v;
	}
	return (int)n;
}

/*
 * The traffic secrets of the session, RFC 8446 s7.1.  OpenSSL hands them
 * out only through its key log, in the NSS format: "LABEL client_random
 * secret", hexadecimal.  Only the application secrets are kept.
 */
static void
keylog(const SSL *ssl, const char *line)
{
	static const char cl[] = "CLIENT_TRAFFIC_SECRET_0 ";
	static const char sl[] = "SERVER_TRAFFIC_SECRET_0 ";
	uint8_t *dst;
	bool *have;
	const char *p;
	int n;

	if (strncmp(line, cl, sizeof(cl) - 1) == 0) {
		dst = nt.nt_csecret;
		have = &have_csecret;
	} else if (strncmp(line, sl, sizeof(sl) - 1) == 0) {
		dst = nt.nt_ssecret;
		have = &have_ssecret;
	} else
		return;
	if ((p = strchr(line + sizeof(cl) - 1, ' ')) == NULL)
		return;
	n = unhex(dst, NFSD_TLS_SECRETMAX, p + 1);
	if (n <= 0 || (nt.nt_secretlen != 0 && nt.nt_secretlen != n))
		return;
	nt.nt_secretlen = n;
	*have = true;
}

/*
 * RFC 9289 s5: the server MUST answer with "sunrpc" alone.  A list without
 * it is refused with no_application_protocol, RFC 7301 s3.2.
 */
static int
alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen, void *arg)
{
	unsigned char *o;

	if (SSL_select_next_proto(&o, outlen, alpn_sunrpc,
	    sizeof(alpn_sunrpc) - 1, in, inlen) != OPENSSL_NPN_NEGOTIATED)
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	*out = o;
	return SSL_TLSEXT_ERR_OK;
}

/* Whatever the client shows, go on; handshake() reads the verdict. */
static int
verify_anonymous(int ok, X509_STORE_CTX *xs)
{

	return 1;
}

static SSL_CTX *
mkctx(const char *cert, const char *key, const char *ca, bool mutual)
{
	SSL_CTX *ctx;

	if ((ctx = SSL_CTX_new(TLS_server_method())) == NULL)
		errx(1, "SSL_CTX_new");
	/* RFC 9289 s5: nothing before TLS 1.3. */
	if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION))
		errx(1, "TLS 1.3");
	/*
	 * The kernel's record layer has TLS_AES_128_GCM_SHA256 alone, the
	 * suite RFC 8446 s9.1 makes mandatory.
	 */
	if (!SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256"))
		errx(1, "ciphersuites");
	/*
	 * No NewSessionTicket: it would follow the handshake under the
	 * application secret, a record the kernel did not see the sequence
	 * number of.  RFC 9289 s6 forbids 0-RTT anyway.
	 */
	SSL_CTX_set_num_tickets(ctx, 0);
	SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
	SSL_CTX_set_max_early_data(ctx, 0);
	SSL_CTX_set_alpn_select_cb(ctx, alpn_select, NULL);
	SSL_CTX_set_keylog_callback(ctx, keylog);
	if (SSL_CTX_use_certificate_chain_file(ctx, cert) != 1 ||
	    SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1 ||
	    SSL_CTX_check_private_key(ctx) != 1) {
		logssl(cert);
		errx(1, "%s, %s: unusable", cert, key);
	}
	if (ca != NULL && SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1) {
		logssl(ca);
		errx(1, "%s: unusable", ca);
	}
	/*
	 * RFC 9289 s4.2: the server MUST ask every client for its identity.
	 * With -m one that has none, or one not verified, is refused: the
	 * mutual host authentication of s4.2 and s5.2.1.  Without it the
	 * client may stay anonymous, and a certificate it shows is noted
	 * as verified or not, in NFSD_TLS_PEERCERT.
	 */
	if (mutual)
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER |
		    SSL_VERIFY_CLIENT_ONCE | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
		    NULL);
	else
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER |
		    SSL_VERIFY_CLIENT_ONCE, verify_anonymous);
	return ctx;
}

/*
 * Shake hands on fd and tell the kernel the outcome.  Runs in a child of
 * its own, which exits after.
 */
static void
handshake(SSL_CTX *ctx, int fd)
{
	const unsigned char *alpn;
	unsigned int alpnlen;
	X509 *peer;
	SSL *ssl;
	int error = ECONNABORTED;

	alarm(HANDSHAKE_TIMEOUT);
	if ((ssl = SSL_new(ctx)) == NULL || !SSL_set_fd(ssl, fd)) {
		logssl("SSL_new");
		goto done;
	}
	if (SSL_accept(ssl) != 1) {
		logssl("handshake");
		goto done;
	}
	alarm(0);
	SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
	if (alpnlen == 0)
		/* s5 makes it the client's MUST; it is not refused here. */
		syslog(LOG_NOTICE, "conn %ju: client offered no ALPN",
		    (uintmax_t)nt.nt_cookie);
	if (SSL_version(ssl) != TLS1_3_VERSION ||
	    !have_csecret || !have_ssecret) {
		syslog(LOG_WARNING, "conn %ju: no TLS 1.3 secrets",
		    (uintmax_t)nt.nt_cookie);
		goto done;
	}
	/*
	 * Records OpenSSL has read past the client's Finished would be lost
	 * to the kernel.  Without read-ahead it reads one record at a time
	 * and there are none.
	 */
	if (SSL_has_pending(ssl)) {
		syslog(LOG_WARNING, "conn %ju: data read during the handshake",
		    (uintmax_t)nt.nt_cookie);
		goto done;
	}
	nt.nt_suite = SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(ssl));
	/* RFC 9266 s2; RFC 8446 s7.5 makes no context and an empty one equal. */
	if (SSL_export_keying_material(ssl, nt.nt_exporter,
	    sizeof(nt.nt_exporter), exporter_label, sizeof(exporter_label) - 1,
	    NULL, 0, 0) != 1) {
		logssl("exporter");
		goto done;
	}
	if ((peer = SSL_get0_peer_certificate(ssl)) != NULL &&
	    SSL_get_verify_result(ssl) == X509_V_OK)
		nt.nt_flags |= NFSD_TLS_PEERCERT;
	syslog(LOG_INFO, "conn %ju: TLS 1.3, suite 0x%04x, ALPN %.*s, %s",
	    (uintmax_t)nt.nt_cookie, nt.nt_suite, (int)alpnlen, alpn,
	    peer == NULL ? "anonymous client" :
	    (nt.nt_flags & NFSD_TLS_PEERCERT) != 0 ? "client verified" :
	    "client unverified");
	error = 0;
done:
	nt.nt_error = error;
	if (nfssvc(NFSSVC_TLSDONE, &nt) == -1)
		syslog(LOG_WARNING, "conn %ju: NFSSVC_TLSDONE: %m",
		    (uintmax_t)nt.nt_cookie);
	explicit_memset(&nt, 0, sizeof(nt));
	/*
	 * No SSL_shutdown(): the session goes on in the kernel.  The
	 * descriptor is only this process's; the kernel holds its own.
	 */
	_exit(0);
}

static void
timeout(int sig)
{

	/* The kernel learns of it from TLSDONE not coming: say so. */
	nt.nt_error = ETIMEDOUT;
	(void)nfssvc(NFSSVC_TLSDONE, &nt);
	_exit(1);
}

__dead static void
usage(void)
{

	fprintf(stderr, "usage: %s [-dm] [-A cafile] -c cert -k key\n",
	    getprogname());
	exit(1);
}

int
main(int argc, char **argv)
{
	const char *cert = NULL, *key = NULL, *ca = NULL;
	struct nfsd_tlsarg w;
	bool mutual = false;
	SSL_CTX *ctx;
	pid_t pid;
	int c;

	while ((c = getopt(argc, argv, "A:c:dk:m")) != -1) {
		switch (c) {
		case 'A':
			ca = optarg;
			break;
		case 'c':
			cert = optarg;
			break;
		case 'd':
			debug = true;
			break;
		case 'k':
			key = optarg;
			break;
		case 'm':
			mutual = true;
			break;
		default:
			usage();
		}
	}
	if (cert == NULL || key == NULL || argc != optind)
		usage();
	if (mutual && ca == NULL)
		errx(1, "-m needs -A");

	openlog(getprogname(), LOG_PID | (debug ? LOG_PERROR : 0), LOG_DAEMON);
	ctx = mkctx(cert, key, ca, mutual);
	if (!debug && daemon(0, 0) == -1)
		err(1, "daemon");
	signal(SIGCHLD, SIG_IGN);	/* no zombies */
	signal(SIGPIPE, SIG_IGN);

	for (;;) {
		memset(&w, 0, sizeof(w));
		if (nfssvc(NFSSVC_TLSWAIT, &w) == -1) {
			if (errno == EINTR)
				continue;
			syslog(LOG_ERR, "NFSSVC_TLSWAIT: %m");
			exit(1);
		}
		if ((w.nt_flags & NFSD_TLS_EVENT) != 0) {
			/* RFC 8446 s6: close_notify is the ordinary end. */
			syslog(w.nt_alertdesc == 0 ? LOG_INFO : LOG_NOTICE,
			    "conn %ju: alert %s, level %u, description %u",
			    (uintmax_t)w.nt_cookie,
			    (w.nt_flags & NFSD_TLS_ALERTSENT) != 0 ?
			    "sent" : "received",
			    w.nt_alertlevel, w.nt_alertdesc);
			continue;
		}
		switch (pid = fork()) {
		case -1:
			syslog(LOG_ERR, "fork: %m");
			w.nt_error = EAGAIN;
			(void)nfssvc(NFSSVC_TLSDONE, &w);
			break;
		case 0:
			nt.nt_cookie = w.nt_cookie;
			signal(SIGALRM, timeout);
			handshake(ctx, w.nt_fd);
			/* NOTREACHED */
		default:
			break;
		}
		close(w.nt_fd);
	}
}
