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
 * The userland half of RPCSEC_GSS: establish contexts for the kernel
 * with the keytab and Heimdal, and turn principals into users.  The kernel calls here over a local socket, one call to a
 * connection, as ONC RPC with no authentication; see
 * sys/oncrpc/oncrpc_gssd.h.  The socket is root's alone, as what comes
 * back holds session keys.
 */

#include <sys/cdefs.h>
__RCSID("$NetBSD$");

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <grp.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <util.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <krb5.h>

#define	GSSD_PATH	"/var/run/gssd.sock"
#define	GSSD_PROG	0x40475353
#define	GSSD_VERS	1
#define	GSSD_ACCEPT	1
#define	GSSD_MAXGROUPS	16
#define	GSSD_MAXMSG	(64 * 1024)
#define	GSSD_MAXPENDING	256	/* contexts between two rounds; chosen */

#define	RPC_REPLY	1
#define	GSS_CONTINUE	1	/* RFC 2203 App. A */
#define	GSS_UNAUTHORIZED 0x000f0000	/* RFC 2203 App. A */

static gss_cred_id_t acceptor = GSS_C_NO_CREDENTIAL;
static char *realm;
static bool debug;

/* A context in the middle of more than one round. */
static struct pending {
	uint64_t	p_id;
	gss_ctx_id_t	p_ctx;
	time_t		p_when;
} pending[GSSD_MAXPENDING];
static uint64_t nextid;

struct buf {
	uint8_t	*b_p;
	size_t	b_off;
	size_t	b_len;
	bool	b_bad;
};

static uint32_t
get32(struct buf *b)
{
	uint32_t v;

	if (b->b_len - b->b_off < 4) {
		b->b_bad = true;
		return 0;
	}
	memcpy(&v, b->b_p + b->b_off, 4);
	b->b_off += 4;
	return ntohl(v);
}

static const void *
getbytes(struct buf *b, size_t len)
{
	const void *p = b->b_p + b->b_off;
	size_t pad = (4 - len % 4) % 4;

	if (b->b_len - b->b_off < len + pad || len > GSSD_MAXMSG) {
		b->b_bad = true;
		return NULL;
	}
	b->b_off += len + pad;
	return p;
}

static void
put32(struct buf *b, uint32_t v)
{

	if (b->b_len - b->b_off < 4) {
		b->b_bad = true;
		return;
	}
	v = htonl(v);
	memcpy(b->b_p + b->b_off, &v, 4);
	b->b_off += 4;
}

static void
putbytes(struct buf *b, const void *p, size_t len)
{
	size_t pad = (4 - len % 4) % 4;

	put32(b, (uint32_t)len);
	if (b->b_len - b->b_off < len + pad) {
		b->b_bad = true;
		return;
	}
	if (len != 0)
		memcpy(b->b_p + b->b_off, p, len);
	memset(b->b_p + b->b_off + len, 0, pad);
	b->b_off += len + pad;
}

static void
log_gss(const char *what, OM_uint32 major, OM_uint32 minor)
{
	OM_uint32 m, ctx = 0;
	gss_buffer_desc s;

	do {
		if (GSS_ERROR(gss_display_status(&m, major, GSS_C_GSS_CODE,
		    GSS_C_NO_OID, &ctx, &s)))
			break;
		syslog(LOG_WARNING, "%s: %.*s", what, (int)s.length,
		    (char *)s.value);
		gss_release_buffer(&m, &s);
	} while (ctx != 0);
	ctx = 0;
	do {
		if (GSS_ERROR(gss_display_status(&m, minor, GSS_C_MECH_CODE,
		    GSS_KRB5_MECHANISM, &ctx, &s)))
			break;
		syslog(LOG_WARNING, "%s: %.*s", what, (int)s.length,
		    (char *)s.value);
		gss_release_buffer(&m, &s);
	} while (ctx != 0);
}

/*
 * A principal to a user.  A client's machine principal, host/name or
 * nfs/name, stands for its root, as the export's -maproot then decides:
 * the state of NFSv4 comes from there with no user behind it.  Whoever
 * has no account here is refused the context: a principal not in the
 * table must not reach an export at all, not even as its anonymous user.
 */
static bool
map_principal(const char *name, size_t len, uint32_t *uid, uint32_t *gid,
    uint32_t *groups, uint32_t *ngroups)
{
	char user[256], *at, *slash;
	struct passwd *pw;
	gid_t gl[GSSD_MAXGROUPS];
	int n, i;

	*ngroups = 0;
	if (len >= sizeof(user))
		return false;
	memcpy(user, name, len);
	user[len] = '\0';
	at = strrchr(user, '@');
	if (at != NULL) {
		if (realm != NULL && strcmp(at + 1, realm) != 0)
			return false;
		*at = '\0';
	}
	slash = strchr(user, '/');
	if (slash != NULL) {
		*slash = '\0';
		if (strcmp(user, "host") == 0 || strcmp(user, "nfs") == 0 ||
		    strcmp(user, "root") == 0) {
			*uid = 0;
			*gid = 0;
			return true;
		}
		return false;
	}
	if ((pw = getpwnam(user)) == NULL)
		return false;
	*uid = pw->pw_uid;
	*gid = pw->pw_gid;
	n = GSSD_MAXGROUPS;
	if (getgrouplist(user, pw->pw_gid, gl, &n) == -1)
		n = GSSD_MAXGROUPS;
	for (i = 0; i < n; i++)
		groups[i] = gl[i];
	*ngroups = n;
	return true;
}

/* The results of RPCSEC_GSS_INIT and CONTINUE_INIT in the kernel's form. */
static void
do_accept(struct buf *a, struct buf *r)
{
	uint32_t hi = get32(a), lo = get32(a), tlen = get32(a), n;
	uint64_t id = (uint64_t)hi << 32 | lo;
	gss_buffer_desc in, out = GSS_C_EMPTY_BUFFER, name = GSS_C_EMPTY_BUFFER;
	gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
	gss_name_t src = GSS_C_NO_NAME;
	OM_uint32 major, minor, m, lifetime = 0;
	void *lp = NULL;
	gss_krb5_lucid_context_v1_t *lc;
	const gss_krb5_lucid_key_t *key;
	struct pending *slot = NULL;
	uint32_t groups[GSSD_MAXGROUPS], uid = 0, gid = 0, ngroups = 0;
	bool mapped;
	size_t i;

	in.length = tlen;
	in.value = __UNCONST(getbytes(a, tlen));
	if (a->b_bad)
		return;
	if (id != 0) {
		for (i = 0; i < GSSD_MAXPENDING; i++)
			if (pending[i].p_id == id)
				slot = &pending[i];
		if (slot == NULL) {
			put32(r, GSS_S_NO_CONTEXT);
			put32(r, 0);
			put32(r, 0);
			put32(r, 0);
			putbytes(r, NULL, 0);
			return;
		}
		ctx = slot->p_ctx;
		slot->p_id = 0;
		slot->p_ctx = GSS_C_NO_CONTEXT;
	}

	major = gss_accept_sec_context(&minor, &ctx, acceptor, &in,
	    GSS_C_NO_CHANNEL_BINDINGS, &src, NULL, &out, NULL, &lifetime,
	    NULL);
	if (GSS_ERROR(major))
		log_gss("gss_accept_sec_context", major, minor);

	if (major == GSS_S_CONTINUE_NEEDED) {
		time_t oldest = 0;

		slot = &pending[0];
		for (i = 0; i < GSSD_MAXPENDING; i++) {
			if (pending[i].p_id == 0) {
				slot = &pending[i];
				break;
			}
			if (oldest == 0 || pending[i].p_when < oldest) {
				oldest = pending[i].p_when;
				slot = &pending[i];
			}
		}
		if (slot->p_id != 0)
			gss_delete_sec_context(&m, &slot->p_ctx,
			    GSS_C_NO_BUFFER);
		id = ++nextid;
		slot->p_id = id;
		slot->p_ctx = ctx;
		slot->p_when = time(NULL);
		put32(r, GSS_CONTINUE);
		put32(r, minor);
		put32(r, (uint32_t)(id >> 32));
		put32(r, (uint32_t)id);
		putbytes(r, out.value, out.length);
		gss_release_buffer(&m, &out);
		return;
	}
	if (major != GSS_S_COMPLETE) {
		if (ctx != GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&m, &ctx, GSS_C_NO_BUFFER);
		gss_release_buffer(&m, &out);
		put32(r, major);
		put32(r, minor);
		put32(r, 0);
		put32(r, 0);
		putbytes(r, NULL, 0);
		return;
	}

	major = gss_display_name(&minor, src, &name, NULL);
	if (major == GSS_S_COMPLETE)
		major = gss_krb5_export_lucid_sec_context(&minor, &ctx, 1, &lp);
	gss_release_name(&m, &src);
	if (major != GSS_S_COMPLETE) {
		log_gss("gss_krb5_export_lucid_sec_context", major, minor);
		if (ctx != GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&m, &ctx, GSS_C_NO_BUFFER);
		gss_release_buffer(&m, &out);
		gss_release_buffer(&m, &name);
		put32(r, GSS_S_FAILURE);
		put32(r, minor);
		put32(r, 0);
		put32(r, 0);
		putbytes(r, NULL, 0);
		return;
	}
	lc = lp;
	if (lc->protocol == 1) {
		key = lc->cfx_kd.have_acceptor_subkey ?
		    &lc->cfx_kd.acceptor_subkey : &lc->cfx_kd.ctx_key;
	} else
		key = &lc->rfc1964_kd.ctx_key;
	mapped = map_principal(name.value, name.length, &uid, &gid, groups,
	    &ngroups);
	syslog(LOG_INFO, "context for %.*s, enctype %u, %s", (int)name.length,
	    (char *)name.value, key->type, mapped ? "mapped" : "not mapped");
	gss_release_buffer(&m, &name);

	if (!mapped) {
		gss_release_buffer(&m, &out);
		gss_krb5_free_lucid_sec_context(&m, lp);
		put32(r, GSS_UNAUTHORIZED);
		put32(r, 0);
		put32(r, 0);
		put32(r, 0);
		putbytes(r, NULL, 0);
		return;
	}

	put32(r, GSS_S_COMPLETE);
	put32(r, minor);
	put32(r, 0);
	put32(r, 0);
	putbytes(r, out.value, out.length);
	gss_release_buffer(&m, &out);
	put32(r, key->type);
	putbytes(r, key->data, key->length);
	put32(r, lc->protocol == 1);
	put32(r, lc->protocol == 1 && lc->cfx_kd.have_acceptor_subkey);
	put32(r, (uint32_t)(lc->send_seq >> 32));
	put32(r, (uint32_t)lc->send_seq);
	put32(r, lifetime == GSS_C_INDEFINITE ? 86400 : lifetime);
	put32(r, uid);
	put32(r, gid);
	put32(r, ngroups);
	for (n = 0; n < ngroups; n++)
		put32(r, groups[n]);
	gss_krb5_free_lucid_sec_context(&m, lp);
}

static bool
read_all(int fd, void *p, size_t len)
{
	char *c = p;
	ssize_t n;

	while (len > 0) {
		n = read(fd, c, len);
		if (n <= 0)
			return false;
		c += n;
		len -= n;
	}
	return true;
}

/* One call, RFC 5531 s9 and s11, and one reply. */
static void
serve(int fd)
{
	static uint8_t in[GSSD_MAXMSG], out[GSSD_MAXMSG];
	struct buf a, r;
	uint32_t mark, len, xid, vlen, proc;

	if (!read_all(fd, &mark, 4))
		return;
	mark = ntohl(mark);
	len = mark & 0x7fffffff;
	if ((mark & 0x80000000U) == 0 || len > sizeof(in) || len < 10 * 4 ||
	    !read_all(fd, in, len))
		return;
	a.b_p = in;
	a.b_off = 0;
	a.b_len = len;
	a.b_bad = false;
	xid = get32(&a);
	(void)get32(&a);	/* CALL */
	(void)get32(&a);	/* 2 */
	if (get32(&a) != GSSD_PROG || get32(&a) != GSSD_VERS)
		return;
	proc = get32(&a);
	(void)get32(&a);
	vlen = get32(&a);
	(void)getbytes(&a, vlen);
	(void)get32(&a);
	vlen = get32(&a);
	(void)getbytes(&a, vlen);
	if (a.b_bad)
		return;

	r.b_p = out;
	r.b_off = 4;
	r.b_len = sizeof(out);
	r.b_bad = false;
	put32(&r, xid);
	put32(&r, RPC_REPLY);
	put32(&r, 0);		/* MSG_ACCEPTED */
	put32(&r, 0);		/* AUTH_NONE */
	put32(&r, 0);
	put32(&r, 0);		/* SUCCESS */
	switch (proc) {
	case GSSD_ACCEPT:
		do_accept(&a, &r);
		break;
	default:
		return;
	}
	if (r.b_bad)
		return;
	mark = htonl(0x80000000U | (uint32_t)(r.b_off - 4));
	memcpy(out, &mark, 4);
	(void)write(fd, out, r.b_off);
	explicit_memset(out, 0, r.b_off);
}

static void
acquire(const char *service)
{
	gss_buffer_desc nb;
	gss_name_t name;
	OM_uint32 major, minor, m;

	/* RFC 2623 s3.1: a GSS_C_NT_HOSTBASED_SERVICE name, nfs@hostname. */
	nb.value = __UNCONST(service);
	nb.length = strlen(service);
	major = gss_import_name(&minor, &nb, GSS_C_NT_HOSTBASED_SERVICE, &name);
	if (major != GSS_S_COMPLETE) {
		log_gss("gss_import_name", major, minor);
		errx(EXIT_FAILURE, "cannot use the name %s", service);
	}
	major = gss_acquire_cred(&minor, name, GSS_C_INDEFINITE,
	    GSS_C_NO_OID_SET, GSS_C_ACCEPT, &acceptor, NULL, NULL);
	gss_release_name(&m, &name);
	if (major != GSS_S_COMPLETE) {
		log_gss("gss_acquire_cred", major, minor);
		errx(EXIT_FAILURE, "no key for %s in the keytab", service);
	}
}

__dead static void
usage(void)
{

	fprintf(stderr, "usage: %s [-d] [-h hostname] "
	    "[-k keytab]\n", getprogname());
	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	struct sockaddr_un sun;
	krb5_context kc;
	char host[MAXHOSTNAMELEN + 1], service[MAXHOSTNAMELEN + 8], *r;
	const char *hostname = NULL;
	int c, ls, s;

	while ((c = getopt(argc, argv, "dh:k:")) != -1) {
		switch (c) {
		case 'd':
			debug = true;
			break;
		case 'h':
			hostname = optarg;
			break;
		case 'k':
			if (setenv("KRB5_KTNAME", optarg, 1) == -1)
				err(EXIT_FAILURE, "setenv");
			break;
		default:
			usage();
		}
	}
	if (argc != optind)
		usage();

	openlog("gssd", LOG_PID | (debug ? LOG_PERROR : 0), LOG_DAEMON);
	if (hostname == NULL) {
		if (gethostname(host, sizeof(host)) == -1)
			err(EXIT_FAILURE, "gethostname");
		host[sizeof(host) - 1] = '\0';
		hostname = host;
	}
	(void)snprintf(service, sizeof(service), "nfs@%s", hostname);
	acquire(service);

	if (krb5_init_context(&kc) == 0) {
		if (krb5_get_default_realm(kc, &r) == 0)
			realm = r;
		krb5_free_context(kc);
	}
	if ((ls = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1)
		err(EXIT_FAILURE, "socket");
	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_LOCAL;
	(void)strlcpy(sun.sun_path, GSSD_PATH, sizeof(sun.sun_path));
	sun.sun_len = SUN_LEN(&sun);
	(void)unlink(GSSD_PATH);
	(void)umask(077);
	if (bind(ls, (struct sockaddr *)&sun, sun.sun_len) == -1)
		err(EXIT_FAILURE, "bind %s", GSSD_PATH);
	if (listen(ls, 64) == -1)
		err(EXIT_FAILURE, "listen");
	(void)signal(SIGPIPE, SIG_IGN);
	if (!debug) {
		if (daemon(0, 0) == -1)
			err(EXIT_FAILURE, "daemon");
		(void)pidfile(NULL);
	}
	for (;;) {
		s = accept(ls, NULL, NULL);
		if (s == -1) {
			if (errno != EINTR)
				syslog(LOG_ERR, "accept: %m");
			continue;
		}
		serve(s);
		(void)close(s);
	}
}
