/*	$NetBSD$	*/

/*
 * RPCSEC_GSS with the tokens of RFC 1964, which no Linux client has any
 * more: libgssapi of the base system against the server, NULLPROC under
 * each service.  KRB5_CONFIG chooses the enctype.  desprobe host
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>

static uint8_t buf[65536];
static size_t len;
static int s;

static void p32(uint32_t v) { v = htonl(v); memcpy(buf + len, &v, 4); len += 4; }
static void popq(const void *p, uint32_t n)
{
	p32(n);
	memcpy(buf + len, p, n);
	memset(buf + len + n, 0, (4 - n % 4) % 4);
	len += n + (4 - n % 4) % 4;
}
static uint32_t g32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return ntohl(v); }

static void
xfer(void)
{
	uint32_t m = htonl(0x80000000U | (uint32_t)len), n;
	size_t got = 0;
	ssize_t r;

	if (write(s, &m, 4) != 4 || write(s, buf, len) != (ssize_t)len)
		err(1, "write");
	if (read(s, &m, 4) != 4)
		err(1, "read");
	n = ntohl(m) & 0x7fffffff;
	while (got < n) {
		if ((r = read(s, buf + got, n - got)) <= 0)
			err(1, "read");
		got += r;
	}
	len = got;
}

int
main(int argc, char **argv)
{
	struct sockaddr_in sin;
	gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
	gss_buffer_desc in = GSS_C_EMPTY_BUFFER, out, nm, msg, tok, ve;
	gss_name_t target;
	OM_uint32 maj, min;
	uint8_t handle[64], hdr[256], cred[128];
	uint32_t hlen, seq = 1, svc, vl, stat, nb;
	size_t h, c, o;
	char name[256];

	(void)snprintf(name, sizeof(name), "nfs@%s", argv[1]);
	nm.value = name;
	nm.length = strlen(name);
	gss_import_name(&min, &nm, GSS_C_NT_HOSTBASED_SERVICE, &target);
	maj = gss_init_sec_context(&min, GSS_C_NO_CREDENTIAL, &ctx, target,
	    GSS_KRB5_MECHANISM, GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG |
	    GSS_C_CONF_FLAG, 0, NULL, &in, NULL, &out, NULL, NULL);
	if (GSS_ERROR(maj))
		errx(1, "init %x %x", maj, min);
	s = socket(AF_INET, SOCK_STREAM, 0);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(2049);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (connect(s, (void *)&sin, sizeof(sin)) == -1)
		err(1, "connect");
	len = 0;
	p32(1); p32(0); p32(2); p32(100003); p32(4); p32(0);
	p32(6); p32(20); p32(1); p32(1); p32(0); p32(1); p32(0);
	p32(0); p32(0);
	popq(out.value, out.length);
	xfer();
	if (g32(buf + 8) != 0 || g32(buf + 20 + ((g32(buf + 16) + 3) & ~3U)) != 0)
		errx(1, "INIT refused");
	o = 12 + 8 + ((g32(buf + 16) + 3) & ~3U) + 4;
	hlen = g32(buf + o);
	memcpy(handle, buf + o + 4, hlen);
	o += 4 + hlen;
	printf("major %x\n", g32(buf + o));
	if (g32(buf + o) != 0)
		return 1;
	nb = g32(buf + o + 12);
	in.value = buf + o + 16;
	in.length = nb;
	if (nb != 0) {
		maj = gss_init_sec_context(&min, GSS_C_NO_CREDENTIAL, &ctx,
		    target, GSS_KRB5_MECHANISM, GSS_C_MUTUAL_FLAG |
		    GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG, 0, NULL, &in, NULL,
		    &out, NULL, NULL);
		if (maj != GSS_S_COMPLETE)
			errx(1, "init2 %x %x", maj, min);
	}
	for (svc = 1; svc <= 3; svc++) {
		uint8_t body[64];

		seq++;
		len = 0;
		p32(1); p32(1); p32(seq); p32(svc); p32(hlen);
		memcpy(buf + len, handle, hlen);
		len += hlen;
		c = len;
		memcpy(cred, buf, c);
		len = 0;
		p32(100 + seq); p32(0); p32(2); p32(100003); p32(4); p32(0);
		p32(6); popq(cred, c);
		h = len;
		memcpy(hdr, buf, h);
		msg.value = hdr;
		msg.length = h;
		if (gss_get_mic(&min, ctx, 0, &msg, &tok) != GSS_S_COMPLETE)
			errx(1, "mic");
		p32(6);
		popq(tok.value, tok.length);
		uint32_t n = htonl(seq);
		memcpy(body, &n, 4);
		msg.value = body;
		msg.length = 4;
		if (svc == 2) {
			gss_get_mic(&min, ctx, 0, &msg, &tok);
			popq(body, 4);
			popq(tok.value, tok.length);
		} else if (svc == 3) {
			int conf;

			if (gss_wrap(&min, ctx, 1, 0, &msg, &conf, &tok) !=
			    GSS_S_COMPLETE)
				errx(1, "wrap");
			popq(tok.value, tok.length);
		}
		xfer();
		if (g32(buf + 8) != 0)
			errx(1, "svc %u denied, %u", svc, g32(buf + 16));
		vl = g32(buf + 16);
		msg.value = &n;
		msg.length = 4;
		ve.value = buf + 20;
		ve.length = vl;
		maj = gss_verify_mic(&min, ctx, &msg, &ve, NULL);
		o = 20 + ((vl + 3) & ~3U);
		stat = g32(buf + o);
		printf("svc %u: accept_stat %u, reply MIC %s\n", svc, stat,
		    maj == GSS_S_COMPLETE ? "good" : "bad");
		if (stat != 0 || maj != GSS_S_COMPLETE)
			return 1;
		if (svc == 3) {
			int conf;

			in.value = buf + o + 8;
			in.length = g32(buf + o + 4);
			maj = gss_unwrap(&min, ctx, &in, &out, &conf, NULL);
			if (maj != GSS_S_COMPLETE || !conf || out.length != 4)
				errx(1, "unwrap %x", maj);
			printf("unwrapped the results\n");
		}
	}
	printf("ok\n");
	return 0;
}
