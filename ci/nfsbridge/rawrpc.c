/*	$NetBSD$	*/

/*
 * Raw calls at the server on 127.0.0.1:2049, for what a client will not
 * send: replays, and calls that are wrong.  Every check prints ok or
 * FAILED, and the exit status counts the latter.
 *   rawrpc tcp|udp DIR [garbage|v2write]
 * DIR is a directory on an exported file system.  Run as root, getfh(2).
 */

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	NFS_PROG	100003		/* RFC 1813 s2.2 */
#define	PROC_GETATTR	1		/* RFC 1813 s3.3.1 */
#define	PROC_READ	6		/* RFC 1813 s3.3.6 */
#define	PROC_V2WRITE	8		/* RFC 1094 s2.2.9 */
#define	PROC_MKDIR	9		/* RFC 1813 s3.3.9 */
#define	NFS3ERR_EXIST	17		/* RFC 1813 s2.6, nfsstat3 */
#define	FATTR3_WORDS	21		/* RFC 1813 s2.5, fattr3 */
#define	BIGREAD		65536		/* above the 60KB of NFS_MAXDGRAMDATA */
#define	DGRAMMAX	(60 * 1024)	/* sys/nfs/nfsproto.h, not from an RFC */
#define	AUTH_NONE_	0		/* RFC 5531 s8.2 */
#define	AUTH_SYS_	1		/* RFC 5531 s8.2 */

static int s, stream, fails, garbage;
static uint32_t rep[32768];

static void
check(const char *what, int ok)
{

	printf("%s: %s\n", what, ok ? "ok" : "FAILED");
	if (!ok)
		fails++;
}

static size_t
put(uint32_t *b, uint32_t xid, uint32_t vers, uint32_t proc, uint32_t flavor)
{
	size_t n = 0;

	b[n++] = htonl(xid);
	b[n++] = htonl(0);		/* CALL, RFC 5531 s9 */
	b[n++] = htonl(2);		/* rpcvers */
	b[n++] = htonl(NFS_PROG);
	b[n++] = htonl(vers);
	b[n++] = htonl(proc);
	b[n++] = htonl(flavor);
	if (flavor == AUTH_SYS_) {
		b[n++] = htonl(5 * 4);	/* authsys_parms, RFC 5531 App. A */
		b[n++] = 0;		/* stamp */
		b[n++] = 0;		/* machinename */
		b[n++] = 0;		/* uid */
		b[n++] = 0;		/* gid */
		b[n++] = 0;		/* gids */
	} else
		b[n++] = 0;
	b[n++] = 0;			/* verf */
	b[n++] = 0;
	return n;
}

/* Returns the words in rep, or -1 with no reply in the time. */
static int
call(uint32_t *b, size_t n)
{
	struct timeval tv = { 3, 0 };
	uint32_t rm;
	ssize_t r;
	size_t got, want;

	(void)setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (stream) {
		rm = htonl(0x80000000U | (uint32_t)(n * 4));	/* 5531 s11 */
		if (write(s, &rm, 4) != 4)
			err(1, "write");
	}
	if (write(s, b, n * 4) != (ssize_t)(n * 4))
		err(1, "write");
	if (!stream) {
		r = read(s, rep, sizeof(rep));
		return r < 0 ? -1 : (int)(r / 4);
	}
	if (read(s, &rm, 4) != 4)
		return -1;
	want = ntohl(rm) & 0x7fffffffU;
	for (got = 0; got < want; got += r)
		if ((r = read(s, (char *)rep + got, want - got)) <= 0)
			return -1;
	return (int)(want / 4);
}

static uint32_t
w(int i)
{

	return ntohl(rep[i]);
}

static size_t
putfh(uint32_t *b, size_t n, const unsigned char *fh, size_t fhlen)
{

	b[n++] = htonl((uint32_t)fhlen);
	memset(&b[n], 0, (fhlen + 3) & ~(size_t)3);
	memcpy(&b[n], fh, fhlen);
	return n + (fhlen + 3) / 4;
}

int
main(int argc, char **argv)
{
	static uint32_t b[1024];
	struct sockaddr_in sin;
	unsigned char fh[64], ffh[64];
	char path[1024];
	size_t fhlen = sizeof(fh), flen, n;
	uint32_t xid = (uint32_t)getpid() << 12, nw;
	char name[16];
	int fd, i, r, rcvbuf = 128 * 1024;

	if (argc < 3)
		errx(1, "usage");
	stream = strcmp(argv[1], "tcp") == 0;
	garbage = argc > 3 && strcmp(argv[3], "garbage") == 0;
	if (getfh(argv[2], fh, &fhlen) == -1)
		err(1, "getfh");
	s = socket(AF_INET, stream ? SOCK_STREAM : SOCK_DGRAM, 0);
	if (s == -1)
		err(1, "socket");
	memset(&sin, 0, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(2049);
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	/* The default of UDP drops a 60KB reply before read() sees it. */
	if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) == -1)
		err(1, "SO_RCVBUF");
	if (connect(s, (void *)&sin, sizeof(sin)) == -1)
		err(1, "connect");

	/* One call and out: the stock server is not expected to survive it. */
	if (argc > 3 && strcmp(argv[3], "v2write") == 0) {
		n = put(b, ++xid, 2, PROC_V2WRITE, AUTH_SYS_);
		r = call(b, n);
		printf("WRITE with no arguments: %d words\n", r);
		return 0;
	}

	/* A MKDIR, sent again with the same xid: only a cache can say OK. */
	snprintf(name, sizeof(name), "d%d", (int)getpid());
	nw = (uint32_t)(strlen(name) + 3) / 4;
	xid++;
	n = put(b, xid, 3, PROC_MKDIR, AUTH_SYS_);
	n = putfh(b, n, fh, fhlen);
	b[n++] = htonl((uint32_t)strlen(name));
	memset(&b[n], 0, nw * 4);
	memcpy(&b[n], name, strlen(name));
	n += nw;
	for (i = 0; i < 6; i++)		/* sattr3, RFC 1813 s2.5: all unset */
		b[n++] = 0;
	r = call(b, n);
	check("MKDIR", r >= 7 && w(0) == xid && w(1) == 1 && w(2) == 0 &&
	    w(5) == 0 && w(6) == 0);
	r = call(b, n);
	check("MKDIR replayed, answered from the cache",
	    r >= 7 && w(0) == xid && w(5) == 0 && w(6) == 0);
	b[0] = htonl(++xid);
	r = call(b, n);
	check("MKDIR with a new xid, EXIST", r >= 7 && w(6) == NFS3ERR_EXIST);

	/* The version range of the program, RFC 5531 s9, mismatch_info. */
	n = put(b, ++xid, 7, 0, AUTH_NONE_);
	r = call(b, n);
	if (r >= 8)
		printf("version 7: accept_stat %u, low %u high %u\n",
		    w(5), w(6), w(7));
	check("version 7, PROG_MISMATCH", r >= 8 && w(5) == 2);

	/* This server takes only AUTH_SYS for a procedure. */
	n = put(b, ++xid, 3, PROC_GETATTR, AUTH_NONE_);
	n = putfh(b, n, fh, fhlen);
	r = call(b, n);
	check("GETATTR with AUTH_NONE, AUTH_ERROR",
	    r >= 4 && w(2) == 1 && w(3) == 1);

	n = put(b, ++xid, 3, 99, AUTH_SYS_);
	r = call(b, n);
	check("procedure 99, PROC_UNAVAIL", r >= 6 && w(5) == 3);

	/* No arguments at all where a handle is due. */
	n = put(b, ++xid, 3, PROC_GETATTR, AUTH_SYS_);
	r = call(b, n);
	printf("GETATTR with no arguments: %d words, accept_stat %u\n", r,
	    r >= 6 ? w(5) : 9999);
	/* The stock server says nothing; the bridge must say GARBAGE_ARGS. */
	if (garbage) {
		check("GETATTR with no arguments, GARBAGE_ARGS",
		    r >= 6 && w(5) == 4);
		n = put(b, ++xid, 2, PROC_V2WRITE, AUTH_SYS_);
		r = call(b, n);
		check("gathered WRITE with no arguments, GARBAGE_ARGS",
		    r >= 6 && w(5) == 4);
		r = call(b, n);
		check("the same again, not dropped as in progress",
		    r >= 6 && w(5) == 4);
	}
	n = put(b, ++xid, 3, 0, AUTH_NONE_);
	r = call(b, n);
	check("NULL still answers afterwards", r >= 6 && w(5) == 0);

	/*
	 * A READ for more than a datagram holds.  FSINFO keeps a client
	 * below this, so only a raw call shows the limit of the procedure.
	 */
	snprintf(path, sizeof(path), "%s/r%d", argv[2], (int)getpid());
	if ((fd = open(path, O_CREAT | O_WRONLY, 0644)) == -1 ||
	    write(fd, rep, BIGREAD) != BIGREAD)
		err(1, "%s", path);
	(void)close(fd);
	flen = sizeof(ffh);
	if (getfh(path, ffh, &flen) == -1)
		err(1, "getfh");
	n = put(b, ++xid, 3, PROC_READ, AUTH_SYS_);
	n = putfh(b, n, ffh, flen);
	b[n++] = 0;			/* offset3 */
	b[n++] = 0;
	b[n++] = htonl(BIGREAD);	/* count3 */
	r = call(b, n);
	/* status, attributes_follow, fattr3, count */
	i = 6 + 2 + FATTR3_WORDS;
	if (r > i)
		printf("READ of %d: count %u\n", BIGREAD, w(i));
	else
		printf("READ of %d: no reply\n", BIGREAD);
	check("READ cut to what the transport carries",
	    r > i && w(6) == 0 && w(i) == (stream ? BIGREAD : DGRAMMAX));
	(void)unlink(path);

	printf("failures: %d\n", fails);
	return fails != 0;
}
