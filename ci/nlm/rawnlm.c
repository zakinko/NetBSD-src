/*	$NetBSD$	*/

/*
 * Two clients of the lock manager, by hand.  Each has an address of its
 * own on lo0, so that the server tells them apart as it would two hosts,
 * and on each runs a port mapper and an NLM of a few lines to take the
 * server's calls.  rawnlm PATH runs the tests on a file in an export,
 * rawnlm -g PATH those of the grace period, just after the server starts.
 *
 * Offsets in each test are its own, and the file is shared.
 */

#include <sys/types.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h>

#include <err.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define	NLM_PROG	100021
#define	SM_PROG		100024
#define	CBPORT		4045

enum { NULLP, TEST, LOCK, CANCEL, UNLOCK, GRANTED, TEST_MSG, LOCK_MSG,
    CANCEL_MSG, UNLOCK_MSG, GRANTED_MSG, TEST_RES, LOCK_RES, CANCEL_RES,
    UNLOCK_RES, GRANTED_RES, SHARE = 20, UNSHARE, NM_LOCK, FREE_ALL };
enum { ST_GRANTED, ST_DENIED, ST_NOLOCKS, ST_BLOCKED, ST_GRACE, ST_DEADLCK,
    ST_ROFS, ST_STALE, ST_FBIG, ST_FAILED };

struct buf {
	uint8_t	b[8192];
	size_t	n;
};

static void
put32(struct buf *b, uint32_t v)
{

	v = htonl(v);
	memcpy(b->b + b->n, &v, 4);
	b->n += 4;
}

static void
put64(struct buf *b, uint64_t v)
{

	put32(b, (uint32_t)(v >> 32));
	put32(b, (uint32_t)v);
}

static void
putobj(struct buf *b, const void *p, size_t len)
{

	put32(b, (uint32_t)len);
	memset(b->b + b->n, 0, (len + 3) & ~3UL);
	memcpy(b->b + b->n, p, len);
	b->n += (len + 3) & ~3UL;
}

static void
putstr(struct buf *b, const char *s)
{

	putobj(b, s, strlen(s));
}

static uint32_t
get32(const uint8_t *p)
{
	uint32_t v;

	memcpy(&v, p, 4);
	return ntohl(v);
}

struct client {
	const char	*c_name;
	const char	*c_ip;
	int		 c_fd;
	/* What its NLM has seen and is to do. */
	pthread_mutex_t	 c_lock;
	int		 c_granted;	/* NLM_GRANTED calls */
	int		 c_tcpgranted;	/* NLM_GRANTED over TCP */
	int		 c_lockres;	/* NLM_LOCK_RES calls */
	uint32_t	 c_lockres_stat;
	uint32_t	 c_lockres_vers;
	uint64_t	 c_goff, c_glen;
	int32_t		 c_gsvid;
	uint32_t	 c_answer;	/* to NLM_GRANTED */
	bool		 c_mute;	/* or nothing */
	bool		 c_tcponly;	/* no UDP NLM at the port mapper */
	int		 c_res[16];	/* calls of NLM_x_RES, by procedure */
	uint32_t	 c_resstat[16];
};

static struct client A = { .c_name = "clienta", .c_ip = "127.0.0.2",
    .c_lock = PTHREAD_MUTEX_INITIALIZER };
static struct client B = { .c_name = "clientb", .c_ip = "127.0.0.3",
    .c_lock = PTHREAD_MUTEX_INITIALIZER };
static struct client C = { .c_name = "clientc", .c_ip = "127.0.0.4",
    .c_lock = PTHREAD_MUTEX_INITIALIZER };
static struct client D = { .c_name = "clientd", .c_ip = "127.0.0.5",
    .c_lock = PTHREAD_MUTEX_INITIALIZER };
static struct sockaddr_in server;
static uint8_t fh[64];
static size_t fhlen;
static uint32_t nextxid = 1000;
static int fails, npass;

static void
check(const char *what, long got, long want)
{

	if (got == want) {
		printf("ok   %s = %ld\n", what, got);
		npass++;
	} else {
		printf("FAIL %s = %ld, wanted %ld\n", what, got, want);
		fails++;
	}
	fflush(stdout);
}

static int
bindto(const char *ip, int port)
{
	struct sockaddr_in sin;
	int s, on = 1;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		err(1, "socket");
	(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	memset(&sin, 0, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(ip);
	sin.sin_port = htons(port);
	if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		err(1, "bind %s:%d", ip, port);
	return s;
}

/*
 * Call and wait.  Returns the accept_stat, or -1 for no reply, -2 for a
 * rejection; *resp is the results in rb.
 */
static int
rpc(const struct client *c, const struct sockaddr_in *to, uint32_t prog,
    uint32_t vers, uint32_t proc, const struct buf *args, struct buf *rb,
    const uint8_t **resp)
{
	struct buf b;
	struct timeval tv = { 3, 0 };
	uint32_t xid = nextxid++;
	const uint8_t *p;
	ssize_t n;
	int i;

	memset(&b, 0, sizeof(b));
	put32(&b, xid);
	put32(&b, 0);
	put32(&b, 2);
	put32(&b, prog);
	put32(&b, vers);
	put32(&b, proc);
	put32(&b, 1);		/* AUTH_SYS */
	put32(&b, 20);
	for (i = 0; i < 7; i++)	/* stamp, "", uid, gid, 0 gids, verifier */
		put32(&b, 0);
	if (args != NULL) {
		memcpy(b.b + b.n, args->b, args->n);
		b.n += args->n;
	}
	(void)setsockopt(c->c_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (sendto(c->c_fd, b.b, b.n, 0, (const struct sockaddr *)to,
	    sizeof(*to)) == -1)
		err(1, "sendto");
	for (;;) {
		n = recv(c->c_fd, rb->b, sizeof(rb->b), 0);
		if (n == -1)
			return -1;
		rb->n = n;
		if (n >= 24 && get32(rb->b) == xid)
			break;
	}
	p = rb->b + 8;
	if (get32(p) != 0)
		return -2;
	p += 4;
	p += 8 + ((get32(p + 4) + 3) & ~3U);
	if (resp != NULL)
		*resp = p + 4;
	return (int)get32(p);
}

static void
alock(struct buf *b, const struct client *c, uint32_t vers, int svid,
    uint64_t off, uint64_t len)
{

	putstr(b, c->c_name);
	putobj(b, fh, vers == 4 ? fhlen : 32);
	putstr(b, "oh");
	put32(b, svid);
	if (vers == 4) {
		put64(b, off);
		put64(b, len);
	} else {
		put32(b, (uint32_t)off);
		put32(b, (uint32_t)len);
	}
}

static long
statres(int r, const uint8_t *p)
{

	if (r != 0)
		return r - 100;
	/* the cookie, then nlm_res */
	return get32(p + 4 + ((get32(p) + 3) & ~3U));
}

static long
lockv(const struct client *c, uint32_t vers, uint32_t proc, int svid,
    uint64_t off, uint64_t len, bool ex, bool block, bool reclaim, int state)
{
	struct buf a, r;
	const uint8_t *p = NULL;
	int rc;

	memset(&a, 0, sizeof(a));
	putobj(&a, "ck", 2);
	put32(&a, block);
	put32(&a, ex);
	alock(&a, c, vers, svid, off, len);
	put32(&a, reclaim);
	put32(&a, state);
	rc = rpc(c, &server, NLM_PROG, vers, proc, &a, &r, &p);
	return statres(rc, p);
}

static long
lock(const struct client *c, int svid, uint64_t off, uint64_t len, bool ex,
    bool block)
{

	return lockv(c, 4, LOCK, svid, off, len, ex, block, false, 3);
}

static long
unlockv(const struct client *c, uint32_t vers, int svid, uint64_t off,
    uint64_t len)
{
	struct buf a, r;
	const uint8_t *p = NULL;
	int rc;

	memset(&a, 0, sizeof(a));
	putobj(&a, "ck", 2);
	alock(&a, c, vers, svid, off, len);
	rc = rpc(c, &server, NLM_PROG, vers, UNLOCK, &a, &r, &p);
	return statres(rc, p);
}

static long
unlock(const struct client *c, int svid, uint64_t off, uint64_t len)
{

	return unlockv(c, 4, svid, off, len);
}

static long
cancel(const struct client *c, int svid, uint64_t off, uint64_t len, bool ex)
{
	struct buf a, r;
	const uint8_t *p = NULL;
	int rc;

	memset(&a, 0, sizeof(a));
	putobj(&a, "ck", 2);
	put32(&a, 1);
	put32(&a, ex);
	alock(&a, c, 4, svid, off, len);
	rc = rpc(c, &server, NLM_PROG, 4, CANCEL, &a, &r, &p);
	return statres(rc, p);
}

struct holder {
	long	h_stat;
	long	h_ex, h_svid;
	uint64_t h_off, h_len;
};

static struct holder
testv(const struct client *c, uint32_t vers, int svid, uint64_t off,
    uint64_t len, bool ex)
{
	struct buf a, r;
	struct holder h;
	const uint8_t *p = NULL;
	int rc;

	memset(&h, 0, sizeof(h));
	memset(&a, 0, sizeof(a));
	putobj(&a, "ck", 2);
	put32(&a, ex);
	alock(&a, c, vers, svid, off, len);
	rc = rpc(c, &server, NLM_PROG, vers, TEST, &a, &r, &p);
	h.h_stat = statres(rc, p);
	if (h.h_stat != ST_DENIED)
		return h;
	p += 8 + ((get32(p) + 3) & ~3U);
	h.h_ex = get32(p);
	h.h_svid = (int32_t)get32(p + 4);
	p += 12 + ((get32(p + 8) + 3) & ~3U);
	if (vers == 4) {
		h.h_off = (uint64_t)get32(p) << 32 | get32(p + 4);
		h.h_len = (uint64_t)get32(p + 8) << 32 | get32(p + 12);
	} else {
		h.h_off = get32(p);
		h.h_len = get32(p + 4);
	}
	return h;
}

static long
sharev(const struct client *c, uint32_t vers, uint32_t proc, const char *oh,
    int mode, int access, bool reclaim)
{
	struct buf a, r;
	const uint8_t *p = NULL;
	int rc;

	memset(&a, 0, sizeof(a));
	putobj(&a, "ck", 2);
	putstr(&a, c->c_name);
	putobj(&a, fh, vers == 4 ? fhlen : 32);
	putstr(&a, oh);
	put32(&a, mode);
	put32(&a, access);
	put32(&a, reclaim);
	rc = rpc(c, &server, NLM_PROG, vers, proc, &a, &r, &p);
	return statres(rc, p);
}

/* From `from`, naming `name`. */
static long
free_all(const struct client *from, const char *name)
{
	struct buf a, r;

	memset(&a, 0, sizeof(a));
	putstr(&a, name);
	put32(&a, 0);
	return rpc(from, &server, NLM_PROG, 4, FREE_ALL, &a, &r, NULL);
}

static int
counter(const char *name)
{
	int v = -1;
	size_t len = sizeof(v);
	char full[64];

	snprintf(full, sizeof(full), "vfs.nlm.%s", name);
	if (sysctlbyname(full, &v, &len, NULL, 0) == -1)
		err(1, "%s", full);
	return v;
}

/* A client's port mapper and NLM, on an address of its own. */
struct listener {
	struct client	*l_c;
	int		 l_port;
};

static void *
listener(void *arg)
{
	struct listener *l = arg;
	struct client *c = l->l_c;
	struct sockaddr_in from;
	struct buf b, r;
	socklen_t fl;
	const uint8_t *p;
	ssize_t n;
	uint32_t proc, ans;
	int s = bindto(c->c_ip, l->l_port);

	for (;;) {
		fl = sizeof(from);
		n = recvfrom(s, b.b, sizeof(b.b), 0,
		    (struct sockaddr *)&from, &fl);
		if (n < 40)
			continue;
		proc = get32(b.b + 20);
		memset(&r, 0, sizeof(r));
		put32(&r, get32(b.b));
		put32(&r, 1);
		put32(&r, 0);
		put32(&r, 0);
		put32(&r, 0);
		put32(&r, 0);
		if (l->l_port == 111) {
			/* the map is past cred and verifier, both empty-ish */
			p = b.b + 24;
			p += 8 + ((get32(p + 4) + 3) & ~3U);
			p += 8 + ((get32(p + 4) + 3) & ~3U);
			put32(&r, c->c_tcponly && get32(p + 8) == IPPROTO_UDP ?
			    0 : CBPORT);
		} else {
			p = b.b + 24;			/* cred */
			p += 8 + ((get32(p + 4) + 3) & ~3U);
			p += 8 + ((get32(p + 4) + 3) & ~3U);	/* verf */
			pthread_mutex_lock(&c->c_lock);
			if (proc >= TEST_RES && proc <= GRANTED_RES) {
				c->c_res[proc]++;
				c->c_resstat[proc] = get32(p + 4 +
				    ((get32(p) + 3) & ~3U));
			}
			if (proc == LOCK_RES) {
				c->c_lockres++;
				c->c_lockres_vers = get32(b.b + 16);
				p += 4 + ((get32(p) + 3) & ~3U);
				c->c_lockres_stat = get32(p);
				pthread_mutex_unlock(&c->c_lock);
				continue;
			}
			if (proc != GRANTED || c->c_tcponly) {
				pthread_mutex_unlock(&c->c_lock);
				continue;
			}
			c->c_granted++;
			ans = c->c_answer;
			if (c->c_mute) {
				pthread_mutex_unlock(&c->c_lock);
				continue;
			}
			/* nlm_testargs: cookie, exclusive, alock */
			putobj(&r, p + 4, get32(p));
			p += 4 + ((get32(p) + 3) & ~3U);
			p += 4;
			p += 4 + ((get32(p) + 3) & ~3U);	/* name */
			p += 4 + ((get32(p) + 3) & ~3U);	/* fh */
			p += 4 + ((get32(p) + 3) & ~3U);	/* oh */
			c->c_gsvid = (int32_t)get32(p);
			c->c_goff = (uint64_t)get32(p + 4) << 32 | get32(p + 8);
			c->c_glen = (uint64_t)get32(p + 12) << 32 |
			    get32(p + 16);
			pthread_mutex_unlock(&c->c_lock);
			put32(&r, ans);
		}
		(void)sendto(s, r.b, r.n, 0, (struct sockaddr *)&from, fl);
	}
	return NULL;
}

/* The client's NLM over TCP, one NLM_GRANTED to a connection. */
static void *
tcplistener(void *arg)
{
	struct client *c = arg;
	struct sockaddr_in sin;
	struct buf b, r;
	const uint8_t *p;
	ssize_t n;
	size_t have;
	uint32_t rm;
	int ls, s, on = 1;

	if ((ls = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		err(1, "socket");
	(void)setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	memset(&sin, 0, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(c->c_ip);
	sin.sin_port = htons(CBPORT);
	if (bind(ls, (struct sockaddr *)&sin, sizeof(sin)) == -1 ||
	    listen(ls, 4) == -1)
		err(1, "tcp listener");
	for (;;) {
		if ((s = accept(ls, NULL, NULL)) == -1)
			continue;
		have = 0;
		while (have < 44 + 4 ||
		    have < 4 + (get32(b.b) & 0x7fffffff)) {
			n = read(s, b.b + have, sizeof(b.b) - have);
			if (n <= 0)
				break;
			have += (size_t)n;
		}
		if (have > 48) {
			pthread_mutex_lock(&c->c_lock);
			c->c_tcpgranted++;
			pthread_mutex_unlock(&c->c_lock);
			memset(&r, 0, sizeof(r));
			put32(&r, 0);		/* the record mark */
			put32(&r, get32(b.b + 4));
			put32(&r, 1);
			put32(&r, 0);
			put32(&r, 0);
			put32(&r, 0);
			put32(&r, 0);
			p = b.b + 4 + 24;
			p += 8 + ((get32(p + 4) + 3) & ~3U);
			p += 8 + ((get32(p + 4) + 3) & ~3U);
			putobj(&r, p + 4, get32(p));
			put32(&r, ST_GRANTED);
			rm = htonl(0x80000000U | (uint32_t)(r.n - 4));
			memcpy(r.b, &rm, 4);
			(void)write(s, r.b, r.n);
		}
		close(s);
	}
	return NULL;
}

static void
listen_on(struct client *c)
{
	static struct listener ls[8];
	static int n;
	pthread_t t;

	ls[n].l_c = c;
	ls[n].l_port = 111;
	pthread_create(&t, NULL, listener, &ls[n++]);
	ls[n].l_c = c;
	ls[n].l_port = CBPORT;
	pthread_create(&t, NULL, listener, &ls[n++]);
	pthread_create(&t, NULL, tcplistener, c);
}

static int
waitfor(int *p, const struct client *c, int want, int secs)
{
	int v = 0, i;

	for (i = 0; i < secs * 10; i++) {
		pthread_mutex_lock(__UNCONST(&c->c_lock));
		v = *p;
		pthread_mutex_unlock(__UNCONST(&c->c_lock));
		if (v >= want)
			return v;
		usleep(100000);
	}
	return v;
}

static long
local_try(const char *path, off_t off, off_t len, int type)
{
	struct flock fl;
	pid_t pid;
	int fd, st;

	if ((pid = fork()) == 0) {
		fd = open(path, O_RDWR);
		memset(&fl, 0, sizeof(fl));
		fl.l_whence = SEEK_SET;
		fl.l_start = off;
		fl.l_len = len;
		fl.l_type = type;
		_exit(fcntl(fd, F_SETLK, &fl) == -1 ? 1 : 0);
	}
	(void)waitpid(pid, &st, 0);
	return WEXITSTATUS(st);
}

static void
t_null(void)
{
	static const uint32_t v[] = { 1, 3, 4 };
	struct buf r;
	const uint8_t *p;
	size_t i;

	puts("# NULL, and what versions there are");
	for (i = 0; i < 3; i++)
		check("NULL", rpc(&A, &server, NLM_PROG, v[i], NULLP, NULL, &r,
		    NULL), 0);
	check("version 2 is PROG_MISMATCH",
	    rpc(&A, &server, NLM_PROG, 2, NULLP, NULL, &r, &p), 2);
	check("  low", get32(p), 0);
	check("  high", get32(p + 4), 4);
	check("SHARE in version 1 is PROC_UNAVAIL",
	    rpc(&A, &server, NLM_PROG, 1, SHARE, NULL, &r, NULL), 3);
	check("procedure 17 is PROC_UNAVAIL",
	    rpc(&A, &server, NLM_PROG, 4, 17, NULL, &r, NULL), 3);
	check("short arguments are GARBAGE_ARGS",
	    rpc(&A, &server, NLM_PROG, 4, LOCK, NULL, &r, NULL), 4);
}

static void
t_ranges(void)
{
	struct holder h;

	puts("# ranges cross, audit item 6");
	check("A ex 0+10", lock(&A, 1, 0, 10, true, false), ST_GRANTED);
	check("B ex 5+5 meets it", lock(&B, 1, 5, 5, true, false), ST_DENIED);
	check("B ex 10+10 does not", lock(&B, 1, 10, 10, true, false),
	    ST_GRANTED);
	h = testv(&B, 4, 1, 0, 1, true);
	check("TEST sees A", h.h_stat, ST_DENIED);
	check("  svid", h.h_svid, 1);
	check("  exclusive", h.h_ex, 1);
	check("  offset", (long)h.h_off, 0);
	check("  length", (long)h.h_len, 10);
	check("TEST by the holder is free", testv(&A, 4, 1, 0, 10, true).h_stat,
	    ST_GRANTED);
	check("another svid of A meets it", lock(&A, 2, 0, 1, true, false),
	    ST_DENIED);
	unlock(&A, 1, 0, 10);
	unlock(&B, 1, 10, 10);

	puts("# shared with shared");
	check("A sh 100+10", lock(&A, 1, 100, 10, false, false), ST_GRANTED);
	check("B sh 105+10", lock(&B, 1, 105, 10, false, false), ST_GRANTED);
	check("B ex 100+1 meets A", lock(&B, 1, 100, 1, true, false),
	    ST_DENIED);
	check("TEST sh passes", testv(&B, 4, 2, 100, 10, false).h_stat,
	    ST_GRANTED);
	unlock(&A, 1, 100, 10);
	unlock(&B, 1, 105, 10);

	puts("# the same owner splits, audit item 6, UNLOCK");
	check("A ex 200+100", lock(&A, 1, 200, 100, true, false), ST_GRANTED);
	check("A unlocks 240+20", unlock(&A, 1, 240, 20), ST_GRANTED);
	check("B has the hole", lock(&B, 1, 240, 20, true, false), ST_GRANTED);
	check("not to the left", lock(&B, 1, 230, 10, true, false), ST_DENIED);
	check("nor to the right", lock(&B, 1, 260, 10, true, false), ST_DENIED);
	unlock(&B, 1, 240, 20);
	check("A takes it back and it joins", lock(&A, 1, 240, 20, true, false),
	    ST_GRANTED);
	h = testv(&B, 4, 1, 250, 1, true);
	check("  TEST reports the whole", (long)h.h_len, 100);
	unlock(&A, 1, 200, 100);

	puts("# the same owner changes a type");
	check("A ex 300+10", lock(&A, 1, 300, 10, true, false), ST_GRANTED);
	check("A sh 300+5", lock(&A, 1, 300, 5, false, false), ST_GRANTED);
	check("B sh 300+5", lock(&B, 1, 300, 5, false, false), ST_GRANTED);
	check("B sh 305+5 still ex", lock(&B, 1, 305, 5, false, false),
	    ST_DENIED);
	unlock(&A, 1, 300, 10);
	unlock(&B, 1, 300, 5);

	puts("# to the end of the file");
	check("A ex 1000+EOF", lock(&A, 1, 1000, 0, true, false), ST_GRANTED);
	check("B ex 1ULL<<40", lock(&B, 1, 1ULL << 40, 1, true, false),
	    ST_DENIED);
	h = testv(&B, 4, 1, 1000, 1, true);
	check("  length 0", (long)h.h_len, 0);
	unlock(&A, 1, 1000, 0);
	check("offset 2^63 is FBIG", lock(&A, 1, 1ULL << 63, 1, true, false),
	    ST_FBIG);
	check("past 2^63 is FBIG", lock(&A, 1, (1ULL << 63) - 1, 2, true, false),
	    ST_FBIG);

	puts("# a handle that is not one");
	memset(fh, 0xa5, 12);
	check("bad handle is STALE_FH", lock(&A, 1, 0, 1, true, false),
	    ST_STALE);
}

static void
t_v13(void)
{
	static const uint32_t vs[] = { 1, 3 };
	struct holder h;
	size_t i;
	uint32_t v;

	for (i = 0; i < 2; i++) {
		v = vs[i];
		printf("# version %u, 32 bits\n", v);
		check("A ex", lockv(&A, v, LOCK, 1, 2000, 10, true, false,
		    false, 3), ST_GRANTED);
		check("B ex", lockv(&B, v, LOCK, 1, 2005, 1, true, false,
		    false, 3), ST_DENIED);
		h = testv(&B, v, 1, 2005, 1, true);
		check("TEST", h.h_stat, ST_DENIED);
		check("  offset", (long)h.h_off, 2000);
		check("  length", (long)h.h_len, 10);
		check("UNLOCK", unlockv(&A, v, 1, 2000, 10), ST_GRANTED);
		check("B ex", lockv(&B, v, LOCK, 1, 2005, 1, true, false,
		    false, 3), ST_GRANTED);
		check("UNLOCK", unlockv(&B, v, 1, 2005, 1), ST_GRANTED);
	}
	puts("# a lock version 3 cannot name, past 2^32");
	check("A v4 ex", lock(&A, 1, 1ULL << 33, 10, true, false), ST_GRANTED);
	check("B v4 meets it", lock(&B, 1, (1ULL << 33) + 1, 1, true, false),
	    ST_DENIED);
	h = testv(&B, 3, 1, 3000, 0, true);
	check("v3 TEST to EOF meets it", h.h_stat, ST_DENIED);
	check("  offset is clamped", (long)h.h_off, 0xffffffffL);
	unlock(&A, 1, 1ULL << 33, 10);
}

static void
t_cancel(void)
{

	puts("# CANCEL leaves what is held, audit item 6");
	check("A ex 400+10", lock(&A, 1, 400, 10, true, false), ST_GRANTED);
	check("CANCEL has nothing to stop", cancel(&A, 1, 400, 10, true),
	    ST_DENIED);
	check("B still meets it", lock(&B, 1, 400, 10, true, false), ST_DENIED);

	puts("# CANCEL stops what is queued");
	check("B blocks", lock(&B, 1, 400, 10, true, true), ST_BLOCKED);
	check("  nwaiters", counter("nwaiters"), 1);
	check("B repeats it", lock(&B, 1, 400, 10, true, true), ST_BLOCKED);
	check("  nwaiters", counter("nwaiters"), 1);
	check("a CANCEL with another range misses", cancel(&B, 1, 400, 9, true),
	    ST_DENIED);
	check("a CANCEL of another type misses", cancel(&B, 1, 400, 10, false),
	    ST_DENIED);
	check("CANCEL", cancel(&B, 1, 400, 10, true), ST_GRANTED);
	check("  nwaiters", counter("nwaiters"), 0);
	B.c_granted = 0;
	check("A unlocks", unlock(&A, 1, 400, 10), ST_GRANTED);
	sleep(2);
	check("no NLM_GRANTED came", B.c_granted, 0);
	check("B gets it by asking", lock(&B, 1, 400, 10, true, false),
	    ST_GRANTED);
	unlock(&B, 1, 400, 10);
}

static void
t_granted(void)
{
	time_t t0;
	int first;

	puts("# blocking, and the callback");
	B.c_granted = 0;
	B.c_answer = ST_GRANTED;
	check("A ex 600+10", lock(&A, 1, 600, 10, true, false), ST_GRANTED);
	check("B blocks", lock(&B, 7, 600, 10, true, true), ST_BLOCKED);
	t0 = time(NULL);
	check("A unlocks", unlock(&A, 1, 600, 10), ST_GRANTED);
	check("NLM_GRANTED came", waitfor(&B.c_granted, &B, 1, 5), 1);
	printf("     after %lld s\n", (long long)(time(NULL) - t0));
	check("  svid", B.c_gsvid, 7);
	check("  offset", (long)B.c_goff, 600);
	check("  length", (long)B.c_glen, 10);
	check("B has it now", lock(&A, 1, 600, 10, true, false), ST_DENIED);
	check("B unlocks", unlock(&B, 7, 600, 10), ST_GRANTED);
	sleep(1);
	check("  nwaiters", counter("nwaiters"), 0);

	puts("# a client that says no gives the lock back");
	B.c_granted = 0;
	B.c_answer = ST_DENIED;
	check("A ex 620+10", lock(&A, 1, 620, 10, true, false), ST_GRANTED);
	check("B blocks", lock(&B, 7, 620, 10, true, true), ST_BLOCKED);
	check("A unlocks", unlock(&A, 1, 620, 10), ST_GRANTED);
	check("NLM_GRANTED came", waitfor(&B.c_granted, &B, 1, 5), 1);
	sleep(1);
	check("A gets it", lock(&A, 1, 620, 10, true, false), ST_GRANTED);
	unlock(&A, 1, 620, 10);
	B.c_answer = ST_GRANTED;

	puts("# NLM_GRANTED not answered is sent again; LOCK ends it");
	B.c_granted = 0;
	B.c_mute = true;
	check("A ex 640+10", lock(&A, 1, 640, 10, true, false), ST_GRANTED);
	check("B blocks", lock(&B, 7, 640, 10, true, true), ST_BLOCKED);
	check("A unlocks", unlock(&A, 1, 640, 10), ST_GRANTED);
	check("two calls", waitfor(&B.c_granted, &B, 2, 20) >= 2, 1);
	check("B asks again and has it", lock(&B, 7, 640, 10, true, true),
	    ST_GRANTED);
	B.c_mute = false;
	sleep(6);
	check("  nwaiters", counter("nwaiters"), 0);
	check("B still has it", lock(&A, 1, 640, 10, true, false), ST_DENIED);
	unlock(&B, 7, 640, 10);

	puts("# two waiting: lockf wakes both, and one wins");
	A.c_granted = B.c_granted = 0;
	check("A ex 660+10", lock(&A, 1, 660, 10, true, false), ST_GRANTED);
	check("B 7 blocks", lock(&B, 7, 660, 10, true, true), ST_BLOCKED);
	usleep(200000);
	check("B 8 blocks", lock(&B, 8, 660, 10, true, true), ST_BLOCKED);
	usleep(200000);
	check("A unlocks", unlock(&A, 1, 660, 10), ST_GRANTED);
	check("one is called", waitfor(&B.c_granted, &B, 1, 5), 1);
	first = B.c_gsvid;
	check("  it unlocks", unlock(&B, first, 660, 10), ST_GRANTED);
	check("the other is called", waitfor(&B.c_granted, &B, 2, 5), 2);
	check("  and it is the other", B.c_gsvid, 15 - first);
	unlock(&B, 15 - first, 660, 10);
}

static void
t_deadlock(void)
{

	puts("# NLM4_DEADLCK, RFC 1813 s6.1.3");
	check("A ex 1200+1", lock(&A, 1, 1200, 1, true, false), ST_GRANTED);
	check("B ex 1210+1", lock(&B, 1, 1210, 1, true, false), ST_GRANTED);
	check("A blocks on B", lock(&A, 1, 1210, 1, true, true), ST_BLOCKED);
	check("B on A closes the cycle", lock(&B, 1, 1200, 1, true, true),
	    ST_DEADLCK);
	check("  in version 3 it is LCK_DENIED", lockv(&B, 3, LOCK, 1, 1200, 1,
	    true, true, false, 3), ST_DENIED);
	check("B 2 on A does not", lock(&B, 2, 1200, 1, true, true),
	    ST_BLOCKED);
	check("cancel B 2", cancel(&B, 2, 1200, 1, true), ST_GRANTED);
	check("cancel A", cancel(&A, 1, 1210, 1, true), ST_GRANTED);
	unlock(&A, 1, 1200, 1);
	unlock(&B, 1, 1210, 1);

	puts("# a cycle of three");
	check("A ex 1220+1", lock(&A, 1, 1220, 1, true, false), ST_GRANTED);
	check("B ex 1230+1", lock(&B, 1, 1230, 1, true, false), ST_GRANTED);
	check("A 2 ex 1240+1", lock(&A, 2, 1240, 1, true, false), ST_GRANTED);
	check("A waits on B", lock(&A, 1, 1230, 1, true, true), ST_BLOCKED);
	check("B waits on A 2", lock(&B, 1, 1240, 1, true, true), ST_BLOCKED);
	check("A 2 on A closes it", lock(&A, 2, 1220, 1, true, true),
	    ST_DEADLCK);
	cancel(&A, 1, 1230, 1, true);
	cancel(&B, 1, 1240, 1, true);
	unlock(&A, 1, 1220, 1);
	unlock(&B, 1, 1230, 1);
	unlock(&A, 2, 1240, 1);
}

static void
t_tcp(void)
{

	puts("# NLM_GRANTED over TCP, to a client with no UDP NLM");
	B.c_tcponly = true;
	B.c_tcpgranted = B.c_granted = 0;
	check("A ex 1300+1", lock(&A, 1, 1300, 1, true, false), ST_GRANTED);
	check("B blocks", lock(&B, 7, 1300, 1, true, true), ST_BLOCKED);
	check("A unlocks", unlock(&A, 1, 1300, 1), ST_GRANTED);
	check("it came by TCP", waitfor(&B.c_tcpgranted, &B, 1, 8), 1);
	check("  nwaiters", (sleep(1), counter("nwaiters")), 0);
	check("B has it", lock(&A, 1, 1300, 1, true, false), ST_DENIED);
	unlock(&B, 7, 1300, 1);
	B.c_tcponly = false;
}

/* A _MSG call, and the proc + 10 it brings. */
static void
msg(const char *what, struct client *c, const struct client *to,
    uint32_t proc, const struct buf *a, uint32_t want)
{
	struct buf r;
	int *n = &c->c_res[proc + 5];

	(void)to;
	*n = 0;
	(void)rpc(c, &server, NLM_PROG, 4, proc, a, &r, NULL);
	check(what, waitfor(n, c, 1, 5), 1);
	check("  status", c->c_resstat[proc + 5], want);
}

static void
t_msgs(void)
{
	struct buf a;

	puts("# the rest of the _MSG procedures");
	check("A ex 1400+1", lock(&A, 1, 1400, 1, true, false), ST_GRANTED);
	memset(&a, 0, sizeof(a));
	putobj(&a, "ck", 2);
	put32(&a, 1);
	alock(&a, &B, 4, 1, 1400, 1);
	msg("TEST_MSG, TEST_RES", &B, NULL, TEST_MSG, &a, ST_DENIED);
	check("B blocks", lock(&B, 1, 1400, 1, true, true), ST_BLOCKED);
	memset(&a, 0, sizeof(a));
	putobj(&a, "ck", 2);
	put32(&a, 1);
	put32(&a, 1);
	alock(&a, &B, 4, 1, 1400, 1);
	msg("CANCEL_MSG, CANCEL_RES", &B, NULL, CANCEL_MSG, &a, ST_GRANTED);
	check("  nwaiters", counter("nwaiters"), 0);
	memset(&a, 0, sizeof(a));
	putobj(&a, "ck", 2);
	alock(&a, &A, 4, 1, 1400, 1);
	msg("UNLOCK_MSG, UNLOCK_RES", &A, NULL, UNLOCK_MSG, &a, ST_GRANTED);
	check("free", lock(&B, 1, 1400, 1, true, false), ST_GRANTED);
	unlock(&B, 1, 1400, 1);
	memset(&a, 0, sizeof(a));
	putobj(&a, "ck", 2);
	put32(&a, 1);
	alock(&a, &A, 4, 1, 1400, 1);
	msg("GRANTED_MSG with nothing waiting", &A, NULL, GRANTED_MSG, &a,
	    ST_DENIED);
}

/* sysctl vfs.nlm.monitor_required */
static void
required(int v)
{

	if (sysctlbyname("vfs.nlm.monitor_required", NULL, NULL, &v,
	    sizeof(v)) == -1)
		err(1, "monitor_required");
}

/*
 * audit T19.  rpc.statd is stopped by the caller, and C and D are
 * addresses it has never been asked about, so SM_MON really goes out.
 */
static void
t_nostatd(void)
{
	struct timeval t0, t1;
	long ms;

	puts("# rpc.statd down: LOCK refused, audit T19");
	gettimeofday(&t0, NULL);
	check("C LOCK", lock(&C, 1, 1500, 1, true, false), ST_NOLOCKS);
	gettimeofday(&t1, NULL);
	ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_usec - t0.tv_usec) / 1000;
	printf("     took %ld ms\n", ms);
	check("  in a blocking one too", lock(&C, 1, 1500, 1, true, true),
	    ST_NOLOCKS);
	check("  nholds", counter("nholds"), 0);
	check("NM_LOCK is not monitored", lockv(&C, 4, NM_LOCK, 2, 1500, 1,
	    true, false, false, 0), ST_GRANTED);
	unlock(&C, 2, 1500, 1);
	puts("# with vfs.nlm.monitor_required=0");
	required(0);
	check("D LOCK passes", lock(&D, 1, 1510, 1, true, false), ST_GRANTED);
	unlock(&D, 1, 1510, 1);
	required(1);
}

/* It is back: the same host, which was not marked monitored, asks again. */
static void
t_statdback(void)
{
	long st = -1;
	int i;

	puts("# rpc.statd back");
	for (i = 0; i < 30; i++) {
		st = lock(&C, 1, 1500, 1, true, false);
		if (st == ST_GRANTED)
			break;
		sleep(1);
	}
	printf("     after %d tries\n", i + 1);
	check("C LOCK", st, ST_GRANTED);
	unlock(&C, 1, 1500, 1);
}

static void
t_msg(void)
{
	struct buf a, r;

	puts("# NLM_LOCK_MSG, and NLM_LOCK_RES comes as a call");
	A.c_lockres = 0;
	memset(&a, 0, sizeof(a));
	putobj(&a, "ck", 2);
	put32(&a, 0);
	put32(&a, 1);
	alock(&a, &A, 4, 1, 680, 10);
	put32(&a, 0);
	put32(&a, 3);
	check("no RPC reply", rpc(&A, &server, NLM_PROG, 4, LOCK_MSG, &a, &r,
	    NULL), -1);
	check("LOCK_RES came", waitfor(&A.c_lockres, &A, 1, 5), 1);
	check("  granted", A.c_lockres_stat, ST_GRANTED);
	check("  version", A.c_lockres_vers, 4);
	check("B meets it", lock(&B, 1, 680, 10, true, false), ST_DENIED);
	unlock(&A, 1, 680, 10);

	puts("# version 1 right after 4 gets a version 1 call, audit T12");
	A.c_lockres = 0;
	memset(&a, 0, sizeof(a));
	putobj(&a, "ck", 2);
	put32(&a, 0);
	put32(&a, 1);
	alock(&a, &A, 1, 1, 680, 10);
	put32(&a, 0);
	put32(&a, 3);
	(void)rpc(&A, &server, NLM_PROG, 1, LOCK_MSG, &a, &r, NULL);
	check("LOCK_RES came", waitfor(&A.c_lockres, &A, 1, 5), 1);
	check("  version", A.c_lockres_vers, 1);
	unlockv(&A, 1, 1, 680, 10);
}

static void
t_share(void)
{

	puts("# SHARE, audit item 7");
	check("A R deny W", sharev(&A, 4, SHARE, "a", 2, 1, false), ST_GRANTED);
	check("  nshares", counter("nshares"), 1);
	check("B W is denied", sharev(&B, 4, SHARE, "b", 0, 2, false),
	    ST_DENIED);
	check("B R deny R meets A's access", sharev(&B, 4, SHARE, "b", 1, 1,
	    false), ST_DENIED);
	check("B R deny none passes", sharev(&B, 4, SHARE, "b", 0, 1, false),
	    ST_GRANTED);
	check("A deny RW meets B's read", sharev(&A, 4, SHARE, "a", 3, 1,
	    false), ST_DENIED);
	check("A's other owner meets B too", sharev(&A, 4, SHARE, "a2", 1, 1,
	    false), ST_DENIED);
	check("B UNSHARE", sharev(&B, 4, UNSHARE, "b", 0, 1, false),
	    ST_GRANTED);
	check("A UNSHARE", sharev(&A, 4, UNSHARE, "a", 2, 1, false),
	    ST_GRANTED);
	check("  nshares", counter("nshares"), 0);
	check("B W passes", sharev(&B, 3, SHARE, "b", 0, 2, false), ST_GRANTED);
	check("v3 A R deny W denied", sharev(&A, 3, SHARE, "a", 2, 1, false),
	    ST_DENIED);
	check("v3 B UNSHARE", sharev(&B, 3, UNSHARE, "b", 0, 2, false),
	    ST_GRANTED);
	check("UNSHARE of nothing is GRANTED", sharev(&B, 4, UNSHARE, "z", 0, 2,
	    false), ST_GRANTED);
}

static void
t_free(void)
{

	puts("# NM_LOCK, audit item 7");
	check("A NM ex 800+10", lockv(&A, 4, NM_LOCK, 1, 800, 10, true, false,
	    false, 0), ST_GRANTED);
	check("B meets it", lock(&B, 1, 800, 10, true, false), ST_DENIED);
	check("B NM_LOCK does not block", lockv(&B, 4, NM_LOCK, 1, 800, 10,
	    true, true, false, 0), ST_DENIED);
	check("  nwaiters", counter("nwaiters"), 0);
	check("UNLOCK releases it", unlock(&A, 1, 800, 10), ST_GRANTED);
	check("B has it", lock(&B, 1, 800, 10, true, false), ST_GRANTED);
	unlock(&B, 1, 800, 10);

	puts("# FREE_ALL, audit item 7");
	check("A ex 820+10", lock(&A, 1, 820, 10, true, false), ST_GRANTED);
	check("A svid 2 ex 840+10", lock(&A, 2, 840, 10, true, false),
	    ST_GRANTED);
	check("A NM ex 860+10", lockv(&A, 4, NM_LOCK, 3, 860, 10, true, false,
	    false, 0), ST_GRANTED);
	check("A share", sharev(&A, 4, SHARE, "a", 2, 1, false), ST_GRANTED);
	check("B ex 880+10", lock(&B, 1, 880, 10, true, false), ST_GRANTED);
	check("A blocks behind B", lock(&A, 4, 880, 10, true, true),
	    ST_BLOCKED);
	check("B naming A does nothing", free_all(&B, "clienta"), 0);
	check("A still has 820", lock(&B, 2, 820, 10, true, false), ST_DENIED);
	check("  nshares", counter("nshares"), 1);
	check("  nwaiters", counter("nwaiters"), 1);
	check("A itself", free_all(&A, "clienta"), 0);
	check("  nwaiters", counter("nwaiters"), 0);
	check("  nshares", counter("nshares"), 0);
	check("  only B's hold is left", counter("nholds"), 1);
	check("820 is free", lock(&B, 1, 820, 10, true, false), ST_GRANTED);
	check("840 is free", lock(&B, 1, 840, 10, true, false), ST_GRANTED);
	check("860 is free", lock(&B, 1, 860, 10, true, false), ST_GRANTED);
	unlock(&B, 1, 800, 100);
}

static void
t_local(const char *path)
{
	struct flock fl;
	struct holder h;
	int fd;

	puts("# against a local process");
	check("A ex 900+10", lock(&A, 1, 900, 10, true, false), ST_GRANTED);
	check("fcntl meets it", local_try(path, 900, 1, F_WRLCK), 1);
	check("fcntl beside it passes", local_try(path, 910, 1, F_WRLCK), 0);
	unlock(&A, 1, 900, 10);
	check("fcntl passes now", local_try(path, 900, 1, F_WRLCK), 0);

	if ((fd = open(path, O_RDWR)) == -1)
		err(1, "%s", path);
	memset(&fl, 0, sizeof(fl));
	fl.l_whence = SEEK_SET;
	fl.l_start = 920;
	fl.l_len = 10;
	fl.l_type = F_WRLCK;
	if (fcntl(fd, F_SETLK, &fl) == -1)
		err(1, "fcntl");
	check("the process stops A", lock(&A, 1, 920, 1, true, false),
	    ST_DENIED);
	h = testv(&A, 4, 1, 920, 1, true);
	check("TEST sees it", h.h_stat, ST_DENIED);
	check("  svid of no client", h.h_svid, 0);
	check("  offset", (long)h.h_off, 920);
	A.c_granted = 0;
	A.c_answer = ST_GRANTED;
	check("A blocks on it", lock(&A, 1, 920, 1, true, true), ST_BLOCKED);
	close(fd);
	check("closing it grants", waitfor(&A.c_granted, &A, 1, 5), 1);
	unlock(&A, 1, 920, 1);
}

/* SM_NOTIFY to rpc.statd, from a client's address. */
static void
notify(const struct client *from, const char *name, int state)
{
	struct sockaddr_in to = server;
	struct buf a, r;
	int port;

	/* It writes the port mapper's port into what it is given. */
	port = pmap_getport(&to, SM_PROG, 1, IPPROTO_UDP);
	if (port == 0) {
		puts("# rpc.statd is not at the port mapper");
		fails++;
		return;
	}
	to.sin_port = htons(port);
	memset(&a, 0, sizeof(a));
	putstr(&a, name);
	put32(&a, state);
	(void)rpc(from, &to, SM_PROG, 1, 6, &a, &r, NULL);
}

static void
t_nsm(void)
{
	struct buf a, r;
	in_addr_t ina = inet_addr("127.0.0.2");

	puts("# NLM_SM_NOTIFY only from rpc.statd, audit item 15");
	check("A ex 1100+10 in state 7", lockv(&A, 4, LOCK, 1, 1100, 10, true,
	    false, false, 7), ST_GRANTED);
	memset(&a, 0, sizeof(a));
	putstr(&a, "127.0.0.2");
	put32(&a, 9);
	memcpy(a.b + a.n, &ina, 4);
	a.n += 16;
	check("to the NLM from a client", rpc(&B, &server, NLM_PROG, 0, 1, &a,
	    &r, NULL), 5);
	check("A keeps it", lock(&B, 1, 1100, 10, true, false), ST_DENIED);

	puts("# SM_NOTIFY through rpc.statd, by the address it monitors");
	notify(&A, "127.0.0.2", 7);
	sleep(2);
	check("state 7 is the lock's own: it stays", lock(&B, 1, 1100, 10, true,
	    false), ST_DENIED);
	notify(&A, "127.0.0.2", 9);
	sleep(2);
	check("state 9: it goes", lock(&B, 1, 1100, 10, true, false),
	    ST_GRANTED);
	unlock(&B, 1, 1100, 10);
}

static void
t_grace(void)
{

	puts("# in the grace period");
	check("LOCK", lock(&A, 1, 0, 1, true, false), ST_GRACE);
	check("TEST", testv(&A, 4, 1, 0, 1, true).h_stat, ST_GRACE);
	check("NM_LOCK", lockv(&A, 4, NM_LOCK, 1, 0, 1, true, false, false, 0),
	    ST_GRACE);
	check("SHARE", sharev(&A, 4, SHARE, "a", 0, 1, false), ST_GRACE);
	check("reclaim LOCK passes", lockv(&A, 4, LOCK, 1, 0, 10, true, false,
	    true, 3), ST_GRANTED);
	check("reclaim SHARE passes", sharev(&A, 4, SHARE, "a", 0, 1, true),
	    ST_GRANTED);
	check("a reclaim in conflict", lockv(&B, 4, LOCK, 1, 5, 1, true, false,
	    true, 3), ST_DENIED);
	check("UNLOCK waits too", unlock(&A, 1, 0, 10), ST_GRACE);
	check("UNSHARE too", sharev(&A, 4, UNSHARE, "a", 0, 1, false), ST_GRACE);
	check("  and reclaim does not change that", sharev(&A, 4, UNSHARE, "a",
	    0, 1, true), ST_GRACE);
	check("CANCEL too", cancel(&A, 1, 0, 10, true), ST_GRACE);
	while (lock(&B, 2, 1000, 1, true, false) == ST_GRACE)
		sleep(1);
	puts("# over");
	check("LOCK", lock(&A, 1, 2000, 1, true, false), ST_GRANTED);
	check("the reclaimed lock held", lock(&B, 1, 5, 1, true, false),
	    ST_DENIED);
	unlock(&A, 1, 0, 3000);
	unlock(&B, 2, 1000, 1);
	check("UNSHARE", sharev(&A, 4, UNSHARE, "a", 0, 1, false), ST_GRANTED);
}

static void
getthefh(const char *path)
{
	size_t len = sizeof(fh);

	memset(fh, 0, sizeof(fh));
	if (getfh(path, fh, &len) == -1)
		err(1, "getfh %s", path);
	fhlen = len;
	printf("# %s: handle of %zu bytes\n", path, fhlen);
}

int
main(int argc, char **argv)
{
	bool grace = argc == 3 && strcmp(argv[1], "-g") == 0;
	bool nostatd = argc == 3 && strcmp(argv[1], "-n") == 0;
	bool statdback = argc == 3 && strcmp(argv[1], "-r") == 0;
	const char *path = argv[argc - 1];
	int fd, port;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if ((fd = open(path, O_RDWR | O_CREAT, 0666)) == -1)
		err(1, "%s", path);
	close(fd);
	getthefh(path);

	memset(&server, 0, sizeof(server));
	server.sin_len = sizeof(server);
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	port = pmap_getport(&server, NLM_PROG, 4, IPPROTO_UDP);
	if (port == 0)
		errx(1, "no NLM at the port mapper");
	server.sin_port = htons(port);
	printf("# NLM at %d\n", port);

	A.c_fd = bindto(A.c_ip, 0);
	B.c_fd = bindto(B.c_ip, 0);
	C.c_fd = bindto(C.c_ip, 0);
	D.c_fd = bindto(D.c_ip, 0);
	listen_on(&A);
	listen_on(&B);
	sleep(1);

	if (grace) {
		t_grace();
	} else if (nostatd) {
		t_nostatd();
	} else if (statdback) {
		t_statdback();
	} else {
		t_null();
		t_ranges();
		getthefh(path);
		t_v13();
		t_cancel();
		t_granted();
		t_msg();
		t_msgs();
		t_deadlock();
		t_tcp();
		t_share();
		t_free();
		t_local(path);
		t_nsm();
		puts("# nothing left behind");
		check("nholds", counter("nholds"), 0);
		check("nwaiters", counter("nwaiters"), 0);
		check("nshares", counter("nshares"), 0);
		check("nowners", counter("nowners"), 0);
	}
	printf("passed: %d\nfailures: %d\n", npass, fails);
	return fails != 0;
}
