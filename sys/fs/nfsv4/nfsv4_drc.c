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
 * The duplicate request cache of version 4.0.  It is here, and not in
 * the RPC layer, because whether a call belongs in it depends on the
 * minor version and on what the COMPOUND turned out to hold, which only
 * the program can see.
 *
 * Operations with a seqid have the replay of RFC 7530 s9.1.7.  The others
 * that change something have nothing, and a client that lost its
 * connection will send them again, s3.1.1: without this a resent REMOVE
 * gets NFS4ERR_NOENT, and s16.33.5 takes the cache for granted for
 * SETCLIENTID.
 *
 * Which COMPOUNDs those are is known only once they have run, so every
 * COMPOUND is entered, as in progress, and all but those are taken out
 * again at the end.  A duplicate of one in progress waits for it.  Going
 * by s3.1.1 it must not be dropped while the connection is up, and that
 * it came at all means the original's connection went, so there is no
 * other reply to wait for.  What it gets is then the saved reply, or, if
 * none was saved, it runs: nothing that needed saving was done.
 *
 * A reply too large to keep is not kept, and the COMPOUND would be run
 * again if resent.  That takes one that changes something and reads a
 * lot besides; the size is the bound on what one entry costs.
 *
 * The key leaves out the port, as a client may reconnect from another,
 * and has the principal, as a reply is not for anyone else to see.  The
 * sum is of the first words of the arguments, to tell apart two clients
 * behind one address or one that restarted and reused an xid.
 *
 * The buckets go by address, and each has its own limit, so that a busy
 * client pushes out its own entries.  Nothing else about the sizes comes
 * from the RFC.  An entry stays for as long as a client should need to
 * get a new connection and resend: twice a lease.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/condvar.h>
#include <sys/hash.h>
#include <sys/kauth.h>
#include <sys/kmem.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <fs/nfsv4/nfsv4_var.h>

#define	NFSV4_DRC_BUCKETS	64
#define	NFSV4_DRC_CHAINS	64
#define	NFSV4_DRC_BUCKETMAX	(256 * 1024)	/* bytes, in a bucket */
#define	NFSV4_DRC_REPLYMAX	8192		/* bytes, in an entry */
#define	NFSV4_DRC_SUMWORDS	64
#define	NFSV4_DRC_LIFE		(2 * NFSV4_LEASE)

struct nfsv4_drc_ent {
	LIST_ENTRY(nfsv4_drc_ent) de_chain;
	TAILQ_ENTRY(nfsv4_drc_ent) de_lru;	/* unless de_busy */
	uint32_t	de_xid;
	uint32_t	de_sum;
	uint32_t	de_uid;
	bool		de_busy;
	time_t		de_time;
	char		*de_reply;
	u_int		de_len;
	uint8_t		de_addr[16];
};

struct nfsv4_drc_bucket {
	kmutex_t	db_lock;
	kcondvar_t	db_cv;		/* an entry stopped being busy */
	TAILQ_HEAD(, nfsv4_drc_ent) db_lru;
	size_t		db_bytes;
	LIST_HEAD(, nfsv4_drc_ent) db_chains[NFSV4_DRC_CHAINS];
};

static struct nfsv4_drc_bucket *nfsv4_drc_buckets;

static inline size_t
ent_size(const struct nfsv4_drc_ent *de)
{

	return sizeof(*de) + de->de_len;
}

static void
ent_free(struct nfsv4_drc_ent *de)
{

	if (de->de_reply != NULL)
		kmem_free(de->de_reply, de->de_len);
	kmem_free(de, sizeof(*de));
}

static struct nfsv4_drc_ent *
ent_find(struct nfsv4_drc_bucket *db, const struct nfsv4_drc *d)
{
	struct nfsv4_drc_ent *de;

	KASSERT(mutex_owned(&db->db_lock));

	LIST_FOREACH(de, &db->db_chains[d->d_xid % NFSV4_DRC_CHAINS],
	    de_chain) {
		if (de->de_xid == d->d_xid && de->de_sum == d->d_sum &&
		    de->de_uid == d->d_uid &&
		    memcmp(de->de_addr, d->d_addr, sizeof(d->d_addr)) == 0)
			return de;
	}
	return NULL;
}

/* Take the oldest finished entries while they are too many or too old. */
static void
bucket_trim(struct nfsv4_drc_bucket *db)
{
	struct nfsv4_drc_ent *de;

	KASSERT(mutex_owned(&db->db_lock));

	while ((de = TAILQ_FIRST(&db->db_lru)) != NULL &&
	    (db->db_bytes > NFSV4_DRC_BUCKETMAX ||
	    time_uptime - de->de_time > NFSV4_DRC_LIFE)) {
		TAILQ_REMOVE(&db->db_lru, de, de_lru);
		LIST_REMOVE(de, de_chain);
		db->db_bytes -= ent_size(de);
		ent_free(de);
	}
}

/*
 * Fill in the key of rq.  False if it has no peer to go by, and the cache
 * has nothing to do with it.  The arguments are left unread.
 */
static bool
drc_key(struct oncrpc_req *rq, struct nfsv4_drc *d)
{
	const struct sockaddr *sa;
	uint32_t words[NFSV4_DRC_SUMWORDS];
	u_int n, pos;

	if (rq->rq_nam == NULL)
		return false;
	sa = mtod(rq->rq_nam, const struct sockaddr *);
	memset(d->d_addr, 0, sizeof(d->d_addr));
	switch (sa->sa_family) {
	case AF_INET:
		memcpy(d->d_addr, &((const struct sockaddr_in *)sa)->sin_addr,
		    sizeof(struct in_addr));
		break;
	case AF_INET6:
		memcpy(d->d_addr, &((const struct sockaddr_in6 *)sa)->sin6_addr,
		    sizeof(struct in6_addr));
		break;
	default:
		return false;
	}

	pos = XDR_GETPOS(rq->rq_args);
	for (n = 0; n < NFSV4_DRC_SUMWORDS; n++) {
		if (!xdr_u_int32_t(rq->rq_args, &words[n]))
			break;
	}
	if (!XDR_SETPOS(rq->rq_args, pos))
		return false;

	d->d_xid = rq->rq_xid;
	d->d_sum = hash32_buf(words, n * sizeof(words[0]), HASH32_BUF_INIT);
	d->d_uid = rq->rq_cred != NULL ? kauth_cred_geteuid(rq->rq_cred) :
	    (uint32_t)-1;
	d->d_hash = hash32_buf(d->d_addr, sizeof(d->d_addr), HASH32_BUF_INIT) %
	    NFSV4_DRC_BUCKETS;
	return true;
}

/*
 * Before a COMPOUND runs.  True if it is a duplicate with a saved reply,
 * which is left in d for nfsv4_drc_replay(), and false if it is to run,
 * when nfsv4_drc_end() must follow.
 */
bool
nfsv4_drc_start(struct oncrpc_req *rq, struct nfsv4_drc *d)
{
	struct nfsv4_drc_bucket *db;
	struct nfsv4_drc_ent *de, *new;
	char *buf = NULL;
	u_int buflen = 0;

	d->d_on = false;
	d->d_buf = NULL;
	if (!drc_key(rq, d))
		return false;
	db = &nfsv4_drc_buckets[d->d_hash];

	new = kmem_zalloc(sizeof(*new), KM_SLEEP);
	new->de_xid = d->d_xid;
	new->de_sum = d->d_sum;
	new->de_uid = d->d_uid;
	new->de_busy = true;
	memcpy(new->de_addr, d->d_addr, sizeof(d->d_addr));

	mutex_enter(&db->db_lock);
	for (;;) {
		bucket_trim(db);
		if ((de = ent_find(db, d)) == NULL) {
			LIST_INSERT_HEAD(
			    &db->db_chains[d->d_xid % NFSV4_DRC_CHAINS],
			    new, de_chain);
			mutex_exit(&db->db_lock);
			if (buf != NULL)
				kmem_free(buf, buflen);
			d->d_on = true;
			return false;
		}
		if (de->de_busy) {
			cv_wait(&db->db_cv, &db->db_lock);
			continue;
		}
		/* Not allocate with the bucket locked. */
		if (buf == NULL || buflen != de->de_len) {
			u_int len = de->de_len;

			mutex_exit(&db->db_lock);
			if (buf != NULL)
				kmem_free(buf, buflen);
			buf = kmem_alloc(len, KM_SLEEP);
			buflen = len;
			mutex_enter(&db->db_lock);
			continue;
		}
		memcpy(buf, de->de_reply, buflen);
		mutex_exit(&db->db_lock);
		kmem_free(new, sizeof(*new));
		d->d_buf = buf;
		d->d_len = buflen;
		return true;
	}
}

/* Answer with the reply nfsv4_drc_start() found. */
bool
nfsv4_drc_replay(struct oncrpc_req *rq, struct nfsv4_drc *d)
{
	bool ok;

	ok = XDR_PUTBYTES(rq->rq_res, d->d_buf, d->d_len);
	kmem_free(d->d_buf, d->d_len);
	d->d_buf = NULL;
	return ok;
}

/*
 * After a COMPOUND that ran.  rq is NULL if its reply is not to be kept,
 * and otherwise has the whole of it in rq_res.
 */
void
nfsv4_drc_end(struct nfsv4_drc *d, struct oncrpc_req *rq)
{
	struct nfsv4_drc_bucket *db;
	struct nfsv4_drc_ent *de;
	char *buf = NULL;
	u_int len = 0, end;

	if (!d->d_on)
		return;
	db = &nfsv4_drc_buckets[d->d_hash];

	if (rq != NULL && (len = XDR_GETPOS(rq->rq_res)) > 0 &&
	    len <= NFSV4_DRC_REPLYMAX) {
		buf = kmem_alloc(len, KM_SLEEP);
		end = len;
		if (!XDR_SETPOS(rq->rq_res, 0) ||
		    !XDR_GETBYTES(rq->rq_res, buf, len) ||
		    !XDR_SETPOS(rq->rq_res, end)) {
			kmem_free(buf, len);
			buf = NULL;
		}
	}

	mutex_enter(&db->db_lock);
	de = ent_find(db, d);
	KASSERT(de != NULL && de->de_busy);
	de->de_busy = false;
	if (buf != NULL) {
		de->de_reply = buf;
		de->de_len = len;
		de->de_time = time_uptime;
		db->db_bytes += ent_size(de);
		TAILQ_INSERT_TAIL(&db->db_lru, de, de_lru);
		bucket_trim(db);
	} else {
		LIST_REMOVE(de, de_chain);
		kmem_free(de, sizeof(*de));
	}
	cv_broadcast(&db->db_cv);
	mutex_exit(&db->db_lock);
}

void
nfsv4_drc_init(void)
{
	struct nfsv4_drc_bucket *db;
	u_int i, j;

	nfsv4_drc_buckets = kmem_zalloc(sizeof(*nfsv4_drc_buckets) *
	    NFSV4_DRC_BUCKETS, KM_SLEEP);
	for (i = 0; i < NFSV4_DRC_BUCKETS; i++) {
		db = &nfsv4_drc_buckets[i];
		mutex_init(&db->db_lock, MUTEX_DEFAULT, IPL_NONE);
		cv_init(&db->db_cv, "nfsv4drc");
		TAILQ_INIT(&db->db_lru);
		for (j = 0; j < NFSV4_DRC_CHAINS; j++)
			LIST_INIT(&db->db_chains[j]);
	}
}

/* The workers have stopped, so nothing is busy. */
void
nfsv4_drc_fini(void)
{
	struct nfsv4_drc_bucket *db;
	struct nfsv4_drc_ent *de;
	u_int i;

	for (i = 0; i < NFSV4_DRC_BUCKETS; i++) {
		db = &nfsv4_drc_buckets[i];
		while ((de = TAILQ_FIRST(&db->db_lru)) != NULL) {
			TAILQ_REMOVE(&db->db_lru, de, de_lru);
			LIST_REMOVE(de, de_chain);
			ent_free(de);
		}
		cv_destroy(&db->db_cv);
		mutex_destroy(&db->db_lock);
	}
	kmem_free(nfsv4_drc_buckets, sizeof(*nfsv4_drc_buckets) *
	    NFSV4_DRC_BUCKETS);
}
