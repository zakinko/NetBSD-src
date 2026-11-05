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
 * Restart: the grace period and the records that make it safe, RFC 7530
 * s9.6.2 and s9.6.3.4.
 *
 * No locks are kept on stable storage: a client that held some says so
 * again in the grace period, and all a server must remember is whom to
 * believe.  s9.6.3.4.3 gives the record for that, and the server stands
 * on the second of its strategies: a file, named by vfs.nfsv4.stable,
 * says which clients can reclaim.  With no file named, the first
 * strategy applies, every reclaim gets NFS4ERR_NO_GRACE, and there is
 * no grace period.
 *
 * The file is a log of records of one instance of the server:
 *
 *	HEAD	this instance began, and its lease
 *	PREV x	x could reclaim when this instance began
 *	GOOD x	x got state in this instance
 *	GONE x	x lost its state: lease over, or a delegation revoked
 *	DONE	the grace period of this instance is over
 *
 * Starting, the log is read and written anew.  Those who can reclaim
 * are the ones with GOOD not followed by GONE, and, if DONE is missing,
 * the ones with PREV likewise: a crash in the grace period must not cost
 * anyone who had not got round to it yet.  That is the two edge
 * conditions of s9.6.3.4: the first is GONE, and the second is that DONE
 * makes a PREV worth nothing.  Records go to disk before the operation
 * that needs them answers.
 *
 * A record that fails its check is damage, and s9.6.3.4.3 wants
 * NFS4ERR_NO_GRACE for all then, which is what an empty set gives.  No
 * one who can reclaim means nothing can conflict, s9.6.2, so there is
 * no grace period then either.  This is all the state a restart has, and
 * the period is not ended early: 4.0 has no way for a client to say
 * that it has finished.
 *
 * vn_lock() of the file keeps writers in order.  It is not taken with
 * nfsv4_state_lock held.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/atomic.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/kauth.h>
#include <sys/kmem.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/vnode.h>

#include <fs/nfsv4/nfsv4_var.h>
#include <fs/nfsv4/nfsv4_state.h>

/* Chosen: what the file may hold, and the form of a record. */
#define	STABLE_MAXFILE		(16 * 1024 * 1024)
#define	STABLE_MAGIC		0x4e345352	/* "N4SR" */
#define	STABLE_HASH		64

#define	REC_HEAD		1
#define	REC_PREV		2
#define	REC_GOOD		3
#define	REC_GONE		4
#define	REC_DONE		5

/* The header of a record, big-endian, then rh_len bytes, padded to 4. */
struct stable_rec {
	uint32_t	rh_magic;
	uint32_t	rh_type;
	uint32_t	rh_len;
	uint32_t	rh_sum;		/* of the bytes, with rh_type and rh_len */
};

/* One who can reclaim. */
struct stable_ent {
	LIST_ENTRY(stable_ent) se_list;
	bool		se_good;
	uint32_t	se_len;
	uint8_t		se_id[];
};

static kmutex_t stable_lock;		/* of stable_set, once being served */
static LIST_HEAD(, stable_ent) stable_set[STABLE_HASH];
static struct vnode *stable_vp;
static off_t stable_off;		/* under the vnode's lock */
static time_t grace_end;		/* 0 for none; atomic */

static uint32_t
stable_sum(uint32_t type, const uint8_t *p, uint32_t len)
{
	uint32_t h = 0x811c9dc5U ^ type ^ (len << 8);	/* FNV-1a */
	uint32_t i;

	for (i = 0; i < len; i++)
		h = (h ^ p[i]) * 16777619U;
	return h;
}

static u_int
stable_hash(const uint8_t *id, uint32_t len)
{

	return stable_sum(0, id, len) % STABLE_HASH;
}

static struct stable_ent *
stable_find(const uint8_t *id, uint32_t len)
{
	struct stable_ent *se;

	LIST_FOREACH(se, &stable_set[stable_hash(id, len)], se_list) {
		if (se->se_len == len && memcmp(se->se_id, id, len) == 0)
			return se;
	}
	return NULL;
}

static void
stable_free(struct stable_ent *se)
{

	LIST_REMOVE(se, se_list);
	kmem_free(se, sizeof(*se) + se->se_len);
}

static void
stable_clear(bool all)
{
	struct stable_ent *se, *next;
	u_int i;

	for (i = 0; i < STABLE_HASH; i++) {
		LIST_FOREACH_SAFE(se, &stable_set[i], se_list, next) {
			if (all || !se->se_good)
				stable_free(se);
		}
	}
}

static void
stable_note(const uint8_t *id, uint32_t len, bool good)
{
	struct stable_ent *se;

	se = stable_find(id, len);
	if (se == NULL) {
		se = kmem_alloc(sizeof(*se) + len, KM_SLEEP);
		se->se_len = len;
		se->se_good = false;
		memcpy(se->se_id, id, len);
		LIST_INSERT_HEAD(&stable_set[stable_hash(id, len)], se,
		    se_list);
	}
	if (good)
		se->se_good = true;
}

/* Parse what the file held.  False for damage. */
static bool
stable_parse(const uint8_t *buf, size_t size)
{
	struct stable_rec rh;
	struct stable_ent *se;
	size_t off = 0, adv;
	uint32_t type, len;

	while (off < size) {
		if (size - off < sizeof(rh))
			return false;
		memcpy(&rh, buf + off, sizeof(rh));
		type = be32toh(rh.rh_type);
		len = be32toh(rh.rh_len);
		off += sizeof(rh);
		if (be32toh(rh.rh_magic) != STABLE_MAGIC ||
		    len > NFS4_OPAQUE_LIMIT || size - off < len ||
		    stable_sum(type, buf + off, len) != be32toh(rh.rh_sum))
			return false;
		switch (type) {
		case REC_HEAD:
			break;
		case REC_PREV:
			stable_note(buf + off, len, false);
			break;
		case REC_GOOD:
			stable_note(buf + off, len, true);
			break;
		case REC_GONE:
			if ((se = stable_find(buf + off, len)) != NULL)
				stable_free(se);
			break;
		case REC_DONE:
			stable_clear(false);
			break;
		default:
			return false;
		}
		adv = roundup2(len, 4);
		if (size - off < adv)
			return false;
		off += adv;
	}
	return true;
}

/* Put one record at the end of the file, on disk. */
static int
stable_put_locked(uint32_t type, const uint8_t *id, uint32_t len)
{
	char buf[sizeof(struct stable_rec) + NFS4_OPAQUE_LIMIT + 4];
	struct stable_rec rh;
	size_t n;
	int error;

	KASSERT(len <= NFS4_OPAQUE_LIMIT);

	rh.rh_magic = htobe32(STABLE_MAGIC);
	rh.rh_type = htobe32(type);
	rh.rh_len = htobe32(len);
	rh.rh_sum = htobe32(stable_sum(type, id, len));
	memset(buf, 0, sizeof(buf));
	memcpy(buf, &rh, sizeof(rh));
	if (len != 0)
		memcpy(buf + sizeof(rh), id, len);
	n = sizeof(rh) + roundup2(len, 4);
	error = vn_rdwr(UIO_WRITE, stable_vp, buf, n, stable_off, UIO_SYSSPACE,
	    IO_NODELOCKED | IO_SYNC | IO_UNIT, kauth_cred_get(), NULL, curlwp);
	if (error == 0)
		stable_off += n;
	return error;
}

static void
stable_put(uint32_t type, const uint8_t *id, uint32_t len)
{
	struct vnode *vp = stable_vp;
	int error;

	if (vp == NULL)
		return;
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	error = stable_put_locked(type, id, len);
	VOP_UNLOCK(vp);
	if (error != 0)
		printf("nfsv4: stable storage: write error %d\n", error);
}

/*
 * Read the file and start the new instance's log.  vp is locked.  The
 * old content is gone before the new is written, and a crash in between
 * leaves an empty log: nobody can reclaim, which is the harsh side of
 * s9.6.3.4.3.
 */
static int
stable_begin(struct vnode *vp, off_t size)
{
	struct stable_ent *se;
	struct vattr va;
	uint8_t *buf = NULL;
	size_t resid;
	uint32_t lease = htobe32(NFSV4_LEASE);
	u_int i, n = 0;
	int error;

	if (size > STABLE_MAXFILE)
		return EFBIG;
	if (size != 0) {
		buf = kmem_alloc(size, KM_SLEEP);
		error = vn_rdwr(UIO_READ, vp, buf, size, 0, UIO_SYSSPACE,
		    IO_NODELOCKED, kauth_cred_get(), &resid, curlwp);
		if (error == 0 && resid != 0)
			error = EIO;
		if (error == 0 && !stable_parse(buf, size)) {
			printf("nfsv4: stable storage damaged, no reclaims\n");
			stable_clear(true);
		}
		kmem_free(buf, size);
		if (error != 0)
			return error;
	}

	vattr_null(&va);
	va.va_size = 0;
	error = VOP_SETATTR(vp, &va, kauth_cred_get());
	if (error != 0)
		return error;
	stable_off = 0;
	stable_vp = vp;
	error = stable_put_locked(REC_HEAD, (const uint8_t *)&lease,
	    sizeof(lease));
	for (i = 0; error == 0 && i < STABLE_HASH; i++) {
		LIST_FOREACH(se, &stable_set[i], se_list) {
			error = stable_put_locked(REC_PREV, se->se_id,
			    se->se_len);
			if (error != 0)
				break;
			se->se_good = false;
			n++;
		}
	}
	if (error != 0)
		stable_vp = NULL;
	else if (n != 0)
		atomic_store_relaxed(&grace_end, time_uptime + NFSV4_LEASE);
	return error;
}

/* vfs.nfsv4.stable names the file, once, before any client is served. */
int
nfsv4_stable_open(const char *path)
{
	struct pathbuf *pb;
	struct vnode *vp;
	struct vattr va;
	int error;

	if (stable_vp != NULL)
		return EBUSY;
	pb = pathbuf_create(path);
	if (pb == NULL)
		return ENOMEM;
	error = vn_open(NULL, pb, 0, FREAD | FWRITE | O_CREAT, 0600, &vp, NULL,
	    NULL);
	pathbuf_destroy(pb);
	if (error != 0)
		return error;
	if (vp->v_type != VREG) {
		VOP_UNLOCK(vp);
		(void)vn_close(vp, FREAD | FWRITE, kauth_cred_get());
		return EFTYPE;
	}
	error = VOP_GETATTR(vp, &va, kauth_cred_get());
	if (error == 0)
		error = stable_begin(vp, va.va_size);
	VOP_UNLOCK(vp);
	if (error != 0)
		(void)vn_close(vp, FREAD | FWRITE, kauth_cred_get());
	return error;
}

void
nfsv4_stable_init(void)
{
	u_int i;

	mutex_init(&stable_lock, MUTEX_DEFAULT, IPL_NONE);
	for (i = 0; i < STABLE_HASH; i++)
		LIST_INIT(&stable_set[i]);
	stable_vp = NULL;
	grace_end = 0;
}

void
nfsv4_stable_fini(void)
{

	if (stable_vp != NULL) {
		(void)vn_close(stable_vp, FREAD | FWRITE, kauth_cred_get());
		stable_vp = NULL;
	}
	stable_clear(true);
	mutex_destroy(&stable_lock);
}

bool
nfsv4_grace_active(void)
{
	time_t end = atomic_load_relaxed(&grace_end);

	return end != 0 && time_uptime < end;
}

/* The lease thread's look at the end of the period. */
void
nfsv4_grace_scan(void)
{
	time_t end = atomic_load_relaxed(&grace_end);

	if (end == 0 || time_uptime < end)
		return;
	atomic_store_relaxed(&grace_end, 0);
	stable_put(REC_DONE, NULL, 0);
	mutex_enter(&stable_lock);
	stable_clear(true);
	mutex_exit(&stable_lock);
}

/*
 * May the client reclaim now?  s9.6.2, and s9.6.3.4.3 for one with no
 * record.  Out of the period no client may.
 */
uint32_t
nfsv4_reclaim_check(const struct nfsv4_client *cl)
{

	uint32_t st;

	if (!nfsv4_grace_active())
		return NFS4ERR_NO_GRACE;
	mutex_enter(&stable_lock);
	st = stable_find(cl->cl_idstr, cl->cl_idlen) != NULL ? NFS4_OK :
	    NFS4ERR_RECLAIM_BAD;
	mutex_exit(&stable_lock);
	return st;
}

/*
 * The client has got state, the first time in this instance.  The caller
 * has seen that with cl_stable clear, and has the client held by a busy
 * owner.  On the disk before the reply goes out, so sleeps.
 */
void
nfsv4_stable_good(const uint8_t *id, uint32_t len)
{

	stable_put(REC_GOOD, id, len);
}

void
nfsv4_stable_gone(const uint8_t *id, uint32_t len)
{

	stable_put(REC_GONE, id, len);
}
