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
 * The operations of NFS version 4.2 on the data of a file, RFC 7862.
 *
 * COPY is synchronous and nothing else is asynchronous either, as there
 * is no way yet to send CB_OFFLOAD on a backchannel; s4.1.2 asks for
 * that only of a server whose COPY returns a stateid.  One COPY or
 * WRITE_SAME holds a thread for NFSV4_COPY_MAX bytes at most.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/filio.h>
#include <sys/kauth.h>
#include <sys/kmem.h>
#include <sys/mount.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/vnode.h>

#include <fs/nfsv4/nfsv4_var.h>
#include <fs/nfsv4/nfsv4_state.h>

/*
 * Choices, none from the RFC.  NFSV4_COPY_MAX is where a COPY or a
 * WRITE_SAME stops and gives a short result, as
 * draft-cel-nfsv4-copy-implementation-experience-03 s8.1 reports of
 * other servers.  NFSV4_ADB_MAX bounds adb_block_size, which is held in
 * memory.  NFSV4_SEEK_SCAN is how many extents one look at a file with
 * no way of seeking goes over.
 */
#define	NFSV4_COPY_MAX		(64 * 1024 * 1024)
#define	NFSV4_ADB_MAX		(1024 * 1024)
#define	NFSV4_SEEK_SCAN		65536

/* The size of a locked file. */
static int
file_size(struct vnode *vp, kauth_cred_t cred, uint64_t *sizep)
{
	struct vattr va;
	int error;

	error = VOP_GETATTR(vp, &va, cred);
	if (error == 0)
		*sizep = va.va_size;
	return error;
}

/* s15.10.3: what READ_PLUS and SEEK say of what is not a regular file. */
static uint32_t
read_type_check(const struct nfsv4_cfh *cf)
{
	struct vnode *vp = cf->cf_vp;

	if (vp == NULL || vp->v_type == VDIR)
		return NFS4ERR_ISDIR;
	if (vp->v_type == VLNK)
		return NFS4ERR_SYMLINK;
	return vp->v_type == VREG ? NFS4_OK : NFS4ERR_WRONG_TYPE;
}

/* s15.1.3, s15.2.3, s15.4.3, s15.13.3 */
static uint32_t
regular_check(const struct nfsv4_cfh *cf)
{

	return cf->cf_vp != NULL && cf->cf_vp->v_type == VREG ? NFS4_OK :
	    NFS4ERR_WRONG_TYPE;
}

static uint32_t
read_prep(struct nfsv4_compound *c, const struct nfsv4_stateid *si)
{
	const struct nfsv4_cfh *cf = &c->c_cur;
	uint32_t st;

	st = read_type_check(cf);
	if (st == NFS4_OK)
		st = nfsv4_io_check(c, si, false);
	if (st == NFS4_OK)
		st = nfsv4_errno(nfsv4_access_vp(cf, VREAD));
	return st;
}

static uint32_t
write_prep(struct nfsv4_compound *c, const struct nfsv4_stateid *si)
{
	const struct nfsv4_cfh *cf = &c->c_cur;
	uint32_t st;

	st = regular_check(cf);
	if (st == NFS4_OK)
		st = nfsv4_io_check(c, si, true);
	if (st == NFS4_OK)
		st = nfsv4_errno(nfsv4_access_vp(cf, VWRITE));
	return st;
}

/* Whether the block at lbn of a locked file is a hole, and the run after. */
static int
block_is_hole(struct vnode *vp, daddr_t lbn, bool *holep, int *runp)
{
	daddr_t bn;
	int error;

	*runp = 0;
	error = VOP_BMAP(vp, lbn, NULL, &bn, runp);
	if (error == 0)
		*holep = bn == (daddr_t)-1;
	return error;
}

/*
 * The next hole or data at or after off below size, for a file system
 * that has only VOP_BMAP, in *nextp.  Without even that, or having
 * looked long enough, what has not been seen is data: all of a file may
 * be, whatever it holds, and s15.11.3 needs no hole but the one at the
 * end of the file.
 */
static void
seek_bmap(struct vnode *vp, bool hole, off_t off, off_t size, off_t *nextp)
{
	off_t pos, bsize;
	daddr_t lbn;
	bool ishole;
	int i, run;

	bsize = vp->v_mount->mnt_stat.f_iosize;
	lbn = off / bsize;
	pos = off;
	vn_lock(vp, LK_SHARED | LK_RETRY);
	for (i = 0; i < NFSV4_SEEK_SCAN && pos < size; i++) {
		if (block_is_hole(vp, lbn, &ishole, &run) != 0)
			break;
		if (ishole == hole) {
			VOP_UNLOCK(vp);
			*nextp = pos;
			return;
		}
		lbn += ishole ? 1 : run + 1;
		pos = lbn * bsize;
	}
	VOP_UNLOCK(vp);
	*nextp = hole ? size : MIN(pos, size);
}

/*
 * The next hole or data at or after off, size if there is none.  ZFS
 * answers FIOSEEKDATA and FIOSEEKHOLE, and locks the vnode itself.
 */
static int
seek_vp(struct vnode *vp, kauth_cred_t cred, bool hole, off_t off,
    off_t size, off_t *nextp)
{
	off_t o = off;
	int error;

	error = VOP_IOCTL(vp, hole ? FIOSEEKHOLE : FIOSEEKDATA, &o, 0, cred);
	switch (error) {
	case 0:
		*nextp = MIN(o, size);
		return 0;
	case ENXIO:
		*nextp = size;
		return 0;
	case ENOTTY:
	case EOPNOTSUPP:
		seek_bmap(vp, hole, off, size, nextp);
		return 0;
	default:
		return error;
	}
}

/* s15.11 */
uint32_t
nfsv4_op_seek(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_seek *sa = &a->seek;
	const struct nfsv4_cfh *cf = &c->c_cur;
	struct vnode *vp = cf->cf_vp;
	uint64_t size, next;
	uint32_t st, eof;
	off_t o;
	int error;

	st = read_prep(c, &sa->stateid);
	if (st != NFS4_OK)
		return st;
	if (sa->what > NFS4_CONTENT_HOLE)
		return NFS4ERR_UNION_NOTSUPP;

	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = file_size(vp, cf->cf_cred, &size);
	VOP_UNLOCK(vp);
	if (error != 0)
		return nfsv4_errno(error);
	if (sa->offset > size)
		return NFS4ERR_NXIO;

	next = size;
	if (sa->offset < size) {
		error = seek_vp(vp, cf->cf_cred, sa->what == NFS4_CONTENT_HOLE,
		    sa->offset, size, &o);
		if (error != 0)
			return nfsv4_errno(error);
		next = o;
	}
	/* s15.11.3: the hole at the end of a file is the virtual one. */
	eof = next >= size;
	return xdr_u_int32_t(c->c_rx, &eof) &&
	    xdr_u_int64_t(c->c_rx, &next) ? NFS4_OK : NFS4ERR_RESOURCE;
}

/*
 * s15.10.3: the end of a hole may not go past a byte range lock of the
 * owner reading.  One lock on the file, of any owner, is enough to stay
 * inside what was asked for.
 */
static bool
file_has_locks(struct vnode *vp)
{
	struct nfsv4_state *st;
	struct nfsv4_file *f;
	bool locks = false;

	mutex_enter(&nfsv4_state_lock);
	f = nfsv4_file_find(vp);
	if (f != NULL) {
		LIST_FOREACH(st, &f->f_states, st_flist) {
			if (st->st_type == NFSV4_ST_LOCK)
				locks = true;
		}
	}
	mutex_exit(&nfsv4_state_lock);
	return locks;
}

/*
 * s15.10.  At most one piece of data and the hole after it, or a hole
 * alone, s15.10.3 leaving the client to ask again.  Zeros that really
 * are stored go as data: the SHOULD to make a hole of them would have
 * this look at every byte of every read.
 */
uint32_t
nfsv4_op_read_plus(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_read *ra = &a->read;
	const struct nfsv4_cfh *cf = &c->c_cur;
	struct vnode *vp = cf->cf_vp;
	XDR *rx = c->c_rx;
	char *buf = NULL;
	uint64_t size, off, reach, end, holelen;
	uint32_t st, count, n, got, nseg, eof, type;
	size_t resid;
	off_t o, d;
	int error;

	st = read_prep(c, &ra->stateid);
	if (st != NFS4_OK)
		return st;

	off = ra->offset;
	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = file_size(vp, cf->cf_cred, &size);
	VOP_UNLOCK(vp);
	if (error != 0)
		return nfsv4_errno(error);

	/* s15.10.3: nothing at or past the end, or for a count of zero. */
	if (off >= size || ra->count == 0) {
		eof = off >= size;
		nseg = 0;
		return xdr_u_int32_t(rx, &eof) && xdr_u_int32_t(rx, &nseg) ?
		    NFS4_OK : NFS4ERR_RESOURCE;
	}

	count = MIN(ra->count, NFSV4_MAXIO);
	error = seek_vp(vp, cf->cf_cred, true, off, size, &o);
	if (error != 0)
		return nfsv4_errno(error);

	n = got = 0;
	if ((uint64_t)o > off) {
		n = MIN((uint64_t)o - off, count);
		buf = kmem_alloc(n, KM_SLEEP);
		vn_lock(vp, LK_SHARED | LK_RETRY);
		error = vn_rdwr(UIO_READ, vp, buf, n, off, UIO_SYSSPACE,
		    IO_NODELOCKED, cf->cf_cred, &resid, NULL);
		VOP_UNLOCK(vp);
		if (error != 0) {
			kmem_free(buf, n);
			return nfsv4_errno(error);
		}
		got = n - resid;
	}
	reach = off + got;

	/* A short read says nothing of what comes after it. */
	holelen = 0;
	if (reach == (uint64_t)o && got < count && reach < size) {
		error = seek_vp(vp, cf->cf_cred, false, reach, size, &d);
		end = error == 0 ? (uint64_t)d : reach;
		if (end > off + count && file_has_locks(vp))
			end = off + count;
		if (end > reach)
			holelen = end - reach;
	}

	nseg = (got != 0 ? 1 : 0) + (holelen != 0 ? 1 : 0);
	eof = reach + holelen >= size;
	if (!xdr_u_int32_t(rx, &eof) || !xdr_u_int32_t(rx, &nseg))
		st = NFS4ERR_RESOURCE;
	type = NFS4_CONTENT_DATA;
	if (st == NFS4_OK && got != 0 && (!xdr_u_int32_t(rx, &type) ||
	    !xdr_u_int64_t(rx, &off) || !xdr_u_int32_t(rx, &got) ||
	    !xdr_opaque(rx, buf, got)))
		st = NFS4ERR_RESOURCE;
	type = NFS4_CONTENT_HOLE;
	if (st == NFS4_OK && holelen != 0 && (!xdr_u_int32_t(rx, &type) ||
	    !xdr_u_int64_t(rx, &reach) || !xdr_u_int64_t(rx, &holelen)))
		st = NFS4ERR_RESOURCE;
	if (buf != NULL)
		kmem_free(buf, n);
	return st;
}

/* The offset and length of ALLOCATE and DEALLOCATE, in off_t. */
static uint32_t
range_check(const struct nfsv4_args_range *ra)
{

	if (ra->length == 0)
		return NFS4ERR_INVAL;		/* the RFC is silent: a choice */
	if (ra->offset > (uint64_t)INT64_MAX ||
	    ra->length > (uint64_t)INT64_MAX - ra->offset)
		return NFS4ERR_FBIG;
	return NFS4_OK;
}

/*
 * Zeros where there is a hole in the range.  The hole is looked for and
 * filled under one hold of the lock: a WRITE coming between would be
 * overwritten.
 */
static int
fill_holes(const struct nfsv4_cfh *cf, uint64_t off, uint64_t end)
{
	struct vnode *vp = cf->cf_vp;
	char *zero;
	uint64_t size, pos, top;
	off_t bsize;
	bool hole;
	int error, run;

	bsize = vp->v_mount->mnt_stat.f_iosize;
	zero = kmem_zalloc(bsize, KM_SLEEP);
	error = 0;
	for (pos = rounddown(off, bsize); pos < end && error == 0;) {
		run = 0;
		hole = false;
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
		error = file_size(vp, cf->cf_cred, &size);
		if (error == 0)
			error = block_is_hole(vp, pos / bsize, &hole, &run);
		if (error == 0 && hole && pos < size) {
			top = MIN(pos + bsize, size);
			error = vn_rdwr(UIO_WRITE, vp, zero, top - pos, pos,
			    UIO_SYSSPACE, IO_NODELOCKED, cf->cf_cred, NULL,
			    NULL);
		}
		VOP_UNLOCK(vp);
		pos += (uint64_t)(hole ? 1 : run + 1) * bsize;
	}
	kmem_free(zero, bsize);
	return error;
}

/*
 * What is left of ALLOCATE where VOP_FALLOCATE is not there.  The only
 * honest answer without a guarantee is NFS4ERR_NOTSUPP, as on ZFS, which
 * never overwrites in place.  tmpfs charges all of a file against its
 * limit as soon as it has that size, tmpfs_reg_resize().  FFS has to be
 * given the blocks; a VOP_FALLOCATE of its own would spare it writing
 * the zeros, but say nothing more to a client.  A snapshot of the file
 * system can still take the guarantee away from FFS.
 */
static int
allocate_fallback(const struct nfsv4_cfh *cf, uint64_t off, uint64_t end)
{
	struct vnode *vp = cf->cf_vp;
	const char *fstype = vp->v_mount->mnt_stat.f_fstypename;
	struct vattr va;
	uint64_t size, now;
	bool tmpfs, grew;
	int error;

	tmpfs = strcmp(fstype, MOUNT_TMPFS) == 0;
	if (!tmpfs && strcmp(fstype, MOUNT_FFS) != 0 &&
	    strcmp(fstype, MOUNT_MFS) != 0)
		return EOPNOTSUPP;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	error = file_size(vp, cf->cf_cred, &size);
	grew = error == 0 && end > size;
	if (grew) {
		vattr_null(&va);
		va.va_size = end;
		error = VOP_SETATTR(vp, &va, cf->cf_cred);
	}
	VOP_UNLOCK(vp);
	if (error != 0 || tmpfs)
		return error;

	error = fill_holes(cf, off, end);
	if (error != 0 && grew) {
		/* Not if someone has moved the size since. */
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
		if (file_size(vp, cf->cf_cred, &now) == 0 && now == end) {
			vattr_null(&va);
			va.va_size = size;
			(void)VOP_SETATTR(vp, &va, cf->cf_cred);
		}
		VOP_UNLOCK(vp);
	}
	return error;
}

/* s15.1 */
uint32_t
nfsv4_op_allocate(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_range *ra = &a->range;
	const struct nfsv4_cfh *cf = &c->c_cur;
	struct vnode *vp = cf->cf_vp;
	uint32_t st;
	int error;

	st = write_prep(c, &ra->stateid);
	if (st == NFS4_OK)
		st = range_check(ra);
	if (st != NFS4_OK)
		return st;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	error = VOP_FALLOCATE(vp, ra->offset, ra->length);
	VOP_UNLOCK(vp);
	if (error == EOPNOTSUPP)
		error = allocate_fallback(cf, ra->offset,
		    ra->offset + ra->length);
	return nfsv4_errno(error);
}

/*
 * Zeros over the range, skipping the holes, never moving the end of the
 * file.  s15.4.3 lets what cannot be deallocated be zeroed, and that is
 * all of it on a file system with no VOP_FDISCARD.
 */
static int
zero_range(const struct nfsv4_cfh *cf, uint64_t off, uint64_t end)
{
	struct vnode *vp = cf->cf_vp;
	char *zero;
	uint64_t size, pos, next, top;
	off_t bsize;
	bool hole;
	int error, run;

	bsize = vp->v_mount->mnt_stat.f_iosize;
	zero = kmem_zalloc(NFSV4_MAXIO, KM_SLEEP);
	error = 0;
	for (pos = off; pos < end && error == 0; pos = next) {
		next = MIN(pos + NFSV4_MAXIO, end);
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
		error = file_size(vp, cf->cf_cred, &size);
		if (error == 0 && pos >= size)
			next = end;
		else if (error == 0) {
			if (block_is_hole(vp, pos / bsize, &hole, &run) != 0)
				hole = false;
			else
				next = MIN(rounddown(pos, bsize) + bsize, end);
			top = MIN(next, size);
			if (!hole)
				error = vn_rdwr(UIO_WRITE, vp, zero, top - pos,
				    pos, UIO_SYSSPACE, IO_NODELOCKED,
				    cf->cf_cred, NULL, NULL);
		}
		VOP_UNLOCK(vp);
	}
	kmem_free(zero, NFSV4_MAXIO);
	return error;
}

/* s15.4 */
uint32_t
nfsv4_op_deallocate(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_range *ra = &a->range;
	const struct nfsv4_cfh *cf = &c->c_cur;
	struct vnode *vp = cf->cf_vp;
	uint64_t size, end;
	uint32_t st;
	int error;

	st = write_prep(c, &ra->stateid);
	if (st == NFS4_OK)
		st = range_check(ra);
	if (st != NFS4_OK)
		return st;

	end = 0;
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	error = file_size(vp, cf->cf_cred, &size);
	if (error == 0) {
		end = MIN(ra->offset + ra->length, size);	/* size stays */
		if (ra->offset < end)
			error = VOP_FDISCARD(vp, ra->offset, end - ra->offset);
	}
	VOP_UNLOCK(vp);
	if (error == EOPNOTSUPP)
		error = zero_range(cf, ra->offset, end);
	return nfsv4_errno(error);
}

/* The source and the destination of a COPY or a CLONE. */
static uint32_t
copy_prep(struct nfsv4_compound *c, const struct nfsv4_args_copy *ca)
{
	const struct nfsv4_cfh *src = &c->c_saved, *dst = &c->c_cur;
	uint32_t st;

	if (!src->cf_set)
		return NFS4ERR_NOFILEHANDLE;
	st = regular_check(src);
	if (st == NFS4_OK)
		st = regular_check(dst);
	if (st == NFS4_OK)
		st = nfsv4_io_check_vp(c, &ca->src_stateid, src->cf_vp, false);
	if (st == NFS4_OK)
		st = nfsv4_io_check_vp(c, &ca->dst_stateid, dst->cf_vp, true);
	if (st == NFS4_OK)
		st = nfsv4_errno(nfsv4_access_vp(src, VREAD));
	if (st == NFS4_OK)
		st = nfsv4_errno(nfsv4_access_vp(dst, VWRITE));
	return st;
}

/*
 * How much of the source a count asks for, s15.2.3 and s15.13.3: 0 is
 * to its end, past its end is NFS4ERR_INVAL.
 */
static uint32_t
copy_count(const struct nfsv4_cfh *src, const struct nfsv4_args_copy *ca,
    uint64_t *countp)
{
	struct vnode *vp = src->cf_vp;
	uint64_t size, count;
	int error;

	vn_lock(vp, LK_SHARED | LK_RETRY);
	error = file_size(vp, src->cf_cred, &size);
	VOP_UNLOCK(vp);
	if (error != 0)
		return nfsv4_errno(error);
	if (ca->src_offset > size)
		return NFS4ERR_INVAL;
	count = ca->count == 0 ? size - ca->src_offset : ca->count;
	if (count > size - ca->src_offset)
		return NFS4ERR_INVAL;
	if (ca->dst_offset > (uint64_t)INT64_MAX ||
	    count > (uint64_t)INT64_MAX - ca->dst_offset)
		return NFS4ERR_FBIG;
	*countp = count;
	return NFS4_OK;
}

/*
 * s15.2.  ca_consecutive and ca_synchronous are met whichever is asked
 * for, so NFS4ERR_OFFLOAD_NO_REQS does not arise.  An error after some
 * bytes went over comes as a short result: COPY4res has nowhere to put
 * wr_count on an error, whatever s15.2.3 says, and the COPY for the rest
 * then gets the error.
 */
uint32_t
nfsv4_op_copy(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_copy *ca = &a->copy;
	const struct nfsv4_cfh *src = &c->c_saved, *dst = &c->c_cur;
	struct nfsv4_verifier verf;
	char *buf;
	uint64_t total, done;
	uint32_t st, none = 0, committed = UNSTABLE4, met = 1;
	size_t resid;
	u_int n, got;
	int error;

	/* s11.1.2.1: the client falls back to copying by itself. */
	if (ca->nsources != 0)
		return NFS4ERR_OFFLOAD_DENIED;
	st = copy_prep(c, ca);
	if (st != NFS4_OK)
		return st;
	if (src->cf_vp == dst->cf_vp)	/* s15.2.3 */
		return NFS4ERR_INVAL;
	st = copy_count(src, ca, &total);
	if (st != NFS4_OK)
		return st;
	total = MIN(total, NFSV4_COPY_MAX);

	buf = kmem_alloc(NFSV4_MAXIO, KM_SLEEP);
	error = 0;
	for (done = 0; done < total && error == 0; done += got) {
		n = MIN(total - done, NFSV4_MAXIO);
		vn_lock(src->cf_vp, LK_SHARED | LK_RETRY);
		error = vn_rdwr(UIO_READ, src->cf_vp, buf, n,
		    ca->src_offset + done, UIO_SYSSPACE, IO_NODELOCKED,
		    src->cf_cred, &resid, NULL);
		VOP_UNLOCK(src->cf_vp);
		got = error == 0 ? n - resid : 0;
		if (got == 0)
			break;		/* the source has become shorter */
		vn_lock(dst->cf_vp, LK_EXCLUSIVE | LK_RETRY);
		error = vn_rdwr(UIO_WRITE, dst->cf_vp, buf, got,
		    ca->dst_offset + done, UIO_SYSSPACE, IO_NODELOCKED,
		    dst->cf_cred, NULL, NULL);
		VOP_UNLOCK(dst->cf_vp);
		if (error != 0)
			got = 0;
	}
	kmem_free(buf, NFSV4_MAXIO);
	if (error != 0 && done == 0)
		return nfsv4_errno(error);

	nfsv4_write_verf(&verf);
	/* write_response4 with no wr_callback_id, then copy_requirements4. */
	return xdr_u_int32_t(c->c_rx, &none) &&
	    xdr_u_int64_t(c->c_rx, &done) &&
	    xdr_u_int32_t(c->c_rx, &committed) &&
	    nfsv4_xdr_verifier(c->c_rx, &verf) &&
	    xdr_u_int32_t(c->c_rx, &met) &&
	    xdr_u_int32_t(c->c_rx, &met) ? NFS4_OK : NFS4ERR_RESOURCE;
}

/*
 * s15.8, s15.9.  Nothing is ever asynchronous here, so no stateid names
 * anything, draft-cel-nfsv4-copy-implementation-experience-03 s7.
 */
uint32_t
nfsv4_op_offload(struct nfsv4_compound *c, union nfsv4_args *a)
{

	return NFS4ERR_BAD_STATEID;
}

/*
 * s15.13.  Whether blocks can be shared, and at what alignment, is the
 * file system's to say; where they cannot this is NFS4ERR_NOTSUPP.
 * VOP_CLONERANGE takes the locks that s15.13.3's atomicity needs.
 */
uint32_t
nfsv4_op_clone(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_copy *ca = &a->copy;
	const struct nfsv4_cfh *src = &c->c_saved, *dst = &c->c_cur;
	uint64_t count;
	uint32_t st;

	st = copy_prep(c, ca);
	if (st != NFS4_OK)
		return st;
	st = copy_count(src, ca, &count);
	if (st != NFS4_OK)
		return st;
	if (src->cf_vp == dst->cf_vp &&
	    ca->src_offset < ca->dst_offset + count &&
	    ca->dst_offset < ca->src_offset + count)
		return NFS4ERR_INVAL;
	if (strcmp(src->cf_vp->v_mount->mnt_stat.f_fstypename,
	    dst->cf_vp->v_mount->mnt_stat.f_fstypename) != 0)
		return NFS4ERR_XDEV;
	return nfsv4_errno(VOP_CLONERANGE(src->cf_vp, ca->src_offset,
	    dst->cf_vp, ca->dst_offset, count, dst->cf_cred));
}

/*
 * s15.5: a hint, which s15.5.3 lets the server ignore and has it say so
 * with IO_ADVISE4_NORMAL.  Share deny bits have nothing to refuse.
 */
uint32_t
nfsv4_op_io_advise(struct nfsv4_compound *c, union nfsv4_args *a)
{
	struct nfsv4_bitmap hints;
	uint32_t st;

	st = read_type_check(&c->c_cur);
	if (st == NFS4_OK)
		st = nfsv4_io_check(c, &a->io_advise.stateid, false);
	if (st != NFS4_OK && st != NFS4ERR_LOCKED)
		return st;
	memset(&hints, 0, sizeof(hints));
	hints.bm_n = 1;
	hints.bm_w[0] = 1U << IO_ADVISE4_NORMAL;
	return nfsv4_xdr_bitmap(c->c_rx, &hints) ? NFS4_OK : NFS4ERR_RESOURCE;
}

/*
 * s15.12, ADBs of s8.1.1.  Stops short of block_count past NFSV4_COPY_MAX
 * bytes, on a whole block, wr_count telling where: the alternative of
 * s15.12.3.1 needs CB_OFFLOAD.  The RFC gives adb_block_num a type but
 * not a form in the block; 32 bits big-endian is what s8.3 shows.
 */
uint32_t
nfsv4_op_write_same(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_write_same *wa = &a->write_same;
	const struct nfsv4_cfh *cf = &c->c_cur;
	struct vnode *vp = cf->cf_vp;
	struct nfsv4_verifier verf;
	char *buf;
	uint64_t bs, count, done, i;
	uint32_t st, none = 0, committed;
	u_int end;
	bool num;
	int error;

	st = write_prep(c, &wa->stateid);
	if (st != NFS4_OK)
		return st;
	bs = wa->block_size;
	num = wa->reloff_blocknum != NFS4_UINT64_MAX;
	if (wa->stable > FILE_SYNC4 || bs == 0 || bs > NFSV4_ADB_MAX)
		return NFS4ERR_INVAL;
	if (wa->reloff_pattern != NFS4_UINT64_MAX && (wa->pattern_len > bs ||
	    wa->reloff_pattern > bs - wa->pattern_len))
		return NFS4ERR_INVAL;
	if (num && (bs < sizeof(uint32_t) ||
	    wa->reloff_blocknum > bs - sizeof(uint32_t)))
		return NFS4ERR_INVAL;
	count = MIN(wa->block_count, NFSV4_COPY_MAX / bs);
	if (wa->offset > (uint64_t)INT64_MAX ||
	    count * bs > (uint64_t)INT64_MAX - wa->offset)
		return NFS4ERR_FBIG;

	buf = kmem_zalloc(bs, KM_SLEEP);
	if (wa->reloff_pattern != NFS4_UINT64_MAX && wa->pattern_len != 0) {
		end = XDR_GETPOS(c->c_ax);
		if (!XDR_SETPOS(c->c_ax, wa->pattern_pos) ||
		    !XDR_GETBYTES(c->c_ax, buf + wa->reloff_pattern,
		    wa->pattern_len) || !XDR_SETPOS(c->c_ax, end)) {
			kmem_free(buf, bs);
			return NFS4ERR_BADXDR;
		}
	}

	error = 0;
	for (i = 0; i < count && error == 0; i++) {
		if (num)
			be32enc(buf + wa->reloff_blocknum,
			    wa->block_num + (uint32_t)i);
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
		error = vn_rdwr(UIO_WRITE, vp, buf, bs, wa->offset + i * bs,
		    UIO_SYSSPACE, IO_NODELOCKED, cf->cf_cred, NULL, NULL);
		VOP_UNLOCK(vp);
	}
	kmem_free(buf, bs);
	done = (error == 0 ? i : i - 1) * bs;
	if (error != 0 && done == 0)
		return nfsv4_errno(error);

	/* As WRITE, s15.12.3, once for all the blocks. */
	committed = wa->stable;
	if (wa->stable != UNSTABLE4 && done != 0) {
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
		error = VOP_FSYNC(vp, cf->cf_cred, FSYNC_WAIT, wa->offset,
		    wa->offset + done);
		VOP_UNLOCK(vp);
		if (error != 0)
			return nfsv4_errno(error);
	}
	nfsv4_write_verf(&verf);
	return xdr_u_int32_t(c->c_rx, &none) &&
	    xdr_u_int64_t(c->c_rx, &done) &&
	    xdr_u_int32_t(c->c_rx, &committed) &&
	    nfsv4_xdr_verifier(c->c_rx, &verf) ? NFS4_OK : NFS4ERR_RESOURCE;
}
