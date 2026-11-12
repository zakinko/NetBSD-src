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
 * pNFS, RFC 8881 s12 and s13: the file layout, with this server as the
 * metadata server and as the one data server.
 *
 * The data server is reached at the address in vfs.nfsv4.pnfs_ds, as
 * "netid uaddr" (RFC 5665 s5.2.3.3), and pNFS is on while that is set.
 * A client then gets USE_PNFS_MDS and USE_PNFS_DS together (s13.1,
 * Table 8), so one client ID serves both.  The filehandle in a layout is
 * the metadata server's own (s13.3 allows it), and the stateids for I/O
 * are those of the metadata server, valid on both as s13.9.1 asks, as
 * the two are one.  So every operation on a filehandle from a layout is
 * of class 1 of s13.6, and no COMPOUND can mix the two personalities.
 *
 * A layout is a state of type NFSV4_ST_LAYOUT, one per client and file,
 * under an owner NFSV4_OWNER_LAYOUT with no name, as delegations are.
 * It covers all of the file, in the modes of st_liomode; a LAYOUTRETURN
 * of less than all of it leaves it held (s18.44.3 lets a part be
 * returned, and holding more than asked is what Table 22 allows).
 *
 * The flexible file layout, RFC 8435, is loosely coupled (s2.3.1): its
 * storage device is the NFSv3 server of this host, nfsd(8), at the
 * address in vfs.nfsv4.ff_ds, "netid uaddr directory".  The data file
 * of a file with a layout is made in that directory, which the NFSv3
 * server exports, owned by synthetic ids (s2.2).  The metadata file is
 * copied to it when the first layout of the file is given, and back at
 * LAYOUTCOMMIT and, by the lease thread, when the last is gone.  While
 * there is one, READ, WRITE and SETATTR of the size on the metadata
 * server recall the layouts and are told NFS4ERR_DELAY, so the two
 * files are never both written.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/atomic.h>
#include <sys/cprng.h>
#include <sys/endian.h>
#include <sys/fcntl.h>
#include <sys/kmem.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/systm.h>
#include <sys/vfs_syscalls.h>
#include <sys/vnode.h>

#include <fs/nfsv4/nfsv4_var.h>
#include <fs/nfsv4/nfsv4_state.h>

#define	NFS4_UINT64_MAX		UINT64_MAX	/* RFC 8881 s18.43.3 */

/* The stripe unit, a multiple of 64 (s13.3); layout_blksize too. */
#define	NFSV4_STRIPE_UNIT	NFSV4_MAXIO

#define	NFSV4_DS_NETID		16
#define	NFSV4_DS_UADDR		64

/*
 * A storage device: its address, and the generation in its device ID,
 * which changes with the address.  s12.2.10, s18.43.4: a device ID is not
 * deleted while a layout refers to it.  So a device replaced while
 * d_refs layouts refer to it is kept, as the type's retired one, until
 * they are returned or revoked, and they are recalled (s13.5, s20.3.4).
 */
struct pnfs_dev {
	char		d_netid[NFSV4_DS_NETID];
	char		d_uaddr[NFSV4_DS_UADDR];
	uint32_t	d_gen;
	u_int		d_refs;		/* layouts that refer to it */
};

static struct pnfs_dev ds_dev, ds_old;	/* the file layout's */
int nfsv4_layouts_given;		/* vfs.nfsv4.layouts_given, to be counted */

/* RFC 8435: the storage device, and the data files. */
#define	NFSV4_FF_DIR		128
#define	NFSV4_FF_NAME		(NFSV4_FF_DIR + 40)

/*
 * s2.2.1 leaves the synthetic ids to the implementation.  They are drawn
 * at random from 2^30 up, never 0 (s2.2.1), and drawn again at each
 * fencing, so that they follow no pattern (s2.2.2).
 */
#define	NFSV4_FF_IDBASE		0x40000000U
#define	NFSV4_FF_IDMASK		0x00ffffffU

/* ff_device_versions4, s4.1: NFSv3, so minor 0 and loosely coupled. */
#define	NFSV4_FF_VERSION	3
#define	NFSV4_FF_RWSIZE		MAXBSIZE	/* NFS_MAXDATA of nfsd(8) */
#define	NFSV4_FF_FHMAX		64		/* RFC 1813 s2.4, NFS3_FHSIZE */

struct ff_data {
	LIST_ENTRY(ff_data) fd_list;
	struct vnode	*fd_mvp;	/* the metadata file; its layouts' */
	struct vnode	*fd_dvp;	/* the data file, open */
	char		fd_name[NFSV4_FF_NAME];
	struct nfsv4_fh	fd_fh;		/* of NFSv3, vfs_composefh() */
	uint32_t	fd_uid;		/* s2.2: read and write */
	uint32_t	fd_gid;		/* s2.2: read */
	u_int		fd_refs;	/* layouts of LAYOUT4_FLEX_FILES */
	bool		fd_fence;	/* to be given new ids, s2.2 */
	bool		fd_dead;	/* no layouts; to be copied back */
};

static struct pnfs_dev ff_dev, ff_old;
static char ff_dir[NFSV4_FF_DIR];
static LIST_HEAD(, ff_data) ff_list = LIST_HEAD_INITIALIZER(ff_list);
static volatile u_int ff_count;		/* on ff_list */
int nfsv4_ff_fences;			/* vfs.nfsv4.ff_fences */

static volatile u_int layout_count;	/* d_refs of all the devices */

/*
 * vfs.nfsv4.layout_max, 0 for no bound: past it LAYOUTGET has none
 * readily available (s18.43.3).  From three quarters of it, the holders
 * are asked to return some, s20.6.3 ("somewhat below"), once a lease.
 */
int nfsv4_layout_max;
static time_t layout_rca_next;
static bool layout_wanted;		/* some cl_lwant is set */

static void layout_recall_type(uint32_t);
static void layout_avail(const struct nfsv4_state *);
static void layout_crowded(void);
static bool layout_full(void);
static uint32_t layout_rcamask(uint32_t, uint32_t);

/* pNFS is on; under nfsv4_state_lock, or as a hint. */
bool
nfsv4_pnfs_on(void)
{

	return ds_dev.d_uaddr[0] != '\0' || ff_dev.d_uaddr[0] != '\0';
}

/* Layouts of type t are given. */
static bool
layout_on(uint32_t t)
{

	switch (t) {
	case LAYOUT4_NFSV4_1_FILES:
		return ds_dev.d_uaddr[0] != '\0';
	case LAYOUT4_FLEX_FILES:
		return ff_dev.d_uaddr[0] != '\0';
	default:
		return false;
	}
}

static bool
layout_known(uint32_t t)
{

	return t == LAYOUT4_NFSV4_1_FILES || t == LAYOUT4_FLEX_FILES;
}

/* fs_layout_type and layout_type, s5.12.1, s5.12.3; at most 2. */
u_int
nfsv4_layout_typelist(uint32_t *types)
{
	u_int n = 0;

	if (layout_on(LAYOUT4_NFSV4_1_FILES))
		types[n++] = LAYOUT4_NFSV4_1_FILES;
	if (layout_on(LAYOUT4_FLEX_FILES))
		types[n++] = LAYOUT4_FLEX_FILES;
	return n;
}

/* The device of a layout type, or the one it has retired. */
static struct pnfs_dev *
dev_of(uint32_t type, bool old)
{

	if (type == LAYOUT4_FLEX_FILES)
		return old ? &ff_old : &ff_dev;
	return old ? &ds_old : &ds_dev;
}

/*
 * s3.3.14: the device ID of each layout type and generation; not valid
 * across restarts, s12.2.10.
 */
static void
ds_devid(uint8_t *id, uint32_t type, uint32_t gen)
{

	memset(id, 0, NFS4_DEVICEID4_SIZE);
	be32enc(id, nfsv4_boot);
	be32enc(id + 4, gen);
	memcpy(id + 8, type == LAYOUT4_FLEX_FILES ? "NetBSDff" : "NetBSDds",
	    8);
}

/*
 * The device ID of type and gen is deleted: no layout refers to it.
 * s20.12.3: NOTIFY_DEVICEID4_DELETE to the clients that asked for it by
 * GETDEVICEINFO, s18.40.3, and the asking is forgotten.  The generation
 * only goes up, so the ID is not used again (s20.12.3).
 */
static void
dev_deleted(uint32_t type, uint32_t gen)
{
	struct nfsv4_client *cl;
	struct nfsv4_devnote *dn;
	uint8_t id[NFS4_DEVICEID4_SIZE];
	u_int i;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	ds_devid(id, type, gen);
	for (cl = nfsv4_client_next(NULL); cl != NULL;
	    cl = nfsv4_client_next(cl)) {
		for (i = 0; i < NFSV4_DEVNOTES; i++) {
			dn = &cl->cl_devnote[i];
			if (dn->dn_mask == 0 || dn->dn_type != type ||
			    dn->dn_gen != gen)
				continue;
			if ((dn->dn_mask & 1U << NOTIFY_DEVICEID4_DELETE) != 0)
				nfsv4_cb_notify_deviceid(cl, type, id);
			memset(dn, 0, sizeof(*dn));
		}
	}
}

/*
 * The device of type is to have a new address.  If layouts refer to it,
 * it is retired and they are recalled; else its ID is deleted now.  An
 * earlier retired one that layouts still refer to cannot be put aside:
 * EBUSY, after recalling those of the present one, so that asking again
 * once they are back succeeds.
 */
static int
dev_replace(uint32_t type)
{
	struct pnfs_dev *d = dev_of(type, false), *o = dev_of(type, true);

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if (d->d_refs != 0 && o->d_refs != 0) {
		layout_recall_type(type);
		return EBUSY;
	}
	if (d->d_refs != 0) {
		*o = *d;
		d->d_refs = 0;
		layout_recall_type(type);
	} else
		dev_deleted(type, d->d_gen);
	d->d_gen++;
	return 0;
}

/*
 * vfs.nfsv4.pnfs_ds: "netid uaddr", or "" for off.  A new address is a
 * new device ID; the old one goes as dev_replace() says.
 */
int
nfsv4_layout_setds(const char *line)
{
	const char *sp = NULL;
	size_t n = 0;
	int error;

	if (*line != '\0') {
		sp = strchr(line, ' ');
		if (sp == NULL || (n = sp - line) == 0 ||
		    n >= sizeof(ds_dev.d_netid) || sp[1] == '\0' ||
		    strlen(sp + 1) >= sizeof(ds_dev.d_uaddr) ||
		    strchr(sp + 1, ' ') != NULL)
			return EINVAL;
	}
	mutex_enter(&nfsv4_state_lock);
	error = dev_replace(LAYOUT4_NFSV4_1_FILES);
	if (error == 0 && sp == NULL)
		ds_dev.d_uaddr[0] = ds_dev.d_netid[0] = '\0';
	else if (error == 0) {
		memcpy(ds_dev.d_netid, line, n);
		ds_dev.d_netid[n] = '\0';
		strlcpy(ds_dev.d_uaddr, sp + 1, sizeof(ds_dev.d_uaddr));
	}
	mutex_exit(&nfsv4_state_lock);
	return error;
}

/*
 * vfs.nfsv4.ff_ds: "netid uaddr directory" of the storage device of the
 * flexible file layout, RFC 8435, or "" for none.  The directory is
 * where the data files are made; the NFSv3 server must export it.
 */
int
nfsv4_layout_setff(const char *line)
{
	const char *sp = NULL, *sp2 = NULL;
	size_t n = 0, u = 0;
	int error;

	if (*line != '\0') {
		sp = strchr(line, ' ');
		if (sp == NULL || (n = sp - line) == 0 ||
		    n >= sizeof(ff_dev.d_netid))
			return EINVAL;
		sp2 = strchr(sp + 1, ' ');
		if (sp2 == NULL || (u = sp2 - sp - 1) == 0 ||
		    u >= sizeof(ff_dev.d_uaddr) || sp2[1] != '/' ||
		    strlen(sp2 + 1) >= sizeof(ff_dir) ||
		    strchr(sp2 + 1, ' ') != NULL)
			return EINVAL;
	}
	mutex_enter(&nfsv4_state_lock);
	error = dev_replace(LAYOUT4_FLEX_FILES);
	if (error == 0 && sp == NULL)
		ff_dev.d_uaddr[0] = ff_dev.d_netid[0] = ff_dir[0] = '\0';
	else if (error == 0) {
		memcpy(ff_dev.d_netid, line, n);
		ff_dev.d_netid[n] = '\0';
		memcpy(ff_dev.d_uaddr, sp + 1, u);
		ff_dev.d_uaddr[u] = '\0';
		strlcpy(ff_dir, sp2 + 1, sizeof(ff_dir));
	}
	mutex_exit(&nfsv4_state_lock);
	return error;
}

/* The roles of EXCHANGE_ID, s13.1: ours and what the client asked. */
uint32_t
nfsv4_pnfs_flags(uint32_t asked, bool *pnfsp)
{

	/*
	 * Table 8 and the paragraph after it: the higher of the roles,
	 * matching the client's where possible; one that asks only to be
	 * a client of a non-pNFS server is given that.
	 */
	*pnfsp = nfsv4_pnfs_on() && (asked & EXCHGID4_FLAG_MASK_PNFS) !=
	    EXCHGID4_FLAG_USE_NON_PNFS;
	return *pnfsp ? EXCHGID4_FLAG_USE_PNFS_MDS | EXCHGID4_FLAG_USE_PNFS_DS :
	    EXCHGID4_FLAG_USE_NON_PNFS;
}

/* s13.1: of a server that is not a metadata server, these are unknown. */
static uint32_t
layout_client(const struct nfsv4_compound *c)
{

	if (c->c_client == NULL || !c->c_client->cl_pnfs)
		return NFS4ERR_NOTSUPP;
	return NFS4_OK;
}

/* s12.5.5.2.1.4: the seqid goes round past 0, which is never used. */
static void
layout_bump(struct nfsv4_state *st)
{

	if (++st->st_seqid == 0)
		st->st_seqid = 1;
}

/*
 * The layout stateid si, for this client and vp.  s12.5.5.2.1.4: a seqid
 * of 0 or ahead of the server's is BAD_STATEID; any one behind is within
 * VALID_SEQID_RANGE, which is taken at its maximum, 2^32 - 2.
 */
static uint32_t
layout_lookup(const struct nfsv4_compound *c, const struct nfsv4_stateid *si,
    struct vnode *vp, struct nfsv4_state **stp)
{
	struct nfsv4_state *st;
	uint32_t status;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if (si->si_seqid == 0)
		return NFS4ERR_BAD_STATEID;
	status = nfsv4_stateid_lookup(c, si, &st);
	if (status != NFS4_OK)
		return status;
	if (st->st_type != NFSV4_ST_LAYOUT)
		return NFS4ERR_BAD_STATEID;
	if (st->st_revoked)
		return NFS4ERR_DELEG_REVOKED;	/* s8.2.4, of any revoked */
	if (st->st_file == NULL)
		return NFS4ERR_BAD_STATEID;	/* s12.5.3, all returned */
	if (vp != NULL && st->st_file->f_vp != vp)
		return NFS4ERR_BAD_STATEID;
	if ((int32_t)(si->si_seqid - st->st_seqid) > 0)
		return NFS4ERR_BAD_STATEID;
	nfsv4_client_renew(st->st_owner->sw_client);
	*stp = st;
	return NFS4_OK;
}

/*
 * s12.9: pNFS MUST NOT remove the open modes.  A layout for writing is
 * of a client that has the file open for writing, or a write delegation
 * of it; the synthetic uid of RFC 8435 s2.2 would let it write anyway.
 */
static bool
layout_may_write(const struct nfsv4_client *cl, struct vnode *vp)
{
	struct nfsv4_file *f;
	struct nfsv4_state *st;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if ((f = nfsv4_file_find(vp)) == NULL)
		return false;
	LIST_FOREACH(st, &f->f_states, st_flist) {
		if (st->st_owner->sw_client != cl)
			continue;
		if (st->st_type == NFSV4_ST_OPEN &&
		    (st->st_access & OPEN4_SHARE_ACCESS_WRITE) != 0)
			return true;
		if (st->st_type == NFSV4_ST_DELEG &&
		    st->st_dtype == OPEN_DELEGATE_WRITE)
			return true;
	}
	return false;
}

/* This client's layout on vp, if it has one. */
static struct nfsv4_state *
layout_find(const struct nfsv4_client *cl, struct vnode *vp)
{
	struct nfsv4_file *f;
	struct nfsv4_state *st;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if ((f = nfsv4_file_find(vp)) == NULL)
		return NULL;
	LIST_FOREACH(st, &f->f_states, st_flist) {
		if (st->st_type == NFSV4_ST_LAYOUT &&
		    st->st_owner->sw_client == cl)
			return st;
	}
	return NULL;
}

/* RFC 8435: the data file of the metadata file vp, under the lock. */
static struct ff_data *
ff_find(struct vnode *vp)
{
	struct ff_data *fd;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	LIST_FOREACH(fd, &ff_list, fd_list) {
		if (fd->fd_mvp == vp)
			return fd;
	}
	return NULL;
}

/* s2.2.1, s2.2.2: new synthetic ids, the two not the same. */
static void
ff_ids(struct ff_data *fd)
{
	uint32_t u, g;

	u = NFSV4_FF_IDBASE + (cprng_fast32() & NFSV4_FF_IDMASK);
	do
		g = NFSV4_FF_IDBASE + (cprng_fast32() & NFSV4_FF_IDMASK);
	while (g == u || g == fd->fd_gid);
	if (u == fd->fd_uid)
		u = g + 1;
	fd->fd_uid = u;
	fd->fd_gid = g;
}

/* Give the data file the ids of fd and the modes of s2.2; locked. */
static int
ff_own(struct ff_data *fd)
{
	struct vattr va;

	vattr_null(&va);
	va.va_uid = fd->fd_uid;
	va.va_gid = fd->fd_gid;
	va.va_mode = 0640;	/* s2.2: uid reads and writes, gid reads */
	return VOP_SETATTR(fd->fd_dvp, &va, lwp0.l_cred);
}

/* Make to the same as from, both locked. */
static int
ff_copy(struct vnode *from, struct vnode *to)
{
	struct vattr va;
	kauth_cred_t cred = lwp0.l_cred;
	off_t off, size;
	size_t n, resid;
	char *buf;
	int error;

	if ((error = VOP_GETATTR(from, &va, cred)) != 0)
		return error;
	size = va.va_size;
	vattr_null(&va);
	va.va_size = size;
	if ((error = VOP_SETATTR(to, &va, cred)) != 0)
		return error;
	buf = kmem_alloc(MAXBSIZE, KM_SLEEP);
	for (off = 0; error == 0 && off < size; off += n) {
		n = MIN(MAXBSIZE, size - off);
		error = vn_rdwr(UIO_READ, from, buf, n, off, UIO_SYSSPACE,
		    IO_NODELOCKED, cred, &resid, curlwp);
		if (error == 0 && resid != 0)
			error = EIO;
		if (error == 0)
			error = vn_rdwr(UIO_WRITE, to, buf, n, off,
			    UIO_SYSSPACE, IO_NODELOCKED, cred, NULL, curlwp);
	}
	kmem_free(buf, MAXBSIZE);
	return error;
}

/* What a layout is made of, taken under the lock. */
struct ff_snap {
	struct nfsv4_fh	fs_fh;
	uint32_t	fs_uid;
	uint32_t	fs_gid;
};

/*
 * Take a reference to the data file of vp, made and filled from vp if
 * there is none.  A data file that is to be copied back first is
 * NFS4ERR_LAYOUTTRYLATER, the layout being unavailable for a time
 * (RFC 8881 s18.43.3), and the lease thread is woken to do it.
 */
static uint32_t
ff_attach(struct vnode *vp, struct ff_snap *sn)
{
	struct ff_data *fd, *nfd;
	struct pathbuf *pb;
	struct vattr va;
	char dir[NFSV4_FF_DIR];
	bool dead = false;
	int error;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	mutex_enter(&nfsv4_state_lock);
	fd = ff_find(vp);
	if (fd != NULL && !fd->fd_dead) {
		fd->fd_refs++;
		sn->fs_fh = fd->fd_fh;
		sn->fs_uid = fd->fd_uid;
		sn->fs_gid = fd->fd_gid;
	}
	if (fd != NULL && fd->fd_dead) {
		dead = true;
		cv_broadcast(&nfsv4_state_cv);
	}
	strlcpy(dir, ff_dir, sizeof(dir));
	mutex_exit(&nfsv4_state_lock);
	if (fd != NULL) {
		VOP_UNLOCK(vp);
		return dead ? NFS4ERR_LAYOUTTRYLATER : NFS4_OK;
	}
	if (dir[0] == '\0') {
		VOP_UNLOCK(vp);
		return NFS4ERR_LAYOUTUNAVAILABLE;
	}

	nfd = kmem_zalloc(sizeof(*nfd), KM_SLEEP);
	nfd->fd_mvp = vp;
	nfd->fd_refs = 1;
	ff_ids(nfd);
	error = VOP_GETATTR(vp, &va, lwp0.l_cred);
	if (error != 0)
		goto fail;
	snprintf(nfd->fd_name, sizeof(nfd->fd_name), "%s/%llx.%llx", dir,
	    (unsigned long long)va.va_fsid, (unsigned long long)va.va_fileid);
	pb = pathbuf_create(nfd->fd_name);
	if (pb == NULL) {
		error = ENOMEM;
		goto fail;
	}
	error = vn_open(NULL, pb, 0, FREAD | FWRITE | O_CREAT | O_TRUNC |
	    O_NOFOLLOW, 0600, &nfd->fd_dvp, NULL, NULL);
	pathbuf_destroy(pb);
	if (error != 0)
		goto fail;
	if (nfd->fd_dvp->v_type != VREG)
		error = EINVAL;
	if (error == 0)
		error = ff_own(nfd);
	if (error == 0)
		error = ff_copy(vp, nfd->fd_dvp);
	if (error == 0) {
		size_t len = sizeof(nfd->fd_fh.fh_data);

		error = vfs_composefh(nfd->fd_dvp,
		    (fhandle_t *)nfd->fd_fh.fh_data, &len);
		nfd->fd_fh.fh_len = len;
		if (error == 0 && len > NFSV4_FF_FHMAX)
			error = EOPNOTSUPP;
	}
	VOP_UNLOCK(nfd->fd_dvp);
	if (error != 0) {
		(void)vn_close(nfd->fd_dvp, FREAD | FWRITE, lwp0.l_cred);
		(void)do_sys_unlink(nfd->fd_name, UIO_SYSSPACE);
		goto fail;
	}
	sn->fs_fh = nfd->fd_fh;
	sn->fs_uid = nfd->fd_uid;
	sn->fs_gid = nfd->fd_gid;
	mutex_enter(&nfsv4_state_lock);
	LIST_INSERT_HEAD(&ff_list, nfd, fd_list);
	atomic_inc_uint(&ff_count);
	mutex_exit(&nfsv4_state_lock);
	VOP_UNLOCK(vp);
	return NFS4_OK;
fail:
	VOP_UNLOCK(vp);
	kmem_free(nfd, sizeof(*nfd));
	return nfsv4_errno(error);
}

/* A reference to the data file of fd is gone; under the lock. */
static void
ff_unref(struct ff_data *fd)
{

	KASSERT(mutex_owned(&nfsv4_state_lock));
	KASSERT(fd->fd_refs > 0);

	if (--fd->fd_refs == 0) {
		fd->fd_dead = true;
		vref(fd->fd_mvp);	/* the layouts' may go */
		cv_broadcast(&nfsv4_state_cv);
	}
}

/* Of a layout ending, from nfsv4_state_unlink(). */
void
nfsv4_layout_gone(struct nfsv4_state *st)
{
	struct ff_data *fd;

	struct pnfs_dev *d, *o;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	d = dev_of(st->st_ltype, false);
	o = dev_of(st->st_ltype, true);
	atomic_dec_uint(&layout_count);
	if (st->st_lgen == d->d_gen) {
		KASSERT(d->d_refs > 0);
		d->d_refs--;
	} else if (o->d_refs != 0 && st->st_lgen == o->d_gen &&
	    --o->d_refs == 0)
		dev_deleted(st->st_ltype, o->d_gen);
	layout_avail(st);
	if (st->st_ltype != LAYOUT4_FLEX_FILES || st->st_file == NULL)
		return;
	fd = ff_find(st->st_file->f_vp);
	KASSERT(fd != NULL && !fd->fd_dead);
	/* s2.3.1: what the client was not told of is fenced, s2.2. */
	if (st->st_lfence)
		fd->fd_fence = true;
	ff_unref(fd);
}

/*
 * The lease thread: give fenced data files new ids, s2.2, and copy back
 * and remove those with no layout.  Each under its metadata file's lock,
 * which ff_attach() and LAYOUTCOMMIT take too.
 */
void
nfsv4_ff_reap(void)
{
	struct ff_data *fd;
	struct vnode *mvp;
	bool dead, fence;
	int error;

	for (;;) {
		mutex_enter(&nfsv4_state_lock);
		LIST_FOREACH(fd, &ff_list, fd_list) {
			if (fd->fd_dead || fd->fd_fence)
				break;
		}
		if (fd == NULL) {
			mutex_exit(&nfsv4_state_lock);
			return;
		}
		mvp = fd->fd_mvp;
		vref(mvp);
		mutex_exit(&nfsv4_state_lock);

		vn_lock(mvp, LK_EXCLUSIVE | LK_RETRY);
		mutex_enter(&nfsv4_state_lock);
		fence = fd->fd_fence;
		fd->fd_fence = false;
		if (fence)
			ff_ids(fd);
		dead = fd->fd_dead;
		if (dead) {
			LIST_REMOVE(fd, fd_list);
			atomic_dec_uint(&ff_count);
		}
		mutex_exit(&nfsv4_state_lock);
		vn_lock(fd->fd_dvp, LK_EXCLUSIVE | LK_RETRY);
		if (fence) {
			error = ff_own(fd);
			if (error == 0)
				atomic_inc_uint((volatile u_int *)
				    &nfsv4_ff_fences);
			else
				printf("nfsv4: fencing %s: error %d\n",
				    fd->fd_name, error);
		}
		if (dead && (error = ff_copy(fd->fd_dvp, mvp)) != 0)
			printf("nfsv4: copying back %s: error %d\n",
			    fd->fd_name, error);
		VOP_UNLOCK(fd->fd_dvp);
		VOP_UNLOCK(mvp);
		vrele(mvp);
		if (dead) {
			(void)vn_close(fd->fd_dvp, FREAD | FWRITE,
			    lwp0.l_cred);
			(void)do_sys_unlink(fd->fd_name, UIO_SYSSPACE);
			vrele(fd->fd_mvp);	/* of ff_unref() */
			kmem_free(fd, sizeof(*fd));
		}
	}
}

/* vfs.nfsv4.ff_fence: fence every data file now, s2.2. */
void
nfsv4_ff_fence_all(void)
{
	struct ff_data *fd;

	mutex_enter(&nfsv4_state_lock);
	LIST_FOREACH(fd, &ff_list, fd_list)
		fd->fd_fence = true;
	cv_broadcast(&nfsv4_state_cv);
	mutex_exit(&nfsv4_state_lock);
}

/* Drop the reference ff_attach() took for a LAYOUTGET that made none. */
static void
ff_drop(struct vnode *vp)
{
	struct ff_data *fd;

	mutex_enter(&nfsv4_state_lock);
	fd = ff_find(vp);
	KASSERT(fd != NULL && !fd->fd_dead);
	ff_unref(fd);
	mutex_exit(&nfsv4_state_lock);
}

/* LAYOUTCOMMIT: the data file's contents to vp, which is locked. */
static int
ff_commit(struct vnode *vp)
{
	struct ff_data *fd;
	struct vnode *dvp;
	int error;

	mutex_enter(&nfsv4_state_lock);
	fd = ff_find(vp);
	dvp = fd != NULL ? fd->fd_dvp : NULL;
	mutex_exit(&nfsv4_state_lock);
	/* Under vp's lock, the lease thread cannot close dvp. */
	if (dvp == NULL)
		return 0;
	vn_lock(dvp, LK_EXCLUSIVE | LK_RETRY);
	error = ff_copy(dvp, vp);
	VOP_UNLOCK(dvp);
	return error;
}

static void
layout_recall(struct nfsv4_state *st)
{

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if (st->st_file == NULL || st->st_lrecall)
		return;
	layout_bump(st);
	st->st_lrecall = true;
	st->st_lanswered = false;
	st->st_lrend = time_uptime + NFSV4_LEASE;
	if (!nfsv4_cb_layoutrecall(st))
		st->st_lrecall = false;
}

/*
 * I/O on the metadata server to vp, of which there is a data file: the
 * layouts are recalled, and it waits for them, RFC 8435 s2.  Also while
 * the data file is to be copied back.
 */
uint32_t
nfsv4_layout_ff_conflict(struct vnode *vp)
{
	struct nfsv4_file *f;
	struct nfsv4_state *st;
	struct ff_data *fd;
	uint32_t status = NFS4_OK;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if (atomic_load_relaxed(&ff_count) == 0 || (fd = ff_find(vp)) == NULL)
		return NFS4_OK;
	if (fd->fd_dead) {
		cv_broadcast(&nfsv4_state_cv);
		return NFS4ERR_DELAY;
	}
	if ((f = nfsv4_file_find(vp)) == NULL)
		return NFS4_OK;
	LIST_FOREACH(st, &f->f_states, st_flist) {
		if (st->st_type == NFSV4_ST_LAYOUT &&
		    st->st_ltype == LAYOUT4_FLEX_FILES) {
			status = NFS4ERR_DELAY;
			layout_recall(st);
		}
	}
	return status;
}

/*
 * da_addr_body of s3.3.15: s13.3, nfsv4_1_file_layout_ds_addr4, or RFC
 * 8435 s4.1, ff_device_addr4.
 */
static u_int
ds_addr_len(uint32_t type, const struct pnfs_dev *d)
{
	size_t n, u;

	n = strlen(d->d_netid);
	u = strlen(d->d_uaddr);
	/* netaddrs<1>, versions<1> of five words */
	if (type == LAYOUT4_FLEX_FILES)
		return 4 + 4 + roundup(n, 4) + 4 + roundup(u, 4) + 4 + 5 * 4;
	/* indices<1>, list<1> of multipath<1> of netaddr4 */
	return 4 + 4 + 4 + 4 + 4 + roundup(n, 4) + 4 + roundup(u, 4);
}

static bool
ds_addr_put(XDR *x, uint32_t type, struct pnfs_dev *d)
{
	char *n = d->d_netid, *u = d->d_uaddr;

	if (type == LAYOUT4_FLEX_FILES) {
		/* s4.1: version 3 MUST have minor 0 and not tightly coupled */
		return nfsv4_xdr_u32(x, 1) &&
		    xdr_string(x, &n, NFSV4_DS_NETID) &&
		    xdr_string(x, &u, NFSV4_DS_UADDR) &&
		    nfsv4_xdr_u32(x, 1) &&
		    nfsv4_xdr_u32(x, NFSV4_FF_VERSION) &&
		    nfsv4_xdr_u32(x, 0) &&
		    nfsv4_xdr_u32(x, NFSV4_FF_RWSIZE) &&
		    nfsv4_xdr_u32(x, NFSV4_FF_RWSIZE) &&
		    nfsv4_xdr_u32(x, 0);
	}
	return nfsv4_xdr_u32(x, 1) && nfsv4_xdr_u32(x, 0) &&
	    nfsv4_xdr_u32(x, 1) && nfsv4_xdr_u32(x, 1) &&
	    xdr_string(x, &n, NFSV4_DS_NETID) &&
	    xdr_string(x, &u, NFSV4_DS_UADDR);
}

/*
 * The device of type whose ID is id, present or retired, copied to *dv;
 * false if there is none.
 */
static bool
dev_find(uint32_t type, const uint8_t *id, struct pnfs_dev *dv)
{
	struct pnfs_dev *d = dev_of(type, false), *o = dev_of(type, true);
	uint8_t did[NFS4_DEVICEID4_SIZE];

	KASSERT(mutex_owned(&nfsv4_state_lock));

	ds_devid(did, type, d->d_gen);
	if (d->d_uaddr[0] != '\0' &&
	    memcmp(did, id, NFS4_DEVICEID4_SIZE) == 0) {
		*dv = *d;
		return true;
	}
	ds_devid(did, type, o->d_gen);
	if (o->d_refs != 0 && memcmp(did, id, NFS4_DEVICEID4_SIZE) == 0) {
		*dv = *o;
		return true;
	}
	return false;
}

/*
 * s18.40.3: the notifications a client asks for, of one device ID; the
 * last asking counts, and an empty one turns them off.  Only deletion is
 * ever sent: a device ID keeps its address (dev_replace()).  The bits
 * that will be sent are returned.
 */
static uint32_t
dev_note(struct nfsv4_client *cl, uint32_t type, uint32_t gen,
    const struct nfsv4_bitmap *bm)
{
	struct nfsv4_devnote *dn, *free = NULL;
	uint32_t mask;
	u_int i;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	mask = bm->bm_n > 0 ? bm->bm_w[0] & 1U << NOTIFY_DEVICEID4_DELETE : 0;
	for (i = 0; i < NFSV4_DEVNOTES; i++) {
		dn = &cl->cl_devnote[i];
		if (dn->dn_mask != 0 && dn->dn_type == type &&
		    dn->dn_gen == gen) {
			dn->dn_mask = mask;
			return mask;
		}
		if (dn->dn_mask == 0 && free == NULL)
			free = dn;
	}
	/*
	 * Two of each layout type, present and retired, are all that can
	 * be known at once, and one deleted is forgotten; so there is room.
	 */
	if (mask == 0 || free == NULL)
		return 0;
	free->dn_type = type;
	free->dn_gen = gen;
	free->dn_mask = mask;
	return mask;
}

/* s18.40, GETDEVICEINFO */
uint32_t
nfsv4_op_getdeviceinfo(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_getdeviceinfo *ga = &a->getdeviceinfo;
	struct pnfs_dev dv;
	uint32_t status, len, need, note = 0;
	bool ok, found;

	if ((status = layout_client(c)) != NFS4_OK)
		return status;
	if (!layout_known(ga->type))
		return NFS4ERR_UNKNOWN_LAYOUTTYPE;
	mutex_enter(&nfsv4_state_lock);
	found = dev_find(ga->type, ga->devid, &dv);
	if (found)
		note = dev_note(c->c_client, ga->type, dv.d_gen, &ga->notify);
	mutex_exit(&nfsv4_state_lock);
	if (!found)
		return NFS4ERR_NOENT;
	len = ds_addr_len(ga->type, &dv);
	/* type, body<>, and gdir_notification of one word or none */
	need = 4 + 4 + len + 4 + (note != 0 ? 4 : 0);
	/* s18.40.3: maxcount 0 has an empty body, never TOOSMALL. */
	if (ga->maxcount != 0 && ga->maxcount < need) {
		(void)nfsv4_xdr_u32(c->c_rx, need);	/* gdir_mincount */
		return NFS4ERR_TOOSMALL;
	}
	if (ga->maxcount == 0)
		len = 0;
	ok = nfsv4_xdr_u32(c->c_rx, ga->type) &&
	    nfsv4_xdr_u32(c->c_rx, len);
	if (ok && len != 0)
		ok = ds_addr_put(c->c_rx, ga->type, &dv);
	if (ok && note != 0)
		ok = nfsv4_xdr_u32(c->c_rx, 1) && nfsv4_xdr_u32(c->c_rx, note);
	else if (ok)
		ok = nfsv4_xdr_u32(c->c_rx, 0);
	if (!ok)
		return NFS4ERR_RESOURCE;
	return NFS4_OK;
}

/* s18.41, GETDEVICELIST: the one device, whatever the file system. */
uint32_t
nfsv4_op_getdevicelist(struct nfsv4_compound *c, union nfsv4_args *a)
{
	const struct nfsv4_args_getdevicelist *ga = &a->getdevicelist;
	uint8_t id[NFS4_DEVICEID4_SIZE];
	struct nfsv4_verifier verf;
	uint32_t status, n;
	bool on;

	if ((status = layout_client(c)) != NFS4_OK)
		return status;
	if (!layout_known(ga->type))
		return NFS4ERR_UNKNOWN_LAYOUTTYPE;
	if (c->c_cur.cf_vp == NULL)
		return NFS4ERR_NOTSUPP;		/* the pseudo file system */
	if (ga->maxdevices == 0)
		return NFS4ERR_INVAL;		/* s18.41.3 */
	mutex_enter(&nfsv4_state_lock);
	ds_devid(id, ga->type, dev_of(ga->type, false)->d_gen);
	on = layout_on(ga->type);
	mutex_exit(&nfsv4_state_lock);
	/* The verifier is the generation; a cookie of 0 needs none. */
	memset(&verf, 0, sizeof(verf));
	memcpy(verf.v_data, id + 4, 4);
	if (ga->cookie != 0 &&
	    memcmp(&verf, &ga->verf, sizeof(verf)) != 0)
		return NFS4ERR_NOT_SAME;
	n = on && ga->cookie == 0 ? 1 : 0;
	if (ga->cookie > 1)
		return NFS4ERR_BAD_COOKIE;
	if (!xdr_u_int64_t(c->c_rx, &(uint64_t){ n }) ||
	    !nfsv4_xdr_verifier(c->c_rx, &verf) ||
	    !nfsv4_xdr_u32(c->c_rx, n) ||
	    (n != 0 && !XDR_PUTBYTES(c->c_rx, (char *)id, sizeof(id))) ||
	    !nfsv4_xdr_u32(c->c_rx, ga->cookie != 0 || n != 0))
		return NFS4ERR_RESOURCE;
	return NFS4_OK;
}

/*
 * s18.43, LAYOUTGET.  The layout is all of the file, in the mode asked:
 * offset 0 and length NFS4_UINT64_MAX meet every row of Table 22 and
 * Table 23.
 */
uint32_t
nfsv4_op_layoutget(struct nfsv4_compound *c, union nfsv4_args *a)
{
	struct nfsv4_args_layoutget *la = &a->layoutget;
	struct vnode *vp = c->c_cur.cf_vp;
	struct nfsv4_state *st, *sst = NULL, *ost;
	struct nfsv4_owner_s *sw, *ssw = NULL;
	struct nfsv4_file *sf = NULL;
	struct nfsv4_stateid si;
	struct nfsv4_fh fh = c->c_cur.cf_fh;
	struct ff_snap sn;
	uint8_t id[NFS4_DEVICEID4_SIZE];
	char user[12], group[12];
	uint32_t status, need, body, util;
	size_t ul, gl;
	bool ff = la->type == LAYOUT4_FLEX_FILES, held = false, signal = false;
	XDR *x = c->c_rx;

	if ((status = layout_client(c)) != NFS4_OK)
		return status;
	if ((status = nfsv4_file_check(c, &c->c_cur)) != NFS4_OK)
		return status;
	if (!layout_known(la->type))
		return NFS4ERR_UNKNOWN_LAYOUTTYPE;
	if (la->iomode != LAYOUTIOMODE4_READ && la->iomode != LAYOUTIOMODE4_RW)
		return NFS4ERR_BADIOMODE;
	if (la->length < la->minlength)
		return NFS4ERR_INVAL;
	if (la->minlength != NFS4_UINT64_MAX &&
	    la->offset > NFS4_UINT64_MAX - la->minlength)
		return NFS4ERR_INVAL;
	if (la->length != NFS4_UINT64_MAX &&
	    la->offset > NFS4_UINT64_MAX - la->length)
		return NFS4ERR_INVAL;
	/* s18.43.3: layouts are not kept across a restart. */
	if (nfsv4_grace_active())
		return NFS4ERR_GRACE;
	if (ff) {
		/* RFC 8435 s5.1, ff_layout4 of one mirror of one server. */
		body = 8 + 4 + 4 + NFS4_DEVICEID4_SIZE + 4 + 16 + 4 +
		    4 + NFSV4_FF_FHMAX + 4 + 12 + 4 + 12 + 4 + 4;
	} else {
		/* nfl_fh_list<1>, s13.3, in layout_content4 of one layout4. */
		body = NFS4_DEVICEID4_SIZE + 4 + 4 + 8 + 4 + 4 +
		    roundup(fh.fh_len, 4);
	}
	need = 4 + 16 + 4 + 8 + 8 + 4 + 4 + 4 + body;
	if (la->maxcount < need)
		return NFS4ERR_TOOSMALL;
	if (ff && (status = ff_attach(vp, &sn)) != NFS4_OK) {
		/* s18.43.2: logr_will_signal_layout_avail, not given */
		if (status == NFS4ERR_LAYOUTTRYLATER)
			(void)nfsv4_xdr_u32(x, 0);
		return status;
	}

	ssw = kmem_zalloc(sizeof(*ssw), KM_SLEEP);
	sst = kmem_zalloc(sizeof(*sst), KM_SLEEP);
	sf = kmem_zalloc(sizeof(*sf), KM_SLEEP);
	mutex_enter(&nfsv4_state_lock);
	if (!layout_on(la->type)) {
		status = NFS4ERR_LAYOUTUNAVAILABLE;
		goto out;
	}
	st = layout_find(c->c_client, vp);
	/*
	 * One layout of a file to a client, of one type.  s18.43.3: layouts
	 * are given, but none that matches: BADLAYOUT, or LAYOUTTRYLATER for
	 * a loga_minlength of 0, which Table 22 does not bind.
	 */
	if (st != NULL && st->st_ltype != la->type) {
		status = la->minlength == 0 ? NFS4ERR_LAYOUTTRYLATER :
		    NFS4ERR_BADLAYOUT;
		goto out;
	}
	status = nfsv4_stateid_lookup(c, &la->stateid, &ost);
	if (status != NFS4_OK)
		goto out;
	if (ost->st_type == NFSV4_ST_LAYOUT) {
		status = layout_lookup(c, &la->stateid, vp, &ost);
		if (status != NFS4_OK)
			goto out;
		st = ost;
	} else {
		/*
		 * s18.43.3: the open, lock or delegation stateid comes only
		 * before a layout is held; after, the layout's own.
		 */
		if (st != NULL) {
			status = NFS4ERR_BAD_STATEID;
			goto out;
		}
		status = nfsv4_stateid_check(&la->stateid, ost, vp, 0);
		if (status != NFS4_OK)
			goto out;
	}
	if (la->iomode == LAYOUTIOMODE4_RW &&
	    !layout_may_write(c->c_client, vp)) {
		status = NFS4ERR_OPENMODE;
		goto out;
	}
	/* Of a retired device, s12.2.10: it is to come back first. */
	if (st != NULL && st->st_lgen != dev_of(la->type, false)->d_gen)
		layout_recall(st);
	/* s12.5.5.2.1.3: a recall of it not yet done. */
	if (st != NULL && st->st_lrecall) {
		status = st->st_lanswered ? NFS4ERR_RETURNCONFLICT :
		    NFS4ERR_RECALLCONFLICT;
		goto out;
	}
	if (st == NULL && layout_full()) {
		/* s18.43.3, resource exhaustion: the want is honoured */
		if (la->signal) {
			c->c_client->cl_lwant |= layout_rcamask(la->type,
			    1U << la->iomode);
			layout_wanted = true;
		}
		signal = la->signal != 0;
		status = NFS4ERR_LAYOUTTRYLATER;
		goto out;
	}
	if (st == NULL) {
		sw = nfsv4_owner_find(c->c_client, NFSV4_OWNER_LAYOUT,
		    (const uint8_t *)"", 0);
		if (sw == NULL) {
			sw = nfsv4_owner_add(c->c_client, &ssw,
			    NFSV4_OWNER_LAYOUT, (const uint8_t *)"", 0);
			sw->sw_confirmed = true;
		}
		st = nfsv4_state_add(&sst, sw, &sf, vp, NFSV4_ST_LAYOUT);
		st->st_ltype = la->type;
		st->st_lgen = dev_of(la->type, false)->d_gen;
		dev_of(la->type, false)->d_refs++;
		atomic_inc_uint(&layout_count);
		layout_crowded();
		held = ff;		/* the reference of ff_attach() */
		if (st->st_file->f_fh.fh_len == 0)
			st->st_file->f_fh = fh;
	} else
		layout_bump(st);		/* s12.5.3 */
	st->st_liomode |= 1U << la->iomode;
	/* s2.10.6.3: what a recall of it is to refer to. */
	if (c->c_sess != NULL && c->c_slot != NULL) {
		st->st_refset = true;
		st->st_refsid = c->c_sess->se_id;
		st->st_refslot = c->c_slot - c->c_sess->se_slots;
		st->st_refseq = c->c_slot->sl_seq;
	}
	nfsv4_stateid_out(st, &si);
	ds_devid(id, la->type, st->st_lgen);
	mutex_exit(&nfsv4_state_lock);
	if (ff && !held)
		ff_drop(vp);

	if (!nfsv4_xdr_u32(x, 0) ||			/* return_on_close */
	    !nfsv4_xdr_stateid(x, &si) ||
	    !nfsv4_xdr_u32(x, 1) ||			/* logr_layout<> */
	    !xdr_u_int64_t(x, &(uint64_t){ 0 }) ||
	    !xdr_u_int64_t(x, &(uint64_t){ NFS4_UINT64_MAX }) ||
	    !nfsv4_xdr_u32(x, la->iomode) ||
	    !nfsv4_xdr_u32(x, la->type)) {
		status = NFS4ERR_RESOURCE;
		goto done;
	}
	if (ff) {
		/*
		 * RFC 8435 s2.2.2: of a layout for reading, a uid that is
		 * not the data file's; the gid gives the reading.
		 */
		snprintf(user, sizeof(user), "%u",
		    la->iomode == LAYOUTIOMODE4_RW ? sn.fs_uid : sn.fs_gid);
		snprintf(group, sizeof(group), "%u", sn.fs_gid);
		ul = strlen(user);
		gl = strlen(group);
		body = 8 + 4 + 4 + NFS4_DEVICEID4_SIZE + 4 + 16 + 4 +
		    4 + roundup(sn.fs_fh.fh_len, 4) + 4 + roundup(ul, 4) +
		    4 + roundup(gl, 4) + 4 + 4;
		/*
		 * s5.1: one stripe, so a stripe unit of 0; the anonymous
		 * stateid, loosely coupled; I/O through the metadata
		 * server only waits for the layouts to come back.
		 */
		if (!nfsv4_xdr_u32(x, body) ||
		    !xdr_u_int64_t(x, &(uint64_t){ 0 }) ||
		    !nfsv4_xdr_u32(x, 1) ||		/* ffl_mirrors<> */
		    !nfsv4_xdr_u32(x, 1) ||		/* ffm_data_servers<> */
		    !XDR_PUTBYTES(x, (char *)id, sizeof(id)) ||
		    !nfsv4_xdr_u32(x, 1) ||		/* ffds_efficiency */
		    !nfsv4_xdr_stateid(x,
		    &(struct nfsv4_stateid){ .si_seqid = 0 }) ||
		    !nfsv4_xdr_u32(x, 1) || !nfsv4_xdr_fh(x, &sn.fs_fh) ||
		    !xdr_string(x, &(char *){ user }, sizeof(user)) ||
		    !xdr_string(x, &(char *){ group }, sizeof(group)) ||
		    !nfsv4_xdr_u32(x, FF_FLAGS_NO_IO_THRU_MDS) ||
		    !nfsv4_xdr_u32(x, 0))		/* stats_collect_hint */
			status = NFS4ERR_RESOURCE;
		goto given;
	}
	/* s13.3: sparse, so the offsets are the file's own; one stripe. */
	util = NFSV4_STRIPE_UNIT & NFL4_UFLG_STRIPE_UNIT_SIZE_MASK;
	if (!nfsv4_xdr_u32(x, body) ||
	    !XDR_PUTBYTES(x, (char *)id, sizeof(id)) ||
	    !nfsv4_xdr_u32(x, util) ||
	    !nfsv4_xdr_u32(x, 0) ||			/* first_stripe_index */
	    !xdr_u_int64_t(x, &(uint64_t){ 0 }) ||	/* pattern_offset */
	    !nfsv4_xdr_u32(x, 1) || !nfsv4_xdr_fh(x, &fh))
		status = NFS4ERR_RESOURCE;
given:
	if (status == NFS4_OK) {
		c->c_curst = si;		/* s18.43.3 */
		atomic_inc_uint((volatile u_int *)&nfsv4_layouts_given);
	}
	goto done;
out:
	mutex_exit(&nfsv4_state_lock);
	if (ff)
		ff_drop(vp);
	/* s18.43.2: logr_will_signal_layout_avail, CB_RECALLABLE_OBJ_AVAIL */
	if (status == NFS4ERR_LAYOUTTRYLATER)
		(void)nfsv4_xdr_u32(x, signal);
done:
	if (ssw != NULL)
		kmem_free(ssw, sizeof(*ssw));
	if (sst != NULL)
		kmem_free(sst, sizeof(*sst));
	if (sf != NULL)
		kmem_free(sf, sizeof(*sf));
	return status;
}

/* Of a layout whose last mode has gone: it ends, s12.5.3. */
static void
layout_end(struct nfsv4_state *st, struct nfsv4_reap *reap)
{

	KASSERT(mutex_owned(&nfsv4_state_lock));

	nfsv4_state_unlink(st, reap, false);
}

/* Give back the modes of iomode, LAYOUTIOMODE4_ANY for all. */
static bool
layout_drop(struct nfsv4_state *st, uint32_t iomode, struct nfsv4_reap *reap)
{

	if (iomode == LAYOUTIOMODE4_ANY)
		st->st_liomode = 0;
	else
		st->st_liomode &= ~(1U << iomode);
	/* s18.44.3: the recall, of all of it, ends with the last mode. */
	if (st->st_liomode == 0) {
		layout_end(st, reap);
		return true;
	}
	return false;
}

/* s18.44, LAYOUTRETURN */
uint32_t
nfsv4_op_layoutreturn(struct nfsv4_compound *c, union nfsv4_args *a)
{
	struct nfsv4_args_layoutreturn *la = &a->layoutreturn;
	struct vnode *vp = c->c_cur.cf_vp;
	struct nfsv4_owner_s *sw;
	struct nfsv4_state *st, *nst;
	struct nfsv4_stateid si;
	struct nfsv4_reap reap;
	uint32_t status;
	bool gone = false;

	if ((status = layout_client(c)) != NFS4_OK)
		return status;
	if (la->rtype != LAYOUT4_RET_REC_ALL && !c->c_cur.cf_set)
		return NFS4ERR_NOFILEHANDLE;
	if (!layout_known(la->type))
		return NFS4ERR_UNKNOWN_LAYOUTTYPE;
	if (la->iomode < LAYOUTIOMODE4_READ || la->iomode > LAYOUTIOMODE4_ANY)
		return NFS4ERR_BADIOMODE;
	if (la->reclaim) {
		if (la->rtype != LAYOUT4_RET_REC_FILE)
			return NFS4ERR_INVAL;
		/* None was kept across the restart; nothing to return. */
		if (!nfsv4_grace_active())
			return NFS4ERR_NO_GRACE;
		return nfsv4_xdr_u32(c->c_rx, 0) ? NFS4_OK : NFS4ERR_RESOURCE;
	}
	if (la->rtype == LAYOUT4_RET_REC_FILE &&
	    (status = nfsv4_file_check(c, &c->c_cur)) != NFS4_OK)
		return status;

	SLIST_INIT(&reap);
	mutex_enter(&nfsv4_state_lock);
	if (la->rtype == LAYOUT4_RET_REC_FILE) {
		status = layout_lookup(c, &la->stateid, vp, &st);
		if (status != NFS4_OK)
			goto out;
		if (st->st_ltype != la->type) {
			status = NFS4ERR_BAD_STATEID;	/* of another type */
			goto out;
		}
		/*
		 * Less than all of it leaves it held, and a recall of it
		 * waiting; all of it, of a mode, gives that mode back.
		 */
		if (la->offset == 0 && la->length == NFS4_UINT64_MAX)
			gone = layout_drop(st, la->iomode, &reap);
		if (!gone) {
			layout_bump(st);
			nfsv4_stateid_out(st, &si);
		}
	} else {
		LIST_FOREACH(sw, &c->c_client->cl_owners, sw_list) {
			if (sw->sw_type != NFSV4_OWNER_LAYOUT)
				continue;
			LIST_FOREACH_SAFE(st, &sw->sw_states, st_olist, nst) {
				if (st->st_file == NULL ||
				    st->st_ltype != la->type ||
				    (la->rtype == LAYOUT4_RET_REC_FSID &&
				    (vp == NULL ||
				    st->st_file->f_vp->v_mount != vp->v_mount)))
					continue;
				(void)layout_drop(st, la->iomode, &reap);
			}
		}
		gone = true;
	}
out:
	mutex_exit(&nfsv4_state_lock);
	nfsv4_reap_finish(&reap);
	if (status != NFS4_OK)
		return status;
	/* s18.44.3: none left, no stateid, and the current one all zeros. */
	if (gone) {
		if (la->rtype == LAYOUT4_RET_REC_FILE)
			memset(&c->c_curst, 0, sizeof(c->c_curst));
		return nfsv4_xdr_u32(c->c_rx, 0) ? NFS4_OK : NFS4ERR_RESOURCE;
	}
	c->c_curst = si;
	return nfsv4_xdr_u32(c->c_rx, 1) && nfsv4_xdr_stateid(c->c_rx, &si) ?
	    NFS4_OK : NFS4ERR_RESOURCE;
}

/*
 * s18.42, LAYOUTCOMMIT.  The data server is this server, so what was
 * written is in the file already; only a size the client says is past
 * it is made so, s12.5.4.2.  loca_time_modify may be used or not, and
 * the server's own time is what the write left.
 */
uint32_t
nfsv4_op_layoutcommit(struct nfsv4_compound *c, union nfsv4_args *a)
{
	struct nfsv4_args_layoutcommit *la = &a->layoutcommit;
	struct vnode *vp = c->c_cur.cf_vp;
	struct nfsv4_state *st;
	struct vattr va;
	uint32_t status;
	bool changed = false;
	int error;

	if ((status = layout_client(c)) != NFS4_OK)
		return status;
	if ((status = nfsv4_file_check(c, &c->c_cur)) != NFS4_OK)
		return status;
	if (!layout_known(la->type))
		return NFS4ERR_UNKNOWN_LAYOUTTYPE;
	/* s18.42.3: none was kept across the restart to reclaim. */
	if (la->reclaim)
		return nfsv4_grace_active() ? NFS4ERR_RECLAIM_BAD :
		    NFS4ERR_NO_GRACE;
	if (la->length != NFS4_UINT64_MAX &&
	    la->offset > NFS4_UINT64_MAX - la->length)
		return NFS4ERR_INVAL;
	mutex_enter(&nfsv4_state_lock);
	status = layout_lookup(c, &la->stateid, vp, &st);
	/* s18.42.3: of a writable layout. */
	if (status == NFS4_OK &&
	    (st->st_liomode & (1U << LAYOUTIOMODE4_RW)) == 0)
		status = NFS4ERR_BADIOMODE;
	if (status == NFS4_OK && st->st_ltype != la->type)
		status = NFS4ERR_BADLAYOUT;	/* s15.1.10.2 */
	mutex_exit(&nfsv4_state_lock);
	if (status != NFS4_OK)
		return status;
	/* s18.42.3: within the range, and no more than NFS4_MAXFILEOFF. */
	if (la->newoffset && (la->lastoffset < la->offset ||
	    (la->length != NFS4_UINT64_MAX &&
	    la->lastoffset >= la->offset + la->length) ||
	    la->lastoffset >= NFS4_UINT64_MAX))
		return NFS4ERR_INVAL;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	/* RFC 8435 s2.1: what was written to the data file, here. */
	error = la->type == LAYOUT4_FLEX_FILES ? ff_commit(vp) : 0;
	if (error == 0)
		error = VOP_GETATTR(vp, &va, c->c_cur.cf_cred);
	if (error == 0 && la->newoffset && la->lastoffset + 1 > va.va_size) {
		vattr_null(&va);
		va.va_size = la->lastoffset + 1;
		error = VOP_SETATTR(vp, &va, c->c_cur.cf_cred);
		changed = error == 0;
	}
	VOP_UNLOCK(vp);
	if (error != 0)
		return nfsv4_errno(error);
	if (!nfsv4_xdr_u32(c->c_rx, changed) ||
	    (changed && !xdr_u_int64_t(c->c_rx, &(uint64_t){ va.va_size })))
		return NFS4ERR_RESOURCE;
	return NFS4_OK;
}

/*
 * s12.5.5: recall every layout, on vfs.nfsv4.layout_recall.  Each is
 * sent its own CB_LAYOUTRECALL of LAYOUTRECALL4_FILE, with the seqid one
 * past the last, s12.5.3.  Until it is answered and returned, LAYOUTGET
 * of it meets the errors of s12.5.5.2.1.3.  A client that does not
 * return it within a lease loses it, nfsv4_layout_scan().
 */
void
nfsv4_layout_recall_all(void)
{

	mutex_enter(&nfsv4_state_lock);
	layout_recall_type(0);
	mutex_exit(&nfsv4_state_lock);
}

/*
 * craa_type_mask bits of a layout type and modes (1 << LAYOUTIOMODE4_*):
 * RFC 8881 s20.6.1 for the file layout, RFC 8435 s13.1 by iomode for
 * the flexible file layout.
 */
static uint32_t
layout_rcamask(uint32_t type, uint32_t modes)
{
	uint32_t m = 0;

	if (type == LAYOUT4_NFSV4_1_FILES)
		return 1U << RCA4_TYPE_MASK_FILE_LAYOUT;
	if ((modes & 1U << LAYOUTIOMODE4_READ) != 0)
		m |= 1U << PNFS_FF_RCA4_TYPE_MASK_READ;
	if ((modes & 1U << LAYOUTIOMODE4_RW) != 0)
		m |= 1U << PNFS_FF_RCA4_TYPE_MASK_RW;
	return m;
}

static bool
layout_full(void)
{
	int max = nfsv4_layout_max;

	return max > 0 && atomic_load_relaxed(&layout_count) >= (u_int)max;
}

/* The layouts cl holds but gone, and their craa_type_mask bits. */
static u_int
layout_held(struct nfsv4_client *cl, const struct nfsv4_state *gone,
    uint32_t *maskp)
{
	struct nfsv4_owner_s *sw;
	struct nfsv4_state *st;
	u_int n = 0;

	*maskp = 0;
	LIST_FOREACH(sw, &cl->cl_owners, sw_list) {
		if (sw->sw_type != NFSV4_OWNER_LAYOUT)
			continue;
		LIST_FOREACH(st, &sw->sw_states, st_olist) {
			if (st->st_file == NULL || st == gone)
				continue;
			n++;
			*maskp |= layout_rcamask(st->st_ltype, st->st_liomode);
		}
	}
	return n;
}

/*
 * A layout was given: past three quarters of vfs.nfsv4.layout_max, each
 * holder is sent CB_RECALL_ANY to keep half of its layouts, s20.6.  The
 * client chooses which; none is recalled by name after it (s20.6.4
 * leaves that to the server).
 */
static void
layout_crowded(void)
{
	struct nfsv4_client *cl;
	uint32_t mask;
	u_int n;
	int max = nfsv4_layout_max;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if (max <= 0 || atomic_load_relaxed(&layout_count) <
	    (u_int)max - (u_int)max / 4 || time_uptime < layout_rca_next)
		return;
	layout_rca_next = time_uptime + NFSV4_LEASE;
	for (cl = nfsv4_client_next(NULL); cl != NULL;
	    cl = nfsv4_client_next(cl)) {
		if ((n = layout_held(cl, NULL, &mask)) != 0)
			nfsv4_cb_recall_any(cl, NFSV4_OP_CB_RECALL_ANY, n / 2,
			    mask);
	}
}

/*
 * The layout gone is going: if there is room again, the clients that
 * asked to be told are sent CB_RECALLABLE_OBJ_AVAIL, s18.43.3, s20.7.
 * craa_objects_to_keep is what each holds and the room (s20.7.3).
 */
static void
layout_avail(const struct nfsv4_state *gone)
{
	struct nfsv4_client *cl;
	uint32_t mask;
	u_int n, room;
	int max = nfsv4_layout_max;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	if (!layout_wanted || layout_full())
		return;
	layout_wanted = false;
	room = max > 0 ? (u_int)max - atomic_load_relaxed(&layout_count) :
	    UINT32_MAX / 2;
	for (cl = nfsv4_client_next(NULL); cl != NULL;
	    cl = nfsv4_client_next(cl)) {
		if (cl->cl_lwant == 0)
			continue;
		n = layout_held(cl, gone, &mask);
		nfsv4_cb_recall_any(cl, NFSV4_OP_CB_RECALLABLE_OBJ_AVAIL,
		    n + room, cl->cl_lwant);
		cl->cl_lwant = 0;
	}
}

/*
 * The layouts of vp are recalled, not waited for; with ff, only those of
 * RFC 8435, which carry access to the data file.
 */
void
nfsv4_layout_recall_vp(struct vnode *vp, bool ff)
{
	struct nfsv4_file *f;
	struct nfsv4_state *st;

	if (atomic_load_relaxed(&layout_count) == 0)
		return;
	mutex_enter(&nfsv4_state_lock);
	if ((f = nfsv4_file_find(vp)) != NULL) {
		LIST_FOREACH(st, &f->f_states, st_flist) {
			if (st->st_type == NFSV4_ST_LAYOUT &&
			    (!ff || st->st_ltype == LAYOUT4_FLEX_FILES))
				layout_recall(st);
		}
	}
	mutex_exit(&nfsv4_state_lock);
}

/*
 * RFC 8881 s12.5.5: REMOVE SHOULD recall the layouts of the file.  That
 * of a name that is not the last link is recalled too; the client only
 * asks again.  The lookup is outside the directory's lock, as in
 * nfsv4_deleg_break_name().
 */
void
nfsv4_layout_recall_name(const struct nfsv4_cfh *dir, const char *name)
{
	struct vnode *vp;

	if (atomic_load_relaxed(&layout_count) == 0)
		return;
	if (nfsv4_lookup_vp(dir->cf_vp, name, dir->cf_cred, &vp) != 0)
		return;
	nfsv4_layout_recall_vp(vp, false);
	vrele(vp);
}

/* The same for the layouts of one type, or of all for 0. */
static void
layout_recall_type(uint32_t type)
{
	struct nfsv4_client *cl;
	struct nfsv4_owner_s *sw;
	struct nfsv4_state *st;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	for (cl = nfsv4_client_next(NULL); cl != NULL;
	    cl = nfsv4_client_next(cl)) {
		LIST_FOREACH(sw, &cl->cl_owners, sw_list) {
			if (sw->sw_type != NFSV4_OWNER_LAYOUT)
				continue;
			LIST_FOREACH(st, &sw->sw_states, st_olist) {
				if (type == 0 || st->st_ltype == type)
					layout_recall(st);
			}
		}
	}
}

/*
 * What the client said to a CB_LAYOUTRECALL of the state other.  s20.3.3:
 * NOMATCHING_LAYOUT is that it has none, and the recall is done.
 */
void
nfsv4_layout_recalled(uint64_t other, int error, uint32_t status,
    struct nfsv4_reap *reap)
{
	struct nfsv4_state *st;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	st = nfsv4_state_byother(other);
	if (st == NULL || st->st_type != NFSV4_ST_LAYOUT ||
	    st->st_file == NULL || !st->st_lrecall)
		return;
	if (error == 0 && status == NFS4ERR_NOMATCHING_LAYOUT)
		layout_end(st, reap);
	else if (error == 0)
		st->st_lanswered = true;
}

/*
 * s12.5.5: a recalled layout not returned within its time is let go.
 * Of the file layout, the data server is this server, so nothing is to
 * be fenced: I/O goes by the open and lock stateids, which stay good
 * (s13.9.1).  Of the flexible file layout, the data file is given new
 * ids, RFC 8435 s2.2, by nfsv4_layout_gone().
 */
void
nfsv4_layout_scan(struct nfsv4_reap *reap)
{
	struct nfsv4_client *cl;
	struct nfsv4_owner_s *sw;
	struct nfsv4_state *st, *nst;

	KASSERT(mutex_owned(&nfsv4_state_lock));

	for (cl = nfsv4_client_next(NULL); cl != NULL;
	    cl = nfsv4_client_next(cl)) {
		LIST_FOREACH(sw, &cl->cl_owners, sw_list) {
			if (sw->sw_type != NFSV4_OWNER_LAYOUT)
				continue;
			LIST_FOREACH_SAFE(st, &sw->sw_states, st_olist, nst) {
				if (st->st_file != NULL && st->st_lrecall &&
				    time_uptime >= st->st_lrend) {
					st->st_lfence = true;
					layout_end(st, reap);
				}
			}
		}
	}
}

/* The layout attributes, s5.12: what this file system offers. */
uint32_t
nfsv4_layout_types(struct vnode *vp)
{

	return vp != NULL && nfsv4_pnfs_on() ? LAYOUT4_NFSV4_1_FILES : 0;
}

uint32_t
nfsv4_layout_blksize(void)
{

	return NFSV4_STRIPE_UNIT;
}
