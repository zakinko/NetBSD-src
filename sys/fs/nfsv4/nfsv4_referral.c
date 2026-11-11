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
 * Referrals, RFC 7530 s8.4.3: a directory stands for an absent file
 * system, which lives elsewhere.  vfs.nfsv4.referral gets a line
 *
 *	/export/there server1,server2:/root;server3:/other
 *
 * for each.  The directory is held until the module goes, and a handle
 * of it is marked, cf_ref, by nfsv4_cfh_setvp().  The checks are s8.2 and
 * s8.3.
 *
 * Migration, s9.14, is the same given to vfs.nfsv4.moved with a mount
 * point: every object of that file system is absent from then on, its
 * state is not carried over, which s9.14.1 leaves as a SHOULD, and a
 * client with state there gets NFS4ERR_LEASE_MOVED from what renews,
 * s9.14.3, until it has probed or two leases are over.  One RENEW after
 * fs_locations counts for all the file systems gone so far.  How the
 * data gets there is the administrator's.
 *
 * The receiving end, RFC 8881 s4.2.2: a migrated file system's new server
 * MUST honor the filehandles of the old one.  vfs.nfsv4.arrived gets
 *
 *	0123abcd:4567ef01 /export/here
 *
 * the fsid (f_fsidx, its two words in hex) that the old server put in
 * its handles, and the mount point where the file system now is.
 * Handles with that fsid are taken as of this mount, and handles of
 * this mount are made with it, so that they stay what they were.  That
 * the file IDs inside are still good is the file system's: so they are
 * when the same disk is mounted here, or a copy that keeps inode numbers
 * and generations (zfs send and receive).  State does not come along;
 * the client reclaims it in the grace period, s11.11.9.  Handle classes
 * are those of s11.11.2: the same, when this is configured.  An empty
 * line forgets them all.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/atomic.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/queue.h>
#include <sys/systm.h>
#include <sys/vnode.h>

#include <fs/nfsv4/nfsv4_var.h>

#define	REFERRAL_MAXLOC		512	/* chosen; fits NFSV4_ATTRBUF */

static kmutex_t referral_lock;
static SLIST_HEAD(, nfsv4_referral) referrals;
static u_int referral_n;
static uint32_t moved_gen;
static time_t moved_end;

struct nfsv4_arrival {
	SLIST_ENTRY(nfsv4_arrival) ar_list;
	fsid_t		ar_fsid;	/* in the old server's handles */
	struct vnode	*ar_vp;		/* the root here, held */
};
static SLIST_HEAD(, nfsv4_arrival) arrivals;

void
nfsv4_referral_init(void)
{

	mutex_init(&referral_lock, MUTEX_DEFAULT, IPL_NONE);
	SLIST_INIT(&referrals);
	SLIST_INIT(&arrivals);
	referral_n = 0;
	moved_gen = 0;
}

void
nfsv4_referral_fini(void)
{
	struct nfsv4_referral *rf;
	struct nfsv4_arrival *ar;

	while ((rf = SLIST_FIRST(&referrals)) != NULL) {
		SLIST_REMOVE_HEAD(&referrals, rf_list);
		vrele(rf->rf_vp);
		kmem_free(rf, sizeof(*rf));
	}
	while ((ar = SLIST_FIRST(&arrivals)) != NULL) {
		SLIST_REMOVE_HEAD(&arrivals, ar_list);
		vrele(ar->ar_vp);
		kmem_free(ar, sizeof(*ar));
	}
	mutex_destroy(&referral_lock);
}

/* One line of vfs.nfsv4.referral. */
int
nfsv4_referral_line(const char *s)
{
	struct nfsv4_referral *rf;
	struct vnode *vp;
	const char *sp;
	size_t plen;
	int error;

	sp = strchr(s, ' ');
	if (sp == NULL || strlen(sp + 1) >= REFERRAL_MAXLOC ||
	    strchr(sp, ':') == NULL)
		return EINVAL;
	plen = sp - s;
	rf = kmem_zalloc(sizeof(*rf), KM_SLEEP);
	if (plen >= sizeof(rf->rf_path)) {
		kmem_free(rf, sizeof(*rf));
		return ENAMETOOLONG;
	}
	memcpy(rf->rf_path, s, plen);
	strlcpy(rf->rf_locs, sp + 1, sizeof(rf->rf_locs));
	error = namei_simple_kernel(rf->rf_path, NSM_FOLLOW_NOEMULROOT, &vp);
	if (error == 0 && vp->v_type != VDIR) {
		vrele(vp);
		error = ENOTDIR;
	}
	if (error != 0) {
		kmem_free(rf, sizeof(*rf));
		return error;
	}
	rf->rf_vp = vp;
	mutex_enter(&referral_lock);
	rf->rf_index = ++referral_n;
	SLIST_INSERT_HEAD(&referrals, rf, rf_list);
	mutex_exit(&referral_lock);
	return 0;
}

const struct nfsv4_referral *
nfsv4_referral_find(const struct vnode *vp)
{
	const struct nfsv4_referral *rf, *found = NULL;

	if (atomic_load_relaxed(&referral_n) == 0)
		return NULL;
	mutex_enter(&referral_lock);
	SLIST_FOREACH(rf, &referrals, rf_list) {
		if (rf->rf_vp == vp ||
		    (rf->rf_moved && rf->rf_vp->v_mount == vp->v_mount)) {
			found = rf;
			break;
		}
	}
	mutex_exit(&referral_lock);
	return found;
}

int
nfsv4_moved_line(const char *s)
{
	struct nfsv4_referral *rf;
	int error;

	error = nfsv4_referral_line(s);
	if (error != 0)
		return error;
	mutex_enter(&referral_lock);
	rf = SLIST_FIRST(&referrals);
	if ((rf->rf_vp->v_vflag & VV_ROOT) == 0)
		error = EINVAL;
	else {
		rf->rf_moved = true;
		moved_gen++;
		moved_end = time_uptime + 2 * NFSV4_LEASE;	/* s9.14.3 */
	}
	mutex_exit(&referral_lock);
	return error;
}

/* Eight hex digits, into *vp; false if they are not that. */
static bool
arrived_hex(const char *s, uint32_t *vp)
{
	uint32_t v = 0;
	int i, d;

	for (i = 0; i < 8; i++) {
		if (s[i] >= '0' && s[i] <= '9')
			d = s[i] - '0';
		else if (s[i] >= 'a' && s[i] <= 'f')
			d = s[i] - 'a' + 10;
		else
			return false;
		v = v << 4 | d;
	}
	*vp = v;
	return true;
}

/* One line of vfs.nfsv4.arrived, s4.2.2. */
int
nfsv4_arrived_line(const char *s)
{
	struct nfsv4_arrival *ar;
	struct vnode *vp;
	uint32_t w0, w1;
	int error;

	if (*s == '\0') {
		mutex_enter(&referral_lock);
		while ((ar = SLIST_FIRST(&arrivals)) != NULL) {
			SLIST_REMOVE_HEAD(&arrivals, ar_list);
			mutex_exit(&referral_lock);
			vrele(ar->ar_vp);
			kmem_free(ar, sizeof(*ar));
			mutex_enter(&referral_lock);
		}
		mutex_exit(&referral_lock);
		return 0;
	}
	if (strlen(s) < 19 || s[8] != ':' || s[17] != ' ' ||
	    !arrived_hex(s, &w0) || !arrived_hex(s + 9, &w1))
		return EINVAL;
	error = namei_simple_kernel(s + 18, NSM_FOLLOW_NOEMULROOT, &vp);
	if (error != 0)
		return error;
	if ((vp->v_vflag & VV_ROOT) == 0) {
		vrele(vp);
		return EINVAL;
	}
	ar = kmem_zalloc(sizeof(*ar), KM_SLEEP);
	ar->ar_fsid.__fsid_val[0] = (int32_t)w0;
	ar->ar_fsid.__fsid_val[1] = (int32_t)w1;
	ar->ar_vp = vp;
	mutex_enter(&referral_lock);
	SLIST_INSERT_HEAD(&arrivals, ar, ar_list);
	mutex_exit(&referral_lock);
	return 0;
}

/* A handle's fsid, of a file system that came here: this mount's. */
void
nfsv4_arrived_in(fsid_t *fsid)
{
	struct nfsv4_arrival *ar;

	mutex_enter(&referral_lock);
	SLIST_FOREACH(ar, &arrivals, ar_list) {
		if (memcmp(&ar->ar_fsid, fsid, sizeof(*fsid)) == 0) {
			*fsid = ar->ar_vp->v_mount->mnt_stat.f_fsidx;
			break;
		}
	}
	mutex_exit(&referral_lock);
}

/* The fsid for handles of mp: the old server's, if it came here. */
void
nfsv4_arrived_out(const struct mount *mp, fsid_t *fsid)
{
	struct nfsv4_arrival *ar;

	mutex_enter(&referral_lock);
	SLIST_FOREACH(ar, &arrivals, ar_list) {
		if (ar->ar_vp->v_mount == mp) {
			*fsid = ar->ar_fsid;
			break;
		}
	}
	mutex_exit(&referral_lock);
}

uint32_t
nfsv4_moved_gen(void)
{

	return atomic_load_relaxed(&moved_gen);
}

bool
nfsv4_moved_grace(void)
{

	return atomic_load_relaxed(&moved_gen) != 0 &&
	    time_uptime < moved_end;
}

bool
nfsv4_moved_mount(const struct mount *mp)
{
	const struct nfsv4_referral *rf;
	bool found = false;

	mutex_enter(&referral_lock);
	SLIST_FOREACH(rf, &referrals, rf_list) {
		if (rf->rf_moved && rf->rf_vp->v_mount == mp)
			found = true;
	}
	mutex_exit(&referral_lock);
	return found;
}

/*
 * May this operation run with an absent file system's node as the
 * current handle?  s8.2 for those that look at it, s8.3.1 for GETATTR
 * and for VERIFY, whose mask must also be all of what is available.
 */
bool
nfsv4_referral_allowed(uint32_t op, const union nfsv4_args *a)
{

	switch (op) {
	case NFSV4_OP_PUTFH:
	case NFSV4_OP_PUTPUBFH:
	case NFSV4_OP_PUTROOTFH:
	case NFSV4_OP_RESTOREFH:
	case NFSV4_OP_RENEW:
	case NFSV4_OP_SETCLIENTID:
	case NFSV4_OP_SETCLIENTID_CONFIRM:
	case NFSV4_OP_DELEGPURGE:
	case NFSV4_OP_RELEASE_LOCKOWNER:
		return true;
	case NFSV4_OP_GETATTR:
		/* RFC 8881 s11.17: fs_locations_info as well. */
		return (a->getattr.mask.bm_n > 0 &&
		    (a->getattr.mask.bm_w[0] & (1U << FATTR4_FS_LOCATIONS)) !=
		    0) || (a->getattr.mask.bm_n > 2 &&
		    (a->getattr.mask.bm_w[2] &
		    (1U << (FATTR4_FS_LOCATIONS_INFO - 64))) != 0);
	case NFSV4_OP_VERIFY:
	case NFSV4_OP_NVERIFY:
		return nfsv4_attr_absent_ok(&a->verify.attrs.fa_mask);
	default:
		return false;
	}
}
