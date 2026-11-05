# What version 4.2 asks of the port and the port does not have yet:
# DEALLOCATE as a hole punch, and CLONE.  Run in the tree of the port,
# until this is in it.  An edit that no longer fits stops the build.
import sys

P = 'module/os/bsd/zfs/zfs_vnops_os.c'
t = open(P).read()


def sub(a, b):
    global t
    if t.count(a) < 1:
        sys.exit('zfs-42.py: no ' + a)
    t = t.replace(a, b, 1)


sub('''static int
zfs_netbsd_ioctl(void *v)
''', '''static int
zfs_netbsd_fdiscard(void *v)
{
	struct vop_fdiscard_args *ap = v;
	znode_t *zp = VTOZ(ap->a_vp);
	zfsvfs_t *zfsvfs = ZTOZSB(zp);
	int error;

	if ((error = zfs_enter_verify_zp(zfsvfs, zp, FTAG)) != 0)
		return (error);
	error = zfs_freesp(zp, ap->a_pos, ap->a_len, FWRITE, B_TRUE);
	zfs_exit(zfsvfs, FTAG);
	return (error);
}

/*
 * The destination's pages go both ways: those dirty before the clone
 * into the file, and those clean after it, which are now of the old
 * blocks.  zfs_clone_range() stops short only for an error it has
 * dropped, and a partial clone is not one a caller can ask for.
 */
static int
zfs_netbsd_clonerange(void *v)
{
	struct vop_clonerange_args *ap = v;
	vnode_t *outvp = ap->a_outvp;
	uint64_t inoff = ap->a_inoff, outoff = ap->a_outoff, len = ap->a_len;
	voff_t lo = trunc_page(ap->a_outoff);
	voff_t hi = round_page(ap->a_outoff + ap->a_len);
	int error;

	vn_lock(outvp, LK_EXCLUSIVE | LK_RETRY);
	rw_enter(outvp->v_uobj.vmobjlock, RW_WRITER);
	error = VOP_PUTPAGES(outvp, lo, hi, PGO_CLEANIT | PGO_SYNCIO |
	    PGO_FREE);
	if (error == 0)
		error = zfs_clone_range(VTOZ(ap->a_invp), &inoff, VTOZ(outvp),
		    &outoff, &len, ap->a_cred);
	if (error == 0 && len != (uint64_t)ap->a_len)
		error = SET_ERROR(EIO);
	rw_enter(outvp->v_uobj.vmobjlock, RW_WRITER);
	(void) VOP_PUTPAGES(outvp, lo, hi, PGO_FREE);
	uvm_vnp_setsize(outvp, VTOZ(outvp)->z_size);
	VOP_UNLOCK(outvp);
	return (error);
}

static int
zfs_netbsd_ioctl(void *v)
''')
sub('''	{ &vop_fdiscard_desc,		genfs_eopnotsupp },
''', '''	{ &vop_fdiscard_desc,		zfs_netbsd_fdiscard },
	{ &vop_clonerange_desc,		zfs_netbsd_clonerange },
''')
open(P, 'w').write(t)
