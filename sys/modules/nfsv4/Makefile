#	$NetBSD$

.include "../Makefile.inc"

KMOD=	nfsv4

.PATH:	${S}/fs/nfsv4

SRCS+=	nfsv4_acl.c nfsv4_attr.c nfsv4_compound.c nfsv4_fh.c nfsv4_lock.c nfsv4_ops.c
SRCS+=	nfsv4_cb.c nfsv4_change.c nfsv4_deleg.c nfsv4_drc.c nfsv4_idmap.c nfsv4_referral.c nfsv4_open.c nfsv4_session.c nfsv4_stable.c nfsv4_state.c nfsv4_xattr.c nfsv4_xdr.c
SRCS+=	nfsv4_layout.c

# Behaviour that departs from the RFCs on purpose, each also a sysctl so
# that both ways can be measured.  As with -DNFSSERVER in ../nfsserver,
# a module has no config file to take "options" from, so they are here;
# the defaults in the sources are the RFCs' when one is left out.
#
# NFSV4_GDD_UNAVAIL_OK: refuse GET_DIR_DELEGATION with GDD4_UNAVAIL, not
# RFC 8881 s18.39.3's NFS4ERR_DIRDELEG_UNAVAIL, which the client of Linux
# turns into EIO.  See nfsv4_deleg.c.
CPPFLAGS+=	-DNFSV4_GDD_UNAVAIL_OK
#
# NFSV4_REMOVE_PAST_DENY: under version 4.0, REMOVE and RENAME take away a
# name that an open denying writes is on, against RFC 7530 s16.26.5's
# SHOULD NOT, for pynfs's RM1r and RLOWN2.  See nfsv4_deleg.c.
CPPFLAGS+=	-DNFSV4_REMOVE_PAST_DENY
#
# NFSV4_NUMERIC_OWNER_SYS: under AUTH_SYS, take a numeric owner or group
# even when the id has a name@domain, against RFC 8881 s5.9's SHOULD.
# The credential under AUTH_SYS is that number already, and the client
# of Linux sends numbers by default.  Under RPCSEC_GSS the RFC's
# NFS4ERR_BADOWNER stands either way.  See nfsv4_attr.c.
CPPFLAGS+=	-DNFSV4_NUMERIC_OWNER_SYS
#
# NFSV4_CB_VERS1: when a client of version 4.1 refuses callback version
# 4, use 1, the version in the XDR of RFC 5662, against RFC 8881
# s18.36.3's MUST of 4.  Without it that client has no callbacks.  See
# nfsv4_cb.c.
CPPFLAGS+=	-DNFSV4_CB_VERS1
#
# NFSV4_EXCL_INHERIT: let the file system inherit ACEs, masked by mode 0,
# into a file made by OPEN with EXCLUSIVE4, against RFC 8881 s6.4.3's
# SHOULD NOT.  Not set: nothing is known to need it.  See nfsv4_acl.c.
#CPPFLAGS+=	-DNFSV4_EXCL_INHERIT
#
# NFSV4_DS_OWNER: give a connection to the file layout's data server
# (vfs.nfsv4.pnfs_ds) a so_major_id of its own, against RFC 8881
# s2.10.5's MUST of one per server, so that the client of Linux sends
# the I/O of layouts there rather than trunking it onto the metadata
# server's connection.  Not set: vfs.nfsv4.ds_owner turns it on.  See
# nfsv4_layout.c.
#CPPFLAGS+=	-DNFSV4_DS_OWNER
#
# NFSV4_BLK_NOHINT: give block layouts (RFC 5663) to a client that has
# set no layout_hint, taking its maximum I/O time to be 60 seconds,
# against RFC 5663 s2.3.8's SHOULD that it be refused them with
# NFS4ERR_LAYOUTUNAVAILABLE.  The client of Linux never sets the hint,
# so it has no block layouts without this.  Not set: vfs.nfsv4.blk_nohint
# turns it on, and 0 there, or this left out, is the RFC's way.  See
# nfsv4_layout.c.
#CPPFLAGS+=	-DNFSV4_BLK_NOHINT
#
# NFSV4_CREATE_MODE_MASK: for a create with neither mode nor ACL, let the
# file system mask the inherited ACEs by the server's default mode,
# against RFC 8881 s6.4.3's SHOULD that they be inherited unchanged.  Not
# set: nothing is known to need it.  See nfsv4_acl.c.
#CPPFLAGS+=	-DNFSV4_CREATE_MODE_MASK

WARNS=	3

.include <bsd.kmodule.mk>
