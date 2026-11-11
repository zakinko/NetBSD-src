#	$NetBSD$

.include "../Makefile.inc"

KMOD=	nfsv4

.PATH:	${S}/fs/nfsv4

SRCS+=	nfsv4_acl.c nfsv4_attr.c nfsv4_compound.c nfsv4_fh.c nfsv4_lock.c nfsv4_ops.c
SRCS+=	nfsv4_cb.c nfsv4_change.c nfsv4_deleg.c nfsv4_drc.c nfsv4_idmap.c nfsv4_referral.c nfsv4_open.c nfsv4_session.c nfsv4_stable.c nfsv4_state.c nfsv4_xattr.c nfsv4_xdr.c

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

WARNS=	3

.include <bsd.kmodule.mk>
