#	$NetBSD$

.include "../Makefile.inc"

KMOD=	nfsv4

.PATH:	${S}/fs/nfsv4

SRCS+=	nfsv4_acl.c nfsv4_attr.c nfsv4_compound.c nfsv4_fh.c nfsv4_lock.c nfsv4_ops.c
SRCS+=	nfsv4_cb.c nfsv4_change.c nfsv4_deleg.c nfsv4_drc.c nfsv4_idmap.c nfsv4_referral.c nfsv4_open.c nfsv4_session.c nfsv4_stable.c nfsv4_state.c nfsv4_xattr.c nfsv4_xdr.c
SRCS+=	nfsv4_copy.c nfsv4_label.c nfsv4_v42.c nfsv4_xattrop.c

# Behaviour that departs from the RFCs on purpose, also a sysctl of the
# same name so that both ways can be measured.  A module has no config
# file to take "options" from, so they are here, as with -DNFSSERVER in
# ../nfsserver; left out, the sources take the RFCs' way.
#
# NFSV4_READ_PLUS_ZERO_DATA: READ_PLUS sends zeros that are stored as
# data, against RFC 7862 s15.10.3's SHOULD to send them as a hole, to
# save looking at every byte read.  Not set: vfs.nfsv4.read_plus_zero_data
# turns it on.  See nfsv4_v42.c.
#CPPFLAGS+=	-DNFSV4_READ_PLUS_ZERO_DATA

WARNS=	3

.include <bsd.kmodule.mk>
