#	$NetBSD$

.include "../Makefile.inc"

KMOD=	nfsv4

.PATH:	${S}/fs/nfsv4

SRCS+=	nfsv4_acl.c nfsv4_attr.c nfsv4_compound.c nfsv4_fh.c nfsv4_lock.c nfsv4_ops.c
SRCS+=	nfsv4_cb.c nfsv4_change.c nfsv4_deleg.c nfsv4_drc.c nfsv4_open.c nfsv4_state.c nfsv4_xdr.c

WARNS=	3

.include <bsd.kmodule.mk>
