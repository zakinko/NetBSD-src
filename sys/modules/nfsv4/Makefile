#	$NetBSD$

.include "../Makefile.inc"

KMOD=	nfsv4

.PATH:	${S}/fs/nfsv4

SRCS+=	nfsv4_attr.c nfsv4_compound.c nfsv4_fh.c nfsv4_ops.c
SRCS+=	nfsv4_xdr.c

WARNS=	3

.include <bsd.kmodule.mk>
