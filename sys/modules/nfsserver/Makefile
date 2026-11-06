#	$NetBSD: Makefile,v 1.3 2019/02/17 04:05:55 rin Exp $

.include "../Makefile.inc"

KMOD=	nfsserver

CPPFLAGS+=	-DNFSSERVER

.PATH:	${S}/nfs

SRCS+=	nfs_export.c nfs_serv.c nfs_srvcache.c
SRCS+=	nfs_srvsubs.c nfs_srvsocket.c nfs_syscalls.c

.if defined(NFSSERVER_ONCRPC)
CPPFLAGS+=	-DNFSSERVER_ONCRPC
SRCS+=	nfs_oncrpc.c
.endif

WARNS=	3

.include <bsd.kmodule.mk>
