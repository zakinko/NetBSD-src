#	$NetBSD: Makefile,v 1.4 2015/10/19 16:16:36 pooka Exp $
#

.PATH:  ${.CURDIR}/../../../../nfs

LIB=	rumpfs_nfsserver
COMMENT=NFS server

SRCS=	nfs_export.c nfs_serv.c nfs_srvcache.c nfs_srvsubs.c		\
	nfs_srvsocket.c nfs_syscalls.c

.if defined(NFSSERVER_ONCRPC)
.PATH:	${.CURDIR}/../../../../oncrpc ${.CURDIR}/../../../../../common/lib/libc/rpc
CPPFLAGS+=	-DNFSSERVER_ONCRPC
SRCS+=	nfs_oncrpc.c oncrpc_auth.c oncrpc_msg.c oncrpc_rm.c oncrpc_svc.c
SRCS+=	xdr.c xdr_array.c xdr_mem.c xdr_mbuf.c xdr_module.c
.endif

.include <bsd.lib.mk>
.include <bsd.klinks.mk>
