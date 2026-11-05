#	$NetBSD$

.include "../Makefile.inc"

KMOD=	xdr

.PATH:	${S}/oncrpc
.PATH:	${NETBSDSRCDIR}/common/lib/libc/rpc

SRCS+=	xdr_mbuf.c xdr_module.c
SRCS+=	xdr.c xdr_array.c xdr_mem.c

.include <bsd.kmodule.mk>
