#	$NetBSD$

.include "../Makefile.inc"

KMOD=	nlm

.PATH:	${S}/fs/nlm

SRCS+=	nlm_client.c nlm_lock.c nlm_nsm.c nlm_svc.c nlm_xdr.c

WARNS=	3

.include <bsd.kmodule.mk>
