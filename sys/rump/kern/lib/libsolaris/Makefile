#	$NetBSD: Makefile,v 1.6 2021/04/15 17:31:44 christos Exp $
#

NEED_ISYSTEM=	# Tell rump that we must use -isystem

.include <bsd.init.mk>

S!=             cd ${.PARSEDIR}/../../../../;pwd

.include "${.CURDIR}/../../../../modules/solaris/Makefile.solmod"

# The kernel gets these from the xdr module.
.PATH:	${S}/oncrpc
.PATH:	${S}/../common/lib/libc/rpc
SRCS+=	xdr_module.c xdr.c xdr_array.c xdr_mem.c

LIB=	rumpkern_solaris
COMMENT=Solaris compatibility layer (for ZFS)

.include <bsd.lib.mk>
.include <bsd.klinks.mk>
