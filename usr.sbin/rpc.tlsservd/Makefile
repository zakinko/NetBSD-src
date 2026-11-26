#	$NetBSD$

.include <bsd.own.mk>

USE_FORT?= yes	# network server

PROG=	rpc.tlsservd
MAN=	rpc.tlsservd.8

LDADD+=	-lssl -lcrypto
DPADD+=	${LIBSSL} ${LIBCRYPTO}

.include <bsd.prog.mk>
