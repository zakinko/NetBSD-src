#	$NetBSD$

.include <bsd.own.mk>

USE_FORT?= yes	# network server

PROG=	gssd
MAN=	gssd.8

CPPFLAGS+= -I${DESTDIR}/usr/include/krb5

LDADD+=	-lgssapi -lkrb5 -lutil
DPADD+=	${LIBGSSAPI} ${LIBKRB5} ${LIBUTIL}

.include <bsd.prog.mk>
