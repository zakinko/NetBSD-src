#	$NetBSD$

.include "../Makefile.inc"

KMOD=	oncrpc

.PATH:	${S}/oncrpc

SRCS+=	gss_krb5.c gss_krb5_crypto.c gss_ssv.c
SRCS+=	oncrpc_auth.c oncrpc_clnt.c oncrpc_gss.c oncrpc_gss_clnt.c oncrpc_gss_svc.c oncrpc_gssd.c oncrpc_msg.c oncrpc_rm.c oncrpc_svc.c
SRCS+=	oncrpc_iwarp_wire.c oncrpc_rdma_chunk.c oncrpc_rdma_hdr.c
SRCS+=	oncrpc_rdma_nfs.c oncrpc_rdma_svc.c

.include <bsd.kmodule.mk>
