/*	$NetBSD$	*/

/*-
 * Copyright (c) 2026 Showta Ishizaki
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * The two procedures of NFS version 4, RFC 7530 s15, and the module.
 *
 * Arguments are decoded one operation at a time, as each is reached,
 * which RFC 7530 s15.2.4 allows and which means a COMPOUND can do work
 * and then turn out to be malformed: the operation at which that
 * happens gets NFS4ERR_BADXDR.
 *
 * A socket is given to the server through a sysctl.  That is for
 * development: the server does not yet share port 2049 with the nfsd of
 * versions 2 and 3, and is not meant to run beside it.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kmem.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <fs/nfsv4/nfsv4_var.h>

/*
 * Not from the RFC.  NFSV4_NTHREADS is how many operations can sleep at
 * once.  NFSV4_RES_ROOM is what must be free in the reply to start
 * another operation, enough for the largest result of one, so that
 * running out is NFS4ERR_RESOURCE (RFC 7530 s15.2.4) and not a failure
 * in the middle of a result.
 */
#define	NFSV4_NTHREADS		8
#define	NFSV4_RES_LIMIT		(1024 * 1024)
#define	NFSV4_RES_ROOM		(256 * 1024)

/* flags of an operation */
#define	NFSV4_OPF_FH		0x01	/* needs the current filehandle */

struct nfsv4_opdesc {
	nfsv4_op_t	od_func;	/* NULL for NFS4ERR_NOTSUPP */
	u_int		od_flags;
};

static const struct nfsv4_opdesc nfsv4_ops[NFSV4_OP_RELEASE_LOCKOWNER + 1] = {
	/* Operations 0, 1 and 2 are not defined, RFC 7530 s15.2.4. */
};

static struct oncrpc_svc *nfsv4_svc;
static struct sysctllog *nfsv4_sysctllog;

static bool
nfsv4_put32(XDR *x, uint32_t v)
{

	return xdr_u_int32_t(x, &v) != 0;
}

/* Overwrite the word at pos, leaving the stream where it was. */
static bool
nfsv4_patch32(XDR *x, u_int pos, uint32_t v)
{
	u_int end;

	end = XDR_GETPOS(x);
	return XDR_SETPOS(x, pos) && nfsv4_put32(x, v) && XDR_SETPOS(x, end);
}

/*
 * Copy the opaque of len bytes at pos in the arguments to the results,
 * with its length.  RFC 7530 s15.2.4 asks for the reply's tag to be the
 * request's, and the RFC puts no bound on it, so it stays in the
 * message rather than be held anywhere.
 */
static bool
nfsv4_copy_tag(XDR *ax, u_int pos, uint32_t len, XDR *rx)
{
	char buf[128];
	u_int end, n, left;

	if (!nfsv4_put32(rx, len))
		return false;
	end = XDR_GETPOS(ax);
	if (!XDR_SETPOS(ax, pos))
		return false;
	for (left = len; left > 0; left -= n) {
		n = MIN(left, sizeof(buf));
		if (!XDR_GETBYTES(ax, buf, n) || !XDR_PUTBYTES(rx, buf, n))
			return false;
	}
	return nfsv4_xdr_pad(rx, len) && XDR_SETPOS(ax, end);
}

/*
 * Evaluate one operation.  Whatever goes wrong before it starts is its
 * status, in the order: is it an operation, does it decode, is it
 * implemented, is there a filehandle.
 */
static uint32_t
nfsv4_one_op(struct nfsv4_compound *c, uint32_t op, union nfsv4_args *a)
{
	const struct nfsv4_opdesc *od;

	if (!nfsv4_xdr_args(c->c_ax, op, a))
		return NFS4ERR_BADXDR;
	od = &nfsv4_ops[op];
	if (od->od_func == NULL)
		return NFS4ERR_NOTSUPP;
	return (*od->od_func)(c, a);
}

static enum oncrpc_dispatch
nfsv4_compound(struct oncrpc_req *rq)
{
	struct nfsv4_compound c;
	union nfsv4_args *a;
	XDR *ax = rq->rq_args, *rx = rq->rq_res;
	uint32_t taglen, minor, numops, op, resop, status, i, n;
	u_int tagpos, numpos, statpos;
	enum oncrpc_dispatch disp;

	if (!xdr_u_int32_t(ax, &taglen))
		return ONCRPC_ERR_ARGS;
	tagpos = XDR_GETPOS(ax);
	if (!nfsv4_xdr_skip(ax, taglen) ||
	    !xdr_u_int32_t(ax, &minor) ||
	    !xdr_u_int32_t(ax, &numops))
		return ONCRPC_ERR_ARGS;

	/* COMPOUND4res: status, tag, then the count of resarray. */
	if (!nfsv4_put32(rx, NFS4_OK) ||
	    !nfsv4_copy_tag(ax, tagpos, taglen, rx))
		return ONCRPC_ERR_SYSTEM;
	numpos = XDR_GETPOS(rx);
	if (!nfsv4_put32(rx, 0))
		return ONCRPC_ERR_SYSTEM;

	/* RFC 7530 s15.2.4: no results at all for a minor version. */
	if (minor != NFSV4_MINORVERSION)
		return nfsv4_patch32(rx, 0, NFS4ERR_MINOR_VERS_MISMATCH) ?
		    ONCRPC_DONE : ONCRPC_ERR_SYSTEM;

	memset(&c, 0, sizeof(c));
	c.c_rq = rq;
	c.c_ax = ax;
	c.c_rx = rx;
	a = kmem_alloc(sizeof(*a), KM_SLEEP);

	disp = ONCRPC_ERR_SYSTEM;
	status = NFS4_OK;
	n = 0;
	for (i = 0; i < numops && status == NFS4_OK; i++) {
		/*
		 * The stream ending early is a count that lied; the
		 * illegal result is the only one with no results of its
		 * own to fill in.
		 */
		if (!xdr_u_int32_t(ax, &op)) {
			op = NFSV4_OP_ILLEGAL;
			status = NFS4ERR_BADXDR;
		}

		/* RFC 7530 s15.2.4: outside the range, ILLEGAL is echoed. */
		resop = op;
		if (op < NFSV4_OP_ACCESS || op > NFSV4_OP_RELEASE_LOCKOWNER) {
			resop = NFSV4_OP_ILLEGAL;
			if (status == NFS4_OK)
				status = NFS4ERR_OP_ILLEGAL;
		}

		if (!nfsv4_put32(rx, resop))
			goto out;
		statpos = XDR_GETPOS(rx);
		if (!nfsv4_put32(rx, status))
			goto out;
		n++;

		if (status == NFS4_OK) {
			if (statpos > NFSV4_RES_LIMIT - NFSV4_RES_ROOM)
				status = NFS4ERR_RESOURCE;
			else
				status = nfsv4_one_op(&c, op, a);
			if (status != NFS4_OK &&
			    !nfsv4_patch32(rx, statpos, status))
				goto out;
		}
	}

	/* RFC 7530 s15.2.4: the status of the last one evaluated. */
	if (nfsv4_patch32(rx, numpos, n) && nfsv4_patch32(rx, 0, status))
		disp = ONCRPC_DONE;
out:
	kmem_free(a, sizeof(*a));
	return disp;
}

static enum oncrpc_dispatch
nfsv4_dispatch(struct oncrpc_req *rq)
{

	switch (rq->rq_proc) {
	case NFSV4_PROC_NULL:
		return ONCRPC_DONE;
	case NFSV4_PROC_COMPOUND:
		return nfsv4_compound(rq);
	default:
		return ONCRPC_ERR_PROC;
	}
}

static const struct oncrpc_program nfsv4_program = {
	.op_prog = NFSV4_PROGRAM,
	.op_vers_low = NFSV4_VERSION,
	.op_vers_high = NFSV4_VERSION,
	.op_nprocs = NFSV4_NPROCS,
	.op_dispatch = nfsv4_dispatch,
};

/*
 * Write a descriptor to vfs.nfsv4.addsock to have it served.  The peer's
 * address goes with it, as the exports are looked up by address.
 */
static int
nfsv4_sysctl_addsock(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct sockaddr_big sb;
	struct mbuf *nam;
	file_t *fp;
	int error, fd;

	fd = -1;
	node.sysctl_data = &fd;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error != 0 || newp == NULL)
		return error;

	if ((fp = fd_getfile(fd)) == NULL)
		return EBADF;
	nam = NULL;
	if (fp->f_type == DTYPE_SOCKET &&
	    fp->f_socket->so_type == SOCK_STREAM) {
		error = do_sys_getpeername(fd, (struct sockaddr *)&sb);
		if (error != 0) {
			fd_putfile(fd);
			return error;
		}
		nam = m_get(M_WAIT, MT_SONAME);
		m_copyback(nam, 0, sb.sb_len, &sb);
	}
	error = oncrpc_svc_addsock(nfsv4_svc, fp, nam);
	fd_putfile(fd);
	return error;
}

static void
nfsv4_sysctl_init(void)
{
	const struct sysctlnode *node = NULL;

	sysctl_createv(&nfsv4_sysctllog, 0, NULL, &node,
	    CTLFLAG_PERMANENT, CTLTYPE_NODE, "nfsv4", SYSCTL_DESCR("NFS version 4 server"),
	    NULL, 0, NULL, 0, CTL_VFS, CTL_CREATE, CTL_EOL);
	sysctl_createv(&nfsv4_sysctllog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE, CTLTYPE_INT, "addsock", SYSCTL_DESCR("Serve this descriptor"),
	    nfsv4_sysctl_addsock, 0, NULL, 0,
	    CTL_VFS, node->sysctl_num, CTL_CREATE, CTL_EOL);
}

MODULE(MODULE_CLASS_MISC, nfsv4, "oncrpc,nfsserver");

static int
nfsv4_modcmd(modcmd_t cmd, void *arg)
{
	int error;

	switch (cmd) {
	case MODULE_CMD_INIT:
		error = oncrpc_svc_create("nfsv4", NFSV4_NTHREADS, &nfsv4_svc);
		if (error != 0)
			return error;
		error = oncrpc_svc_register(nfsv4_svc, &nfsv4_program);
		if (error != 0) {
			oncrpc_svc_destroy(nfsv4_svc);
			return error;
		}
		nfsv4_sysctl_init();
		return 0;
	case MODULE_CMD_FINI:
		sysctl_teardown(&nfsv4_sysctllog);
		oncrpc_svc_unregister(nfsv4_svc, &nfsv4_program);
		oncrpc_svc_destroy(nfsv4_svc);
		return 0;
	default:
		return ENOTTY;
	}
}
