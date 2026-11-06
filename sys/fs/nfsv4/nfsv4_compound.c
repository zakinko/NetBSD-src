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
#include <sys/acl.h>
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
#include <sys/vnode.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfs_var.h>

#include <fs/nfsv4/nfsv4_var.h>
#include <fs/nfsv4/nfsv4_state.h>

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
#define	NFSV4_OPF_DRC		0x02	/* its reply is for the DRC */

struct nfsv4_opdesc {
	nfsv4_op_t	od_func;	/* NULL for NFS4ERR_NOTSUPP */
	u_int		od_flags;
};

static const struct nfsv4_opdesc nfsv4_ops[NFSV4_OP_RELEASE_LOCKOWNER + 1] = {
	/* Operations 0, 1 and 2 are not defined, RFC 7530 s15.2.4. */
	[NFSV4_OP_ACCESS]	= { nfsv4_op_access,	NFSV4_OPF_FH },
	[NFSV4_OP_CLOSE]	= { nfsv4_op_close,	NFSV4_OPF_FH },
	[NFSV4_OP_COMMIT]	= { nfsv4_op_commit,	NFSV4_OPF_FH },
	[NFSV4_OP_CREATE]	= { nfsv4_op_create,	NFSV4_OPF_FH | NFSV4_OPF_DRC },
	[NFSV4_OP_DELEGPURGE]	= { nfsv4_op_delegpurge, 0 },
	[NFSV4_OP_DELEGRETURN]	= { nfsv4_op_delegreturn, NFSV4_OPF_FH | NFSV4_OPF_DRC },
	[NFSV4_OP_GETATTR]	= { nfsv4_op_getattr,	NFSV4_OPF_FH },
	[NFSV4_OP_GETFH]	= { nfsv4_op_getfh,	NFSV4_OPF_FH },
	[NFSV4_OP_LINK]		= { nfsv4_op_link,	NFSV4_OPF_FH | NFSV4_OPF_DRC },
	[NFSV4_OP_LOCK]		= { nfsv4_op_lock,	NFSV4_OPF_FH },
	[NFSV4_OP_LOCKT]	= { nfsv4_op_lockt,	NFSV4_OPF_FH },
	[NFSV4_OP_LOCKU]	= { nfsv4_op_locku,	NFSV4_OPF_FH },
	[NFSV4_OP_LOOKUP]	= { nfsv4_op_lookup,	NFSV4_OPF_FH },
	[NFSV4_OP_LOOKUPP]	= { nfsv4_op_lookupp,	NFSV4_OPF_FH },
	[NFSV4_OP_NVERIFY]	= { nfsv4_op_nverify,	NFSV4_OPF_FH },
	[NFSV4_OP_OPEN]		= { nfsv4_op_open,	NFSV4_OPF_FH },
	[NFSV4_OP_OPENATTR]	= { nfsv4_op_openattr,	NFSV4_OPF_FH },
	[NFSV4_OP_OPEN_CONFIRM]	= { nfsv4_op_open_confirm, NFSV4_OPF_FH },
	[NFSV4_OP_OPEN_DOWNGRADE] =
				  { nfsv4_op_open_downgrade, NFSV4_OPF_FH },
	[NFSV4_OP_PUTFH]	= { nfsv4_op_putfh,	0 },
	[NFSV4_OP_PUTPUBFH]	= { nfsv4_op_putpubfh,	0 },
	[NFSV4_OP_PUTROOTFH]	= { nfsv4_op_putrootfh,	0 },
	[NFSV4_OP_READ]		= { nfsv4_op_read,	NFSV4_OPF_FH },
	[NFSV4_OP_READDIR]	= { nfsv4_op_readdir,	NFSV4_OPF_FH },
	[NFSV4_OP_READLINK]	= { nfsv4_op_readlink,	NFSV4_OPF_FH },
	[NFSV4_OP_RELEASE_LOCKOWNER] =
				  { nfsv4_op_release_lockowner, 0 },
	[NFSV4_OP_REMOVE]	= { nfsv4_op_remove,	NFSV4_OPF_FH | NFSV4_OPF_DRC },
	[NFSV4_OP_RENAME]	= { nfsv4_op_rename,	NFSV4_OPF_FH | NFSV4_OPF_DRC },
	[NFSV4_OP_RENEW]	= { nfsv4_op_renew,	0 },
	[NFSV4_OP_RESTOREFH]	= { nfsv4_op_restorefh,	0 },
	[NFSV4_OP_SAVEFH]	= { nfsv4_op_savefh,	NFSV4_OPF_FH },
	[NFSV4_OP_SECINFO]	= { nfsv4_op_secinfo,	NFSV4_OPF_FH },
	[NFSV4_OP_SETATTR]	= { nfsv4_op_setattr,	NFSV4_OPF_FH | NFSV4_OPF_DRC },
	[NFSV4_OP_SETCLIENTID]	= { nfsv4_op_setclientid, NFSV4_OPF_DRC },
	[NFSV4_OP_SETCLIENTID_CONFIRM] =
				  { nfsv4_op_setclientid_confirm, NFSV4_OPF_DRC },
	[NFSV4_OP_VERIFY]	= { nfsv4_op_verify,	NFSV4_OPF_FH },
	[NFSV4_OP_WRITE]	= { nfsv4_op_write,	NFSV4_OPF_FH | NFSV4_OPF_DRC },
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
	uint32_t st;

	if (!nfsv4_xdr_args(c->c_ax, op, 0, a))
		st = NFS4ERR_BADXDR;
	else if ((od = &nfsv4_ops[op])->od_func == NULL)
		st = NFS4ERR_NOTSUPP;
	else if ((od->od_flags & NFSV4_OPF_FH) != 0 && !c->c_cur.cf_set)
		st = NFS4ERR_NOFILEHANDLE;
	else if (c->c_cur.cf_set && c->c_cur.cf_ref != NULL &&
	    !nfsv4_referral_allowed(op, a))
		st = NFS4ERR_MOVED;		/* s8.2 */
	else {
		if ((od->od_flags & NFSV4_OPF_DRC) != 0)
			c->c_drc = true;
		if (c->c_cur.cf_set && c->c_cur.cf_attr != 0)
			return nfsv4_xattr_op(c, op, a, od->od_func);
		return (*od->od_func)(c, a);
	}

	/* SETATTR4res has its bitmap whatever the status, s16.32.3. */
	if (op == NFSV4_OP_SETATTR && !nfsv4_attr_put_mask(c->c_rx, 0))
		return NFS4ERR_RESOURCE;
	return st;
}

static enum oncrpc_dispatch
nfsv4_compound(struct oncrpc_req *rq, bool *drc)
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
	c.c_rbuf = kmem_alloc(NFSV4_REPLAY_MAX, KM_SLEEP);

	/* As versions 2 and 3: the exports hold still for the whole call. */
	netexport_rdlock();

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
	*drc = c.c_drc;
	nfsv4_cfh_clear(&c.c_cur);
	nfsv4_cfh_clear(&c.c_saved);
	nfsv4_cfh_clear(&c.c_scratch);
	netexport_rdunlock();
	if (c.c_setacl != NULL)
		acl_free(c.c_setacl);
	kmem_free(c.c_rbuf, NFSV4_REPLAY_MAX);
	kmem_free(a, sizeof(*a));
	return disp;
}

static enum oncrpc_dispatch
nfsv4_dispatch(struct oncrpc_req *rq)
{
	struct nfsv4_drc d;
	enum oncrpc_dispatch disp;
	bool drc = false;

	switch (rq->rq_proc) {
	case NFSV4_PROC_NULL:
		return ONCRPC_DONE;
	case NFSV4_PROC_COMPOUND:
		if (nfsv4_drc_start(rq, &d))
			return nfsv4_drc_replay(rq, &d) ? ONCRPC_DONE :
			    ONCRPC_ERR_SYSTEM;
		disp = nfsv4_compound(rq, &drc);
		nfsv4_drc_end(&d, disp == ONCRPC_DONE && drc ? rq : NULL);
		return disp;
	default:
		return ONCRPC_ERR_PROC;
	}
}

/*
 * Write the path of the file of clients that can reclaim, once, before
 * giving the server any socket.  See nfsv4_stable.c.
 */
static int
nfsv4_sysctl_stable(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	char path[MAXPATHLEN];
	int error;

	path[0] = '\0';
	node.sysctl_data = path;
	node.sysctl_size = sizeof(path);
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error != 0 || newp == NULL)
		return error;
	return nfsv4_stable_open(path);
}

/* What is written goes to fn, a line at a time being a write. */
static int
nfsv4_sysctl_line(SYSCTLFN_ARGS, int (*fn)(const char *))
{
	struct sysctlnode node = *rnode;
	char *buf;
	int error;

	buf = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	node.sysctl_data = buf;
	node.sysctl_size = MAXPATHLEN;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error == 0 && newp != NULL)
		error = (*fn)(buf);
	kmem_free(buf, MAXPATHLEN);
	return error;
}

static int
nfsv4_sysctl_idmap(SYSCTLFN_ARGS)
{

	return nfsv4_sysctl_line(SYSCTLFN_CALL(rnode), nfsv4_idmap_line);
}

static int
nfsv4_sysctl_domain(SYSCTLFN_ARGS)
{

	return nfsv4_sysctl_line(SYSCTLFN_CALL(rnode), nfsv4_idmap_setdomain);
}

static int
nfsv4_sysctl_referral(SYSCTLFN_ARGS)
{

	return nfsv4_sysctl_line(SYSCTLFN_CALL(rnode), nfsv4_referral_line);
}

static int
nfsv4_sysctl_moved(SYSCTLFN_ARGS)
{

	return nfsv4_sysctl_line(SYSCTLFN_CALL(rnode), nfsv4_moved_line);
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
	sysctl_createv(&nfsv4_sysctllog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE, CTLTYPE_STRING, "idmap", SYSCTL_DESCR("Add a line to the owner table"),
	    nfsv4_sysctl_idmap, 0, NULL, MAXPATHLEN,
	    CTL_VFS, node->sysctl_num, CTL_CREATE, CTL_EOL);
	sysctl_createv(&nfsv4_sysctllog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE, CTLTYPE_STRING, "domain", SYSCTL_DESCR("dns_domain of owners"),
	    nfsv4_sysctl_domain, 0, NULL, MAXPATHLEN,
	    CTL_VFS, node->sysctl_num, CTL_CREATE, CTL_EOL);
	sysctl_createv(&nfsv4_sysctllog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE, CTLTYPE_STRING, "referral", SYSCTL_DESCR("Add a referral"),
	    nfsv4_sysctl_referral, 0, NULL, MAXPATHLEN,
	    CTL_VFS, node->sysctl_num, CTL_CREATE, CTL_EOL);
	sysctl_createv(&nfsv4_sysctllog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE, CTLTYPE_STRING, "moved", SYSCTL_DESCR("Say a file system has migrated"),
	    nfsv4_sysctl_moved, 0, NULL, MAXPATHLEN,
	    CTL_VFS, node->sysctl_num, CTL_CREATE, CTL_EOL);
	sysctl_createv(&nfsv4_sysctllog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE, CTLTYPE_INT, "delegations", SYSCTL_DESCR("0 none, 1 read, 2 read and write"),
	    NULL, 0, &nfsv4_deleg_mode, 0,
	    CTL_VFS, node->sysctl_num, CTL_CREATE, CTL_EOL);
	sysctl_createv(&nfsv4_sysctllog, 0, NULL, NULL,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE, CTLTYPE_STRING, "stable", SYSCTL_DESCR("File of clients that can reclaim"),
	    nfsv4_sysctl_stable, 0, NULL, MAXPATHLEN,
	    CTL_VFS, node->sysctl_num, CTL_CREATE, CTL_EOL);
}

MODULE(MODULE_CLASS_MISC, nfsv4, "oncrpc,nfsserver");

static int
nfsv4_modcmd(modcmd_t cmd, void *arg)
{
	int error;

	switch (cmd) {
	case MODULE_CMD_INIT:
		nfsv4_state_init();
		nfsv4_drc_init();
		nfsv4_cb_init();
		nfsv4_stable_init();
		nfsv4_idmap_init();
		nfsv4_referral_init();
		error = oncrpc_svc_create("nfsv4", NFSV4_NTHREADS, &nfsv4_svc);
		if (error != 0) {
			nfsv4_referral_fini();
			nfsv4_idmap_fini();
			nfsv4_stable_fini();
			nfsv4_deleg_fini();
			nfsv4_cb_fini();
			nfsv4_drc_fini();
			nfsv4_state_fini();
			return error;
		}
		error = oncrpc_svc_register(nfsv4_svc, &nfsv4_program);
		if (error != 0) {
			oncrpc_svc_destroy(nfsv4_svc);
			nfsv4_referral_fini();
			nfsv4_idmap_fini();
			nfsv4_deleg_fini();
			nfsv4_stable_fini();
			nfsv4_cb_fini();
			nfsv4_drc_fini();
			nfsv4_state_fini();
			return error;
		}
		nfsv4_sysctl_init();
		return 0;
	case MODULE_CMD_FINI:
		nfsv4_deleg_fini();
		sysctl_teardown(&nfsv4_sysctllog);
		oncrpc_svc_unregister(nfsv4_svc, &nfsv4_program);
		oncrpc_svc_destroy(nfsv4_svc);
		nfsv4_cb_fini();
		nfsv4_drc_fini();
		nfsv4_state_fini();
		nfsv4_stable_fini();
		nfsv4_idmap_fini();
		nfsv4_referral_fini();
		return 0;
	default:
		return ENOTTY;
	}
}
