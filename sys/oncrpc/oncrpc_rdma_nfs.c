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
 * The upper-layer binding of NFS versions 2 and 3, RFC 8267 s4: only
 * the data of WRITE and the path of SYMLINK may come by a Read chunk,
 * and of the results only those of READ and READLINK may go by a Write
 * chunk.  MOUNT, NLM and NSM have no binding here, s5.1, for they stay
 * on TCP, and NFSACL has nothing eligible, s5.2.
 *
 * This lives apart from sys/nfs because that is a place which does not
 * know of chunks, and in sys/oncrpc as it is plain arithmetic on the
 * stream that a program registers by name.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <string.h>
#endif

#include <oncrpc/oncrpc_rdma.h>

#define	PADLEN(n)	((4 - ((n) & 3)) & 3)

/* RFC 1094 s2.2 and RFC 1813 s3.3 */
#define	NFS2PROC_READLINK	5
#define	NFS2PROC_READ		6
#define	NFS2PROC_WRITE		8
#define	NFS2PROC_SYMLINK	13
#define	NFS3PROC_READLINK	5
#define	NFS3PROC_READ		6
#define	NFS3PROC_WRITE		7
#define	NFS3PROC_SYMLINK	10

#define	NFS2_FHSIZE		32	/* RFC 1094 s2.3.3 */
#define	NFS3_FHSIZE		64	/* RFC 1813 s2.4 */
#define	NFS2_FATTRSIZE		68	/* RFC 1094 s2.3.5, 11 words, 3 timevals */
#define	NFS3_FATTRSIZE		84	/* RFC 1813 s2.6, fattr3 */
#define	NFS_OK			0	/* RFC 1094 s2.3.1, RFC 1813 s2.6 */

struct cur {
	const uint8_t	*c_p;
	u_int		c_len;
	u_int		c_off;
};

static bool
cur_32(struct cur *c, uint32_t *v)
{
	const uint8_t *p;

	if (c->c_len - c->c_off < 4)
		return false;
	p = c->c_p + c->c_off;
	*v = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	    (uint32_t)p[2] << 8 | p[3];
	c->c_off += 4;
	return true;
}

static bool
cur_skip(struct cur *c, uint32_t n)
{

	if (n > c->c_len - c->c_off)
		return false;
	c->c_off += n;
	return true;
}

/* A variable opaque, not eligible. */
static bool
cur_opaque(struct cur *c, uint32_t max)
{
	uint32_t n;

	if (!cur_32(c, &n) || n > max || n + PADLEN(n) < n)
		return false;
	return cur_skip(c, n + PADLEN(n));
}

/* An eligible item, at its length word. */
static bool
cur_item(struct cur *c, struct oncrpc_rdma_ddpscan *rd)
{
	uint32_t n, skip;

	return cur_32(c, &n) &&
	    oncrpc_rdma_ddp_item(rd, c->c_off, n, &skip) &&
	    cur_skip(c, skip);
}

/* sattr3, RFC 1813 s2.5 */
static bool
cur_sattr3(struct cur *c)
{
	static const uint8_t size[4] = { 4, 4, 4, 8 };
	uint32_t v;
	u_int i;

	for (i = 0; i < 4; i++) {
		if (!cur_32(c, &v) || v > 1)
			return false;
		if (v != 0 && !cur_skip(c, size[i]))
			return false;
	}
	for (i = 0; i < 2; i++) {	/* set_atime, set_mtime */
		if (!cur_32(c, &v) || v > 2)
			return false;
		if (v == 2 && !cur_skip(c, 8))	/* SET_TO_CLIENT_TIME */
			return false;
	}
	return true;
}

static bool
nfs23_scan(const void *buf, u_int len, u_int off, uint32_t vers, uint32_t proc,
    struct oncrpc_rdma_ddpscan *rd)
{
	struct cur c = { buf, len, off };

	if (vers == 2 && proc == NFS2PROC_WRITE)
		return cur_skip(&c, NFS2_FHSIZE + 3 * 4) && cur_item(&c, rd);
	if (vers == 2 && proc == NFS2PROC_SYMLINK)
		return cur_skip(&c, NFS2_FHSIZE) && cur_opaque(&c, UINT32_MAX) &&
		    cur_item(&c, rd);
	if (vers == 3 && proc == NFS3PROC_WRITE)
		return cur_opaque(&c, NFS3_FHSIZE) && cur_skip(&c, 8 + 4 + 4) &&
		    cur_item(&c, rd);
	if (vers == 3 && proc == NFS3PROC_SYMLINK)
		return cur_opaque(&c, NFS3_FHSIZE) &&
		    cur_opaque(&c, UINT32_MAX) && cur_sattr3(&c) &&
		    cur_item(&c, rd);
	return true;			/* no chunk can match */
}

/*
 * The result of READ or READLINK, s4: of version 2 the data or path is
 * after the status and, for READ, a fattr (RFC 1094 s2.2.6, s2.2.7); of
 * version 3 after the status and a post_op_attr, and for READ count and
 * eof (RFC 1813 s3.3.5, s3.3.6).  A reply that is not NFS_OK has none.
 */
static bool
nfs23_reply(const void *buf, u_int len, u_int off, u_int total, uint32_t vers,
    uint32_t proc, struct oncrpc_rdma_mark *dm)
{
	struct cur c = { buf, len, off };
	uint32_t v, n;

	if (proc != (vers == 2 ? NFS2PROC_READ : NFS3PROC_READ) &&
	    proc != (vers == 2 ? NFS2PROC_READLINK : NFS3PROC_READLINK))
		return false;
	if (vers != 2 && vers != 3)
		return false;
	if (!cur_32(&c, &v) || v != NFS_OK)
		return false;
	if (vers == 2) {
		if (proc == NFS2PROC_READ && !cur_skip(&c, NFS2_FATTRSIZE))
			return false;
	} else {
		if (!cur_32(&c, &v) || v > 1 ||
		    (v == 1 && !cur_skip(&c, NFS3_FATTRSIZE)))
			return false;
		if (proc == NFS3PROC_READ && !cur_skip(&c, 4 + 4))
			return false;
	}
	if (!cur_32(&c, &n) || n > total || c.c_off > total - n)
		return false;
	dm->dm_pos = c.c_off;
	dm->dm_len = n;
	return true;
}

const struct oncrpc_rdma_ulb oncrpc_rdma_ulb_nfs23 = {
	.ub_scan = nfs23_scan,
	.ub_reply = nfs23_reply,
};

/*
 * NFSACL, RFC 8267 s5.2: on the connection of NFS, with no item that is
 * DDP-eligible, so any Read chunk past the base is ERR_CHUNK, s6.1, and
 * any Write chunk goes back unused.  A GETACL that does not fit inline
 * goes by the Reply chunk the client gives, as any long reply does.
 * Given here for the program of NFSACL to name in op_ulb; a program with
 * none there is answered the same, but says nothing of why.
 */
static bool
nfsacl_scan(const void *buf, u_int len, u_int off, uint32_t vers,
    uint32_t proc, struct oncrpc_rdma_ddpscan *rd)
{

	return true;
}

const struct oncrpc_rdma_ulb oncrpc_rdma_ulb_nfsacl = {
	.ub_scan = nfsacl_scan,
};
