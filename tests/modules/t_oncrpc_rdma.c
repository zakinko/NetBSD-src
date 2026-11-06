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
 * RPC-over-RDMA headers, chunks and bindings, and the iWARP wire, in
 * userland against xdrmem.  Built under ASan and UBSan it also shows no
 * input reads out of bounds.  Exit status 0 is success.
 *
 *	cc -fsanitize=address,undefined -I../../sys -o t t_oncrpc_rdma.c
 */

#include <sys/types.h>
#include <sys/param.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#ifndef __KERNEL_RCSID
#define	__KERNEL_RCSID(a, b)
#endif
#ifndef __UNCONST
#define	__UNCONST(a)	((void *)(uintptr_t)(a))
#endif
#ifndef EPROTO
#define	EPROTO		100
#endif

#include "oncrpc/oncrpc_rdma_hdr.c"
#undef	WORD
#undef	SEG_WORDS
#include "oncrpc/oncrpc_rdma_chunk.c"
#undef	PADLEN
#define	get32		wire_get32
#include "oncrpc/oncrpc_iwarp_wire.c"
#undef	get32
#include "oncrpc/oncrpc_rdma_nfs.c"
#include "fs/nfsv4/nfsv4_xdr.c"
#undef	U32
#undef	U64
#include "fs/nfsv4/nfsv4_ulb.c"

static int failed, checks;

#define	CHECK(e) do {							\
	checks++;							\
	if (!(e)) {							\
		printf("FAIL line %d: %s\n", __LINE__, #e);		\
		failed++;						\
	}								\
} while (0)

/* A word at a time, as the examples of RFC 8166 s4.7 are written. */
static uint8_t wire[1 << 17];
static u_int wn;

static void
w(uint32_t v)
{

	wire[wn++] = v >> 24;
	wire[wn++] = v >> 16;
	wire[wn++] = v >> 8;
	wire[wn++] = v;
}

static void
fixed(uint32_t proc)
{

	wn = 0;
	w(0x11223344);		/* xid */
	w(ONCRPC_RDMA_VERS);
	w(32);			/* credit */
	w(proc);
}

static void
hloo(uint32_t h, uint32_t l, uint64_t o)
{

	w(h);
	w(l);
	w(o >> 32);
	w((uint32_t)o);
}

static void
test_hdr_decode(void)
{
	struct oncrpc_rdma_hdr h;

	/* "after the four fixed fields ... three 32-bit fields" s4.7 */
	fixed(ONCRPC_RDMA_MSG);
	w(0); w(0); w(0);
	CHECK(wn == ONCRPC_RDMA_MINHDR);
	CHECK(oncrpc_rdma_hdr_decode(wire, wn, &h) == ONCRPC_RDMA_DEC_OK);
	CHECK(h.rh_xid == 0x11223344 && h.rh_credit == 32);
	CHECK(h.rh_nread == 0 && h.rh_nwrite == 0 && !h.rh_hasreply);
	CHECK(h.rh_hdrlen == 28);
	oncrpc_rdma_hdr_fini(&h);

	/* 1 PHLOO 1 PHLOO 0, 1 3 HLOO HLOO HLOO 1 2 HLOO HLOO 0, 1 2 HLOO HLOO */
	fixed(ONCRPC_RDMA_MSG);
	w(1); w(8); hloo(1, 100, 0x1000);
	w(1); w(8); hloo(2, 200, 0xffffffff00000000ULL);
	w(0);
	w(1); w(3); hloo(3, 1, 0); hloo(4, 2, 0); hloo(5, 3, 0);
	w(1); w(2); hloo(6, 4, 0); hloo(7, 5, 0);
	w(0);
	w(1); w(2); hloo(8, 6, 0); hloo(9, 7, 77);
	CHECK(oncrpc_rdma_hdr_decode(wire, wn, &h) == ONCRPC_RDMA_DEC_OK);
	CHECK(h.rh_nread == 2 && h.rh_nwrite == 2 && h.rh_hasreply);
	CHECK(h.rh_reads[1].rr_position == 8);
	CHECK(h.rh_reads[1].rr_seg.rs_offset == 0xffffffff00000000ULL);
	CHECK(h.rh_writes[0].rw_nseg == 3);
	CHECK(h.rh_writes[0].rw_segs[2].rs_handle == 5);
	CHECK(h.rh_writes[1].rw_nseg == 2);
	CHECK(h.rh_writes[1].rw_segs[1].rs_length == 5);
	CHECK(h.rh_reply.rw_nseg == 2);
	CHECK(h.rh_reply.rw_segs[1].rs_offset == 77);
	CHECK(h.rh_hdrlen == wn);
	CHECK(oncrpc_rdma_hdr_size(&h) == wn);
	{
		/* Encoding gives back the same bytes. */
		static uint8_t out[sizeof(wire)];
		XDR x;

		xdrmem_create(&x, (char *)out, sizeof(out), XDR_ENCODE);
		CHECK(oncrpc_rdma_hdr_encode(&x, &h));
		CHECK(XDR_GETPOS(&x) == wn);
		CHECK(memcmp(out, wire, wn) == 0);
	}
	oncrpc_rdma_hdr_fini(&h);
}

static void
test_hdr_reject(void)
{
	struct oncrpc_rdma_hdr h;
	u_int i, keep;

	/* s4.5: under 28 bytes, silently, for the XID cannot be trusted. */
	fixed(ONCRPC_RDMA_MSG);
	w(0); w(0);
	CHECK(oncrpc_rdma_hdr_decode(wire, wn, &h) == ONCRPC_RDMA_DEC_DROP);

	/* s4.5.1 */
	fixed(ONCRPC_RDMA_MSG);
	w(0); w(0); w(0);
	wire[7] = 2;
	CHECK(oncrpc_rdma_hdr_decode(wire, wn, &h) == ONCRPC_RDMA_DEC_ERR_VERS);
	CHECK(h.rh_vers == 2 && h.rh_xid == 0x11223344);

	/* s4.6.1, s4.6.2, s4.2.4, s4.5.2 */
	fixed(ONCRPC_RDMA_MSGP); w(0); w(0); w(0);
	CHECK(oncrpc_rdma_hdr_decode(wire, wn, &h) ==
	    ONCRPC_RDMA_DEC_ERR_CHUNK);
	fixed(ONCRPC_RDMA_DONE); w(0); w(0); w(0);
	CHECK(oncrpc_rdma_hdr_decode(wire, wn, &h) == ONCRPC_RDMA_DEC_DROP);
	fixed(ONCRPC_RDMA_ERROR); w(2); w(0); w(0);
	CHECK(oncrpc_rdma_hdr_decode(wire, wn, &h) == ONCRPC_RDMA_DEC_DROP);
	fixed(5); w(0); w(0); w(0);
	CHECK(oncrpc_rdma_hdr_decode(wire, wn, &h) ==
	    ONCRPC_RDMA_DEC_ERR_CHUNK);

	/* An optional that is neither 0 nor 1. */
	fixed(ONCRPC_RDMA_MSG); w(2); w(0); w(0);
	CHECK(oncrpc_rdma_hdr_decode(wire, wn, &h) ==
	    ONCRPC_RDMA_DEC_ERR_CHUNK);

	/* A count past the end of the message. */
	fixed(ONCRPC_RDMA_MSG); w(0); w(1); w(0xffffffff); w(0); w(0); w(0);
	CHECK(oncrpc_rdma_hdr_decode(wire, wn, &h) ==
	    ONCRPC_RDMA_DEC_ERR_CHUNK);

	/* Every truncation of a good one. */
	fixed(ONCRPC_RDMA_MSG);
	w(1); w(8); hloo(1, 100, 0x1000); w(0);
	w(1); w(1); hloo(2, 2, 2); w(0);
	w(1); w(1); hloo(3, 3, 3);
	keep = wn;
	for (i = ONCRPC_RDMA_MINHDR; i < keep; i++) {
		CHECK(oncrpc_rdma_hdr_decode(wire, i, &h) ==
		    ONCRPC_RDMA_DEC_ERR_CHUNK);
	}
	CHECK(oncrpc_rdma_hdr_decode(wire, keep, &h) == ONCRPC_RDMA_DEC_OK);
	oncrpc_rdma_hdr_fini(&h);
}

static void
test_hdr_fuzz(void)
{
	struct oncrpc_rdma_hdr h;
	u_int i, j, len, pos;

	srandom(8166);
	for (i = 0; i < 200000; i++) {
		fixed(ONCRPC_RDMA_MSG);
		w(1); w(8); hloo(1, 100, 0x1000); w(0);
		w(1); w(1); hloo(2, 2, 2); w(0);
		w(1); w(2); hloo(3, 3, 3); hloo(4, 4, 4);
		len = wn;
		for (j = 0; j < 1 + (u_int)(random() % 4); j++) {
			pos = (u_int)random() % len;
			wire[pos] = (uint8_t)random();
		}
		if (oncrpc_rdma_hdr_decode(wire, len, &h) == ONCRPC_RDMA_DEC_OK)
			oncrpc_rdma_hdr_fini(&h);
	}
	CHECK(1);
}

static void
test_error_encode(void)
{
	static const uint8_t vers[] = {
		0, 0, 0, 7,  0, 0, 0, 9,  0, 0, 0, 32,  0, 0, 0, 4,
		0, 0, 0, 1,  0, 0, 0, 1,  0, 0, 0, 1
	};
	static uint8_t out[64];
	XDR x;

	xdrmem_create(&x, (char *)out, sizeof(out), XDR_ENCODE);
	CHECK(oncrpc_rdma_error_encode(&x, 7, 9, 32, ONCRPC_RDMA_ERR_VERS));
	CHECK(XDR_GETPOS(&x) == sizeof(vers));
	CHECK(memcmp(out, vers, sizeof(vers)) == 0);

	xdrmem_create(&x, (char *)out, sizeof(out), XDR_ENCODE);
	CHECK(oncrpc_rdma_error_encode(&x, 7, 1, 32, ONCRPC_RDMA_ERR_CHUNK));
	CHECK(XDR_GETPOS(&x) == 20);
}

static struct oncrpc_rdma_rseg rs[8];

static void
rs_set(u_int i, uint32_t pos, uint32_t handle, uint32_t len)
{

	memset(&rs[i], 0, sizeof(rs[i]));
	rs[i].rr_position = pos;
	rs[i].rr_seg.rs_handle = handle;
	rs[i].rr_seg.rs_length = len;
}

static void
test_group(void)
{
	struct oncrpc_rdma_hdr h;
	struct oncrpc_rdma_rchunk rc[8];
	u_int n;

	memset(&h, 0, sizeof(h));
	h.rh_reads = rs;

	/* Same Position is one chunk, in list order. */
	rs_set(0, 100, 1, 10);
	rs_set(1, 100, 2, 20);
	rs_set(2, 0, 3, 40);
	rs_set(3, 100, 4, 30);
	h.rh_nread = 4;
	CHECK(oncrpc_rdma_reads_group(&h, rc, &n, 1000) == 0);
	CHECK(n == 2);
	CHECK(rc[0].rc_pos == 0 && rc[0].rc_len == 40 && rc[0].rc_nseg == 1);
	CHECK(rc[1].rc_pos == 100 && rc[1].rc_len == 60 && rc[1].rc_nseg == 3);
	CHECK(rs[1].rr_seg.rs_handle == 1 && rs[2].rr_seg.rs_handle == 2 &&
	    rs[3].rr_seg.rs_handle == 4);

	/* s3.4.5 */
	rs_set(0, 6, 1, 10);
	h.rh_nread = 1;
	CHECK(oncrpc_rdma_reads_group(&h, rc, &n, 1000) == EINVAL);

	/* s8.1.4 */
	rs_set(0, 4, 1, 1001);
	CHECK(oncrpc_rdma_reads_group(&h, rc, &n, 1000) == EFBIG);
	rs_set(0, 4, 1, 0xffffffff);
	rs_set(1, 4, 1, 0xffffffff);
	h.rh_nread = 2;
	CHECK(oncrpc_rdma_reads_group(&h, rc, &n, 1 << 20) == EFBIG);

	/* A segment that wraps. */
	rs_set(0, 4, 1, 16);
	rs[0].rr_seg.rs_offset = UINT64_MAX - 3;
	h.rh_nread = 1;
	CHECK(oncrpc_rdma_reads_group(&h, rc, &n, 1000) == EINVAL);
}

/* Run a layout over a base of 'b's with chunks of 'c', 'd', ... */
static u_int
assemble(const struct oncrpc_rdma_rchunk *rc, u_int n, u_int baselen,
    uint8_t *out)
{
	struct oncrpc_rdma_layout rl;
	struct oncrpc_rdma_piece p;
	u_int o = 0;

	oncrpc_rdma_layout_init(&rl, rc, n, baselen);
	while (oncrpc_rdma_layout_next(&rl, &p)) {
		switch (p.rp_type) {
		case RDMA_P_BASE:
			memset(out + o, 'b', p.rp_len);
			o += p.rp_len;
			break;
		case RDMA_P_CHUNK:
			memset(out + o, 'c' + p.rp_chunk,
			    rc[p.rp_chunk].rc_len);
			o += rc[p.rp_chunk].rc_len;
			break;
		case RDMA_P_PAD:
			memset(out + o, 0, p.rp_len);
			o += p.rp_len;
			break;
		}
	}
	return o;
}

static void
test_layout(void)
{
	struct oncrpc_rdma_layout rl;
	struct oncrpc_rdma_rchunk rc[3];
	uint8_t out[128];
	u_int n;

	memset(rc, 0, sizeof(rc));

	/* One chunk mid-stream, its padding taken out of the base. */
	rc[0].rc_pos = 8;
	rc[0].rc_len = 5;
	n = assemble(rc, 1, 12, out);
	CHECK(n == 20);
	CHECK(memcmp(out, "bbbbbbbbccccc\0\0\0bbbb", 20) == 0);

	/* At the very end. */
	rc[0].rc_pos = 12;
	rc[0].rc_len = 4;
	CHECK(assemble(rc, 1, 12, out) == 16);
	CHECK(memcmp(out, "bbbbbbbbbbbbcccc", 16) == 0);

	/* Position is of the unreduced stream: the second counts the first. */
	rc[0].rc_pos = 4;
	rc[0].rc_len = 6;
	rc[1].rc_pos = 16;
	rc[1].rc_len = 4;
	oncrpc_rdma_layout_init(&rl, rc, 2, 12);
	CHECK(oncrpc_rdma_layout_check(&rl));
	CHECK(assemble(rc, 2, 12, out) == 24);
	CHECK(memcmp(out, "bbbbcccccc\0\0" "bbbbdddd" "bbbb", 24) == 0);

	/* Next to each other. */
	rc[1].rc_pos = 12;
	CHECK(assemble(rc, 2, 4, out) == 16);
	CHECK(memcmp(out, "bbbbcccccc\0\0dddd", 16) == 0);

	/* Past the end of the base, and inside the one before. */
	rc[0].rc_pos = 16;
	rc[0].rc_len = 4;
	oncrpc_rdma_layout_init(&rl, rc, 1, 12);
	CHECK(!oncrpc_rdma_layout_check(&rl));
	rc[0].rc_pos = 4;
	rc[0].rc_len = 16;
	rc[1].rc_pos = 8;
	oncrpc_rdma_layout_init(&rl, rc, 2, 12);
	CHECK(!oncrpc_rdma_layout_check(&rl));
}

/* An RPC call for prog, vers and proc, with AUTH_SYS of 16 bytes. */
static void
call(uint32_t prog, uint32_t vers, uint32_t proc)
{

	wn = 0;
	w(0x11223344);
	w(0);			/* CALL */
	w(2);
	w(prog);
	w(vers);
	w(proc);
	w(1); w(16); w(0); w(0); w(0); w(0);
	w(0); w(0);
}

static void
test_peek(void)
{
	struct oncrpc_rdma_callinfo ri;

	call(100003, 3, 7);
	CHECK(oncrpc_rdma_call_peek(wire, wn, &ri));
	CHECK(ri.ri_xid == 0x11223344 && ri.ri_mtype == 0);
	CHECK(ri.ri_prog == 100003 && ri.ri_vers == 3 && ri.ri_proc == 7);
	CHECK(ri.ri_argoff == wn);

	/* A cred length to the moon leaves no place for the arguments. */
	wire[28] = 0xff;
	CHECK(oncrpc_rdma_call_peek(wire, wn, &ri));
	CHECK(ri.ri_argoff == 0);

	CHECK(!oncrpc_rdma_call_peek(wire, 7, &ri));
	CHECK(oncrpc_rdma_call_peek(wire, 8, &ri) && ri.ri_argoff == 0);
}

/* What a chunk at pos of len comes to, for one binding. */
static bool
scan(const struct oncrpc_rdma_ulb *ub, uint32_t vers, uint32_t proc,
    u_int argoff, const struct oncrpc_rdma_rchunk *rc, u_int n)
{
	struct oncrpc_rdma_ddpscan rd;

	oncrpc_rdma_ddp_init(&rd, rc, n);
	return (*ub->ub_scan)(wire, wn, argoff, vers, proc, &rd) &&
	    oncrpc_rdma_ddp_done(&rd);
}

static void
test_ulb_v3(void)
{
	struct oncrpc_rdma_rchunk rc;
	const struct oncrpc_rdma_ulb *ub = &oncrpc_rdma_ulb_nfs23;
	u_int a, d;

	memset(&rc, 0, sizeof(rc));

	/* WRITE3args: fh, offset, count, stable, data; 7 bytes reduced. */
	call(100003, 3, 7);
	a = wn;
	w(8); w(1); w(2);	/* nfs_fh3 */
	w(0); w(0);		/* offset */
	w(7);			/* count */
	w(0);			/* stable */
	w(7);			/* opaque data<>: the length stays, s3.4.4.1 */
	d = wn;
	rc.rc_pos = d;
	rc.rc_len = 7;
	CHECK(scan(ub, 3, 7, a, &rc, 1));
	rc.rc_len = 8;		/* with the roundup, s3.4.5.2 */
	CHECK(scan(ub, 3, 7, a, &rc, 1));
	rc.rc_len = 6;
	CHECK(!scan(ub, 3, 7, a, &rc, 1));
	rc.rc_len = 7;
	rc.rc_pos = d - 4;	/* the wrong place: s6.1 violation */
	CHECK(!scan(ub, 3, 7, a, &rc, 1));

	/* Nothing else in the protocol is eligible. */
	rc.rc_pos = d;
	CHECK(!scan(ub, 3, 6, a, &rc, 1));	/* READ */
	CHECK(!scan(ub, 3, 1, a, &rc, 1));	/* GETATTR */

	/* SYMLINK3args: where, then sattr3 with a size and mtime, then path */
	call(100003, 3, 10);
	a = wn;
	w(8); w(1); w(2);	/* dir */
	w(3); w(0x61620000);	/* name "ab." */
	w(1); w(0755);		/* mode */
	w(0); w(0);		/* uid gid */
	w(1); w(0); w(9);	/* size */
	w(0);			/* atime: DONT_CHANGE */
	w(2); w(5); w(6);	/* mtime: SET_TO_CLIENT_TIME */
	w(10);			/* path length */
	rc.rc_pos = wn;
	rc.rc_len = 10;
	CHECK(scan(ub, 3, 10, a, &rc, 1));

	/* An inline item, with the args cut short. */
	call(100003, 3, 7);
	a = wn;
	w(8);
	rc.rc_pos = wn + 100;
	CHECK(!scan(ub, 3, 7, a, &rc, 1));
}

static void
test_ulb_v2(void)
{
	struct oncrpc_rdma_rchunk rc;
	const struct oncrpc_rdma_ulb *ub = &oncrpc_rdma_ulb_nfs23;
	u_int a, i;

	memset(&rc, 0, sizeof(rc));

	/* writeargs: fhandle, beginoffset, offset, totalcount, data */
	call(100003, 2, 8);
	a = wn;
	for (i = 0; i < 8; i++)
		w(0);
	w(0); w(0); w(0);
	w(1024);
	rc.rc_pos = wn;
	rc.rc_len = 1024;
	CHECK(scan(ub, 2, 8, a, &rc, 1));

	/* symlinkargs: from diropargs, to path, attributes */
	call(100003, 2, 13);
	a = wn;
	for (i = 0; i < 8; i++)
		w(0);
	w(4); w(0x61626364);
	w(6);
	rc.rc_pos = wn;
	rc.rc_len = 6;
	for (i = 0; i < 8; i++)
		w(0);
	CHECK(scan(ub, 2, 13, a, &rc, 1));
	CHECK(!scan(ub, 2, 8, a, &rc, 1));
}

static void
test_ulb_v4(void)
{
	struct oncrpc_rdma_rchunk rc[2];
	const struct oncrpc_rdma_ulb *ub = &nfsv4_ulb;
	u_int a, i, d;

	memset(rc, 0, sizeof(rc));

	/* COMPOUND: PUTFH WRITE GETATTR */
	call(100003, 4, NFSV4_PROC_COMPOUND);
	a = wn;
	w(0);			/* tag */
	w(0);			/* minorversion */
	w(3);
	w(NFSV4_OP_PUTFH); w(8); w(1); w(2);
	w(NFSV4_OP_WRITE);
	for (i = 0; i < 4; i++)
		w(0);		/* stateid */
	w(0); w(0);		/* offset */
	w(0);			/* stable */
	w(5);			/* data<> */
	d = wn;
	w(NFSV4_OP_GETATTR); w(1); w(0x10);
	rc[0].rc_pos = d;
	rc[0].rc_len = 5;
	CHECK(scan(ub, 4, NFSV4_PROC_COMPOUND, a, rc, 1));

	/* In GETATTR's bitmap: not an eligible item. */
	rc[0].rc_pos = d + 8;
	CHECK(!scan(ub, 4, NFSV4_PROC_COMPOUND, a, rc, 1));

	/* Two WRITEs; the second Position counts the first's roundup. */
	call(100003, 4, NFSV4_PROC_COMPOUND);
	a = wn;
	w(0); w(0); w(2);
	w(NFSV4_OP_WRITE);
	for (i = 0; i < 7; i++)
		w(0);
	w(5);
	rc[0].rc_pos = wn;
	rc[0].rc_len = 5;
	w(NFSV4_OP_WRITE);
	for (i = 0; i < 7; i++)
		w(0);
	w(4);
	rc[1].rc_pos = wn + 8;
	rc[1].rc_len = 4;
	CHECK(scan(ub, 4, NFSV4_PROC_COMPOUND, a, rc, 2));

	/* One chunked, then one inline. */
	call(100003, 4, NFSV4_PROC_COMPOUND);
	a = wn;
	w(0); w(0); w(2);
	w(NFSV4_OP_WRITE);
	for (i = 0; i < 7; i++)
		w(0);
	w(4); w(0x41424344);	/* inline */
	w(NFSV4_OP_WRITE);
	for (i = 0; i < 7; i++)
		w(0);
	w(8);
	rc[0].rc_pos = wn;
	rc[0].rc_len = 8;
	CHECK(scan(ub, 4, NFSV4_PROC_COMPOUND, a, rc, 1));

	/* CREATE of an NF4LNK: linkdata, then the name and attributes. */
	call(100003, 4, NFSV4_PROC_COMPOUND);
	a = wn;
	w(0); w(0); w(2);
	w(NFSV4_OP_CREATE);
	w(NF4LNK);
	w(9);
	rc[0].rc_pos = wn;
	rc[0].rc_len = 9;
	w(1); w(0x61000000);	/* objname */
	w(0); w(0);		/* createattrs */
	w(NFSV4_OP_GETFH);
	CHECK(scan(ub, 4, NFSV4_PROC_COMPOUND, a, rc, 1));

	/* A directory has no linkdata; a chunk there is out of place. */
	call(100003, 4, NFSV4_PROC_COMPOUND);
	a = wn;
	w(0); w(0); w(1);
	w(NFSV4_OP_CREATE);
	w(NF4DIR);
	w(1);
	rc[0].rc_pos = wn;
	rc[0].rc_len = 1;
	w(0x61000000);
	w(0); w(0);
	CHECK(!scan(ub, 4, NFSV4_PROC_COMPOUND, a, rc, 1));

	/* An unknown operation ends the walk. */
	call(100003, 4, NFSV4_PROC_COMPOUND);
	a = wn;
	w(0); w(0); w(2);
	w(9999);
	w(NFSV4_OP_WRITE);
	rc[0].rc_pos = wn + 40;
	rc[0].rc_len = 1;
	CHECK(!scan(ub, 4, NFSV4_PROC_COMPOUND, a, rc, 1));
}

static struct oncrpc_rdma_seg segs[8];

static struct oncrpc_rdma_wchunk
wc(u_int first, u_int n, uint32_t each)
{
	struct oncrpc_rdma_wchunk rw;
	u_int i;

	for (i = 0; i < n; i++) {
		segs[first + i].rs_handle = 100 + first + i;
		segs[first + i].rs_length = each;
		segs[first + i].rs_offset = 0;
	}
	rw.rw_nseg = n;
	rw.rw_segs = &segs[first];
	return rw;
}

static void
test_plan(void)
{
	struct oncrpc_rdma_hdr h;
	struct oncrpc_rdma_wchunk wl[3];
	struct oncrpc_rdma_mark m[3];
	struct oncrpc_rdma_plan rp;
	int co[3];

	memset(&h, 0, sizeof(h));
	h.rh_writes = wl;

	/* No chunks, fits: 28 of header. */
	oncrpc_rdma_reply_plan(&h, NULL, 0, 996, 1024, co, &rp);
	CHECK(rp.rp_form == ONCRPC_RDMA_SHORT && rp.rp_reduced == 996);
	CHECK(rp.rp_hdrlen == 28);
	/* One byte too many, and nowhere for it to go. */
	oncrpc_rdma_reply_plan(&h, NULL, 0, 997, 1024, co, &rp);
	CHECK(rp.rp_form == ONCRPC_RDMA_NOFIT);

	/* s3.5.3: by the Reply chunk */
	h.rh_hasreply = true;
	h.rh_reply = wc(6, 2, 1000);
	oncrpc_rdma_reply_plan(&h, NULL, 0, 2000, 1024, co, &rp);
	CHECK(rp.rp_form == ONCRPC_RDMA_LONG);
	oncrpc_rdma_reply_plan(&h, NULL, 0, 2001, 1024, co, &rp);
	CHECK(rp.rp_form == ONCRPC_RDMA_NOFIT);
	/* It fits inline, s4.3.3 says MAY. */
	oncrpc_rdma_reply_plan(&h, NULL, 0, 100, 1024, co, &rp);
	CHECK(rp.rp_form == ONCRPC_RDMA_SHORT);
	h.rh_hasreply = false;

	/* A READ into a Write chunk: the roundup leaves the stream too. */
	wl[0] = wc(0, 2, 4096);
	h.rh_nwrite = 1;
	m[0].dm_pos = 100;
	m[0].dm_len = 8191;
	oncrpc_rdma_reply_plan(&h, m, 1, 100 + 8192 + 40, 1024, co, &rp);
	CHECK(rp.rp_form == ONCRPC_RDMA_SHORT);
	CHECK(co[0] == 0 && rp.rp_reduced == 140);
	CHECK(rp.rp_hdrlen == 28 + 8 + 2 * 16);

	/* Over what the chunk offers. */
	m[0].dm_len = 8193;
	oncrpc_rdma_reply_plan(&h, m, 1, 100 + 8196 + 40, 1024, co, &rp);
	CHECK(rp.rp_form == ONCRPC_RDMA_NOFIT);

	/* RFC 8267 s6.4.1: an empty chunk leaves its READ inline. */
	wl[0] = wc(0, 0, 0);
	m[0].dm_len = 400;
	oncrpc_rdma_reply_plan(&h, m, 1, 600, 1024, co, &rp);
	CHECK(rp.rp_form == ONCRPC_RDMA_SHORT);
	CHECK(co[0] == ONCRPC_RDMA_INLINE_ITEM && rp.rp_reduced == 600);

	/* More READs than chunks: the rest inline. */
	wl[0] = wc(0, 1, 4096);
	m[0].dm_pos = 100;
	m[0].dm_len = 4000;
	m[1].dm_pos = 4200;
	m[1].dm_len = 100;
	oncrpc_rdma_reply_plan(&h, m, 2, 4400, 1024, co, &rp);
	CHECK(co[0] == 0 && co[1] == ONCRPC_RDMA_INLINE_ITEM);
	CHECK(rp.rp_reduced == 400);

	/* Chunks left over are returned, so count in the header. */
	wl[1] = wc(1, 3, 4096);
	h.rh_nwrite = 2;
	oncrpc_rdma_reply_plan(&h, m, 1, 4200, 1024, co, &rp);
	CHECK(rp.rp_hdrlen == 28 + 8 + 16 + 8 + 3 * 16);
}

static void
test_fill(void)
{
	struct oncrpc_rdma_wchunk rw;

	rw = wc(0, 3, 100);
	oncrpc_rdma_chunk_fill(&rw, 150);
	CHECK(segs[0].rs_length == 100 && segs[1].rs_length == 50 &&
	    segs[2].rs_length == 0);

	/* s4.3.2.2: an unused chunk keeps its count. */
	rw = wc(0, 2, 100);
	oncrpc_rdma_chunk_fill(&rw, 0);
	CHECK(rw.rw_nseg == 2 && segs[0].rs_length == 0 &&
	    segs[1].rs_length == 0);
}

static void
test_bc(void)
{
	struct oncrpc_rdma_bc rb;

	oncrpc_rdma_bc_init(&rb);
	CHECK(oncrpc_rdma_bc_start(&rb));	/* one until told, s3.3.3 */
	CHECK(!oncrpc_rdma_bc_start(&rb));
	oncrpc_rdma_bc_done(&rb, 2);
	CHECK(oncrpc_rdma_bc_start(&rb));
	CHECK(oncrpc_rdma_bc_start(&rb));
	CHECK(!oncrpc_rdma_bc_start(&rb));
	oncrpc_rdma_bc_done(&rb, 0);		/* zero is no grant */
	CHECK(rb.rb_granted == 2);
}

static void
test_crc(void)
{
	/* RFC 5044 s4.4 Figure 5, Marker and all. */
	static const uint8_t f[0x30] = {
		0, 0, 0, 0, 0x00, 0x2a, 0x41, 0x43,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 1, 0, 0, 0, 0,
	};
	uint32_t c;

	c = oncrpc_iw_crc_init();
	c = oncrpc_iw_crc_update(c, f, sizeof(f));
	CHECK(oncrpc_iw_crc_final(c) == 0x52239983);

	/* The check value of CRC-32C, in two pieces. */
	c = oncrpc_iw_crc_init();
	c = oncrpc_iw_crc_update(c, "1234", 4);
	c = oncrpc_iw_crc_update(c, "56789", 5);
	CHECK(oncrpc_iw_crc_final(c) == 0x839206e3);
}

static void
test_mpa(void)
{
	static uint8_t f[IW_MPA_HDRLEN + IW_MPA_PDMAX], out[sizeof(f) + 4];
	struct oncrpc_iw_mpa im;
	u_int n, i;

	memset(f, 0, sizeof(f));
	memcpy(f, "MPA ID Req Frame", 16);
	f[16] = IW_MPA_F_S;
	f[17] = 2;
	f[19] = 12;		/* enhanced, then 8797 */
	f[20] = 0x00; f[21] = 0x10;	/* IRD 16 */
	f[22] = 0x00; f[23] = 0x00;	/* ORD 0 */
	f[24] = 0xf6;
	CHECK(oncrpc_iw_mpa_parse(f, 32, &im) == 0);
	CHECK(im.im_ird == 16 && im.im_ord == 0);
	CHECK(im.im_ulpoff == 24 && im.im_ulplen == 8 && im.im_len == 32);

	for (i = 0; i < 32; i++)
		CHECK(oncrpc_iw_mpa_parse(f, i, &im) == EAGAIN);

	n = oncrpc_iw_mpa_reply(out, &im, 0, 1, 1, "PRIVDATA", 8);
	CHECK(n == 32);
	CHECK(memcmp(out, "MPA ID Rep Frame", 16) == 0);
	CHECK(out[16] == IW_MPA_F_S && out[17] == 2 && out[19] == 12);
	CHECK(out[21] == 1 && out[23] == 1);
	CHECK(memcmp(out + 24, "PRIVDATA", 8) == 0);

	/* Revision 1: no enhanced data, and S off. */
	f[16] = 0;
	f[17] = 1;
	f[19] = 0;
	CHECK(oncrpc_iw_mpa_parse(f, 20, &im) == 0 && im.im_ulplen == 0);
	CHECK(oncrpc_iw_mpa_reply(out, &im, IW_MPA_F_C, 1, 1, NULL, 0) == 20);
	CHECK(out[16] == IW_MPA_F_C && out[17] == 1);

	/* S set in a revision 1 frame means nothing. */
	f[16] = IW_MPA_F_S;
	CHECK(oncrpc_iw_mpa_parse(f, 20, &im) == 0);
	CHECK((im.im_flags & IW_MPA_F_S) == 0);

	/* s7.1.1: over 512 of Private Data, too short for S, wrong key, Rev */
	f[16] = IW_MPA_F_S;
	f[17] = 2;
	f[18] = 0x02; f[19] = 0x01;
	CHECK(oncrpc_iw_mpa_parse(f, sizeof(f), &im) == EPROTO);
	f[18] = 0; f[19] = 2;
	CHECK(oncrpc_iw_mpa_parse(f, 22, &im) == EPROTO);
	f[19] = 0;
	f[17] = 3;
	CHECK(oncrpc_iw_mpa_parse(f, 20, &im) == EPROTO);
	f[17] = 2;
	f[0] = 'X';
	CHECK(oncrpc_iw_mpa_parse(f, 20, &im) == EPROTO);
}

static void
test_ddp(void)
{
	struct oncrpc_iw_seg a, b;
	struct oncrpc_iw_readreq rr;
	uint8_t f[64];
	u_int n;

	/* s4.1 of RFC 5044: padded to four, with the two of the length. */
	CHECK(oncrpc_iw_fpdu_len(42) == 2 + 42 + 4);
	CHECK(oncrpc_iw_fpdu_len(43) == 2 + 43 + 3 + 4);
	CHECK(oncrpc_iw_fpdu_len(0) == 2 + 2 + 4);
	CHECK((oncrpc_iw_fpdu_len(65535) & 3) == 0);

	/* RFC 5044 Figure 5 gives the header of a Send, byte for byte. */
	memset(&a, 0, sizeof(a));
	a.is_last = true;
	a.is_op = IW_OP_SEND;
	a.is_msn = 1;
	n = oncrpc_iw_seg_build(f, &a);
	CHECK(n == 18);
	CHECK(f[0] == 0x41 && f[1] == 0x43);
	CHECK(f[13] == 1 && f[9] == 0 && f[17] == 0);
	CHECK(oncrpc_iw_seg_parse(f, n, &b) == 0);
	CHECK(!b.is_tagged && b.is_last && b.is_op == IW_OP_SEND);
	CHECK(b.is_msn == 1 && b.is_hdrlen == 18);

	memset(&a, 0, sizeof(a));
	a.is_tagged = true;
	a.is_op = IW_OP_READ_RESP;
	a.is_stag = 0x01020304;
	a.is_to = 0x1122334455667788ULL;
	n = oncrpc_iw_seg_build(f, &a);
	CHECK(n == 14 && f[0] == 0x81 && f[1] == 0x42);
	CHECK(oncrpc_iw_seg_parse(f, n, &b) == 0);
	CHECK(b.is_tagged && !b.is_last && b.is_stag == 0x01020304);
	CHECK(b.is_to == 0x1122334455667788ULL && b.is_hdrlen == 14);

	CHECK(oncrpc_iw_seg_parse(f, 13, &b) == EPROTO);
	f[0] = 0x82;		/* DDP version 2 */
	CHECK(oncrpc_iw_seg_parse(f, 14, &b) == EPROTO);
	f[0] = 0x41;
	CHECK(oncrpc_iw_seg_parse(f, 17, &b) == EPROTO);	/* untagged */
	f[1] = 0x03;		/* RDMAP version 0 */
	CHECK(oncrpc_iw_seg_parse(f, 18, &b) == EPROTO);

	rr.ir_sinkstag = 0x01020304;
	rr.ir_sinkto = 0x05;
	rr.ir_size = 0x06;
	rr.ir_srcstag = 0x0708090a;
	rr.ir_srcto = 0x0b;
	oncrpc_iw_readreq_build(f, &rr);
	CHECK(f[0] == 1 && f[3] == 4 && f[11] == 5 && f[15] == 6);
	CHECK(f[16] == 7 && f[19] == 10 && f[27] == 0x0b);
}

static void
test_fuzz_wire(void)
{
	static uint8_t f[256];
	struct oncrpc_iw_mpa im;
	struct oncrpc_iw_seg is;
	u_int i, j;

	srandom(5044);
	for (i = 0; i < 200000; i++) {
		for (j = 0; j < sizeof(f); j++)
			f[j] = (uint8_t)random();
		if (i & 1)
			memcpy(f, "MPA ID Req Frame", 16);
		(void)oncrpc_iw_mpa_parse(f, (u_int)random() % sizeof(f), &im);
		(void)oncrpc_iw_seg_parse(f, (u_int)random() % sizeof(f), &is);
	}
	CHECK(1);
}

int
main(void)
{

	test_hdr_decode();
	test_hdr_reject();
	test_hdr_fuzz();
	test_error_encode();
	test_group();
	test_layout();
	test_peek();
	test_ulb_v3();
	test_ulb_v2();
	test_ulb_v4();
	test_plan();
	test_fill();
	test_bc();
	test_crc();
	test_mpa();
	test_ddp();
	test_fuzz_wire();
	printf("%d checks, %d failed\n", checks, failed);
	return failed != 0;
}
