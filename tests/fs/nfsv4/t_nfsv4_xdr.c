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
 * Round trips and malformed input for the XDR filters of NFS version 4.
 * This runs in userland on anything with an RPC library, against
 * xdrmem.  Built under ASan it also shows that no input reads out of
 * bounds.  Exit status 0 is success.
 *
 *	cc -I../../../sys -o t t_nfsv4_xdr.c
 */

#include <sys/types.h>
#include <sys/param.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef __KERNEL_RCSID
#define	__KERNEL_RCSID(a, b)
#endif
#ifndef __UNCONST
#define	__UNCONST(a)	((void *)(uintptr_t)(a))
#endif

#include "fs/nfsv4/nfsv4_xdr.c"

static int failed;

#define	CHECK(e) do {							\
	if (!(e)) {							\
		printf("FAIL line %d: %s\n", __LINE__, #e);		\
		failed++;						\
	}								\
} while (0)

static char wire[1 << 16];
static union nfsv4_args a, b;

static void
fill_owner(struct nfsv4_owner *o)
{

	o->ow_clientid = 0x0102030405060708ULL;
	o->ow_len = 5;
	memcpy(o->ow_data, "owner", 5);
}

static void
fill_si(struct nfsv4_stateid *si)
{

	si->si_seqid = 7;
	memcpy(si->si_other, "abcdefghijkl", NFS4_OTHER_SIZE);
}

static void
fill_name(struct nfsv4_name *n, const char *s)
{

	n->nm_len = strlen(s);
	strcpy(n->nm_str, s);
}

static void
fill_bm(struct nfsv4_bitmap *bm)
{

	bm->bm_n = 2;
	bm->bm_w[0] = 0x00100012;
	bm->bm_w[1] = 0x00800000;
}

/*
 * Encode a, decode it into b, and show that every shorter stream fails
 * without reading past its end.  The positional fields are appended to
 * the stream by hand, and stay out of the comparison of b with a.
 */
static u_int
trip(uint32_t op, u_int extra)
{
	XDR x;
	u_int len, i;
	char *copy;

	xdrmem_create(&x, wire, sizeof(wire), XDR_ENCODE);
	CHECK(nfsv4_xdr_args(&x, op, 0, &a));
	len = xdr_getpos(&x);
	memset(wire + len, 0xee, extra);
	len += extra;

	memset(&b, 0x5a, sizeof(b));
	xdrmem_create(&x, wire, len, XDR_DECODE);
	CHECK(nfsv4_xdr_args(&x, op, 0, &b));
	CHECK(xdr_getpos(&x) == len);

	for (i = 0; i < len; i++) {
		copy = malloc(i ? i : 1);	/* ASan fences the end */
		memcpy(copy, wire, i);
		xdrmem_create(&x, copy, i, XDR_DECODE);
		CHECK(!nfsv4_xdr_args(&x, op, 0, &b));
		free(copy);
	}
	memset(&b, 0, sizeof(b));
	xdrmem_create(&x, wire, len, XDR_DECODE);
	CHECK(nfsv4_xdr_args(&x, op, 0, &b));
	return len;
}

static void
test_trips(void)
{

	memset(&a, 0, sizeof(a));
	a.access.access = ACCESS4_READ | ACCESS4_EXECUTE;
	CHECK(trip(NFSV4_OP_ACCESS, 0) == 4);
	CHECK(b.access.access == a.access.access);

	memset(&a, 0, sizeof(a));
	a.close.seqid = 9;
	fill_si(&a.close.stateid);
	CHECK(trip(NFSV4_OP_CLOSE, 0) == 4 + 16);
	CHECK(b.close.seqid == 9);
	CHECK(memcmp(&b.close.stateid, &a.close.stateid,
	    sizeof(a.close.stateid)) == 0);

	memset(&a, 0, sizeof(a));
	a.commit.offset = 0x100000000ULL;
	a.commit.count = 3;
	CHECK(trip(NFSV4_OP_COMMIT, 0) == 12);
	CHECK(b.commit.offset == a.commit.offset);
	CHECK(b.commit.count == 3);

	memset(&a, 0, sizeof(a));
	a.create.type = NF4LNK;
	a.create.link.ln_len = 3;
	strcpy(a.create.link.ln_str, "tgt");
	fill_name(&a.create.name, "lk");
	fill_bm(&a.create.attrs.fa_mask);
	a.create.attrs.fa_len = 8;
	CHECK(trip(NFSV4_OP_CREATE, 8) ==
	    4 + 8 + 8 + 12 + 4 + 8);
	CHECK(strcmp(b.create.link.ln_str, "tgt") == 0);
	CHECK(strcmp(b.create.name.nm_str, "lk") == 0);
	CHECK(b.create.attrs.fa_mask.bm_w[1] == 0x00800000);
	CHECK(b.create.attrs.fa_len == 8);
	CHECK(b.create.attrs.fa_pos == 4 + 8 + 8 + 12 + 4);

	memset(&a, 0, sizeof(a));
	a.create.type = NF4BLK;
	a.create.spec1 = 1;
	a.create.spec2 = 2;
	fill_name(&a.create.name, "b");
	(void)trip(NFSV4_OP_CREATE, 0);
	CHECK(b.create.spec2 == 2);

	memset(&a, 0, sizeof(a));
	a.lock.type = WRITE_LT;
	a.lock.offset = 1;
	a.lock.length = UINT64_MAX;
	a.lock.newowner = 1;
	a.lock.open_seqid = 2;
	fill_si(&a.lock.open_stateid);
	a.lock.lock_seqid = 3;
	fill_owner(&a.lock.owner);
	(void)trip(NFSV4_OP_LOCK, 0);
	CHECK(b.lock.length == UINT64_MAX);
	CHECK(b.lock.lock_seqid == 3);
	CHECK(b.lock.owner.ow_len == 5);
	CHECK(b.lock.owner.ow_clientid == a.lock.owner.ow_clientid);

	memset(&a, 0, sizeof(a));
	a.lock.type = READ_LT;
	fill_si(&a.lock.lock_stateid);
	a.lock.lock_seqid = 4;
	CHECK(trip(NFSV4_OP_LOCK, 0) == 4 + 4 + 8 + 8 + 4 + 16 + 4);
	CHECK(b.lock.lock_seqid == 4);
	CHECK(b.lock.lock_stateid.si_seqid == 7);

	memset(&a, 0, sizeof(a));
	a.lockt.type = READW_LT;
	fill_owner(&a.lockt.owner);
	(void)trip(NFSV4_OP_LOCKT, 0);
	CHECK(b.lockt.owner.ow_data[4] == 'r');

	memset(&a, 0, sizeof(a));
	a.locku.seqid = 6;
	fill_si(&a.locku.stateid);
	a.locku.length = 10;
	(void)trip(NFSV4_OP_LOCKU, 0);
	CHECK(b.locku.length == 10);

	memset(&a, 0, sizeof(a));
	a.open.seqid = 1;
	a.open.share_access = OPEN4_SHARE_ACCESS_BOTH;
	fill_owner(&a.open.owner);
	a.open.opentype = OPEN4_CREATE;
	a.open.createmode = EXCLUSIVE4;
	memcpy(a.open.createverf.v_data, "verifier", 8);
	a.open.claim = CLAIM_NULL;
	fill_name(&a.open.file, "file");
	(void)trip(NFSV4_OP_OPEN, 0);
	CHECK(memcmp(b.open.createverf.v_data, "verifier", 8) == 0);
	CHECK(strcmp(b.open.file.nm_str, "file") == 0);

	memset(&a, 0, sizeof(a));
	fill_owner(&a.open.owner);
	a.open.opentype = OPEN4_NOCREATE;
	a.open.claim = CLAIM_DELEGATE_CUR;
	fill_si(&a.open.delegate_stateid);
	fill_name(&a.open.file, "f");
	(void)trip(NFSV4_OP_OPEN, 0);
	CHECK(b.open.delegate_stateid.si_seqid == 7);

	memset(&a, 0, sizeof(a));
	a.open.claim = CLAIM_PREVIOUS;
	a.open.delegate_type = OPEN_DELEGATE_READ;
	(void)trip(NFSV4_OP_OPEN, 0);
	CHECK(b.open.delegate_type == OPEN_DELEGATE_READ);

	memset(&a, 0, sizeof(a));
	a.putfh.fh.fh_len = NFS4_FHSIZE;
	memset(a.putfh.fh.fh_data, 0xab, NFS4_FHSIZE);
	CHECK(trip(NFSV4_OP_PUTFH, 0) == 4 + NFS4_FHSIZE);
	CHECK(b.putfh.fh.fh_data[NFS4_FHSIZE - 1] == 0xab);

	memset(&a, 0, sizeof(a));
	fill_si(&a.read.stateid);
	a.read.count = 4096;
	(void)trip(NFSV4_OP_READ, 0);
	CHECK(b.read.count == 4096);

	memset(&a, 0, sizeof(a));
	a.readdir.cookie = 3;
	a.readdir.maxcount = 8192;
	fill_bm(&a.readdir.mask);
	(void)trip(NFSV4_OP_READDIR, 0);
	CHECK(b.readdir.mask.bm_n == 2);
	CHECK(b.readdir.maxcount == 8192);

	memset(&a, 0, sizeof(a));
	fill_name(&a.rename.oldname, "o");
	fill_name(&a.rename.newname, "nn");
	CHECK(trip(NFSV4_OP_RENAME, 0) == 8 + 8);
	CHECK(strcmp(b.rename.newname.nm_str, "nn") == 0);

	memset(&a, 0, sizeof(a));
	memcpy(a.setclientid.verifier.v_data, "12345678", 8);
	a.setclientid.idlen = 2;
	memcpy(a.setclientid.id, "id", 2);
	a.setclientid.cb_program = 0x40000000;
	a.setclientid.cb_location.ca_netidlen = 3;
	memcpy(a.setclientid.cb_location.ca_netid, "tcp", 3);
	a.setclientid.cb_location.ca_addrlen = 11;
	memcpy(a.setclientid.cb_location.ca_addr, "127.0.0.1.8", 11);
	a.setclientid.cb_ident = 42;
	(void)trip(NFSV4_OP_SETCLIENTID, 0);
	CHECK(b.setclientid.cb_ident == 42);
	CHECK(memcmp(b.setclientid.cb_location.ca_addr, "127.0.0.1.8",
	    11) == 0);

	memset(&a, 0, sizeof(a));
	fill_si(&a.write.stateid);
	a.write.offset = 512;
	a.write.stable = FILE_SYNC4;
	a.write.len = 5;		/* 3 of padding */
	CHECK(trip(NFSV4_OP_WRITE, 8) == 16 + 8 + 4 + 4 + 8);
	CHECK(b.write.pos == 16 + 8 + 4 + 4);
	CHECK(b.write.len == 5);

	memset(&a, 0, sizeof(a));
	fill_owner(&a.release_lockowner.owner);
	(void)trip(NFSV4_OP_RELEASE_LOCKOWNER, 0);
	CHECK(b.release_lockowner.owner.ow_len == 5);
}

/* The bytes on the wire, worked out by hand from RFC 4506. */
static void
test_wire(void)
{
	static const unsigned char want[] = {
		0, 0, 0, 3, 'a', 'b', 'c', 0
	};
	static const unsigned char si[] = {
		0, 0, 0, 7, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
		'i', 'j', 'k', 'l'
	};
	struct nfsv4_name n;
	struct nfsv4_stateid s;
	struct nfsv4_change_info ci;
	XDR x;

	memset(wire, 0xff, 16);
	xdrmem_create(&x, wire, sizeof(wire), XDR_ENCODE);
	fill_name(&n, "abc");
	CHECK(nfsv4_xdr_name(&x, &n));
	CHECK(xdr_getpos(&x) == sizeof(want));
	CHECK(memcmp(wire, want, sizeof(want)) == 0);

	xdrmem_create(&x, wire, sizeof(wire), XDR_ENCODE);
	fill_si(&s);
	CHECK(nfsv4_xdr_stateid(&x, &s));
	CHECK(memcmp(wire, si, sizeof(si)) == 0);

	/* nfsv4_xdr_pad() writes exactly up to the next word. */
	memset(wire, 0xff, 16);
	xdrmem_create(&x, wire, sizeof(wire), XDR_ENCODE);
	CHECK(XDR_PUTBYTES(&x, "ab", 2));
	CHECK(nfsv4_xdr_pad(&x, 2));
	CHECK(xdr_getpos(&x) == 4);
	CHECK(wire[2] == 0 && wire[3] == 0);
	xdrmem_create(&x, wire, sizeof(wire), XDR_ENCODE);
	CHECK(nfsv4_xdr_pad(&x, 4));
	CHECK(xdr_getpos(&x) == 0);

	ci.ci_atomic = 1;
	ci.ci_before = 2;
	ci.ci_after = 3;
	xdrmem_create(&x, wire, sizeof(wire), XDR_ENCODE);
	CHECK(nfsv4_xdr_change_info(&x, &ci));
	CHECK(xdr_getpos(&x) == 20);
	CHECK(wire[3] == 1 && wire[11] == 2 && wire[19] == 3);
}

static u_int
put32(u_int off, uint32_t v)
{

	wire[off++] = (char)(v >> 24);
	wire[off++] = (char)(v >> 16);
	wire[off++] = (char)(v >> 8);
	wire[off++] = (char)v;
	return off;
}

static void
test_limits(void)
{
	struct nfsv4_name n;
	struct nfsv4_bitmap bm;
	struct nfsv4_fh fh;
	struct nfsv4_fattr fa;
	XDR x;
	u_int off, i;

	/* One past the longest name is marked, and the stream moves on. */
	off = put32(0, NFSV4_NAME_MAX + 1);
	memset(wire + off, 'x', NFSV4_NAME_MAX + 1);
	off = put32(off + NFSV4_NAME_MAX + 1, 0);
	xdrmem_create(&x, wire, off, XDR_DECODE);
	CHECK(nfsv4_xdr_name(&x, &n));
	CHECK(n.nm_toolong);
	CHECK(xdr_getpos(&x) == off - 4);

	/* The longest name is not. */
	off = put32(0, NFSV4_NAME_MAX);
	xdrmem_create(&x, wire, off + NFSV4_NAME_MAX + 1, XDR_DECODE);
	CHECK(nfsv4_xdr_name(&x, &n));
	CHECK(!n.nm_toolong);
	CHECK(n.nm_len == NFSV4_NAME_MAX);
	CHECK(n.nm_str[NFSV4_NAME_MAX] == '\0');

	/* A length that does not fit the stream, near the top of u_int. */
	put32(0, UINT32_MAX - 1);
	xdrmem_create(&x, wire, 64, XDR_DECODE);
	CHECK(!nfsv4_xdr_name(&x, &n));

	/* A file handle one too long. */
	put32(0, NFS4_FHSIZE + 1);
	xdrmem_create(&x, wire, sizeof(wire), XDR_DECODE);
	CHECK(!nfsv4_xdr_fh(&x, &fh));

	/* A bitmap longer than three words: the rest counts only if set. */
	off = put32(0, 4);
	off = put32(off, 1);
	off = put32(off, 2);
	off = put32(off, 0);
	off = put32(off, 0);
	xdrmem_create(&x, wire, off, XDR_DECODE);
	CHECK(nfsv4_xdr_bitmap(&x, &bm));
	CHECK(bm.bm_n == 3 && bm.bm_w[1] == 2 && !bm.bm_more);
	put32(16, 1);
	xdrmem_create(&x, wire, off, XDR_DECODE);
	CHECK(nfsv4_xdr_bitmap(&x, &bm));
	CHECK(bm.bm_more);

	/* An empty one. */
	off = put32(0, 0);
	xdrmem_create(&x, wire, off, XDR_DECODE);
	CHECK(nfsv4_xdr_bitmap(&x, &bm));
	CHECK(bm.bm_n == 0);

	off = put32(0, NFSV4_BITMAP_READ + 1);
	for (i = 0; i <= NFSV4_BITMAP_READ; i++)
		off = put32(off, 0);
	xdrmem_create(&x, wire, off, XDR_DECODE);
	CHECK(!nfsv4_xdr_bitmap(&x, &bm));

	/* attr_vals running off the end. */
	off = put32(0, 0);
	off = put32(off, 8);
	off = put32(off, 0);
	xdrmem_create(&x, wire, off, XDR_DECODE);
	CHECK(!nfsv4_xdr_fattr(&x, &fa));

	/* Booleans. */
	off = put32(0, 2);
	xdrmem_create(&x, wire, off, XDR_DECODE);
	CHECK(!nfsv4_xdr_args(&x, NFSV4_OP_OPENATTR, 0, &a));

	/* The arms that have no default. */
	memset(&a, 0, sizeof(a));
	fill_owner(&a.open.owner);
	a.open.opentype = OPEN4_CREATE;
	a.open.createmode = 9;
	xdrmem_create(&x, wire, sizeof(wire), XDR_ENCODE);
	CHECK(!nfsv4_xdr_args(&x, NFSV4_OP_OPEN, 0, &a));
	memset(&a, 0, sizeof(a));
	a.open.claim = 9;
	xdrmem_create(&x, wire, sizeof(wire), XDR_ENCODE);
	CHECK(!nfsv4_xdr_args(&x, NFSV4_OP_OPEN, 0, &a));
}

/* Noise must never read out of bounds.  What it decodes to is no matter. */
static void
test_noise(void)
{
	static const uint32_t ops[] = {
		NFSV4_OP_CREATE, NFSV4_OP_LOCK, NFSV4_OP_OPEN, NFSV4_OP_PUTFH,
		NFSV4_OP_READDIR, NFSV4_OP_SETATTR, NFSV4_OP_SETCLIENTID,
		NFSV4_OP_WRITE, NFSV4_OP_RENAME
	};
	char *buf;
	u_int i, len, j;
	XDR x;

	srandom(1);
	for (i = 0; i < 200000; i++) {
		len = random() % 512;
		buf = malloc(len ? len : 1);
		for (j = 0; j < len; j++)
			/* Small words, so that lengths are often plausible. */
			buf[j] = (j & 3) == 3 ? (char)(random() & 0x1f) :
			    (random() % 16 == 0 ? (char)random() : 0);
		xdrmem_create(&x, buf, len, XDR_DECODE);
		(void)nfsv4_xdr_args(&x, ops[i % (sizeof(ops) / sizeof(ops[0]))], 0, &b);
		free(buf);
	}
}

int
main(void)
{

	test_trips();
	test_wire();
	test_limits();
	test_noise();
	printf("%s\n", failed ? "FAILED" : "OK");
	return failed != 0;
}
