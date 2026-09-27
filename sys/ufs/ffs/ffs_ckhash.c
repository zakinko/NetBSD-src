/*	$NetBSD$	*/

/*-
 * Copyright (c) 2026 The NetBSD Foundation, Inc.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Metadata check-hashes.
 *
 * A check-hash is the CRC32C (Castagnoli, reflected polynomial
 * 0x82f63b78) of a structure as it lies on disk, taken with its own
 * check-hash field as zero, started from ~0 and not inverted at the
 * end.  It is stored in the byte order of the file system.  This is
 * the format of the file systems FreeBSD makes, which carry one for the
 * superblock, each cylinder group and each UFS2 inode in use.
 *
 * The functions here hash around the check-hash field rather than
 * clearing it, so the buffer they are given is never written.
 *
 * The CRC is taken eight bytes at a time, with the crc32 instruction
 * where the CPU has it (amd64 with SSE4.2) and with tables otherwise.
 */

#if HAVE_NBTOOL_CONFIG_H
#include "nbtool_config.h"
#endif

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#if defined(_KERNEL)
#include <sys/systm.h>
#else
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#define	KASSERT(x)	assert(x)
#define	FFS_EI		/* always include byteswapped filesystems support */
#endif

#include <ufs/ufs/dinode.h>
#include <ufs/ufs/ufs_bswap.h>
#include <ufs/ffs/fs.h>
#include <ufs/ffs/ffs_extern.h>

#define	CRC32C_POLY	0x82f63b78U

/*
 * Tables for taking eight bytes at a time: crc32c_table[k][b] is the
 * CRC of byte b followed by k zero bytes.
 */
static uint32_t crc32c_table[8][256];
static bool crc32c_ready;

#if defined(__x86_64__) && !defined(HAVE_NBTOOL_CONFIG_H)
#define	CRC32C_INSN

static bool crc32c_insn;

/*
 * Whether the CPU has SSE4.2, whose crc32 instruction is CRC32C.  Ask
 * cpuid directly: this runs once, and the same way in the kernel, in
 * a rump kernel and in the utilities.
 */
static bool
crc32c_insn_present(void)
{
	uint32_t eax, ebx, ecx, edx;

	__asm volatile("cpuid"
	    : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
	    : "a" (1), "c" (0));
	return (ecx & (1U << 20)) != 0;		/* CPUID2_SSE42 */
}

/*
 * The crc32 instruction works on general registers only, so the
 * kernel needs no FPU state for it.
 */
static uint32_t
crc32c_update_insn(uint32_t crc, const uint8_t *p, size_t len)
{
	uint64_t crc64 = crc, v;

	for (; len >= 8; p += 8, len -= 8) {
		memcpy(&v, p, sizeof(v));
		__asm("crc32q %1, %0" : "+r" (crc64) : "rm" (v));
	}
	crc = (uint32_t)crc64;
	for (; len > 0; p++, len--)
		__asm("crc32b %1, %0" : "+r" (crc) : "rm" (*p));
	return crc;
}
#endif /* __x86_64__ */

/*
 * Fill in the tables.  The kernel calls this from ffs_init(), the
 * utilities before they use a check-hash; calling it again does
 * nothing.
 */
void
ffs_ckhash_init(void)
{
	uint32_t crc;
	unsigned int i, j;

	if (crc32c_ready)
		return;
	for (i = 0; i < 256; i++) {
		crc = i;
		for (j = 0; j < 8; j++)
			crc = (crc >> 1) ^ (CRC32C_POLY & (0U - (crc & 1)));
		crc32c_table[0][i] = crc;
	}
	for (i = 0; i < 256; i++) {
		crc = crc32c_table[0][i];
		for (j = 1; j < 8; j++) {
			crc = crc32c_table[0][crc & 0xff] ^ (crc >> 8);
			crc32c_table[j][i] = crc;
		}
	}
#ifdef CRC32C_INSN
	crc32c_insn = crc32c_insn_present();
#endif
	crc32c_ready = true;
}

static uint32_t
crc32c_update(uint32_t crc, const uint8_t *p, size_t len)
{
	uint32_t lo, hi;

	KASSERT(crc32c_ready);
#ifdef CRC32C_INSN
	if (crc32c_insn)
		return crc32c_update_insn(crc, p, len);
#endif
	for (; len >= 8; p += 8, len -= 8) {
		/* Byte by byte: any alignment, any host byte order. */
		lo = crc ^ ((uint32_t)p[0] | (uint32_t)p[1] << 8 |
		    (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24);
		hi = (uint32_t)p[4] | (uint32_t)p[5] << 8 |
		    (uint32_t)p[6] << 16 | (uint32_t)p[7] << 24;
		crc = crc32c_table[7][lo & 0xff] ^
		    crc32c_table[6][(lo >> 8) & 0xff] ^
		    crc32c_table[5][(lo >> 16) & 0xff] ^
		    crc32c_table[4][lo >> 24] ^
		    crc32c_table[3][hi & 0xff] ^
		    crc32c_table[2][(hi >> 8) & 0xff] ^
		    crc32c_table[1][(hi >> 16) & 0xff] ^
		    crc32c_table[0][hi >> 24];
	}
	for (; len > 0; p++, len--)
		crc = crc32c_table[0][(crc ^ *p) & 0xff] ^ (crc >> 8);
	return crc;
}

/*
 * The check-hash of the len bytes at buf, whose check-hash field is
 * at byte offset off.
 */
static uint32_t
ckhash_around(const void *buf, size_t len, size_t off)
{
	static const uint8_t zero[sizeof(uint32_t)];
	const uint8_t *p = buf;
	uint32_t crc;

	KASSERT(off + sizeof(uint32_t) <= len);
	crc = crc32c_update(~0U, p, off);
	crc = crc32c_update(crc, zero, sizeof(zero));
	return crc32c_update(crc, p + off + sizeof(uint32_t),
	    len - off - sizeof(uint32_t));
}

/*
 * Whether the superblock fs, in host byte order, says that the file
 * system carries check-hashes.  FS_METACKHASH is also FS_DOQUOTA2; it
 * means check-hashes when the quota2 header is absent, as it always is
 * on such a file system and never is with quota2.
 */
int
ffs_ckhash_present(const struct fs *fs)
{

	return (fs->fs_flags & FS_METACKHASH) != 0 &&
	    fs->fs_quota_magic == 0 && fs->fs_quota_flags == 0 &&
	    fs->fs_quotafile[0] == 0 && fs->fs_quotafile[1] == 0;
}

/* The check-hash of a superblock of sbsize bytes as on disk. */
uint32_t
ffs_sb_ckhash(const void *sb, size_t sbsize)
{

	return ckhash_around(sb, sbsize, offsetof(struct fs, fs_ckhash));
}

/* The check-hash of a cylinder group of cgsize bytes as on disk. */
uint32_t
ffs_cg_ckhash(const void *cg, size_t cgsize)
{

	return ckhash_around(cg, cgsize, offsetof(struct cg, cg_ckhash));
}

/* The check-hash of a UFS2 inode as on disk. */
uint32_t
ffs_dinode_ckhash(const void *dp)
{

	return ckhash_around(dp, sizeof(struct ufs2_dinode),
	    offsetof(struct ufs2_dinode, di_ckhash));
}

/*
 * Give the cylinder group at cgp, as it will be written, its
 * check-hash, if the file system keeps them.
 */
void
ffs_cg_setckhash(const struct fs *fs, struct cg *cgp)
{

	if ((fs->fs_metackhash & CK_CYLGRP) == 0)
		return;
	cgp->cg_ckhash = ufs_rw32(ffs_cg_ckhash(cgp, (size_t)fs->fs_cgsize),
	    UFS_FSNEEDSWAP(fs));
}

/* Whether the cylinder group at cgp, as read, has a good check-hash. */
int
ffs_cg_ckhash_ok(const struct fs *fs, const struct cg *cgp)
{

	if ((fs->fs_metackhash & CK_CYLGRP) == 0)
		return 1;
	return ufs_rw32(cgp->cg_ckhash, UFS_FSNEEDSWAP(fs)) ==
	    ffs_cg_ckhash(cgp, (size_t)fs->fs_cgsize);
}

/*
 * The same for a UFS2 inode.  An unused inode, di_mode 0, has no
 * check-hash.
 */
void
ffs_dinode_setckhash(const struct fs *fs, struct ufs2_dinode *dp)
{

	if ((fs->fs_metackhash & CK_INODE) == 0 || dp->di_mode == 0)
		return;
	dp->di_ckhash = ufs_rw32(ffs_dinode_ckhash(dp),
	    UFS_FSNEEDSWAP(fs));
}

int
ffs_dinode_ckhash_ok(const struct fs *fs, const struct ufs2_dinode *dp)
{

	if ((fs->fs_metackhash & CK_INODE) == 0 || dp->di_mode == 0)
		return 1;
	return ufs_rw32(dp->di_ckhash, UFS_FSNEEDSWAP(fs)) ==
	    ffs_dinode_ckhash(dp);
}
