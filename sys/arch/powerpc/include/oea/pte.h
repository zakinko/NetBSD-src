/*	$NetBSD: pte.h,v 1.10 2020/07/06 08:17:01 rin Exp $	*/

/*-
 * Copyright (C) 2003 Matt Thomas
 * Copyright (C) 1995, 1996 Wolfgang Solfrank.
 * Copyright (C) 1995, 1996 TooLs GmbH.
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by TooLs GmbH.
 * 4. The name of TooLs GmbH may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY TOOLS GMBH ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL TOOLS GMBH BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef	_POWERPC_OEA_PTE_H_
#define	_POWERPC_OEA_PTE_H_

#include <sys/queue.h>

/*
 * Page Table Entries
 */
#ifndef	_LOCORE
#if defined(PMAP_OEA64) || defined(PMAP_OEA64_BRIDGE) || \
    defined(PMAP_OEA64_SLB)
struct pte {
	register64_t pte_hi;
	register64_t pte_lo;
};
#else	/* PMAP_OEA */
struct pte {
	register_t pte_hi;
	register_t pte_lo;
};
#endif

struct pteg {
	struct pte pt[8];
};
#endif	/* _LOCORE */

/* High word: */
/*
 * The SLB generation belongs with the other 64-bit ones.  Falling to
 * the 32-bit arm gives it PTE_VALID 0x80000000 -- the valid bit of a
 * 32-bit PTE, which in a 64-bit one is a bit of the VSID -- so every
 * entry it writes reads back as invalid and the processor finds no
 * translation for the kernel itself.
 */
#if defined (PMAP_OEA64) || defined (PMAP_OEA64_SLB)
#define	PTE_VALID	0x00000001
#define	PTE_HID		0x00000002
#define	PTE_API		0x00000f80
#define	PTE_API_SHFT	7
#define	PTE_VSID_SHFT	12
#define	PTE_VSID	(~0xfffL)
#elif defined (PMAP_OEA64_BRIDGE)
#define	PTE_VALID	0x00000001
#define	PTE_HID		0x00000002
#define	PTE_API		0x00000f80
#define	PTE_API_SHFT	7
#define	PTE_VSID_SHFT	12
#define	PTE_VSID	(~0xfffULL)
#else
#define	PTE_VALID	0x80000000
#define	PTE_VSID	0x7fffff80
#define	PTE_VSID_SHFT	7
#define	PTE_VSID_LEN	24
#define	PTE_HID		0x00000040
#define	PTE_API		0x0000003f
#define	PTE_API_SHFT	0
#endif	/* PMAP_OEA64 */


/* Low word: */
#if defined (PMAP_OEA64_BRIDGE)
#define	PTE_RPGN	(~0xfffULL)
#else
#define	PTE_RPGN	(~0xfffUL)
#endif
#define	PTE_RPGN_SHFT	12
#define	PTE_REF		0x00000100
#define	PTE_CHG		0x00000080
#define	PTE_W		0x00000040	/* 1 = write-through, 0 = write-back */
#define	PTE_I		0x00000020	/* cache inhibit */
#define	PTE_M		0x00000010	/* memory coherency enable */
#define	PTE_G		0x00000008	/* guarded region (not on 601) */
#define	PTE_WIMG	(PTE_W|PTE_I|PTE_M|PTE_G)
#define	PTE_IG		(PTE_I|PTE_G)
#define	PTE_N		0x00000004	/* 61    No-execute page */
#define	PTE_AC		0x00000200	/* 54    Address Compare */
#define	PTE_PP		0x00000003
#define	PTE_SO		0x00000000	/* Super. Only       (U: XX, S: RW) */
#define	PTE_SW		0x00000001	/* Super. Write-Only (U: RO, S: RW) */
#define	PTE_BW		0x00000002	/* Supervisor        (U: RW, S: RW) */
#define	PTE_BR		0x00000003	/* Both Read Only    (U: RO, S: RO) */
#define	PTE_RW		PTE_BW
#define	PTE_RO		PTE_BR

/*
 * Not a bit of the PTE.  pmap_attr_fetch() and its friends keep this
 * per page in software; it shares a value with PTE_AC and never meets
 * it, because nothing stores it into a PTE.
 */
#define	PTE_EXEC	0x00000200	/* pseudo bit; page is exec */

/*
 * Extract bits from address
 */
#define	ADDR_SR	        (~0x0fffffffL)
#define	ADDR_SR_SHFT	28
#define	ADDR_PIDX	0x0ffff000
#define	ADDR_PIDX_SHFT	12
#if defined (PMAP_OEA64) || defined (PMAP_OEA64_BRIDGE) || \
    defined (PMAP_OEA64_SLB)
#define	ADDR_API_SHFT	23	/* API is 5 bits */
#else
#define	ADDR_API_SHFT	22	/* API is 6 bits */
#endif /* PMAP_OEA64 */
#define	ADDR_POFF	0x00000fff

#if defined(PMAP_OEA64) || defined(PMAP_OEA64_SLB) || defined(PPC_OEA64_SLB)
/*
 * Segment Table Element
 */
#ifndef	_LOCORE
struct ste {
	register_t ste_hi;
	register_t ste_lo;
};

struct steg {
	struct ste st[8];
};
#endif	/* _LOCORE */

/* High Word */
#define	STE_VALID	0x00000080
#define	STE_TYPE	0x00000040
#define	STE_SUKEY	0x00000020	/* Super-state protection */
#define	STE_PRKEY	0x00000010	/* User-state protection */
#define	STE_NOEXEC	0x00000008	/* No-execute protection bit */
#define	STE_ESID	(~0x0fffffffL)	/* Effective Segment ID */
#define	STE_ESID_SHFT	28
#define	STE_ESID_MASK	0x0000001f	/* low 5 bits of the ESID */

/* Low Word */
#define	STE_VSID	(~0xfffL)	/* Virtual Segment ID */
#define	STE_VSID_SHFT	12
#define	STE_VSID_WIDTH	52

#define	SR_VSID_SHFT	STE_VSID_SHFT	/* compatibility with PPC_OEA */
#define	SR_VSID_WIDTH	STE_VSID_WIDTH	/* compatibility with PPC_OEA */

/*
 * PPC_OEA64_SLB as well as PMAP_OEA64_SLB: struct pmap holds a
 * pm_slb[SLB_NENTRIES], so every file that sees struct pmap needs
 * these, not only the one that is the SLB pmap.
 */
#if defined(PMAP_OEA64_SLB) || defined(PPC_OEA64_SLB)
/*
 * Segment Lookaside Buffer Entry
 *
 * For implementations that leave the SLB to software rather than walking
 * a segment table.  Book III 2.01 Figure 15 gives the entry; slbmte
 * takes it in two registers (Figure 25), so the fields are named for the
 * register they arrive in rather than for the 94-bit entry they make up.
 *
 * Figure 15 numbers the bits from the most significant, as the rest of
 * this file does:
 *
 *	 0:35	ESID	36 V	37:88 VSID
 *	89 Ks	90 Kp	91 N	92 L	93 C
 */
#ifndef	_LOCORE
struct slb {
	register_t slb_v;		/* VSID and the keys */
	register_t slb_e;		/* ESID, valid, and the index */
};
#endif	/* _LOCORE */

/*
 * How many entries there are.  4.4.1 guarantees at least 32 and leaves
 * any more to the implementation, so 32 is the number that is true of
 * every processor; using it means the software copy never describes an
 * entry the SLB does not have.
 */
#define	SLB_NENTRIES	32

/* slb_v, the RS of slbmte: Figure 25, VSID 0:51 then the keys */
#define	SLBV_VSID	(~0xfffL)	/* 0:51  Virtual Segment ID */
#define	SLBV_VSID_SHFT	12		/*       52 bits, so 12 below */
#define	SLBV_SUKEY	0x00000800	/* 52    Super-state protection */
#define	SLBV_PRKEY	0x00000400	/* 53    User-state protection */
#define	SLBV_NOEXEC	0x00000200	/* 54    No-execute segment */
#define	SLBV_LARGE	0x00000100	/* 55    Large virtual pages */
#define	SLBV_CLASS	0x00000080	/* 56    Class, for slbie */

/* slb_e, the RB of slbmte: Figure 25, ESID 0:35 and the slot to write */
#define	SLBE_ESID	(~0xfffffffL)	/* 0:35  Effective Segment ID */
#define	SLBE_ESID_SHFT	28		/*       36 bits, so 28 below */
#define	SLBE_VALID	0x08000000	/* 36    Entry is valid */
#define	SLBE_INDEX	0x00000fff	/* 52:63 Which entry slbmte writes */

/*
 * Large pages.  The SLB's L bit picks between 4KB (p=12) and "large",
 * and 4.4 leaves the large size to the implementation, allowing 8KB to
 * 256MB (13 <= p <= 28).  The 970FX picks 16MB (p=24) -- Table 5-1 of
 * its User's Manual, "Page size / 970FX-specific / 16 MB" -- and there
 * is no second choice to make, so p is a constant here.
 *
 * The editions disagree about the PTE.  Book III 2.01 (Figure 17) gives
 * doubleword 0 as AVPN 0:56, SW 57:60, H 62, V 63 and calls the rest
 * reserved, so read alone it makes the size the segment's and nothing
 * else's.  2.02 (Figure 23) makes bit 61 L, "Virtual page is large
 * (L=1) or 4 KB (L=0)".  The 970FX goes with 2.02: its User's Manual
 * calls its 16MB pages a "new large page architecture", and an entry
 * without L in a segment whose SLB entry has L set is not matched.  So
 * both carry it -- the SLB's L says how to search, the PTE's says what
 * the entry is.
 *
 * With p = 24 the PTE fields change shape.  "If p <= 23, the AVPN field
 * contains bits 0:56 of the VPN.  Otherwise bits 0:79-p of the AVPN
 * field contain bits 0:79-p of the VPN, and bits 80-p:56 of the AVPN
 * field must be zeros" -- so AVPN holds VPN 0:55 and bit 56 is zero,
 * which leaves the VSID where it was and the four bits below it holding
 * EA 36:39 instead of the five of a 4KB API.
 */
#define	ADDR_LPIDX	0x0f000000	/* EA 36:39, page within segment */
#define	ADDR_LPIDX_SHFT	24		/*           p = 24 */
#define	PTE_LAPI	0x00000f00	/* AVPN 52:55; 56 stays zero */
#define	PTE_LAPI_SHFT	8
#define	PTE_L		0x00000004	/* 61    Large page; 2.02 Figure 23 */
#endif /* PMAP_OEA64_SLB */

#define	SR_KEY_LEN	9		/* 64 groups of 8 segment entries */
#else	/* !PMAP_OEA64 && !PMAP_OEA64_SLB */

/*
 * Segment registers
 */
#define	SR_KEY_LEN	4		/* 16 segment registers */
#define	SR_TYPE		0x80000000	/* T=0 selects memory format */
#define	SR_SUKEY	0x40000000	/* Supervisor protection key */
#define	SR_PRKEY	0x20000000	/* User protection key */
#define	SR_NOEXEC	0x10000000	/* No-execute protection bit */
#define	SR_VSID_SHFT	0		/* Starts at LSB */
#define	SR_VSID_WIDTH	24		/* Goes for 24 bits */

#endif	/* PMAP_OEA64 */

					/* Virtual segment ID */
#define	SR_VSID		(((1L << SR_VSID_WIDTH) - 1) << SR_VSID_SHFT)

#endif	/* _POWERPC_OEA_PTE_H_ */
