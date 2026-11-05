/*	$NetBSD: pmap.h,v 1.40 2026/06/30 17:21:18 rkujawa Exp $	*/

/*-
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

#ifndef	_POWERPC_OEA_PMAP_H_
#define	_POWERPC_OEA_PMAP_H_

#ifdef _LOCORE
#error use assym.h instead
#endif

#ifdef _MODULE
#error this file should not be included by loadable kernel modules
#endif

#ifdef _KERNEL_OPT
#include "opt_ppcarch.h"
#include "opt_modular.h"
#endif
#include <powerpc/oea/pte.h>

#define	__HAVE_PMAP_PV_TRACK
#include <uvm/pmap/pmap_pvt.h>

/*
 * Pmap stuff
 */
struct pmap {
#ifdef PPC_OEA64
	struct steg *pm_steg_table;		/* segment table pointer */
	/* XXX need way to track exec pages */
#endif

#if defined(PPC_OEA) || defined (PPC_OEA64_BRIDGE)
	register_t pm_sr[16];			/* segments used in this pmap */
	int pm_exec[16];			/* counts of exec mappings */
#endif
	register_t pm_vsid;			/* VSID bits */
	int pm_refs;				/* ref count */
	struct pmap_statistics pm_stats;	/* pmap statistics */
	unsigned int pm_evictions;		/* pvo's not in page table */

#ifdef PPC_OEA64
	unsigned int pm_ste_evictions;
#endif
};

struct pmap_ops {
	int (*pmapop_pte_spill)(struct pmap *, vaddr_t, bool);
	void (*pmapop_real_memory)(paddr_t *, psize_t *);
	void (*pmapop_init)(void);
	void (*pmapop_virtual_space)(vaddr_t *, vaddr_t *);
	pmap_t (*pmapop_create)(void);
	void (*pmapop_reference)(pmap_t);
	void (*pmapop_destroy)(pmap_t);
	void (*pmapop_copy)(pmap_t, pmap_t, vaddr_t, vsize_t, vaddr_t);
	void (*pmapop_update)(pmap_t);
	int (*pmapop_enter)(pmap_t, vaddr_t, paddr_t, vm_prot_t, u_int);
	void (*pmapop_remove)(pmap_t, vaddr_t, vaddr_t);
	void (*pmapop_kenter_pa)(vaddr_t, paddr_t, vm_prot_t, u_int);
	void (*pmapop_kremove)(vaddr_t, vsize_t);
	bool (*pmapop_extract)(pmap_t, vaddr_t, paddr_t *);

	void (*pmapop_protect)(pmap_t, vaddr_t, vaddr_t, vm_prot_t);
	void (*pmapop_unwire)(pmap_t, vaddr_t);
	void (*pmapop_page_protect)(struct vm_page *, vm_prot_t);
	void (*pmapop_pv_protect)(paddr_t, vm_prot_t);
	bool (*pmapop_query_bit)(struct vm_page *, int);
	bool (*pmapop_clear_bit)(struct vm_page *, int);

	void (*pmapop_activate)(struct lwp *);
	void (*pmapop_deactivate)(struct lwp *);

	void (*pmapop_pinit)(pmap_t);
	void (*pmapop_procwr)(struct proc *, vaddr_t, size_t);

	void (*pmapop_pte_print)(volatile struct pte *);
	void (*pmapop_pteg_check)(void);
	void (*pmapop_print_mmuregs)(void);
	void (*pmapop_print_pte)(pmap_t, vaddr_t);
	void (*pmapop_pteg_dist)(void);
	void (*pmapop_pvo_verify)(void);
	vaddr_t (*pmapop_steal_memory)(vsize_t, vaddr_t *, vaddr_t *);
	void (*pmapop_bootstrap)(paddr_t, paddr_t);
	void (*pmapop_bootstrap1)(paddr_t, paddr_t);
	void (*pmapop_bootstrap2)(void);
};

#ifdef	_KERNEL
#include <sys/cdefs.h>
__BEGIN_DECLS
#include <sys/param.h>
#include <sys/systm.h>

/*
 * Physical memory below PMAP_DIRECT_MAPPED_LEN is direct-mapped 
 * (pa == va). Direct region covers the segments below BOTH 
 * the user copyin window (USER_SR) and the kernel HTAB window
 * (KERNEL_SR), so it can never overlap.
 */
#if defined(PPC_OEA) || defined(PPC_OEA64_BRIDGE)
#define	PMAP_DIRECT_MAPPED_SR	(MIN(USER_SR, KERNEL_SR) - 1)
#define	PMAP_DIRECT_MAPPED_LEN \
    ((vaddr_t)SEGMENT_LENGTH * (PMAP_DIRECT_MAPPED_SR + 1))
#elif defined(PPC_OEA64_SLB)
/*
 * Only segment 0 is mapped 1:1, as with segment registers.  The SLB is
 * not reloaded on entry to the kernel, so the user's entries are still in
 * it there, and the user's address space starts at segment 1 -- the ABI
 * links programs at 0x10000000.  Memory 1:1 above segment 0 was reached
 * through whichever entry held that ESID, the user's included: the
 * kernel took a DSI on its own pool pages once they came from above
 * 256MB.
 *
 * The rest of physical memory is mapped at PMAP_DMAP_BASE + pa, in
 * ESIDs no user address has (VM_MAXUSER_ADDRESS is 2^48).  The base is
 * this kernel's choice, not the architecture's: the lowest address of
 * the upper 2^20 ESIDs, the ones va_to_vsid() gives kernel VSIDs to,
 * below USER_ADDR and the kernel's own space.  PMAP_MAP_POOLPAGE() hands
 * out either.  Whatever must be reached with translation off and on
 * alike -- the page table, the pvos, uareas -- comes from below
 * PMAP_DIRECT_MAPPED_LEN.
 *
 * Left undefined, <powerpc/pmap.h> makes it ~0UL, which puts the whole
 * kernel map inside the direct region: pmap_pvo_find_va() then panics
 * on uvm's "not mapped yet" question, and the range checks against
 * this bound in pmap_bootstrap() can never fire.
 */
#define	PMAP_DIRECT_MAPPED_LEN	SEGMENT_LENGTH
#define	PMAP_DMAP_BASE		((vaddr_t)0xffffUL << 48)
#endif

#if defined (PPC_OEA) || defined (PPC_OEA64_BRIDGE)
extern register_t iosrtable[];
#endif
extern int pmap_use_altivec;

#define pmap_clear_modify(pg)		(pmap_clear_bit((pg), PTE_CHG))
#define	pmap_clear_reference(pg)	(pmap_clear_bit((pg), PTE_REF))
#define	pmap_is_modified(pg)		(pmap_query_bit((pg), PTE_CHG))
#define	pmap_is_referenced(pg)		(pmap_query_bit((pg), PTE_REF))

#define	pmap_resident_count(pmap)	((pmap)->pm_stats.resident_count)
#define	pmap_wired_count(pmap)		((pmap)->pm_stats.wired_count)

/* ARGSUSED */
static __inline bool
pmap_remove_all(struct pmap *pmap)
{
	/* Nothing. */
	return false;
}

#if (defined(PPC_OEA) + defined(PPC_OEA64) + defined(PPC_OEA64_BRIDGE) \
    + defined(PPC_OEA64_SLB)) != 1
#define	PMAP_NEEDS_FIXUP
#endif

extern volatile struct pteg *pmap_pteg_table;
extern unsigned int pmap_pteg_cnt;
extern unsigned int pmap_pteg_mask;

void pmap_bootstrap(vaddr_t, vaddr_t);
void pmap_bootstrap1(vaddr_t, vaddr_t);
void pmap_bootstrap2(void);
bool pmap_extract(pmap_t, vaddr_t, paddr_t *);
bool pmap_query_bit(struct vm_page *, int);
bool pmap_clear_bit(struct vm_page *, int);
void pmap_real_memory(paddr_t *, psize_t *);
void pmap_procwr(struct proc *, vaddr_t, size_t);
int pmap_pte_spill(pmap_t, vaddr_t, bool);
#ifdef PPC_OEA64_SLB
extern u_int pmap_pft_shift;
extern paddr_t pmap_boot_rma_end;
void pmap_slb_cpu_init(void);
void pmap_slb_cpu_hid(void);
/*
 * Called from the Data and Instruction Segment vectors, which is why it
 * is not static: nothing in C calls it.  pmap_pte_spill() above is here
 * for the same reason, from the DSI vector.
 */
int pmap_slb_fault(pmap_t, vaddr_t);
void pmap_setusr_refresh(void);
#endif
int pmap_ste_spill(pmap_t, vaddr_t, bool);
void pmap_pinit(pmap_t);

#ifdef PPC_OEA601
bool	pmap_extract_ioseg601(vaddr_t, paddr_t *);
#endif /* PPC_OEA601 */
#ifdef PPC_OEA
bool	pmap_extract_battable(vaddr_t, paddr_t *);
#endif /* PPC_OEA */

u_int powerpc_mmap_flags(paddr_t);
#define POWERPC_MMAP_FLAG_MASK	0xf
#define POWERPC_MMAP_FLAG_PREFETCHABLE	0x1
#define POWERPC_MMAP_FLAG_CACHEABLE	0x2

#define pmap_phys_address(ppn)		(ppn & ~POWERPC_MMAP_FLAG_MASK)
#define pmap_mmap_flags(ppn)		powerpc_mmap_flags(ppn)

static __inline paddr_t vtophys (vaddr_t);

/*
 * Alternate mapping hooks for pool pages.  Avoids thrashing the TLB.
 *
 * Note: This won't work if we have more memory than can be direct-mapped
 * VA==PA all at once.  But pmap_copy_page() and pmap_zero_page() will have
 * this problem, too.
 */
#if defined(PPC_OEA64_SLB)
#define	PMAP_MAP_POOLPAGE(pa)	((pa) < PMAP_DIRECT_MAPPED_LEN ? \
				    (vaddr_t)(pa) : PMAP_DMAP_BASE + (pa))
#define	PMAP_UNMAP_POOLPAGE(va)	((va) < PMAP_DMAP_BASE ? \
				    (paddr_t)(va) : (va) - PMAP_DMAP_BASE)
#elif !defined(PPC_OEA64)
#define	PMAP_MAP_POOLPAGE(pa)	(pa)
#define	PMAP_UNMAP_POOLPAGE(pa)	(pa)
#endif
#if !defined(PPC_OEA64)
#define POOL_VTOPHYS(va)	vtophys((vaddr_t) va)

#define	PMAP_ALLOC_POOLPAGE(flags)	pmap_alloc_poolpage(flags)
struct vm_page *pmap_alloc_poolpage(int);
#endif

static __inline paddr_t
vtophys(vaddr_t va)
{
	paddr_t pa;

	if (pmap_extract(pmap_kernel(), va, &pa))
		return pa;
	KASSERTMSG(0, "vtophys: pmap_extract of %#"PRIxVADDR" failed", va);
	return (paddr_t) -1;
}


#ifdef PMAP_NEEDS_FIXUP
extern const struct pmap_ops *pmapops;
extern const struct pmap_ops pmap32_ops;
extern const struct pmap_ops pmap64_ops;
extern const struct pmap_ops pmap64bridge_ops;

static __inline void
pmap_setup32(void)
{
	pmapops = &pmap32_ops;
}

static __inline void
pmap_setup64(void)
{
	pmapops = &pmap64_ops;
}

static __inline void
pmap_setup64bridge(void)
{
	pmapops = &pmap64bridge_ops;
}
#endif

bool pmap_pageidlezero (paddr_t);
void pmap_syncicache (paddr_t, psize_t);
#if defined(PPC_OEA64) || defined(PPC_OEA64_SLB)
vaddr_t pmap_setusr (vaddr_t);
vaddr_t pmap_unsetusr (void);
#endif

#if defined(PPC_OEA64_BRIDGE) || defined(PPC_OEA64_SLB)
int pmap_setup_segment0_map(int use_large_pages, ...);
#endif

#define PMAP_MD_PREFETCHABLE		0x2000000
#define PMAP_STEAL_MEMORY
#define PMAP_NEED_PROCWR

void pmap_zero_page(paddr_t);
void pmap_copy_page(paddr_t, paddr_t);

LIST_HEAD(pvo_head, pvo_entry);

#define	__HAVE_VM_PAGE_MD

struct pmap_page {
	unsigned int pp_attrs;
	struct pvo_head pp_pvoh;
#ifdef MODULAR
	uintptr_t pp_dummy[3];
#endif
};

struct vm_page_md {
	struct pmap_page mdpg_pp;
#define	mdpg_attrs	mdpg_pp.pp_attrs
#define	mdpg_pvoh	mdpg_pp.pp_pvoh
#ifdef MODULAR
#define	mdpg_dummy	mdpg_pp.pp_dummy
#endif
};

#define	VM_MDPAGE_INIT(pg) do {			\
	(pg)->mdpage.mdpg_attrs = 0;		\
	LIST_INIT(&(pg)->mdpage.mdpg_pvoh);	\
} while (/*CONSTCOND*/0)

__END_DECLS
#endif	/* _KERNEL */

#endif	/* _POWERPC_OEA_PMAP_H_ */
