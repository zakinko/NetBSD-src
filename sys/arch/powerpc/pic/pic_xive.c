/* $NetBSD$ */
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
 * XIVE exploitation mode of a PAPR partition (PAPR 10.60, Table 210),
 * chosen by ofwboot through byte 23 of option vector 5.
 *
 * PAPR defines the hcalls (14.5.4.7.6-16) and the device tree (B.6.7),
 * and leaves the meaning of the ESB and TIMA operations and the layout
 * of an event queue to "the XIVE spec", which IBM has not published.
 * Those come from QEMU's docs/specs/ppc-xive.rst and ppc-spapr-xive.rst,
 * its hw/intc/xive.c, and Linux's arch/powerpc/include/asm/xive-regs.h,
 * marked [X] below.  QEMU's model and the Linux driver were written by
 * the same people; they are one source, not two.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include "opt_multiprocessor.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/atomic.h>
#include <sys/cpu.h>
#include <sys/intr.h>
#include <sys/kmem.h>

#include <uvm/uvm.h>

#include <dev/ofw/openfirm.h>

#include <powerpc/pic/picvar.h>
#ifdef MULTIPROCESSOR
#include <powerpc/pic/ipivar.h>
#endif

/* Table 175 */
#define	H_INT_GET_SOURCE_INFO	0x3a8
#define	H_INT_SET_SOURCE_CONFIG	0x3ac
#define	H_INT_SET_QUEUE_CONFIG	0x3b8
#define	H_INT_ESB		0x3c8

#define	H_SUCCESS		0

/* Bits of 64-bit flag words, numbered from the left as PAPR does */
#define	PAPR_BIT(n)		(1UL << (63 - (n)))

/* Table 219, the flags H_INT_GET_SOURCE_INFO returns */
#define	SRC_H_INT_ESB		PAPR_BIT(60)
#define	SRC_LSI			PAPR_BIT(61)
#define	SRC_TRIGGER		PAPR_BIT(62)

/* Table 220 */
#define	SRC_SET_EISN		PAPR_BIT(62)

/* Table 224 */
#define	EQ_ALWAYS_NOTIFY	PAPR_BIT(63)

/* Table 231 */
#define	ESB_HCALL_STORE		PAPR_BIT(63)

/*
 * [X] ESB management page offsets, each an 8-byte load that returns the
 * PQ bits as they were.  0x000 is the EOI: it clears P, and the source
 * notifies again if Q was set or, for an LSI, if the line is still up.
 * PAPR's Table 210 gives 0xC00 for H_EOI instead; that sets PQ to 00
 * and does neither, so an event that came in while P was set would be
 * lost.
 */
#define	ESB_LOAD_EOI		0x000
#define	ESB_SET_PQ_00		0xc00
#define	ESB_SET_PQ_01		0xd00
#define	ESB_VAL_Q		0x1

/*
 * The OS view of the TIMA.  Table 210 gives the CPPR as a byte at +0x11
 * and the acknowledge as a halfword load at +0x810; [X] the halfword is
 * NSR << 8 | CPPR, the CPPR raised to the priority being taken, and
 * bit 0 of the NSR (EO) says there was an OS exception to take.
 */
#define	TM_OS_CPPR		0x11
#define	TM_ACK_OS_REG		0x810
#define	TM_NSR_EO		0x80

/*
 * [X] An event queue entry is a big-endian word: the generation bit at
 * the top and the EISN in the other 31.  The generation starts at 1
 * (14.5.4.7.10) and the platform flips it each time it wraps.
 */
#define	EQ_GEN			0x80000000U
#define	EQ_EISN			0x7fffffffU

#define	XIVE_PRIO_LEAST		0xff

#define	XIVE_NSLOTS		64
#define	XIVE_SLOT_IPI		0

struct xive_src {
	uint32_t	lisn;
	uint64_t	flags;
	bool		ready;
	volatile uint8_t *esb;		/* management page, or NULL */
	volatile uint8_t *trig;		/* trigger page, or NULL */
};

struct xive_cpu {
	volatile uint32_t *eq;
	uint32_t	eq_mask;
	uint32_t	eq_idx;
	uint32_t	eq_gen;
	int		server;
	struct xive_src	ipi;
};

static struct pic_ops xive_pic;
static struct xive_src xive_src[XIVE_NSLOTS];
static u_int xive_nslots = 1;
static struct xive_cpu *xive_cpu;
static volatile uint8_t *xive_tima;
static int xive_prio;
static int xive_eq_shift;
static uint32_t xive_ipi_base, xive_ipi_count;

bool xive_active;

/*
 * 14.5.3: the token in r3 and the parameters from r4, the status back in
 * r3 and outputs from r4; r0, r3-r12, CTR, XER and CR fields 0, 1 and 5-7
 * are not preserved.  out[] takes r4-r7, the most these return
 * (H_INT_GET_SOURCE_INFO, 14.5.4.7.6).
 */
static long
xive_hcall(register_t token, register_t a1, register_t a2, register_t a3,
    register_t a4, register_t a5, register_t out[4])
{
	register register_t r3 __asm("r3") = token;
	register register_t r4 __asm("r4") = a1;
	register register_t r5 __asm("r5") = a2;
	register register_t r6 __asm("r6") = a3;
	register register_t r7 __asm("r7") = a4;
	register register_t r8 __asm("r8") = a5;

	__asm volatile("sc 1"
	    : "+r"(r3), "+r"(r4), "+r"(r5), "+r"(r6), "+r"(r7), "+r"(r8)
	    :
	    : "r0", "r9", "r10", "r11", "r12",
	      "ctr", "xer", "cr0", "cr1", "cr5", "cr6", "cr7", "memory");
	if (out != NULL) {
		out[0] = r4; out[1] = r5; out[2] = r6; out[3] = r7;
	}
	return r3;
}

static uint64_t
xive_esb_load(struct xive_src *s, u_int off)
{
	register_t out[4];
	uint64_t v;

	if (s->flags & SRC_H_INT_ESB) {
		/* 14.5.4.7.14 */
		if (xive_hcall(H_INT_ESB, 0, s->lisn, off, 0, 0, out) !=
		    H_SUCCESS)
			return ~0UL;
		return out[0];
	}
	__asm volatile("sync; ld %0,0(%1); twi 0,%0,0; isync"
	    : "=r"(v) : "b"(s->esb + off) : "memory");
	return v;
}

/* Table 210: H_IPI becomes a store to offset 0 of the trigger page */
static void
xive_trigger(struct xive_src *s)
{
	volatile uint8_t *p;

	if (s->flags & SRC_H_INT_ESB) {
		xive_hcall(H_INT_ESB, ESB_HCALL_STORE, s->lisn, 0, 0, 0, NULL);
		return;
	}
	p = s->trig != NULL ? s->trig : s->esb;
	__asm volatile("sync; std %0,0(%1)" :: "r"(0UL), "b"(p) : "memory");
}

static volatile uint8_t *
xive_map_page(register_t pa, register_t shift)
{

	if (pa == -1)
		return NULL;
	return mapiodev(pa, (psize_t)1 << shift, false);
}

/*
 * Find where isn's ESB pages are and point it at the boot processor's
 * queue, with the LISN itself as the EISN the queue reports.  Which
 * server takes it is the OS's choice.
 */
static int
xive_src_init(struct xive_src *s, uint32_t lisn, int server)
{
	register_t out[4];

	s->lisn = lisn;
	/* 14.5.4.7.6 */
	if (xive_hcall(H_INT_GET_SOURCE_INFO, 0, lisn, 0, 0, 0, out) !=
	    H_SUCCESS)
		return -1;
	s->flags = out[0];
	if ((s->flags & SRC_H_INT_ESB) == 0) {
		s->esb = xive_map_page(out[1], out[3]);
		s->trig = xive_map_page(out[2], out[3]);
	}
	/* 14.5.4.7.7 */
	if (xive_hcall(H_INT_SET_SOURCE_CONFIG, SRC_SET_EISN, lisn, server,
	    xive_prio, lisn, NULL) != H_SUCCESS)
		return -1;
	s->ready = true;
	return 0;
}

static int
xive_slot(uint32_t lisn)
{
	u_int i;

	if (lisn - xive_ipi_base < xive_ipi_count)
		return XIVE_SLOT_IPI;
	for (i = XIVE_SLOT_IPI + 1; i < xive_nslots; i++)
		if (xive_src[i].lisn == lisn)
			return i;
	return -1;
}

static void
xive_enable_irq(struct pic_ops *pic, int irq, int type)
{
	struct xive_src *s = &xive_src[irq];

	if (irq == XIVE_SLOT_IPI)
		return;
	if (!s->ready && xive_src_init(s, s->lisn, xive_cpu[0].server)) {
		printf("xive: cannot route interrupt %#x\n", s->lisn);
		return;
	}
	/* [X] PQ 00 lets the source notify */
	xive_esb_load(s, ESB_SET_PQ_00);
}

/*
 * [X] An event that came while the source was off is not sent again by
 * turning it back on: PQ 00 only lets the next one through.  An MSI left
 * Q set, so it is triggered again here; a level-sensitive line that is
 * still up is looked at again by an EOI, which is the only operation
 * that sends it.  pic_handle_intr() turned the source off and EOIed it
 * while masked, and that EOI, made with the source off, did nothing, so
 * without this the interrupt was lost for good.
 */
static void
xive_reenable_irq(struct pic_ops *pic, int irq, int type)
{
	struct xive_src *s = &xive_src[irq];
	uint64_t old;

	if (irq == XIVE_SLOT_IPI)
		return;
	old = xive_esb_load(s, ESB_SET_PQ_00);
	if (s->flags & SRC_LSI)
		xive_esb_load(s, ESB_LOAD_EOI);
	else if (old & ESB_VAL_Q)
		xive_trigger(s);
}

static void
xive_disable_irq(struct pic_ops *pic, int irq)
{

	/* [X] PQ 01 is "off": events are kept in Q and not sent */
	if (irq != XIVE_SLOT_IPI)
		xive_esb_load(&xive_src[irq], ESB_SET_PQ_01);
}

/*
 * Take the next entry off this processor's queue.  When it is empty the
 * CPPR goes back down, and an event queued after the last look raises
 * the exception again.
 */
static int
xive_get_irq(struct pic_ops *pic, int mode)
{
	struct xive_cpu * const xc = &xive_cpu[cpu_index(curcpu())];
	uint32_t e;
	int slot;

	if (mode == PIC_GET_IRQ)
		(void)*(volatile uint16_t *)(xive_tima + TM_ACK_OS_REG);

	for (;;) {
		e = be32toh(xc->eq[xc->eq_idx]);
		if ((e & EQ_GEN) != xc->eq_gen) {
			xive_tima[TM_OS_CPPR] = XIVE_PRIO_LEAST;
			__asm volatile("sync" ::: "memory");
			return 255;
		}
		xc->eq_idx = (xc->eq_idx + 1) & xc->eq_mask;
		if (xc->eq_idx == 0)
			xc->eq_gen ^= EQ_GEN;
		slot = xive_slot(e & EQ_EISN);
		if (slot >= 0)
			return slot;
		/* Nothing routed this; drop it. */
	}
}

static void
xive_ack_irq(struct pic_ops *pic, int irq)
{

	if (irq == XIVE_SLOT_IPI)
		xive_esb_load(&xive_cpu[cpu_index(curcpu())].ipi,
		    ESB_LOAD_EOI);
	else
		xive_esb_load(&xive_src[irq], ESB_LOAD_EOI);
}

/*
 * Hand out a slot for lisn and return the interrupt number the pic
 * framework knows it by, or -1 when the slots are used up.  The source
 * is set up when it is first enabled.
 */
int
xive_map_lisn(uint32_t lisn)
{
	int slot;

	slot = xive_slot(lisn);
	if (slot < 0) {
		if (xive_nslots == XIVE_NSLOTS)
			return -1;
		slot = xive_nslots++;
		xive_src[slot].lisn = lisn;
	}
	return xive_pic.pic_intrbase + slot;
}

/*
 * Each processor lets the OS ring take interrupts by lowering its own
 * CPPR; Table 210 puts H_CPPR at this byte.
 */
void
xive_cpu_init(void)
{

	xive_tima[TM_OS_CPPR] = XIVE_PRIO_LEAST;
	__asm volatile("sync" ::: "memory");
}

#ifdef MULTIPROCESSOR
static void
xive_send_ipi(cpuid_t target, uint32_t mesg)
{
	struct cpu_info * const ci = curcpu();
	u_int i;

	for (i = 0; i < ncpu; i++) {
		struct cpu_info * const dst_ci = cpu_lookup(i);

		if (target == IPI_DST_ALL ||
		    (target == IPI_DST_NOTME && dst_ci != ci) ||
		    target == i) {
			atomic_or_32(&dst_ci->ci_pending_ipis, mesg);
			xive_trigger(&xive_cpu[i].ipi);
		}
	}
}

static void
xive_establish_ipi(int type, int level, void *ih_args)
{

	intr_establish_xname(ipiops.ppc_ipi_vector, type, level, ipi_intr,
	    ih_args, "xive ipi");
}
#endif

static int
xive_getprop_cells(int node, const char *name, uint32_t *buf, int n)
{
	int len;

	len = OF_getprop(node, name, buf, n * sizeof(*buf));
	if (len <= 0)
		return 0;
	return len / sizeof(*buf);
}

/*
 * The least favored priority the platform leaves to the OS: priorities
 * run 0 (most favored) to 7, eight queues per target (Auernhammer and
 * Arndt, IBM J. Res. & Dev. 62(4/5), 2018, paper 5), less the ranges the root's
 * "ibm,plat-res-int-priorities" reserves (B.6.2.1).  Which of the free
 * ones to use is the OS's choice.
 */
static int
xive_pick_prio(void)
{
	uint32_t res[16];
	int n, i, p;

	n = xive_getprop_cells(OF_finddevice("/"),
	    "ibm,plat-res-int-priorities", res, __arraycount(res));
	for (p = 7; p >= 0; p--) {
		for (i = 0; i + 1 < n; i += 2)
			if ((uint32_t)p >= res[i] &&
			    (uint32_t)p - res[i] < res[i + 1])
				break;
		if (i + 1 >= n)
			return p;
	}
	return -1;
}

static int
xive_eq_init(struct xive_cpu *xc)
{
	struct pglist pglist;
	psize_t size = (psize_t)1 << xive_eq_shift;
	paddr_t pa;
	vaddr_t va;
	psize_t off;

	/* 14.5.4.7.10: zeroed by the OS, in memory the partition owns */
	if (uvm_pglistalloc(size, 0, ~(paddr_t)0, size, 0, &pglist, 1, 1))
		return -1;
	pa = VM_PAGE_TO_PHYS(TAILQ_FIRST(&pglist));
	va = uvm_km_alloc(kernel_map, size, 0, UVM_KMF_VAONLY);
	if (va == 0)
		return -1;
	for (off = 0; off < size; off += PAGE_SIZE)
		pmap_kenter_pa(va + off, pa + off,
		    VM_PROT_READ | VM_PROT_WRITE, 0);
	pmap_update(pmap_kernel());
	memset((void *)va, 0, size);

	xc->eq = (volatile uint32_t *)va;
	xc->eq_mask = size / sizeof(uint32_t) - 1;
	xc->eq_idx = 0;
	xc->eq_gen = EQ_GEN;
	if (xive_hcall(H_INT_SET_QUEUE_CONFIG, EQ_ALWAYS_NOTIFY, xc->server,
	    xive_prio, pa, xive_eq_shift, NULL) != H_SUCCESS)
		return -1;
	return 0;
}

/*
 * node is the "ibm,power-ivpe" one (B.6.7).  Its "reg" is two entries,
 * the user and the OS views of the TIMA; the second is the one used.
 */
void
setup_xive(int node)
{
	CPU_INFO_ITERATOR cii;
	struct cpu_info *ci;
	uint32_t reg[8], v[8];
	int ac, sc, n, i, cpus, cpu, r, server;
	uint64_t tima = 0, tsize = 0;

	if (OF_getprop(OF_parent(node), "#address-cells", &ac,
	    sizeof(ac)) != sizeof(ac))
		ac = 2;
	if (OF_getprop(OF_parent(node), "#size-cells", &sc,
	    sizeof(sc)) != sizeof(sc))
		sc = 1;
	n = xive_getprop_cells(node, "reg", reg, __arraycount(reg));
	if (n < 2 * (ac + sc) || ac > 2) {
		printf("xive: bad reg\n");
		return;
	}
	for (i = 0; i < ac; i++)
		tima = (tima << 32) | reg[ac + sc + i];
	for (i = 0; i < sc; i++)
		tsize = (tsize << 32) | reg[2 * ac + sc + i];

	/* ibm,xive-eq-sizes, in ascending order; 4K if offered */
	n = xive_getprop_cells(node, "ibm,xive-eq-sizes", v, __arraycount(v));
	if (n == 0) {
		printf("xive: no ibm,xive-eq-sizes\n");
		return;
	}
	xive_eq_shift = v[0];
	for (i = 0; i < n; i++)
		if (v[i] == PAGE_SHIFT)
			xive_eq_shift = v[i];

	/* The first range of ibm,xive-lisn-ranges has one per thread */
	if (xive_getprop_cells(node, "ibm,xive-lisn-ranges", v, 2) < 2) {
		printf("xive: no ibm,xive-lisn-ranges\n");
		return;
	}
	xive_ipi_base = v[0];
	xive_ipi_count = v[1];

	if ((xive_prio = xive_pick_prio()) < 0) {
		printf("xive: no priority left to the OS\n");
		return;
	}

	xive_tima = mapiodev(tima, tsize, false);
	xive_cpu = kmem_zalloc((ncpu ? ncpu : 1) * sizeof(*xive_cpu),
	    KM_SLEEP);

	for (CPU_INFO_FOREACH(cii, ci)) {
		struct xive_cpu *xc = &xive_cpu[cpu_index(ci)];

		/* R-4.1.6-1, B.6.4 */
		server = ci->ci_cpuid;
		cpus = OF_finddevice("/cpus");
		for (cpu = OF_child(cpus); cpu != 0; cpu = OF_peer(cpu))
			if (OF_getprop(cpu, "reg", &r, sizeof(r)) ==
			    sizeof(r) && r == ci->ci_cpuid) {
				OF_getprop(cpu, "ibm,ppc-interrupt-server#s",
				    &server, sizeof(server));
				break;
			}
		xc->server = server;
		if (xive_eq_init(xc) != 0) {
			printf("xive: cannot set up the queue of cpu%d\n",
			    cpu_index(ci));
			return;
		}
		if (cpu_index(ci) >= xive_ipi_count ||
		    xive_src_init(&xc->ipi, xive_ipi_base + cpu_index(ci),
		    server) != 0) {
			printf("xive: cannot set up the IPI of cpu%d\n",
			    cpu_index(ci));
			return;
		}
		xive_esb_load(&xc->ipi, ESB_SET_PQ_00);
	}

	xive_pic.pic_numintrs = XIVE_NSLOTS;
	xive_pic.pic_cookie = NULL;
	xive_pic.pic_enable_irq = xive_enable_irq;
	xive_pic.pic_reenable_irq = xive_reenable_irq;
	xive_pic.pic_disable_irq = xive_disable_irq;
	xive_pic.pic_get_irq = xive_get_irq;
	xive_pic.pic_ack_irq = xive_ack_irq;
	xive_pic.pic_establish_irq = dummy_pic_establish_intr;
	xive_pic.pic_finish_setup = NULL;
	strcpy(xive_pic.pic_name, "xive");
	pic_add(&xive_pic);

	xive_cpu_init();
	xive_active = true;
	aprint_normal("xive: exploitation mode, priority %d, %d-byte queues\n",
	    xive_prio, 1 << xive_eq_shift);

#ifdef MULTIPROCESSOR
	ipiops.ppc_send_ipi = xive_send_ipi;
	ipiops.ppc_establish_ipi = xive_establish_ipi;
	ipiops.ppc_ipi_vector = xive_pic.pic_intrbase + XIVE_SLOT_IPI;
#endif
}
