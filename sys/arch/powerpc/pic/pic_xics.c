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
 * The PowerPC External Interrupt option of a PAPR partition in XIVE
 * legacy mode (PAPR 10.60, Table 210): the presentation layer is reached
 * through hcalls (14.5.4.7), the sources through RTAS (7.3.10).
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

#include <dev/ofw/openfirm.h>

#include <powerpc/rtas.h>

#include <powerpc/pic/picvar.h>
#ifdef MULTIPROCESSOR
#include <powerpc/pic/ipivar.h>
#endif

/* Table 175 */
#define	H_EOI		0x64
#define	H_CPPR		0x68
#define	H_IPI		0x6c
#define	H_XIRR		0x74

#define	H_SUCCESS	0

/* Table 213: the CPPR in bits 32:39, the ISN in bits 40:63 */
#define	XIRR_CPPR_SHIFT	24
#define	XIRR_ISN	0x00ffffff

/*
 * PAPR does not number these.  They are the XISR values of the PowerPC
 * External Interrupt Architecture for "no interrupt" and for the
 * processor's own MFRR (US patent 5,701,495, Table 3); qemu's XICS uses
 * the same two.
 */
#define	XISR_NONE	0
#define	XISR_IPI	2

/* 0x00 is the most favored priority and 0xff the least (R-6.2.1-12) */
#define	XICS_PRIO_LEAST	0xff

/*
 * The priority of each source and of the IPI is the OS's to choose.  They
 * all get the same one, so the CPPR that H_XIRR raises to it holds every
 * other source off until the H_EOI, and interrupts here never nest: the
 * H_EOI can always put the CPPR back to the least favored level.
 */
#define	XICS_PRIO	5

/*
 * ISNs are sparse and large (qemu's start at 0x1000), the pic framework
 * wants small numbers.  A slot is handed out to each ISN as an interrupt
 * map names it; slot 0 stands for the IPI.
 */
#define	XICS_NSLOTS	64
#define	XICS_SLOT_IPI	0

static struct pic_ops xics_pic;
static uint32_t xics_isn[XICS_NSLOTS];
static u_int xics_nslots = 1;

/* Interrupt server numbers, by cpu_index() */
static int *xics_server;

bool xics_active;

/*
 * 14.5.3: the token in r3 and the parameters from r4, the status back in
 * r3 and the output in r4; r0, r3-r12, CTR, XER and CR fields 0, 1 and 5-7
 * are not preserved.  sc with LEV=1 invokes the hypervisor (Book III-S
 * 3.3.1).
 */
static long
xics_hcall(register_t token, register_t a1, register_t a2, register_t *out)
{
	register register_t r3 __asm("r3") = token;
	register register_t r4 __asm("r4") = a1;
	register register_t r5 __asm("r5") = a2;

	__asm volatile("sc 1"
	    : "+r"(r3), "+r"(r4), "+r"(r5)
	    :
	    : "r0", "r6", "r7", "r8", "r9", "r10", "r11", "r12",
	      "ctr", "xer", "cr0", "cr1", "cr5", "cr6", "cr7", "memory");
	if (out != NULL)
		*out = r4;
	return r3;
}

static int
xics_slot(uint32_t isn)
{
	u_int i;

	for (i = XICS_SLOT_IPI + 1; i < xics_nslots; i++)
		if (xics_isn[i] == isn)
			return i;
	return -1;
}

/*
 * Every source is routed to the boot processor; which server takes it is
 * the OS's choice too.
 */
static void
xics_enable_irq(struct pic_ops *pic, int irq, int type)
{
	int status;

	if (irq == XICS_SLOT_IPI)
		return;
	/* 7.3.10.2, then 7.3.10.4 */
	if (rtas_call(RTAS_FUNC_IBM_SET_XIVE, 3, 1, xics_isn[irq],
	    xics_server[0], XICS_PRIO, &status) < 0 || status != 0 ||
	    rtas_call(RTAS_FUNC_IBM_INT_ON, 1, 1, xics_isn[irq],
	    &status) < 0 || status != 0)
		printf("xics: cannot enable interrupt %#x\n", xics_isn[irq]);
}

static void
xics_reenable_irq(struct pic_ops *pic, int irq, int type)
{
	int status;

	if (irq != XICS_SLOT_IPI)
		rtas_call(RTAS_FUNC_IBM_INT_ON, 1, 1, xics_isn[irq], &status);
}

static void
xics_disable_irq(struct pic_ops *pic, int irq)
{
	int status;

	/* 7.3.10.3 */
	if (irq != XICS_SLOT_IPI)
		rtas_call(RTAS_FUNC_IBM_INT_OFF, 1, 1, xics_isn[irq], &status);
}

static int
xics_get_irq(struct pic_ops *pic, int mode)
{
	register_t xirr;
	uint32_t isn;
	int slot, status;

	for (;;) {
		/* 14.5.4.7.5 */
		if (xics_hcall(H_XIRR, XICS_PRIO_LEAST, 0, &xirr) != H_SUCCESS)
			return 255;
		isn = xirr & XIRR_ISN;
		if (isn == XISR_NONE)
			return 255;
		if (isn == XISR_IPI) {
			/*
			 * Put the MFRR back before the handler reads the
			 * pending bits, or one sent meanwhile is lost.
			 */
			xics_hcall(H_IPI, xics_server[cpu_index(curcpu())],
			    XICS_PRIO_LEAST, NULL);
			return XICS_SLOT_IPI;
		}
		slot = xics_slot(isn);
		if (slot >= 0)
			return slot;
		/* No map named it; turn it off rather than take it again. */
		rtas_call(RTAS_FUNC_IBM_INT_OFF, 1, 1, isn, &status);
		xics_hcall(H_EOI, (XICS_PRIO_LEAST << XIRR_CPPR_SHIFT) | isn,
		    0, NULL);
	}
}

static void
xics_ack_irq(struct pic_ops *pic, int irq)
{
	uint32_t isn;

	isn = irq == XICS_SLOT_IPI ? XISR_IPI : xics_isn[irq];
	/* 14.5.4.7.1 */
	xics_hcall(H_EOI, (XICS_PRIO_LEAST << XIRR_CPPR_SHIFT) | isn, 0, NULL);
}

/*
 * Hand out a slot for isn and return the interrupt number the pic
 * framework knows it by, or -1 when the slots are used up.
 */
int
xics_map_isn(uint32_t isn)
{
	int slot;

	slot = xics_slot(isn);
	if (slot < 0) {
		if (xics_nslots == XICS_NSLOTS)
			return -1;
		slot = xics_nslots++;
		xics_isn[slot] = isn;
	}
	return xics_pic.pic_intrbase + slot;
}

/*
 * The platform hands over with the CPPR at the most favored level, so that
 * nothing is presented until the OS sets it (R-6.2.1-12).  H_CPPR sets the
 * calling processor's own (14.5.4.7.2); each processor does this once.
 */
void
xics_cpu_init(void)
{

	xics_hcall(H_CPPR, XICS_PRIO_LEAST, 0, NULL);
}

#ifdef MULTIPROCESSOR
static void
xics_send_ipi(cpuid_t target, uint32_t mesg)
{
	struct cpu_info * const ci = curcpu();
	u_int i;

	for (i = 0; i < ncpu; i++) {
		struct cpu_info * const dst_ci = cpu_lookup(i);

		if (target == IPI_DST_ALL ||
		    (target == IPI_DST_NOTME && dst_ci != ci) ||
		    target == i) {
			atomic_or_32(&dst_ci->ci_pending_ipis, mesg);
			/* 14.5.4.7.3 */
			xics_hcall(H_IPI, xics_server[i], XICS_PRIO, NULL);
		}
	}
}

static void
xics_establish_ipi(int type, int level, void *ih_args)
{

	intr_establish_xname(ipiops.ppc_ipi_vector, type, level, ipi_intr,
	    ih_args, "xics ipi");
}
#endif

/*
 * node is the presentation layer's.  The processors are attached by now,
 * and each one's server number is the first of its
 * "ibm,ppc-interrupt-server#s", one per thread (R-4.1.6-1, B.6.4).
 */
void
setup_xics(int node)
{
	CPU_INFO_ITERATOR cii;
	struct cpu_info *ci;
	int cpus, cpu, reg, server;

	xics_server = kmem_zalloc((ncpu ? ncpu : 1) * sizeof(*xics_server),
	    KM_SLEEP);
	for (CPU_INFO_FOREACH(cii, ci)) {
		server = ci->ci_cpuid;
		cpus = OF_finddevice("/cpus");
		for (cpu = OF_child(cpus); cpu != 0; cpu = OF_peer(cpu))
			if (OF_getprop(cpu, "reg", &reg, sizeof(reg)) ==
			    sizeof(reg) && reg == ci->ci_cpuid) {
				OF_getprop(cpu, "ibm,ppc-interrupt-server#s",
				    &server, sizeof(server));
				break;
			}
		xics_server[cpu_index(ci)] = server;
	}

	xics_pic.pic_numintrs = XICS_NSLOTS;
	xics_pic.pic_cookie = NULL;
	xics_pic.pic_enable_irq = xics_enable_irq;
	xics_pic.pic_reenable_irq = xics_reenable_irq;
	xics_pic.pic_disable_irq = xics_disable_irq;
	xics_pic.pic_get_irq = xics_get_irq;
	xics_pic.pic_ack_irq = xics_ack_irq;
	xics_pic.pic_establish_irq = dummy_pic_establish_intr;
	xics_pic.pic_finish_setup = NULL;
	strcpy(xics_pic.pic_name, "xics");
	pic_add(&xics_pic);

	xics_cpu_init();
	xics_active = true;

#ifdef MULTIPROCESSOR
	ipiops.ppc_send_ipi = xics_send_ipi;
	ipiops.ppc_establish_ipi = xics_establish_ipi;
	ipiops.ppc_ipi_vector = xics_pic.pic_intrbase + XICS_SLOT_IPI;
#endif
}
