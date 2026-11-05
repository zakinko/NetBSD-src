/*	$NetBSD: Locore.c,v 1.35 2021/02/28 20:27:40 thorpej Exp $	*/

/*
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

#include <sys/param.h>
#include <lib/libsa/stand.h>

#include <machine/cpu.h>
#include <powerpc/oea/spr.h>

#include "openfirm.h"

/*
 * Open Firmware's client interface passes its arguments and results as
 * an array of cells, and the cells are 32 bits wide even where the
 * firmware itself is 64-bit.  Laying these structures out with C
 * pointers works only while a pointer is one cell, so on an LP64 build
 * the low half of the first pointer is read as nargs and the firmware
 * walks off the end of the array.
 *
 * Every slot is therefore one cell, and a pointer goes in as OFW_CELL().
 * The loader is placed below 4GB, so an address fits.
 */
typedef uint32_t	cell_t;

#define	OFW_CELL(p)	((cell_t)(uintptr_t)(p))
#define	OFW_PTR(c)	((void *)(uintptr_t)(c))

static int (*openfirmware)(void *);

#ifdef _LP64
/*
 * What Open Firmware hands us is a code address, but an ELF V1 call
 * through a function pointer reads the pointed-to words as an entry
 * point and a TOC.  Give it a descriptor of our own that says so.
 */
static unsigned long openfirmware_desc[3];
#endif

/*
 * The firmware's own code address, kept apart from the pointer this
 * loader calls through: the kernel branches to what OF_chain() hands it
 * with mtctr/bctrl, so it must be the code and not a descriptor.
 */
static int (*openfirmware_code)(void *);

static void startup(void *, int, int (*)(void *), char *, int)
		__attribute__((__used__));
static void setup(void);

#ifdef HEAP_VARIABLE
#ifndef HEAP_SIZE
#define HEAP_SIZE 0x20000
#endif
char *heapspace;
#endif

static int stack[8192/4 + 4] __attribute__((__used__));

#ifdef XCOFF_GLUE
__asm(
"	.text			\n"
"	.globl	_entry		\n"
"_entry:			\n"
"	.long	_start,0,0	\n"
);
#endif /* XCOFF_GLUE */

__asm(
"	.text			\n"
"	.globl	_start		\n"
"_start:			\n"
"	sync			\n"
"	isync			\n"
"	lis	%r1,stack@ha	\n"
"	addi	%r1,%r1,stack@l	\n"
"	addi	%r1,%r1,8192	\n"
"				\n"
"	mfmsr	%r8		\n"
"	li	%r0,0		\n"
"	mtmsr	%r0		\n"
"	isync			\n"
"				\n"
"				\n" /* test for 601 */
"	mfspr	%r0,287		\n" /* mfpvbr %r0 PVR = 287 */
"	srwi	%r0,%r0,0x10	\n"
"	cmplwi	%r0,0x02	\n" /* 601 CPU = 0x0001 */
"	blt	2f		\n" /* skip over non-601 BAT setup */
"	cmplwi	%r0,0x39	\n" /* PPC970 */
"	blt	0f		\n"
"	cmplwi	%r0,0x45	\n" /* PPC970GX */
"	ble	1f		\n"
	/* non PPC 601 BATs */
"0:	li	%r0,0		\n"
"	mtibatu	0,%r0		\n"
"	mtibatu	1,%r0		\n"
"	mtibatu	2,%r0		\n"
"	mtibatu	3,%r0		\n"
"	mtdbatu	0,%r0		\n"
"	mtdbatu	1,%r0		\n"
"	mtdbatu	2,%r0		\n"
"	mtdbatu	3,%r0		\n"
"				\n"
"	li	%r9,0x12	\n"	/* BATL(0, BAT_M, BAT_PP_RW) */
"	mtibatl	0,%r9		\n"
"	mtdbatl	0,%r9		\n"
"	li	%r9,0x1ffe	\n"	/* BATU(0, BAT_BL_256M, BAT_Vs) */
"	mtibatu	0,%r9		\n"
"	mtdbatu	0,%r9		\n"
"	b	3f		\n"
	/* 970 initialization stuff */
"1:				\n"
	/* make sure we're in bridge mode */
"	clrldi	%r8,%r8,3	\n"
"	mtmsrd	%r8		\n"
"	isync			\n"
	 /* clear HID5 DCBZ bits (56/57), need to do this early */
"	mfspr	%r9,0x3f6	\n"
"	rldimi	%r9,0,6,56	\n"
"	sync			\n"
"	mtspr	0x3f6,%r9	\n"
"	isync			\n"
"	sync			\n"
	/* Setup HID1 features, prefetch + i-cacheability controlled by PTE */
"	mfspr	%r9,0x3f1	\n"
"	li	%r11,0x1200	\n"
"	sldi	%r11,%r11,44	\n"
"	or	%r9,%r9,%r11	\n"
"	mtspr	0x3f1,%r9	\n"
"	isync			\n"
"	sync			\n"
"	b	3f		\n"	
	/* PPC 601 BATs */
"2:	li	%r0,0		\n"
"	mtibatu	0,%r0		\n"
"	mtibatu	1,%r0		\n"
"	mtibatu	2,%r0		\n"
"	mtibatu	3,%r0		\n"
"				\n"
"	li	%r9,0x7f	\n"
"	mtibatl	0,%r9		\n"
"	li	%r9,0x1a	\n"
"	mtibatu	0,%r9		\n"
"				\n"
"	lis	%r9,0x80	\n"
"	addi	%r9,%r9,0x7f	\n"
"	mtibatl	1,%r9		\n"
"	lis	%r9,0x80	\n"
"	addi	%r9,%r9,0x1a	\n"
"	mtibatu	1,%r9		\n"
"				\n"
"	lis	%r9,0x100	\n"
"	addi	%r9,%r9,0x7f	\n"
"	mtibatl	2,%r9		\n"
"	lis	%r9,0x100	\n"
"	addi	%r9,%r9,0x1a	\n"
"	mtibatu	2,%r9		\n"
"				\n"
"	lis	%r9,0x180	\n"
"	addi	%r9,%r9,0x7f	\n"
"	mtibatl	3,%r9		\n"
"	lis	%r9,0x180	\n"
"	addi	%r9,%r9,0x1a	\n"
"	mtibatu	3,%r9		\n"
"				\n"
"3:	isync			\n"
"				\n"
"	mtmsr	%r8		\n"
"	isync			\n"
"				\n"
	/*
	 * Make sure that .bss is zeroed
	 */
"				\n"
"	li	%r0,0		\n"
"	lis	%r8,_edata@ha	\n"
"	addi	%r8,%r8,_edata@l\n"
"	lis	%r9,_end@ha	\n"
"	addi	%r9,%r9,_end@l	\n"
"				\n"
"5:	cmpw	0,%r8,%r9	\n"
"	bge	6f		\n"
	/*
	 * clear by bytes to avoid ppc601 alignment exceptions
	 */
"	stb	%r0,0(%r8)	\n"
"	stb	%r0,1(%r8)	\n"
"	stb	%r0,2(%r8)	\n"
"	stb	%r0,3(%r8)	\n"
"	addi	%r8,%r8,4	\n"
"	b	5b		\n"
"				\n"
"6:	b	startup		\n"
);

#if 0
static int
openfirmware(void *arg)
{

	__asm volatile ("sync; isync");
	openfirmware_entry(arg);
	__asm volatile ("sync; isync");
}
#endif

int	ofw_real_mode;
int	ofw_address_cells;
int	ofw_size_cells;

int	ofw_root;		/* / */
int	ofw_options;		/* /options */
int	ofw_openprom;		/* /openprom */
int	ofw_chosen;		/* /chosen (package) */
int	ofw_stdin;		/* /chosen/stdin */
int	ofw_stdout;		/* /chosen/stdout */
int	ofw_memory_ihandle;	/* /chosen/memory */
int	ofw_mmu_ihandle;	/* /chosen/mmu */

bool
ofw_option_truefalse(const char *prop, int proplen)
{
	/* These are all supposed to be strings. */
	switch (prop[0]) {  
	case 'y':
	case 'Y':
	case 't':
	case 'T':
	case '1':
		return true; 
	}
	return false;
}

static void
startup(void *vpd, int res, int (*openfirm)(void *), char *arg, int argl)
{

	openfirmware_code = openfirm;
#ifdef _LP64
    {
	register unsigned long toc __asm("r2");

	openfirmware_desc[0] = (unsigned long)openfirm;
	openfirmware_desc[1] = toc;
	openfirmware = (int (*)(void *))openfirmware_desc;
    }
#else
	openfirmware = openfirm;
#endif
	setup();
	main();
	OF_exit();
}

#if 0
void
OF_enter(void)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
	} args = {
		0,
		0,
		0
	};

	args.name = OFW_CELL("enter");

	openfirmware(&args);
}
#endif	/* OF_enter */

__dead void
OF_exit(void)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
	} args = {
		0,
		0,
		0
	};

	args.name = OFW_CELL("exit");

	openfirmware(&args);
	for (;;);			/* just in case */
}

int
OF_finddevice(const char *name)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	device;
		cell_t	phandle;
	} args = {
		0,
		1,
		1,
	};

	args.name = OFW_CELL("finddevice");

	args.device = OFW_CELL(name);
	if (openfirmware(&args) == -1)
		return -1;
	return args.phandle;
}

int
OF_instance_to_package(int ihandle)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	ihandle;
		cell_t	phandle;
	} args = {
		0,
		1,
		1,
	};

	args.name = OFW_CELL("instance-to-package");

	args.ihandle = ihandle;
	if (openfirmware(&args) == -1)
		return -1;
	return args.phandle;
}

int
OF_getprop(int handle, const char *prop, void *buf, int buflen)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	phandle;
		cell_t	prop;
		cell_t	buf;
		cell_t	buflen;
		cell_t	size;
	} args = {
		0,
		4,
		1,
	};

	args.name = OFW_CELL("getprop");

	args.phandle = handle;
	args.prop = OFW_CELL(prop);
	args.buf = OFW_CELL(buf);
	args.buflen = buflen;
	if (openfirmware(&args) == -1)
		return -1;
	return args.size;
}

#ifdef	__notyet__	/* Has a bug on FirePower */
int
OF_setprop(int handle, const char *prop, void *buf, int len)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	phandle;
		cell_t	prop;
		cell_t	buf;
		cell_t	len;
		cell_t	size;
	} args = {
		0,
		4,
		1,
	};

	args.name = OFW_CELL("setprop");

	args.phandle = handle;
	args.prop = OFW_CELL(prop);
	args.buf = OFW_CELL(buf);
	args.len = len;
	if (openfirmware(&args) == -1)
		return -1;
	return args.size;
}
#endif

int
OF_open(const char *dname)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	dname;
		cell_t	handle;
	} args = {
		0,
		1,
		1,
	};

	args.name = OFW_CELL("open");

#ifdef OFW_DEBUG
	printf("OF_open(%s) -> ", dname);
#endif
	args.dname = OFW_CELL(dname);
	if (openfirmware(&args) == -1 ||
	    args.handle == 0) {
#ifdef OFW_DEBUG
		printf("lose\n");
#endif
		return -1;
	}
#ifdef OFW_DEBUG
	printf("%d\n", args.handle);
#endif
	return args.handle;
}

void
OF_close(int handle)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	handle;
	} args = {
		0,
		1,
		0,
	};

	args.name = OFW_CELL("close");

#ifdef OFW_DEBUG
	printf("OF_close(%d)\n", handle);
#endif
	args.handle = handle;
	openfirmware(&args);
}

int
OF_write(int handle, void *addr, int len)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	ihandle;
		cell_t	addr;
		cell_t	len;
		cell_t	actual;
	} args = {
		0,
		3,
		1,
	};

	args.name = OFW_CELL("write");

#ifdef OFW_DEBUG
	if (len != 1)
		printf("OF_write(%d, %p, %x) -> ", handle, addr, len);
#endif
	args.ihandle = handle;
	args.addr = OFW_CELL(addr);
	args.len = len;
	if (openfirmware(&args) == -1) {
#ifdef OFW_DEBUG
		printf("lose\n");
#endif
		return -1;
	}
#ifdef OFW_DEBUG
	if (len != 1)
		printf("%x\n", args.actual);
#endif
	return args.actual;
}

int
OF_read(int handle, void *addr, int len)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	ihandle;
		cell_t	addr;
		cell_t	len;
		cell_t	actual;
	} args = {
		0,
		3,
		1,
	};

	args.name = OFW_CELL("read");

#ifdef OFW_DEBUG
	if (len != 1)
		printf("OF_read(%d, %p, %x) -> ", handle, addr, len);
#endif
	args.ihandle = handle;
	args.addr = OFW_CELL(addr);
	args.len = len;
	if (openfirmware(&args) == -1) {
#ifdef OFW_DEBUG
		printf("lose\n");
#endif
		return -1;
	}
#ifdef OFW_DEBUG
	if (len != 1)
		printf("%x\n", args.actual);
#endif
	return args.actual;
}

int
OF_seek(int handle, u_quad_t pos)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	handle;
		cell_t	poshi;
		cell_t	poslo;
		cell_t	status;
	} args = {
		0,
		3,
		1,
	};

	args.name = OFW_CELL("seek");

#ifdef OFW_DEBUG
	printf("OF_seek(%d, %x, %x) -> ", handle, (int)(pos >> 32), (int)pos);
#endif
	args.handle = handle;
	args.poshi = (int)(pos >> 32);
	args.poslo = (int)pos;
	if (openfirmware(&args) == -1) {
#ifdef OFW_DEBUG
		printf("lose\n");
#endif
		return -1;
	}
#ifdef OFW_DEBUG
	printf("%d\n", args.status);
#endif
	return args.status;
}

void *
OF_claim(void *virt, u_int size, u_int align)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	virt;
		cell_t	size;
		cell_t	align;
		cell_t	baseaddr;
	} args = {
		0,
		3,
		1,
	};

	args.name = OFW_CELL("claim");

#ifdef OFW_DEBUG
	printf("OF_claim(%p, %x, %x) -> ", virt, size, align);
#endif
	args.virt = OFW_CELL(virt);
	args.size = size;
	args.align = align;
	if (openfirmware(&args) == -1) {
#ifdef OFW_DEBUG
		printf("lose\n");
#endif
		return (void *)-1;
	}
#ifdef OFW_DEBUG
	printf("%p\n", OFW_PTR(args.baseaddr));
#endif
	return OFW_PTR(args.baseaddr);
}

void
OF_release(void *virt, u_int size)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	virt;
		cell_t	size;
	} args = {
		0,
		2,
		0,
	};

	args.name = OFW_CELL("release");

#ifdef OFW_DEBUG
	printf("OF_release(%p, %x)\n", virt, size);
#endif
	args.virt = OFW_CELL(virt);
	args.size = size;
	openfirmware(&args);
}

int
OF_milliseconds(void)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	ms;
	} args = {
		0,
		0,
		1,
	};

	args.name = OFW_CELL("milliseconds");

	openfirmware(&args);
	return args.ms;
}

#ifdef	__notyet__
void
OF_chain(void *virt, u_int size, void (*entry)(), void *arg, u_int len)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	virt;
		cell_t	size;
		cell_t	entry;
		cell_t	arg;
		cell_t	len;
	} args = {
		0,
		5,
		0,
	};

	args.name = OFW_CELL("chain");

	args.virt = OFW_CELL(virt);
	args.size = size;
	args.entry = OFW_CELL(entry);
	args.arg = OFW_CELL(arg);
	args.len = len;
	openfirmware(&args);
}
#else
void
OF_chain(void *virt, u_int size, boot_entry_t entry, void *arg, u_int len)
{
	/*
	 * This is a REALLY dirty hack till the firmware gets this going
	 */
#if 0
	OF_release(virt, size);
#endif
#ifdef _LP64
    {
	/*
	 * loadfile() hands back the kernel's e_entry, which is a code
	 * address.  An ELF V1 call through a function pointer would read
	 * the words there as an entry point and a TOC, so wrap it the same
	 * way the firmware's own entry is wrapped.  A 32-bit loader
	 * branches straight to e_entry, so this keeps the two widths
	 * asking the same thing of the kernel.
	 */
	static unsigned long kdesc[3];
	register unsigned long toc __asm("r2");

	kdesc[0] = (unsigned long)entry;
	kdesc[1] = toc;
	((boot_entry_t)(void *)kdesc)(0, 0, openfirmware_code, arg, len);
    }
#else
	entry(0, 0, openfirmware_code, arg, len);
#endif
}
#endif

int
OF_call_method(const char *method, int ihandle, int nargs, int nreturns,
    int *cells)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	method;
		cell_t	ihandle;
		cell_t	args_n_results[12];
	} args = {
		0,
		2,
		1,
	};

	args.name = OFW_CELL("call-method");
	cell_t *ip;
	int n;

	if (nargs > 6)
		return -1;

	args.nargs = nargs + 2;
	args.nreturns = nreturns + 1;
	args.method = OFW_CELL(method);
	args.ihandle = ihandle;

	for (ip = args.args_n_results + (n = nargs); --n >= 0;)
		*--ip = *cells++;

	if (openfirmware(&args) == -1) {
		return -1;
	}

	if (args.args_n_results[nargs]) {
		return args.args_n_results[nargs];
	}

	for (ip = args.args_n_results + nargs + (n = args.nreturns); --n > 0;)
		*cells++ = *--ip;

	return 0;
}

static void
setup(void)
{
	char prop[32];
	int proplen;
	const char *reason = NULL;

	if ((ofw_chosen = OF_finddevice("/chosen")) == -1)
		OF_exit();
	if (OF_getprop(ofw_chosen, "stdin", &ofw_stdin, sizeof(ofw_stdin)) !=
	    sizeof(ofw_stdin) ||
	    OF_getprop(ofw_chosen, "stdout", &ofw_stdout, sizeof(ofw_stdout)) !=
	    sizeof(ofw_stdout))
		OF_exit();

	if (ofw_stdout == 0) {
		/* screen should be console, but it is not open */
		ofw_stdout = OF_open("screen");
	}

#ifdef HEAP_VARIABLE
	uint32_t pvr, vers, hsize = HEAP_SIZE;

	__asm volatile ("mfpvr %0" : "=r"(pvr));
	vers = pvr >> 16;
	if (vers >= IBM970 && vers <= IBM970GX) hsize = 0x800000;

	heapspace = OF_claim(0, hsize, NBPG);
	if (heapspace == (char *)-1) {
		panic("Failed to allocate heap");
	}

	setheap(heapspace, heapspace + HEAP_SIZE);
#endif	/* HEAP_VARIABLE */

	ofw_root = OF_finddevice("/");
	ofw_options = OF_finddevice("/options");
	ofw_openprom = OF_finddevice("/openprom");
	ofw_chosen = OF_finddevice("/chosen");

	if (ofw_root == -1) {
		reason = "No root node";
		goto bad_environment;
	}
	if (ofw_chosen == -1) {
		reason = "No chosen node";
		goto bad_environment;
	}

	if (ofw_options != -1) {
		proplen = OF_getprop(ofw_options, "real-mode?", prop,
		    sizeof(prop));
		if (proplen > 0) {
			ofw_real_mode = ofw_option_truefalse(prop, proplen);
		}
	}

	/*
	 * Get #address-cells and #size-cells.
	 */
	ofw_address_cells = 1;
	ofw_size_cells = 1;
	OF_getprop(ofw_root, "#address-cells", &ofw_address_cells,
		   sizeof(ofw_address_cells));
	OF_getprop(ofw_root, "#size-cells", &ofw_size_cells,
		   sizeof(ofw_size_cells));

	/* See loadfile_machdep.c */
	if (ofw_size_cells != 1) {
		printf("#size-cells = %d not yet supported\n", ofw_size_cells);
		reason = "unsupported #size-cells";
		goto bad_environment;
	}

	/*
	 * Get the ihandle on /chosen/memory and /chosen/mmu.
	 */
	ofw_memory_ihandle = -1;
	ofw_mmu_ihandle = -1;
	OF_getprop(ofw_chosen, "memory", &ofw_memory_ihandle,
		   sizeof(ofw_memory_ihandle));
	OF_getprop(ofw_chosen, "mmu", &ofw_mmu_ihandle,
		   sizeof(ofw_mmu_ihandle));
	if (ofw_memory_ihandle == -1) {
		reason = "no /chosen/memory";
		goto bad_environment;
	}
	if (ofw_mmu_ihandle == -1) {
		reason = "no /chosen/mmu";
		goto bad_environment;
	}

	return;

 bad_environment:
	if (reason == NULL) {
		reason = "unknown reason";
	}
	printf("Invalid Openfirmware environment: %s\n", reason);
	OF_exit();
}

void
putchar(int c)
{
	char ch = c;

	if (c == '\n')
		putchar('\r');
	OF_write(ofw_stdout, &ch, 1);
}

int
getchar(void)
{
	unsigned char ch = '\0';
	int l;

	while ((l = OF_read(ofw_stdin, &ch, 1)) != 1)
		if (l != -2 && l != 0)
			return -1;
	return ch;
}
