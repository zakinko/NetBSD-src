/*	$NetBSD: boot.c,v 1.25 2020/09/15 08:14:31 mrg Exp $	*/

/*-
 * Copyright (c) 1997 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe.
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
 * Copyright (C) 1995, 1996 Wolfgang Solfrank.
 * Copyright (C) 1995, 1996 TooLs GmbH.
 * All rights reserved.
 *
 * ELF support derived from NetBSD/alpha's boot loader, written
 * by Christopher G. Demetriou.
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

/*
 * First try for the boot code
 *
 * Input syntax is:
 *	[promdev[{:|,}partition]]/[filename] [flags]
 */

#define	ELFSIZE		32		/* We use 32-bit ELF. */

#include <sys/param.h>
#include <sys/exec.h>
#include <sys/exec_elf.h>
#include <sys/reboot.h>
#include <sys/disklabel.h>
#include <sys/boot_flag.h>

#include <lib/libsa/stand.h>
#include <lib/libsa/loadfile.h>
#include <lib/libkern/libkern.h>

#include <machine/cpu.h>

#include "boot.h"
#include "ofdev.h"
#include "openfirm.h"

#ifdef DEBUG
# define DPRINTF printf
#else
# define DPRINTF while (/*CONSTCOND*/0) printf
#endif

char bootdev[128];
char bootfile[128];
int boothowto;
int debug;

#ifdef OFWDUMP
void dump_ofwtree(int);
#endif

static char *kernels[] = { "/netbsd.ofppc", "/netbsd",
			   "/netbsd.gz", "onetbsd", NULL };
static char *kernels64[] = { "/netbsd.ofppc64", "/netbsd64", "/netbsd64.gz",
			     "onetbsd64", "/netbsd.ofppc", "/netbsd",
			     "/netbsd.gz", "onetbsd", NULL };

static void
prom2boot(char *dev)
{
	char *cp, *ocp;
	
	ocp = dev;
	cp = dev + strlen(dev) - 1;
	for (; cp >= ocp; cp--) {
		if (*cp == ':') {
			*cp = '\0';
			return;
		}
	}
}

static void
parseargs(char *str, int *howtop)
{
	char *cp;

	/* Allow user to drop back to the PROM. */
	if (strcmp(str, "exit") == 0)
		OF_exit();
	if (strcmp(str, "halt") == 0)
		OF_exit();
	if (strcmp(str, "reboot") == 0)
		OF_boot("");

	*howtop = 0;

	for (cp = str; *cp; cp++)
		if (*cp == ' ' || *cp == '-')
			goto found;
	
	return;

 found:
	*cp++ = '\0';
	while (*cp)
		BOOT_FLAG(*cp++, *howtop);
}

static void
chain(boot_entry_t entry, char *args, void *ssym, void *esym)
{
	extern char end[];
	u_int l, magic = 0x19730224;

	/*
	 * Stash pointer to start and end of symbol table after the argument
	 * strings.
	 */
	l = strlen(args) + 1;
	DPRINTF("ssym @ %p\n", args + l);
	memcpy(args + l, &ssym, sizeof(ssym));
	l += sizeof(ssym); 
	DPRINTF("esym @ %p\n", args + l);
	memcpy(args + l, &esym, sizeof(esym));
	l += sizeof(esym);
	DPRINTF("magic @ %p\n", args + l);
	memcpy(args + l, &magic, sizeof(magic));
	l += sizeof(magic);
	DPRINTF("args + l -> %p\n", args + l);

	OF_chain((void *) RELOC, end - (char *)RELOC, entry, args, l);
	panic("chain");
}

/*
 * PAPR 10.60, B.6.2.3: a client program tells the platform what it
 * supports through the root node's "ibm,client-architecture-support"
 * method, and on a platform built on ISA 3.0 or later it has to choose
 * the page table model there (Table 515, notes 9 and 10).  The Boot
 * Loader Note in the same section puts the call in the boot loader.
 *
 * The kernel keeps a hashed page table through the hcall()s of 14.5.4.1,
 * and says so; the vectors it has no use for carry the Ignore bit, which
 * leaves them at the platform's configuration (note 1).
 */
static uint8_t ofw_cas_vec[] __aligned(8) = {
	/*
	 * PVR list, mask then value.  An entry whose value has bits
	 * outside its mask ends the list.
	 */
	0xff, 0xff, 0x00, 0x00,  0x00, 0x3c, 0x00, 0x00,	/* 970FX */
	0xff, 0xff, 0x00, 0x00,  0x00, 0x44, 0x00, 0x00,	/* 970MP */
	0xff, 0xff, 0x00, 0x00,  0x00, 0x4d, 0x00, 0x00,	/* POWER8 */
	0xff, 0xff, 0x00, 0x00,  0x00, 0x4e, 0x00, 0x00,	/* POWER9 */
	0xff, 0xff, 0x00, 0x00,  0x00, 0x80, 0xff, 0xff,	/* Power10 */

	4,			/* option vectors 1 to 5 */

	/*
	 * 1: architecture levels.  The PTE layouts of these were checked:
	 * 2.01 to 2.07 in byte 2, 3.00 and 3.10 in byte 3.  LoPAR 2.9
	 * names byte 3 bit 0 "2.08" and reserves bit 1; PAPR 10.60, which
	 * covers the ISA 3.1 processors that bit is for, defines it.
	 */
	2, 0x00, 0x7f, 0xc0,

	/* 2 to 4: Ignore */
	0, 0x80,
	0, 0x80,
	0, 0x80,

	/* 5: 24 bytes */
	23,
	0x00,			/*  1 */
	0x90,			/*  2 logical partitioning, large pages */
	0, 0, 0, 0, 0, 0,	/*  3-8 */
	0, 0, 0, 64,		/*  9-12 processors: 64, as when absent */
	0, 0,			/* 13-14 */
	0, 0,			/* 15-16 */
	0, 0, 0, 0,		/* 17-20 */
	0,			/* 21 */
	0,			/* 22 */
	0x00,			/* 23 interrupts, set below */
	0x00,			/* 24 hashed page table only */
};

static void
ofw_cas(int chosen)
{
	uint8_t sup[64];
	int root, len, i, cells[2];	/* the argument, then err? */

	/*
	 * Asking for a value the platform does not offer in bytes 23 or
	 * 24 ends the boot (note 8).  "ibm,arch-vec-5-platform-support"
	 * is a list of byte number, value pairs (B.6.3.1); 0b01 in bits
	 * 0-1 means only the other model.
	 */
	len = OF_getprop(chosen, "ibm,arch-vec-5-platform-support", sup,
	    sizeof(sup));
	if (len > (int)sizeof(sup))
		len = sizeof(sup);
	for (i = 0; i + 1 < len; i += 2) {
		if (sup[i] == 24 && (sup[i + 1] & 0xc0) == 0x40) {
			printf("platform offers only radix; not negotiating\n");
			return;
		}
		/*
		 * Byte 23 bits 0-1: 0b01 XIVE exploitation only, 0b10
		 * either.  Where XIVE is offered, ask for it; the kernel
		 * drives both, and finds which from the interrupt
		 * controller node the platform then presents.
		 */
		if (sup[i] == 23 && ((sup[i + 1] & 0xc0) == 0x40 ||
		    (sup[i + 1] & 0xc0) == 0x80))
			ofw_cas_vec[sizeof(ofw_cas_vec) - 2] = 0x40;
	}

	if ((root = OF_open("/")) == -1)
		return;
	cells[0] = (int)(uintptr_t)ofw_cas_vec;
	/* Firmware without the method is not PAPR; nothing to say. */
	if (OF_call_method("ibm,client-architecture-support", root, 1, 1,
	    cells) == 0 && cells[1] != 0)
		printf("ibm,client-architecture-support: error\n");
	OF_close(root);
}

__dead void
_rtt(void)
{

	OF_exit();
}

void
main(void)
{
	extern char bootprog_name[], bootprog_rev[];
	int chosen, cpu, cpunode, j, is64=0;
	char bootline[512];		/* Should check size? */
	char *cp;
	u_long marks[MARK_MAX];
	u_int32_t entry;
	void *ssym, *esym;

	printf("\n");
	printf(">> %s, Revision %s\n", bootprog_name, bootprog_rev);

#ifdef OFWDUMP
	chosen = OF_finddevice("/");
	dump_ofwtree(chosen);
#endif
	/*
	 * Get the boot arguments from Openfirmware
	 */
	if ((chosen = OF_finddevice("/chosen")) == -1 ||
	    OF_getprop(chosen, "bootpath", bootdev, sizeof bootdev) < 0 ||
	    OF_getprop(chosen, "bootargs", bootline, sizeof bootline) < 0) {
		printf("Invalid Openfirmware environment\n");
		OF_exit();
	}

	ofw_cas(chosen);

	/* lets see if we can guess the 64bittedness */
	if (OF_getprop(chosen, "cpu", &cpu, sizeof cpu) ==  sizeof(cpu)) {
		cpunode = OF_instance_to_package(cpu);
		if (OF_getprop(cpunode, "64-bit", &j, sizeof j) >= 0) {
			is64 = 1;
		}
	}

	prom2boot(bootdev);
	parseargs(bootline, &boothowto);
	DPRINTF("bootline=%s\n", bootline);

	for (;;) {
		int i;

		if (boothowto & RB_ASKNAME) {
			printf("Boot: ");
			kgets(bootline, sizeof(bootline));
			parseargs(bootline, &boothowto);
		}

		if (bootline[0]) {
			kernels[0] = bootline;
			kernels[1] = NULL;
		}
		if (!bootline[0] && is64) {
			for (i = 0; kernels64[i]; i++) {
				DPRINTF("Trying %s\n", kernels64[i]);

				marks[MARK_START] = 0;
				if (loadfile(kernels64[i], marks, LOAD_KERNEL) >= 0)
					goto loaded;
			}
		} else {
			for (i = 0; kernels[i]; i++) {
				DPRINTF("Trying %s\n", kernels[i]);

				marks[MARK_START] = 0;
				if (loadfile(kernels[i], marks, LOAD_KERNEL) >= 0)
					goto loaded;
			}
		}

		boothowto |= RB_ASKNAME;
	}
 loaded:

#ifdef	__notyet__
	OF_setprop(chosen, "bootpath", opened_name, strlen(opened_name) + 1);
	cp = bootline;
#else
	strcpy(bootline, opened_name);
	cp = bootline + strlen(bootline);
	*cp++ = ' ';
#endif
	*cp = '-';
	if (boothowto & RB_ASKNAME)
		*++cp = 'a';
	if (boothowto & RB_SINGLE)
		*++cp = 's';
	if (boothowto & RB_KDB)
		*++cp = 'd';
	if (*cp == '-')
#ifdef	__notyet__
		*cp = 0;
#else
		*--cp = 0;
#endif
	else
		*++cp = 0;
#ifdef	__notyet__
	OF_setprop(chosen, "bootargs", bootline, strlen(bootline) + 1);
#endif

	entry = marks[MARK_ENTRY];
	ssym = (void *)marks[MARK_SYM];
	esym = (void *)marks[MARK_END];

	printf(" start=0x%x\n", entry);
	__syncicache((void *)(uintptr_t)entry, (uintptr_t) ssym - entry);
	chain((boot_entry_t)(uintptr_t)entry, bootline, ssym, esym);

	OF_exit();
}
