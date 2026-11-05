/*	$NetBSD: Locore.c,v 1.23 2014/09/20 23:10:46 phx Exp $	*/

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

#include "openfirm.h"
#include <sys/param.h>
#include <lib/libsa/stand.h>

#include <machine/cpu.h>

/*
 * Open Firmware's client interface passes its arguments and results as
 * an array of cells, and SLOF fetches them a 32-bit word at a time --
 * client.fs reads nargs with l@ at the second word and walks the array
 * with la1+.  The cells stay 32 bits wide on a 64-bit firmware, so an
 * LP64 client cannot lay this array out with C pointers: the low half
 * of the first pointer is read as nargs, and the firmware then walks
 * off the end of the array.
 *
 * Everything in these structures is therefore one cell, and a pointer
 * goes in as OFW_CELL().  The client is loaded below 4GB, so an
 * address fits.
 */
typedef uint32_t	cell_t;

#define	OFW_CELL(p)	((cell_t)(uintptr_t)(p))
#define	OFW_PTR(c)	((void *)(uintptr_t)(c))

static int (*openfirmware_entry)(void *);
static int openfirmware(void *);
#ifdef _LP64
/*
 * What Open Firmware hands us is a code address, but an ELF V1 call
 * through a function pointer reads the pointed-to words as an entry
 * point and a TOC.  Give it a descriptor of our own that says so.  The
 * TOC word is ours, so that the call leaves r2 as the firmware found
 * it -- a zero there is not "no TOC", it is a null r2 handed to the
 * firmware.
 */
static unsigned long openfirmware_desc[3];
/*
 * What gets handed on to the kernel is the firmware's own code address,
 * not the descriptor above: the kernel branches to it with mtctr/bctrl
 * and would otherwise execute the descriptor's words.
 */
#endif

/*
 * The firmware's own code address, kept apart from the pointer this
 * loader calls through: the kernel branches to what OF_chain() hands it
 * with mtctr/bctrl, so it must be the code and not a descriptor.
 */
static int (*openfirmware_code)(void *);

void startup(void *, int, int (*)(void *), char *, int)
	__attribute__((__used__));
static void setup(void);

/* this pad gets the rodata laignment right, don't EVER fiddle it */
char *pad __attribute__((__aligned__ (8))) = "pad";
int stack[0x20000/4 + 4] __attribute__((__aligned__ (4), __used__));
char *heapspace __attribute__((__aligned__ (4)));
char altheap[0x20000] __attribute__((__aligned__ (4)));

static int
openfirmware(void *arg)
{
	int r;

	__asm volatile ("sync; isync");
	r = openfirmware_entry(arg);
	__asm volatile ("sync; isync");

	return r;
}

void
startup(void *vpd, int res, int (*openfirm)(void *), char *arg, int argl)
{

	openfirmware_code = openfirm;
#ifdef _LP64
    {
	register unsigned long toc __asm("r2");

	openfirmware_desc[0] = (unsigned long)openfirm;
	openfirmware_desc[1] = toc;
	openfirmware_entry = (int (*)(void *))openfirmware_desc;
    }
#else
	openfirmware_entry = openfirm;
#endif
	setup();
	main();
	OF_exit();
}

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

__dead void
OF_boot(char *bootspec)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	bootspec;
	} args = {
		0,
		1,
		0,
	};

	args.name = OFW_CELL("boot");

	args.bootspec = OFW_CELL(bootspec);
	openfirmware(&args);
	for (;;);			/* just in case */
}

int
OF_finddevice(char *name)
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
OF_getprop(int handle, char *prop, void *buf, int buflen)
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
OF_setprop(int handle, char *prop, void *buf, int len)
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
OF_open(char *dname)
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
OF_alloc_mem(u_int size)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	size;
		cell_t	baseaddr;
	} args = {
		0,
		1,
		1,
	};

	args.name = OFW_CELL("alloc-mem");
#ifdef OFW_DEBUG
	printf("alloc-mem %x -> ", size);
#endif
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

/*
 * The same interface, and the same cell order, as macppc's loader: the
 * nargs arguments are read from cells[] and the results written after
 * them, from cells[nargs] on, so cells[] needs room for both.
 * IEEE 1275-1994, 6.3.2.2 "call-method": the arguments follow the
 * method and the ihandle with stack-arg1 the one left on top, the
 * catch-result comes back ahead of the results, and nothing more is
 * returned when it is nonzero.  Six of each is the least a firmware
 * has to allow, hence the limit.
 */
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
	cell_t *ip;
	int n;

	args.name = OFW_CELL("call-method");

	if (nargs > 6)
		return -1;

	args.nargs = nargs + 2;
	args.nreturns = nreturns + 1;
	args.method = OFW_CELL(method);
	args.ihandle = ihandle;

	for (ip = args.args_n_results + (n = nargs); --n >= 0;)
		*--ip = *cells++;

	if (openfirmware(&args) == -1)
		return -1;

	if (args.args_n_results[nargs])
		return args.args_n_results[nargs];

	for (ip = args.args_n_results + nargs + (n = args.nreturns); --n > 0;)
		*cells++ = *--ip;

	return 0;
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

static int stdin;
static int stdout;

static void
setup(void)
{
	int chosen;

	if ((chosen = OF_finddevice("/chosen")) == -1)
		OF_exit();
	if (OF_getprop(chosen, "stdin", &stdin, sizeof(stdin)) !=
	    sizeof(stdin) ||
	    OF_getprop(chosen, "stdout", &stdout, sizeof(stdout)) !=
	    sizeof(stdout))
		OF_exit();

	//printf("Allocating 0x20000 bytes of ram for boot\n");
	heapspace = OF_claim(0, 0x20000, NBPG);
	if (heapspace == (char *)-1) {
		printf("WARNING: Failed to alloc ram, using bss\n");
		setheap(&altheap, &altheap[0x20000]);
	} else
		setheap(heapspace, heapspace+0x20000);
}

void
putchar(int c)
{
	char ch = c;

	if (c == '\n')
		putchar('\r');
	OF_write(stdout, &ch, 1);
}

int
getchar(void)
{
	unsigned char ch = '\0';
	int l;

	while ((l = OF_read(stdin, &ch, 1)) != 1)
		if (l != -2 && l != 0)
			return -1;
	return ch;
}

#ifdef OFWDUMP

static int
OF_peer(int phandle)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	phandle;
		cell_t	sibling;
	} args = {
		0,
			1,
			1,
	};

	args.name = OFW_CELL("peer");
	
	args.phandle = phandle;
	if (openfirmware(&args) == -1)
		return 0;
	return args.sibling;
}

static int
OF_child(int phandle)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	phandle;
		cell_t	child;
	} args = {
		0,
			1,
			1,
	};

	args.name = OFW_CELL("child");

	args.phandle = phandle;
	if (openfirmware(&args) == -1)
		return 0;
	return args.child;
}

int
OF_nextprop(int handle, const char *prop, void *nextprop)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	phandle;
		cell_t	prop;
		cell_t	buf;
		cell_t	flag;
	} args = {
		0,
			3,
			1,
	};

	args.name = OFW_CELL("nextprop");

	args.phandle = handle;
	args.prop = OFW_CELL(prop);
	args.buf = OFW_CELL(nextprop);
	if (openfirmware(&args) == -1)
		return -1;
	return args.flag;
}

static int
OF_package_to_path(int phandle, char *buf, int buflen)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	phandle;
		cell_t	buf;
		cell_t	buflen;
		cell_t	length;
	} args = {
		0,
			3,
			1,
	};

	args.name = OFW_CELL("package-to-path");

	if (buflen > 4096)
		return -1;
	args.phandle = phandle;
	args.buf = OFW_CELL(buf);
	args.buflen = buflen;
	if (openfirmware(&args) < 0)
		return -1;
	if (args.length > buflen)
		args.length = buflen;
	return args.length;
}

void
dump_ofwtree(int node)
{
	int peer, child, namelen, dlen, i;
	char namebuf[33], newnamebuf[33];
	char path[256], data[256];

	for (peer = node; peer; peer = OF_peer(peer)) {
		printf("\nnode: 0x%x ", peer);
		if (OF_package_to_path(peer, path, 512) >= 0)
			printf("path=%s", path);
		printf("\n");
		namebuf[0] = '\0';
		namelen = OF_nextprop(peer, namebuf, &newnamebuf);
		while (namelen >= 0) {
			/*printf("namelen == %d namebuf=%s new=%s\n", namelen,
			  namebuf, newnamebuf);*/
			//newnamebuf[namelen] = '\0';
			strcpy(namebuf, newnamebuf);
			printf("  %s :", newnamebuf);
			dlen = OF_getprop(peer, newnamebuf, data, 256);
			if (dlen > 0) {
				if (data[0] < 0177)
					printf(" %s\n", data);
				else
					printf("\n");
				printf("    ");
				for (i=0; i < dlen && i < 256; i++) {
					if (data[i] < 0x10)
						printf("0");
					printf("%x", data[i]);
					if ((i+1)%4 == 0)
						printf(" ");
					if ((i+1)%32 == 0)
						printf("\n    ");
				}
			}
			printf("\n");
			namelen = OF_nextprop(peer, namebuf, &newnamebuf);
			if (newnamebuf[0] == '\0' ||
			    strcmp(namebuf, newnamebuf) == 0)
				break;
		}
		child = OF_child(peer);
		if (child > 0)
			dump_ofwtree(child);
	}
}

#endif /* OFWDUMP */
