/*	$NetBSD: openfirm.c,v 1.33 2021/02/13 01:48:33 thorpej Exp $	*/

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

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: openfirm.c,v 1.33 2021/02/13 01:48:33 thorpej Exp $");

#ifdef _KERNEL_OPT
#include "opt_multiprocessor.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>

#include <uvm/uvm_extern.h>

#include <machine/psl.h>
#include <machine/autoconf.h>

#include <dev/ofw/openfirm.h>

char *OF_buf;

static void ofbcopy(const void *, void *, size_t);

#ifdef MULTIPROCESSOR
void OF_start_cpu(int, u_int, int);


static __cpu_simple_lock_t ofw_mutex = __SIMPLELOCK_UNLOCKED;
#endif /* MULTIPROCESSOR */

static inline register_t
ofw_lock(void)
{
	const register_t s = mfmsr();

	mtmsr(s & ~(PSL_EE|PSL_RI));	/* disable interrupts */

#ifdef MULTIPROCESSOR
	__cpu_simple_lock(&ofw_mutex);
#endif /* MULTIPROCESSOR */

	return s;
}

static inline void
ofw_unlock(register_t s)
{
#ifdef MULTIPROCESSOR
	__cpu_simple_unlock(&ofw_mutex);
#endif /* MULTIPROCESSOR */
	mtmsr(s);
}
/*
 * The client interface passes its arguments and results as an array of
 * cells, and the cells are 32 bits wide even where the firmware itself is
 * 64-bit: SLOF's client.fs reads nargs with l@ and walks the array with
 * la1+.  Laying these structures out with C pointers works only while a
 * pointer is one cell, so on an LP64 kernel the low half of the first
 * pointer is read as nargs and the firmware walks off the end.
 *
 * Every slot is therefore one cell, and a pointer goes in as OFW_CELL().
 * That truncates, so every address handed to the firmware this way has to
 * be below 4GB -- which is where the kernel is loaded, and where the
 * firmware's own memory lives.  A caller passing something from above
 * that line would need to bounce it through OF_buf, as the property and
 * path calls already do.
 */
typedef uint32_t	cell_t;

#define	OFW_CELL(p)	((cell_t)(uintptr_t)(p))
#define	OFW_PTR(c)	((void *)(uintptr_t)(c))
/*
 * A count the firmware returns is signed, -1 for failure (IEEE 1275-1994,
 * 6.3.2.2 getprop, 6.3.2.3 read), and it is no longer an int once cell_t
 * is unsigned: compared with one it is converted to unsigned, so -1 passed
 * "size > 0" and a failed read copied 0xffffffff bytes.
 */
#define	OFW_INT(c)	((int)(int32_t)(c))


int
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

	const register_t s = ofw_lock();
	int rv;

	args.name = OFW_CELL("peer");
	args.phandle = phandle;
	if (openfirmware(&args) == -1)
		rv = 0;
	else
		rv = args.sibling;

	ofw_unlock(s);
	return rv;
}

int
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

	const register_t s = ofw_lock();
	int rv;

	args.name = OFW_CELL("child");
	args.phandle = phandle;
	if (openfirmware(&args) == -1)
		rv = 0;
	else
		rv = args.child;

	ofw_unlock(s);
	return rv;
}

int
OF_parent(int phandle)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	phandle;
		cell_t	parent;
	} args = {
		0,
		1,
		1,
	};

	const register_t s = ofw_lock();
	int rv;

	args.name = OFW_CELL("parent");
	args.phandle = phandle;
	if (openfirmware(&args) == -1)
		rv = 0;
	else
		rv = args.parent;

	ofw_unlock(s);
	return rv;
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

	const register_t s = ofw_lock();
	int rv;

	args.name = OFW_CELL("instance-to-package");
	args.ihandle = ihandle;
	if (openfirmware(&args) == -1)
		rv = -1;
	else
		rv = args.phandle;

	ofw_unlock(s);
	return rv;
}

int
OF_getproplen(int handle, const char *prop)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	phandle;
		cell_t	prop;
		cell_t	proplen;
	} args = {
		0,
		2,
		1,
	};

	const register_t s = ofw_lock();
	int rv;

	args.name = OFW_CELL("getproplen");
	strncpy(OF_buf, prop, 32);
	args.phandle = handle;
	args.prop = OFW_CELL(OF_buf);
	if (openfirmware(&args) == -1)
		rv = -1;
	else
		rv = args.proplen;

	ofw_unlock(s);
	return rv;
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

	if (buflen > PAGE_SIZE)
		return -1;

	const register_t s = ofw_lock();
	int rv;

	args.name = OFW_CELL("getprop");
	strncpy(OF_buf, prop, 32);
	args.phandle = handle;
	args.prop = OFW_CELL(OF_buf);
	args.buf = OFW_CELL(&OF_buf[33]);
	args.buflen = buflen;
	if (openfirmware(&args) == -1)
		rv = -1;
	else {
		rv = OFW_INT(args.size);
		if (rv > buflen)
			rv = buflen;
		if (rv > 0)
			ofbcopy(&OF_buf[33], buf, rv);
	}

	ofw_unlock(s);
	return rv;
}

int
OF_setprop(int handle, const char *prop, const void *buf, int buflen)
{
	struct {
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
		1
	};

	if (buflen > PAGE_SIZE)
		return -1;

	const register_t s = ofw_lock();
	int rv;

	args.name = OFW_CELL("setprop");
	ofbcopy(buf, OF_buf, buflen);
	args.phandle = handle;
	args.prop = OFW_CELL(prop);
	args.buf = OFW_CELL(OF_buf);
	args.buflen = buflen;
	if (openfirmware(&args) == -1)
		rv = -1;
	else
		rv = args.size;

	ofw_unlock(s);
	return rv;
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

	const register_t s = ofw_lock();
	int rv;

	args.name = OFW_CELL("nextprop");
	strncpy(OF_buf, prop, 32);
	args.phandle = handle;
	args.prop = OFW_CELL(OF_buf);
	args.buf = OFW_CELL(&OF_buf[33]);
	if (openfirmware(&args) == -1)
		rv = -1;
	else {
		strncpy(nextprop, &OF_buf[33], 32);
		rv = args.flag;
	}

	ofw_unlock(s);
	return rv;
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

	const register_t s = ofw_lock();
	int rv;

	args.name = OFW_CELL("finddevice");
	strncpy(OF_buf, name, NBPG);
	args.device = OFW_CELL(OF_buf);
	if (openfirmware(&args) == -1)
		rv = -1;
	else
		rv = args.phandle;

	ofw_unlock(s);
	return rv;
}

int
OF_instance_to_path(int ihandle, char *buf, int buflen)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	ihandle;
		cell_t	buf;
		cell_t	buflen;
		cell_t	length;
	} args = {
		0,
		3,
		1,
	};

	if (buflen > PAGE_SIZE)
		return -1;

	const register_t s = ofw_lock();
	int rv;

	args.name = OFW_CELL("instance-to-path");
	args.ihandle = ihandle;
	args.buf = OFW_CELL(OF_buf);
	args.buflen = buflen;
	if (openfirmware(&args) < 0)
		rv = -1;
	else {
		rv = OFW_INT(args.length);
		if (rv > buflen)
			rv = buflen;
		if (rv > 0)
			ofbcopy(OF_buf, buf, rv);
	}

	ofw_unlock(s);
	return rv;
}

int
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

	if (buflen > PAGE_SIZE)
		return -1;

	const register_t s = ofw_lock();
	int rv;

	args.name = OFW_CELL("package-to-path");
	args.phandle = phandle;
	args.buf = OFW_CELL(OF_buf);
	args.buflen = buflen;
	if (openfirmware(&args) < 0)
		rv = -1;
	else {
		rv = OFW_INT(args.length);
		if (rv > buflen)
			rv = buflen;
		if (rv > 0)
			ofbcopy(OF_buf, buf, rv);
	}

	ofw_unlock(s);
	return rv;
}

int
OF_call_method(const char *method, int ihandle, int nargs, int nreturns, ...)
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

	if (nargs > 6)
		return -1;

	va_list ap;
	int *ip, n;
	int rv;

	const register_t s = ofw_lock();

	args.name = OFW_CELL("call-method");
	args.nargs = nargs + 2;
	args.nreturns = nreturns + 1;
	args.method = OFW_CELL(method);
	args.ihandle = ihandle;

	va_start(ap, nreturns);

	for (ip = args.args_n_results + (n = nargs); --n >= 0;) {
		*--ip = va_arg(ap, int);
	}

	if (openfirmware(&args) == -1) {
		rv = -1;
	} else if (args.args_n_results[nargs]) {
		rv = args.args_n_results[nargs];
	} else {
		for (ip = args.args_n_results + nargs + (n = args.nreturns);
		     --n > 0;) {
			*va_arg(ap, int *) = *--ip;
		}
		rv = 0;
	}

	va_end(ap);

	ofw_unlock(s);
	return rv;
}

int
OF_call_method_1(const char *method, int ihandle, int nargs, ...)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	method;
		cell_t	ihandle;
		cell_t	args_n_results[8];
	} args = {
		0,
		2,
		2,
	};

	if (nargs > 6)
		return -1;

	va_list ap;
	int *ip, n;
	int rv;

	const register_t s = ofw_lock();

	args.name = OFW_CELL("call-method");
	args.nargs = nargs + 2;
	args.method = OFW_CELL(method);
	args.ihandle = ihandle;

	va_start(ap, nargs);
	for (ip = args.args_n_results + (n = nargs); --n >= 0;) {
		*--ip = va_arg(ap, int);
	}
	va_end(ap);

	if (openfirmware(&args) == -1)
		rv = -1;
	else if (args.args_n_results[nargs])
		rv = -1;
	else
		rv = args.args_n_results[nargs + 1];

	ofw_unlock(s);
	return rv;
}

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

	int l;

	if ((l = strlen(dname)) >= PAGE_SIZE)
		return -1;

	const register_t s = ofw_lock();
	int rv;

	args.name = OFW_CELL("open");
	ofbcopy(dname, OF_buf, l + 1);
	args.dname = OFW_CELL(OF_buf);
	if (openfirmware(&args) == -1)
		rv = -1;
	else
		rv = args.handle;

	ofw_unlock(s);
	return rv;
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

	const register_t s = ofw_lock();

	args.name = OFW_CELL("close");
	args.handle = handle;
	openfirmware(&args);

	ofw_unlock(s);
}

/*
 * This assumes that character devices don't read in multiples of PAGE_SIZE.
 */
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

	int l, act = 0;
	char *p = addr;

	const register_t s = ofw_lock();

	args.name = OFW_CELL("read");
	args.ihandle = handle;
	args.addr = OFW_CELL(OF_buf);
	for (; len > 0; len -= l, p += l) {
		l = uimin(PAGE_SIZE, len);
		args.len = l;
		if (openfirmware(&args) == -1) {
			act = -1;
			goto out;
		}
		if (OFW_INT(args.actual) > 0) {
			ofbcopy(OF_buf, p, OFW_INT(args.actual));
			act += OFW_INT(args.actual);
		}
		if (OFW_INT(args.actual) < l) {
			if (act == 0) {
				act = OFW_INT(args.actual);
			}
			goto out;
		}
	}

 out:
	ofw_unlock(s);
	return act;
}

int
OF_write(int handle, const void *addr, int len)
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

	int l, act = 0;
	const char *p = addr;

	const register_t s = ofw_lock();

	args.name = OFW_CELL("write");
	args.ihandle = handle;
	args.addr = OFW_CELL(OF_buf);
	for (; len > 0; len -= l, p += l) {
		l = uimin(PAGE_SIZE, len);
		ofbcopy(p, OF_buf, l);
		args.len = l;
		args.actual = l;	/* work around a PIBS bug */
		if (openfirmware(&args) == -1) {
			act = -1;
			goto out;
		}
		l = OFW_INT(args.actual);
		act += l;
	}

 out:
	ofw_unlock(s);
	return act;
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

	const register_t s = ofw_lock();
	int rv;

	args.name = OFW_CELL("seek");
	args.handle = handle;
	args.poshi = (int)(pos >> 32);
	args.poslo = (int)pos;
	if (openfirmware(&args) == -1)
		rv = -1;
	else
		rv = args.status;

	ofw_unlock(s);
	return rv;
}

#ifdef MULTIPROCESSOR
void
OF_start_cpu(int phandle, u_int pc, int arg)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	phandle;
		cell_t	pc;
		cell_t	arg;
	} args = {
		0,
		3,
		0,
	};

	const register_t s = ofw_lock();
	bool failed = false;

	args.name = OFW_CELL("start-cpu");
	args.phandle = phandle;
	args.pc = pc;
	args.arg = arg;
	if (openfirmware(&args) == -1)
		failed = true;

	ofw_unlock(s);
	if (failed) {
		panic("WTF?");
	}
}
#endif

void
OF_boot(const char *bstr)
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

	int l;

	if ((l = strlen(bstr)) >= PAGE_SIZE)
		panic("OF_boot");

	const register_t s = ofw_lock();

	args.name = OFW_CELL("boot");
	ofbcopy(bstr, OF_buf, l + 1);
	args.bootspec = OFW_CELL(OF_buf);
	openfirmware(&args);

	ofw_unlock(s);
	panic("OF_boot didn't");
}

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
		0,
	};

	const register_t s = ofw_lock();

	args.name = OFW_CELL("enter");
	openfirmware(&args);

	ofw_unlock(s);
}

void
OF_exit(void)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
	} args = {
		0,
		0,
		0,
	};

	const register_t s = ofw_lock();

	args.name = OFW_CELL("exit");
	openfirmware(&args);

	ofw_unlock(s);
	while (1);			/* just in case */
}

void
(*OF_set_callback (void (*newfunc)(void *))) (void *)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	newfunc;
		cell_t	oldfunc;
	} args = {
		0,
		1,
		1,
	};

	const register_t s = ofw_lock();
	void (*rv)(void *);

	args.name = OFW_CELL("set-callback");
	args.newfunc = OFW_CELL(newfunc);
	if (openfirmware(&args) == -1)
		rv = NULL;
	else
		rv = (void (*)(void *))(uintptr_t)args.oldfunc;

	ofw_unlock(s);
	return rv;
}

int
OF_interpret(const char *cmd, int nargs, int nreturns, ...)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
		cell_t	slots[16];
	} args = {
		0,
		1,
		2,
	};

	va_list ap;
	int i, len;
	int rv;

	if (nreturns > 8)
		return -1;
	if ((len = strlen(cmd)) >= PAGE_SIZE)
		return -1;

	const register_t s = ofw_lock();

	args.name = OFW_CELL("interpret");
	ofbcopy(cmd, OF_buf, len + 1);
	i = 0;
	args.slots[i] = (uintptr_t)OF_buf;
	args.nargs = nargs + 1;
	args.nreturns = nreturns + 1;
	va_start(ap, nreturns);
	i++;
	while (i < args.nargs) {
		args.slots[i] = (uintptr_t)va_arg(ap, uint32_t *);
		i++;
	}

	if (openfirmware(&args) == -1)
		rv = -1;
	else {
		rv = args.slots[i];
		i++;

		while (i < args.nargs + args.nreturns) {
			*va_arg(ap, uint32_t *) = args.slots[i];
			i++;
		}
	}
	va_end(ap);

	ofw_unlock(s);
	return rv;
}

void
OF_quiesce(void)
{
	static struct {
		cell_t	name;
		cell_t	nargs;
		cell_t	nreturns;
	} args = {
		0,
		0,
		0,
	};

	const register_t s = ofw_lock();

	args.name = OFW_CELL("quiesce");
	openfirmware(&args);

	ofw_unlock(s);
}

/*
 * This version of bcopy doesn't work for overlapping regions!
 */
static void
ofbcopy(const void *src, void *dst, size_t len)
{
	const char *sp = src;
	char *dp = dst;

	if (src == dst)
		return;

	while (len-- > 0)
		*dp++ = *sp++;
}
