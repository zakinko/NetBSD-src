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
 * The client virtual terminal of a PAPR partition (PAPR 10.60, 17.5):
 * a "vty" node under /vdevice, driven by H_GET_TERM_CHAR and
 * H_PUT_TERM_CHAR.  Its interrupt is optional for a client vterm
 * (17.5.2.2), so input is polled.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/device.h>
#include <sys/kauth.h>
#include <sys/proc.h>
#include <sys/tty.h>

#include <dev/cons.h>
#include <dev/ofw/openfirm.h>

#include <machine/autoconf.h>

/* Table 175 */
#define	H_GET_TERM_CHAR		0x54
#define	H_PUT_TERM_CHAR		0x58

/* Table 180 */
#define	H_SUCCESS		0
#define	H_BUSY			1

/* 17.5.2.1: up to 16 bytes each way, in two registers */
#define	PVTY_CHUNK		16

/* Input poll interval; the choice is the OS's */
#define	PVTY_POLL		(hz / 50 ? hz / 50 : 1)

struct pvty_softc {
	device_t	sc_dev;
	struct tty	*sc_tty;
	register_t	sc_termno;
	struct callout	sc_poll;
	u_char		sc_in[PVTY_CHUNK];
	u_int		sc_inlen, sc_inpos;
};

static int pvty_match(device_t, cfdata_t, void *);
static void pvty_attach(device_t, device_t, void *);

CFATTACH_DECL_NEW(pvty, sizeof(struct pvty_softc),
    pvty_match, pvty_attach, NULL, NULL);

extern struct cfdriver pvty_cd;

static dev_type_open(pvty_open);
static dev_type_close(pvty_close);
static dev_type_read(pvty_read);
static dev_type_write(pvty_write);
static dev_type_ioctl(pvty_ioctl);
static dev_type_tty(pvty_tty);
static dev_type_poll(pvty_poll);

const struct cdevsw pvty_cdevsw = {
	.d_open = pvty_open,
	.d_close = pvty_close,
	.d_read = pvty_read,
	.d_write = pvty_write,
	.d_ioctl = pvty_ioctl,
	.d_stop = nullstop,
	.d_tty = pvty_tty,
	.d_poll = pvty_poll,
	.d_mmap = nommap,
	.d_kqfilter = ttykqfilter,
	.d_discard = nodiscard,
	.d_flag = D_TTY
};

static void pvty_start(struct tty *);
static int pvty_param(struct tty *, struct termios *);
static void pvty_pollin(void *);

/*
 * 14.5.3: the token in r3 and the parameters from r4, the status back in
 * r3 and the outputs from r4; r0, r3-r12, CTR, XER and CR fields 0, 1 and
 * 5-7 are not preserved.
 */
static long
pvty_hcall(register_t token, register_t a1, register_t a2, register_t a3,
    register_t a4, register_t out[3])
{
	register register_t r3 __asm("r3") = token;
	register register_t r4 __asm("r4") = a1;
	register register_t r5 __asm("r5") = a2;
	register register_t r6 __asm("r6") = a3;
	register register_t r7 __asm("r7") = a4;

	__asm volatile("sc 1"
	    : "+r"(r3), "+r"(r4), "+r"(r5), "+r"(r6), "+r"(r7)
	    :
	    : "r0", "r8", "r9", "r10", "r11", "r12",
	      "ctr", "xer", "cr0", "cr1", "cr5", "cr6", "cr7", "memory");
	if (out != NULL) {
		out[0] = r4; out[1] = r5; out[2] = r6;
	}
	return r3;
}

/*
 * 17.5.2.1.2: the string starts in the high order byte of R6 and goes on
 * into R7.  H_Busy means none of it was taken.
 */
static long
pvty_put(register_t termno, const u_char *buf, u_int len)
{
	uint64_t w[2] = { 0, 0 };
	u_int i;

	for (i = 0; i < len; i++)
		w[i / 8] |= (uint64_t)buf[i] << (56 - 8 * (i % 8));
	return pvty_hcall(H_PUT_TERM_CHAR, termno, len, w[0], w[1], NULL);
}

/* 17.5.2.1.1: R4 the count, the bytes from the high order byte of R5 on */
static u_int
pvty_get(register_t termno, u_char *buf)
{
	register_t out[3];
	u_int i, n;

	if (pvty_hcall(H_GET_TERM_CHAR, termno, 0, 0, 0, out) != H_SUCCESS)
		return 0;
	n = out[0] > PVTY_CHUNK ? PVTY_CHUNK : out[0];
	for (i = 0; i < n; i++)
		buf[i] = (uint64_t)out[1 + i / 8] >> (56 - 8 * (i % 8));
	return n;
}

/* The unit address is the "reg" of the vty node (Table 398) */
static int
pvty_termno(int node, register_t *termnop)
{
	uint32_t reg;

	if (OF_getprop(node, "reg", &reg, sizeof(reg)) != sizeof(reg))
		return -1;
	*termnop = reg;
	return 0;
}

static int
pvty_find(int vdevice)
{
	static const char * const compat[] = { "hvterm1", NULL };
	int node;

	for (node = OF_child(vdevice); node != 0; node = OF_peer(node))
		if (of_compatible(node, compat) > 0)
			return node;
	return 0;
}

static int
pvty_match(device_t parent, cfdata_t cf, void *aux)
{
	struct confargs *ca = aux;

	if (strcmp(ca->ca_name, "vdevice") != 0)
		return 0;
	return pvty_find(ca->ca_node) != 0;
}

static void
pvty_attach(device_t parent, device_t self, void *aux)
{
	struct pvty_softc *sc = device_private(self);
	struct confargs *ca = aux;
	int node;

	sc->sc_dev = self;
	node = pvty_find(ca->ca_node);
	if (pvty_termno(node, &sc->sc_termno) != 0) {
		aprint_error(": no reg\n");
		return;
	}
	callout_init(&sc->sc_poll, 0);
	callout_setfunc(&sc->sc_poll, pvty_pollin, sc);

	sc->sc_tty = tty_alloc();
	sc->sc_tty->t_oproc = pvty_start;
	sc->sc_tty->t_param = pvty_param;
	sc->sc_tty->t_dev = makedev(cdevsw_lookup_major(&pvty_cdevsw),
	    device_unit(self));
	tty_attach(sc->sc_tty);

	aprint_normal(": unit address %#lx\n", (u_long)sc->sc_termno);
	if (cn_tab != NULL && cn_tab->cn_dev == sc->sc_tty->t_dev)
		aprint_normal_dev(self, "console\n");
}

static void
pvty_pollin(void *arg)
{
	struct pvty_softc *sc = arg;
	struct tty *tp = sc->sc_tty;
	u_char buf[PVTY_CHUNK];
	u_int i, n;

	while ((n = pvty_get(sc->sc_termno, buf)) != 0)
		for (i = 0; i < n; i++)
			(*tp->t_linesw->l_rint)(buf[i], tp);
	if (tp->t_state & TS_ISOPEN)
		callout_schedule(&sc->sc_poll, PVTY_POLL);
}

static void
pvty_start(struct tty *tp)
{
	struct pvty_softc *sc = device_lookup_private(&pvty_cd,
	    minor(tp->t_dev));
	u_char buf[PVTY_CHUNK];
	int s, n;

	s = spltty();
	if (tp->t_state & (TS_TIMEOUT | TS_BUSY | TS_TTSTOP)) {
		splx(s);
		return;
	}
	tp->t_state |= TS_BUSY;
	while (tp->t_outq.c_cc != 0) {
		n = q_to_b(&tp->t_outq, buf, sizeof(buf));
		while (pvty_put(sc->sc_termno, buf, n) == H_BUSY)
			continue;
	}
	tp->t_state &= ~TS_BUSY;
	ttypull(tp);
	splx(s);
}

static int
pvty_param(struct tty *tp, struct termios *t)
{

	tp->t_ispeed = t->c_ispeed;
	tp->t_ospeed = t->c_ospeed;
	tp->t_cflag = t->c_cflag;
	return 0;
}

static int
pvty_open(dev_t dev, int flag, int mode, struct lwp *l)
{
	struct pvty_softc *sc = device_lookup_private(&pvty_cd, minor(dev));
	struct tty *tp;

	if (sc == NULL)
		return ENXIO;
	tp = sc->sc_tty;
	if (kauth_authorize_device_tty(l->l_cred, KAUTH_DEVICE_TTY_OPEN, tp))
		return EBUSY;
	if ((tp->t_state & TS_ISOPEN) == 0) {
		ttychars(tp);
		tp->t_iflag = TTYDEF_IFLAG;
		tp->t_oflag = TTYDEF_OFLAG;
		tp->t_cflag = TTYDEF_CFLAG;
		tp->t_lflag = TTYDEF_LFLAG;
		tp->t_ispeed = tp->t_ospeed = TTYDEF_SPEED;
		ttsetwater(tp);
		tp->t_state |= TS_CARR_ON;
		callout_schedule(&sc->sc_poll, PVTY_POLL);
	}
	return (*tp->t_linesw->l_open)(dev, tp);
}

static int
pvty_close(dev_t dev, int flag, int mode, struct lwp *l)
{
	struct pvty_softc *sc = device_lookup_private(&pvty_cd, minor(dev));
	struct tty *tp = sc->sc_tty;

	(*tp->t_linesw->l_close)(tp, flag);
	ttyclose(tp);
	return 0;
}

static int
pvty_read(dev_t dev, struct uio *uio, int flag)
{
	struct tty *tp = pvty_tty(dev);

	return (*tp->t_linesw->l_read)(tp, uio, flag);
}

static int
pvty_write(dev_t dev, struct uio *uio, int flag)
{
	struct tty *tp = pvty_tty(dev);

	return (*tp->t_linesw->l_write)(tp, uio, flag);
}

static int
pvty_poll(dev_t dev, int events, struct lwp *l)
{
	struct tty *tp = pvty_tty(dev);

	return (*tp->t_linesw->l_poll)(tp, events, l);
}

static int
pvty_ioctl(dev_t dev, u_long cmd, void *data, int flag, struct lwp *l)
{
	struct tty *tp = pvty_tty(dev);
	int error;

	error = (*tp->t_linesw->l_ioctl)(tp, cmd, data, flag, l);
	if (error != EPASSTHROUGH)
		return error;
	return ttioctl(tp, cmd, data, flag, l);
}

static struct tty *
pvty_tty(dev_t dev)
{
	struct pvty_softc *sc = device_lookup_private(&pvty_cd, minor(dev));

	return sc->sc_tty;
}

/*
 * Console.  The console vty is the console node itself; unit 0 is
 * assumed to be the one pvty_attach() gives it, there being one.
 */
static register_t pvty_cntermno;
static u_char pvty_cnbuf[PVTY_CHUNK];
static u_int pvty_cnlen, pvty_cnpos;

static void
pvty_cnprobe(struct consdev *cd)
{
	extern int console_node;

	if (pvty_termno(console_node, &pvty_cntermno) != 0)
		return;
	cd->cn_dev = makedev(cdevsw_lookup_major(&pvty_cdevsw), 0);
	cd->cn_pri = CN_REMOTE;
}

static void
pvty_cninit(struct consdev *cd)
{
}

static int
pvty_cngetc(dev_t dev)
{

	while (pvty_cnpos == pvty_cnlen) {
		pvty_cnlen = pvty_get(pvty_cntermno, pvty_cnbuf);
		pvty_cnpos = 0;
	}
	return pvty_cnbuf[pvty_cnpos++];
}

static void
pvty_cnputc(dev_t dev, int c)
{
	u_char ch = c;

	while (pvty_put(pvty_cntermno, &ch, 1) == H_BUSY)
		continue;
}

static void
pvty_cnpollc(dev_t dev, int on)
{
}

struct consdev pvty_cons = {
	pvty_cnprobe, pvty_cninit, pvty_cngetc, pvty_cnputc, pvty_cnpollc,
	NULL, NULL, NULL, NODEV, CN_DEAD
};
