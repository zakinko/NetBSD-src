/* $NetBSD$ */

/*-
 * Copyright (c) 2026 Showta Ishizaki <zakinko@snowrabbit.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Apple NCO: the numerically controlled oscillators that clock the audio
 * serial ports (MCA).
 *
 * Apple publishes nothing on this block.  What is here is the model the
 * Asahi Linux project worked out and describes as postulated, in
 * drivers/clk/clk-apple-nco.c (GPL-2.0-only OR MIT), and the device tree
 * binding apple,nco.yaml.  It has not been checked against hardware from
 * NetBSD.
 *
 * Each channel divides the reference clock by a base divisor of about
 * twice the wanted ratio, lengthened by one input cycle whenever the top
 * bit of a 32-bit phase accumulator is set; the accumulator steps by INC1
 * or INC2 per output cycle, again chosen by its top bit.  The divisor is
 * written in quarters: the fine two bits directly, the coarse part as a
 * state of an 11-bit Galois LFSR, since that is how the hardware counts.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/device.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/systm.h>

#include <dev/clk/clk_backend.h>

#include <dev/fdt/fdtvar.h>

#define	NCO_CHANNEL_STRIDE	0x4000
#define	NCO_CHANNEL_REGSIZE	0x14

#define	NCO_CTRL		0x00
#define	 NCO_CTRL_ENABLE	__BIT(31)
#define	NCO_DIV			0x04
#define	 NCO_DIV_COARSE		__BITS(12,2)
#define	 NCO_DIV_FINE		__BITS(1,0)
#define	NCO_INC1		0x08
#define	NCO_INC2		0x0c
#define	NCO_ACCINIT		0x10
#define	 NCO_ACCINIT_NEUTRAL	__BIT(31)

#define	LFSR_POLY		0xa01
#define	LFSR_INIT		0x7ff
#define	LFSR_LEN		11
#define	LFSR_PERIOD		((1 << LFSR_LEN) - 1)
#define	LFSR_STATES		(1 << LFSR_LEN)

/*
 * Divisor in quarters: coarse part (div / 4) from COARSE_MIN up to, not
 * including, COARSE_MIN + LFSR_STATES; the fine part is div % 4.
 */
#define	COARSE_MIN		2
#define	DIV_MIN			(4 * COARSE_MIN)
#define	DIV_END			(4 * (COARSE_MIN + LFSR_STATES))

struct apple_nco_tables {
	uint16_t	fwd[LFSR_STATES];	/* coarse - COARSE_MIN -> state */
	uint16_t	inv[LFSR_STATES];	/* state -> coarse - COARSE_MIN */
};

struct apple_nco_clk {
	struct clk	base;
	bus_size_t	off;
};

struct apple_nco_softc {
	device_t		sc_dev;
	bus_space_tag_t		sc_bst;
	bus_space_handle_t	sc_bsh;
	int			sc_phandle;
	kmutex_t		sc_lock;

	struct clk_domain	sc_clkdom;
	struct apple_nco_tables	*sc_tbl;
	u_int			sc_nclks;
	struct apple_nco_clk	*sc_clks;
};

#define	NCO_READ(sc, c, reg) \
	bus_space_read_4((sc)->sc_bst, (sc)->sc_bsh, (c)->off + (reg))
#define	NCO_WRITE(sc, c, reg, val) \
	bus_space_write_4((sc)->sc_bst, (sc)->sc_bsh, (c)->off + (reg), (val))

static const struct device_compatible_entry compat_data[] = {
	{ .compat = "apple,nco" },
	DEVICE_COMPAT_EOL
};

static void
apple_nco_tables(struct apple_nco_tables *tbl)
{
	uint32_t state = LFSR_INIT;
	int i;

	/* Walk the LFSR backwards so that fwd[i] is i steps from the end. */
	for (i = LFSR_PERIOD; i > 0; i--) {
		if (state & 1)
			state = (state >> 1) ^ (LFSR_POLY >> 1);
		else
			state >>= 1;
		tbl->fwd[i] = state;
		tbl->inv[state] = i;
	}
	/* State 0 is not on the cycle; it stands for the smallest divisor. */
	tbl->fwd[0] = 0;
	tbl->inv[0] = 0;
}

static u_int
apple_nco_parent_rate(struct apple_nco_softc *sc)
{
	struct clk *parent;

	parent = fdtbus_clock_get_index(sc->sc_phandle, 0);
	return parent != NULL ? clk_get_rate(parent) : 0;
}

static struct clk *
apple_nco_decode(device_t dev, int cc_phandle, const void *data, size_t len)
{
	struct apple_nco_softc * const sc = device_private(dev);
	u_int idx;

	if (len != 4)
		return NULL;
	idx = be32dec(data);
	if (idx >= sc->sc_nclks)
		return NULL;
	return &sc->sc_clks[idx].base;
}

static const struct fdtbus_clock_controller_func apple_nco_fdt_funcs = {
	.decode = apple_nco_decode
};

static struct clk *
apple_nco_get(void *priv, const char *name)
{
	struct apple_nco_softc * const sc = priv;
	u_int i;

	for (i = 0; i < sc->sc_nclks; i++) {
		if (strcmp(sc->sc_clks[i].base.name, name) == 0)
			return &sc->sc_clks[i].base;
	}
	return NULL;
}

static void
apple_nco_put(void *priv, struct clk *clk)
{
}

static u_int
apple_nco_get_rate(void *priv, struct clk *clk)
{
	struct apple_nco_softc * const sc = priv;
	struct apple_nco_clk * const c = (struct apple_nco_clk *)clk;
	uint32_t reg, inc1, inc2, span;
	uint64_t div;

	mutex_enter(&sc->sc_lock);
	reg = NCO_READ(sc, c, NCO_DIV);
	inc1 = NCO_READ(sc, c, NCO_INC1);
	inc2 = NCO_READ(sc, c, NCO_INC2);
	mutex_exit(&sc->sc_lock);

	/* Only the form apple_nco_set_rate() writes: 0 <= inc1 < 2^31 <= inc2. */
	if (inc1 >= NCO_ACCINIT_NEUTRAL || inc2 < NCO_ACCINIT_NEUTRAL)
		return 0;

	div = 4 * (sc->sc_tbl->inv[__SHIFTOUT(reg, NCO_DIV_COARSE)] +
	    COARSE_MIN) + __SHIFTOUT(reg, NCO_DIV_FINE);

	/*
	 * inc1 = 2 * parent - div * rate and inc2 = inc1 - rate, so
	 * rate = inc1 - inc2 and 2 * parent = div * span + inc1.  Solve
	 * with span as the scale to keep precision.
	 */
	span = inc1 - inc2;
	if (span == 0)
		return 0;
	return (u_int)((uint64_t)apple_nco_parent_rate(sc) * 2 * span /
	    (div * span + inc1));
}

/* Rates whose divisor is in range: div = 2 * parent / rate, DIV_MIN..DIV_END. */
static u_int
apple_nco_round_rate(void *priv, struct clk *clk, u_int rate)
{
	struct apple_nco_softc * const sc = priv;
	const uint64_t parent2 = 2 * (uint64_t)apple_nco_parent_rate(sc);
	const u_int lo = (u_int)(parent2 / DIV_END) + 1;
	const u_int hi = (u_int)(parent2 / DIV_MIN);

	if (parent2 == 0)
		return 0;
	return MAX(lo, MIN(hi, rate));
}

static int
apple_nco_set_rate(void *priv, struct clk *clk, u_int rate)
{
	struct apple_nco_softc * const sc = priv;
	struct apple_nco_clk * const c = (struct apple_nco_clk *)clk;
	const uint64_t parent2 = 2 * (uint64_t)apple_nco_parent_rate(sc);
	uint64_t div;
	uint32_t ctrl, inc1, inc2, reg;

	if (rate == 0 || parent2 == 0)
		return EINVAL;
	div = parent2 / rate;
	if (div < DIV_MIN || div >= DIV_END)
		return EINVAL;
	inc1 = (uint32_t)(parent2 - div * rate);	/* < rate */
	inc2 = inc1 - rate;				/* wraps: >= 2^31 */

	reg = __SHIFTIN(sc->sc_tbl->fwd[div / 4 - COARSE_MIN], NCO_DIV_COARSE) |
	    __SHIFTIN(div % 4, NCO_DIV_FINE);

	/* Stopped while the three values change together. */
	mutex_enter(&sc->sc_lock);
	ctrl = NCO_READ(sc, c, NCO_CTRL);
	NCO_WRITE(sc, c, NCO_CTRL, ctrl & ~NCO_CTRL_ENABLE);
	NCO_WRITE(sc, c, NCO_DIV, reg);
	NCO_WRITE(sc, c, NCO_INC1, inc1);
	NCO_WRITE(sc, c, NCO_INC2, inc2);
	NCO_WRITE(sc, c, NCO_ACCINIT, NCO_ACCINIT_NEUTRAL);
	NCO_WRITE(sc, c, NCO_CTRL, ctrl);
	mutex_exit(&sc->sc_lock);

	return 0;
}

static int
apple_nco_enable(void *priv, struct clk *clk)
{
	struct apple_nco_softc * const sc = priv;
	struct apple_nco_clk * const c = (struct apple_nco_clk *)clk;

	mutex_enter(&sc->sc_lock);
	NCO_WRITE(sc, c, NCO_CTRL, NCO_READ(sc, c, NCO_CTRL) | NCO_CTRL_ENABLE);
	mutex_exit(&sc->sc_lock);
	return 0;
}

static int
apple_nco_disable(void *priv, struct clk *clk)
{
	struct apple_nco_softc * const sc = priv;
	struct apple_nco_clk * const c = (struct apple_nco_clk *)clk;

	mutex_enter(&sc->sc_lock);
	NCO_WRITE(sc, c, NCO_CTRL, NCO_READ(sc, c, NCO_CTRL) & ~NCO_CTRL_ENABLE);
	mutex_exit(&sc->sc_lock);
	return 0;
}

static struct clk *
apple_nco_get_parent(void *priv, struct clk *clk)
{
	struct apple_nco_softc * const sc = priv;

	return fdtbus_clock_get_index(sc->sc_phandle, 0);
}

static const struct clk_funcs apple_nco_clk_funcs = {
	.get = apple_nco_get,
	.put = apple_nco_put,
	.get_rate = apple_nco_get_rate,
	.set_rate = apple_nco_set_rate,
	.round_rate = apple_nco_round_rate,
	.enable = apple_nco_enable,
	.disable = apple_nco_disable,
	.get_parent = apple_nco_get_parent,
};

static int
apple_nco_match(device_t parent, cfdata_t cf, void *aux)
{
	struct fdt_attach_args * const faa = aux;

	return of_compatible_match(faa->faa_phandle, compat_data);
}

static void
apple_nco_attach(device_t parent, device_t self, void *aux)
{
	struct apple_nco_softc * const sc = device_private(self);
	struct fdt_attach_args * const faa = aux;
	const int phandle = faa->faa_phandle;
	bus_addr_t addr;
	bus_size_t size;
	u_int i;

	if (fdtbus_get_reg(phandle, 0, &addr, &size) != 0) {
		aprint_error(": couldn't get registers\n");
		return;
	}
	if (size < NCO_CHANNEL_REGSIZE) {
		aprint_error(": register window too small\n");
		return;
	}

	sc->sc_dev = self;
	sc->sc_phandle = phandle;
	sc->sc_bst = faa->faa_bst;
	if (bus_space_map(sc->sc_bst, addr, size, 0, &sc->sc_bsh) != 0) {
		aprint_error(": couldn't map registers\n");
		return;
	}
	mutex_init(&sc->sc_lock, MUTEX_DEFAULT, IPL_NONE);

	sc->sc_tbl = kmem_zalloc(sizeof(*sc->sc_tbl), KM_SLEEP);
	apple_nco_tables(sc->sc_tbl);

	/* As many channels as whole register sets fit in the window. */
	sc->sc_nclks = (size - NCO_CHANNEL_REGSIZE) / NCO_CHANNEL_STRIDE + 1;
	sc->sc_clks = kmem_zalloc(sizeof(*sc->sc_clks) * sc->sc_nclks,
	    KM_SLEEP);

	sc->sc_clkdom.name = device_xname(self);
	sc->sc_clkdom.funcs = &apple_nco_clk_funcs;
	sc->sc_clkdom.priv = sc;
	for (i = 0; i < sc->sc_nclks; i++) {
		char name[16];

		snprintf(name, sizeof(name), "%s.%u", device_xname(self), i);
		sc->sc_clks[i].off = (bus_size_t)i * NCO_CHANNEL_STRIDE;
		sc->sc_clks[i].base.domain = &sc->sc_clkdom;
		sc->sc_clks[i].base.name = kmem_strdup(name, KM_SLEEP);
		clk_attach(&sc->sc_clks[i].base);
	}

	aprint_naive("\n");
	aprint_normal(": Apple NCO, %u channels\n", sc->sc_nclks);

	fdtbus_register_clock_controller(self, phandle, &apple_nco_fdt_funcs);
}

CFATTACH_DECL_NEW(apple_nco, sizeof(struct apple_nco_softc),
	apple_nco_match, apple_nco_attach, NULL, NULL);
