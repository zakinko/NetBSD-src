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
 * Apple CPU cluster performance states ("apple,cluster-cpufreq").
 *
 * Each cluster has a DVFS controller in its management block; the CPUs
 * name it with performance-domains, and their operating-points-v2 table
 * gives each state's frequency (opp-hz) and hardware p-state
 * (opp-level).  From the binding apple,cluster-cpufreq.yaml; the
 * register layout is a fact from the Asahi Linux driver
 * drivers/cpufreq/apple-soc-cpufreq.c.  Not run on hardware from NetBSD.
 *
 * The states are offered to the utilization governor as a
 * cpufreq_domain (kern_sched_util.c); there is no other interface.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/cpu.h>
#include <sys/cpufreq_domain.h>
#include <sys/device.h>
#include <sys/kcpuset.h>
#include <sys/kmem.h>
#include <sys/systm.h>

#include <dev/fdt/fdtvar.h>

#define	DVFS_CMD		0x20		/* 64 bits */
#define	DVFS_STATUS		0x50
#define	 DVFS_CMD_BUSY		__BIT(31)
#define	 DVFS_CMD_SET		__BIT(25)
#define	 DVFS_CMD_PS2		__BITS(15,12)
#define	 DVFS_CMD_PS1		__BITS(4,0)

/* The controller finishes a change within this, polled every 2 us. */
#define	DVFS_TIMEOUT_US		400
#define	DVFS_POLL_US		2

struct apple_cpufreq_soc {
	bool		has_ps2;	/* p-state also goes in PS2 */
	u_int		max_pstate;
	uint32_t	cur_pstate;	/* field of DVFS_STATUS, 0: unknown */
};

/* The current p-state moved in DVFS_STATUS on the t8112. */
static const struct apple_cpufreq_soc t8103_soc = { true, 15, __BITS(7,4) };
static const struct apple_cpufreq_soc t8112_soc = { false, 31, __BITS(9,5) };
static const struct apple_cpufreq_soc default_soc = { false, 15, 0 };

/*
 * The s5l8960x layout differs (PS1 at 24:22); those SoCs are not Macs
 * and are left unmatched rather than guessed at.
 */
static const struct device_compatible_entry compat_data[] = {
	{ .compat = "apple,t8103-cluster-cpufreq",	.data = &t8103_soc },
	{ .compat = "apple,t8112-cluster-cpufreq",	.data = &t8112_soc },
	{ .compat = "apple,cluster-cpufreq",		.data = &default_soc },
	DEVICE_COMPAT_EOL
};

struct apple_cpufreq_softc {
	device_t		sc_dev;
	bus_space_tag_t		sc_bst;
	bus_space_handle_t	sc_bsh;
	const struct apple_cpufreq_soc *sc_soc;
	int			sc_phandle;

	u_int			sc_nstates;
	u_int			*sc_khz;	/* ascending */
	u_int			*sc_pstate;	/* matching sc_khz */
	struct cpufreq_domain	sc_domain;
};

static int
apple_cpufreq_set(void *cookie, u_int idx)
{
	struct apple_cpufreq_softc * const sc = cookie;
	u_int pstate, waited;
	uint64_t cmd;

	if (idx >= sc->sc_nstates)
		return EINVAL;
	pstate = MIN(sc->sc_pstate[idx], sc->sc_soc->max_pstate);

	for (waited = 0;; waited += DVFS_POLL_US) {
		cmd = bus_space_read_8(sc->sc_bst, sc->sc_bsh, DVFS_CMD);
		if ((cmd & DVFS_CMD_BUSY) == 0)
			break;
		if (waited >= DVFS_TIMEOUT_US)
			return EIO;
		delay(DVFS_POLL_US);
	}
	cmd &= ~(uint64_t)DVFS_CMD_PS1;
	cmd |= __SHIFTIN(pstate, DVFS_CMD_PS1);
	if (sc->sc_soc->has_ps2) {
		cmd &= ~(uint64_t)DVFS_CMD_PS2;
		cmd |= __SHIFTIN(pstate, DVFS_CMD_PS2);
	}
	cmd |= DVFS_CMD_SET;
	bus_space_write_8(sc->sc_bst, sc->sc_bsh, DVFS_CMD, cmd);
	return 0;
}

static int
apple_cpufreq_get(void *cookie)
{
	struct apple_cpufreq_softc * const sc = cookie;
	uint32_t pstate;
	u_int i;

	/* Without a known status layout, the command register's request. */
	if (sc->sc_soc->cur_pstate != 0) {
		pstate = __SHIFTOUT(bus_space_read_4(sc->sc_bst, sc->sc_bsh,
		    DVFS_STATUS), sc->sc_soc->cur_pstate);
	} else {
		pstate = __SHIFTOUT(bus_space_read_8(sc->sc_bst, sc->sc_bsh,
		    DVFS_CMD), DVFS_CMD_PS1);
	}
	for (i = 0; i < sc->sc_nstates; i++) {
		if (MIN(sc->sc_pstate[i], sc->sc_soc->max_pstate) == pstate)
			return i;
	}
	return -1;
}

/*
 * The states from one CPU's table, sorted by frequency.  All CPUs of a
 * cluster share one table in Apple's trees; the first found is used.
 */
static int
apple_cpufreq_parse_opp(struct apple_cpufreq_softc *sc, int table)
{
	int node, len;
	u_int n, i, j;

	n = 0;
	for (node = OF_child(table); node; node = OF_peer(node))
		n++;
	if (n == 0)
		return ENOENT;
	sc->sc_khz = kmem_zalloc(sizeof(u_int) * n, KM_SLEEP);
	sc->sc_pstate = kmem_zalloc(sizeof(u_int) * n, KM_SLEEP);

	for (node = OF_child(table); node; node = OF_peer(node)) {
		const uint8_t *opp_hz;
		uint32_t level;
		uint64_t rate;

		opp_hz = fdtbus_get_prop(node, "opp-hz", &len);
		if (opp_hz == NULL || len != 8 ||
		    of_getprop_uint32(node, "opp-level", &level) != 0)
			continue;
		rate = be64dec(opp_hz);
		/* Insert sorted. */
		for (i = sc->sc_nstates; i > 0 &&
		    sc->sc_khz[i - 1] > rate / 1000; i--) {
			sc->sc_khz[i] = sc->sc_khz[i - 1];
			sc->sc_pstate[i] = sc->sc_pstate[i - 1];
		}
		sc->sc_khz[i] = rate / 1000;
		sc->sc_pstate[i] = level;
		sc->sc_nstates++;
	}
	for (j = 0; j < sc->sc_nstates; j++) {
		if (sc->sc_pstate[j] > sc->sc_soc->max_pstate) {
			aprint_verbose_dev(sc->sc_dev, "p-state %u above %u, "
			    "capped\n", sc->sc_pstate[j], sc->sc_soc->max_pstate);
		}
	}
	return sc->sc_nstates > 0 ? 0 : ENOENT;
}

static void
apple_cpufreq_init(device_t self)
{
	struct apple_cpufreq_softc * const sc = device_private(self);
	CPU_INFO_ITERATOR cii;
	struct cpu_info *ci;
	int table = -1;

	/* The CPUs of this cluster name it in performance-domains. */
	kcpuset_create(&sc->sc_domain.cd_cpus, true);
	for (CPU_INFO_FOREACH(cii, ci)) {
		int cpu;

		if (ci->ci_dev == NULL)
			continue;
		cpu = devhandle_to_of(device_handle(ci->ci_dev));
		if (cpu <= 0 || fdtbus_get_phandle(cpu, "performance-domains") !=
		    sc->sc_phandle)
			continue;
		kcpuset_set(sc->sc_domain.cd_cpus, cpu_index(ci));
		if (table < 0)
			table = fdtbus_get_phandle(cpu, "operating-points-v2");
	}
	if (table <= 0 || apple_cpufreq_parse_opp(sc, table) != 0) {
		aprint_error_dev(self, "no CPUs or no states\n");
		return;
	}
	aprint_normal_dev(self, "%u states, %u.%03u to %u.%03u MHz\n",
	    sc->sc_nstates, sc->sc_khz[0] / 1000, sc->sc_khz[0] % 1000,
	    sc->sc_khz[sc->sc_nstates - 1] / 1000,
	    sc->sc_khz[sc->sc_nstates - 1] % 1000);

	sc->sc_domain.cd_name = device_xname(self);
	sc->sc_domain.cd_nstates = sc->sc_nstates;
	sc->sc_domain.cd_khz = sc->sc_khz;
	sc->sc_domain.cd_set = apple_cpufreq_set;
	sc->sc_domain.cd_get = apple_cpufreq_get;
	sc->sc_domain.cd_cookie = sc;
	(void)cpufreq_domain_register(&sc->sc_domain);
}

static int
apple_cpufreq_match(device_t parent, cfdata_t cf, void *aux)
{
	struct fdt_attach_args * const faa = aux;

	return of_compatible_match(faa->faa_phandle, compat_data);
}

static void
apple_cpufreq_attach(device_t parent, device_t self, void *aux)
{
	struct apple_cpufreq_softc * const sc = device_private(self);
	struct fdt_attach_args * const faa = aux;
	const int phandle = faa->faa_phandle;
	bus_addr_t addr;
	bus_size_t size;

	if (fdtbus_get_reg(phandle, 0, &addr, &size) != 0) {
		aprint_error(": couldn't get registers\n");
		return;
	}
	sc->sc_dev = self;
	sc->sc_bst = faa->faa_bst;
	sc->sc_soc = of_compatible_lookup(phandle, compat_data)->data;
	if (bus_space_map(sc->sc_bst, addr, size, 0, &sc->sc_bsh) != 0) {
		aprint_error(": couldn't map registers\n");
		return;
	}
	sc->sc_phandle = phandle;
	aprint_naive("\n");
	aprint_normal(": Apple cluster performance states\n");

	/* Every CPU has attached by then. */
	config_interrupts(self, apple_cpufreq_init);
}

CFATTACH_DECL_NEW(apple_cpufreq, sizeof(struct apple_cpufreq_softc),
	apple_cpufreq_match, apple_cpufreq_attach, NULL, NULL);
