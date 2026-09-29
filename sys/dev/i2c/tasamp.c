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
 * Texas Instruments TAS2764 and TAS2770 mono class-D speaker amplifiers
 * with voltage and current sense.
 *
 * Written from the data sheets: TAS2764 SLOS998A (September 2021) and
 * TAS2770 (2023).  Section numbers below refer to those.
 *
 * These parts protect nothing by themselves.  Out of reset the output
 * level is at or near its maximum (TAS2764 8.9.7, TAS2770 8.5.2.4) and
 * the digital volume at 0 dB, so a full scale input drives the speaker
 * with up to 21 dBV; the small speakers these are paired with fail in
 * seconds at that.  Whatever is upstream of this driver is therefore
 * not trusted to keep the level down.  The rules are:
 *
 *  - The amplifier stays in software shutdown until a speaker limit
 *    has been set through audio_dai_set_speaker_limit().  There is no
 *    default limit: this driver cannot know what speaker is attached.
 *
 *  - Every register write that affects level is read back.  Any I2C
 *    failure or mismatch latches a fault: the part is put in software
 *    shutdown and SDZ is pulled low (hardware shutdown, 8.5.1), and it
 *    stays there until reboot.  SDZ is often shared by all amplifiers
 *    of a machine, which is the intent: one fault silences them all.
 *
 *  - While the limit is locked, the digital volume is held at mute
 *    whatever is asked for, and on the TAS2764 safe mode (8.4.2.3.1)
 *    is also set.
 *
 *  - The output level is never set above limit->amp_gain_max.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/bitops.h>
#include <sys/bus.h>
#include <sys/device.h>
#include <sys/kernel.h>
#include <sys/mutex.h>
#include <sys/systm.h>
#include <sys/time.h>

#include <dev/audio/audio_dai.h>

#include <dev/i2c/i2cvar.h>

#include <dev/fdt/fdtvar.h>

/* Registers common to both parts, book 0 page 0 (TAS2764 8.9, TAS2770 8.5.2). */
#define	TASAMP_PAGE_REG			0x00
#define	TASAMP_SW_RESET_REG		0x01
#define	 SW_RESET			__BIT(0)
#define	TASAMP_MODE_REG			0x02
#define	 MODE_ISNS_PD			__BIT(4)	/* TAS2764 */
#define	 MODE_VSNS_PD			__BIT(3)	/* TAS2764 */

/* TAS2764 */
#define	TAS2764_MODE_MASK		__BITS(2,0)	/* 8.9.6 */
#define	 TAS2764_MODE_ACTIVE		0
#define	 TAS2764_MODE_MUTE		1
#define	 TAS2764_MODE_SHUTDOWN		2
#define	TAS2764_CHNL_0_REG		0x03		/* 8.9.7 */
#define	 TAS2764_AMP_LEVEL		__BITS(5,1)
#define	TAS2764_MISC_CFG1_REG		0x06		/* 8.9.10 */
#define	 TAS2764_SMODE_EN		__BIT(2)
#define	TAS2764_TDM_CFG0_REG		0x08		/* 8.9.12 */
#define	TAS2764_TDM_CFG1_REG		0x09		/* 8.9.13 */
#define	TAS2764_TDM_CFG2_REG		0x0a		/* 8.9.14 */
#define	TAS2764_TDM_CFG4_REG		0x0d		/* 8.9.17 */
#define	TAS2764_TDM_CFG3_REG		0x0c		/* 8.9.16 */
#define	TAS2764_TDM_CFG5_REG		0x0e		/* 8.9.18 */
#define	TAS2764_TDM_CFG6_REG		0x0f		/* 8.9.19 */
#define	TAS2764_DVC_REG			0x1a		/* 8.9.30 */

/* TAS2770 */
#define	TAS2770_ISNS_PD			__BIT(3)	/* 8.5.2.3 */
#define	TAS2770_VSNS_PD			__BIT(2)
#define	TAS2770_MODE_MASK		__BITS(1,0)
#define	 TAS2770_MODE_ACTIVE		0
#define	 TAS2770_MODE_MUTE		1
#define	 TAS2770_MODE_SHUTDOWN		2
#define	TAS2770_PB_CFG0_REG		0x03		/* 8.5.2.4 */
#define	 TAS2770_AMP_LEVEL		__BITS(4,0)
#define	TAS2770_PB_CFG2_REG		0x05		/* 8.5.2.6 */
#define	TAS2770_TDM_CFG0_REG		0x0a		/* 8.5.2.11 */
#define	TAS2770_TDM_CFG1_REG		0x0b		/* 8.5.2.12 */
#define	TAS2770_TDM_CFG2_REG		0x0c		/* 8.5.2.13 */
#define	TAS2770_TDM_CFG4_REG		0x0e		/* 8.5.2.15 */
#define	TAS2770_TDM_CFG3_REG		0x0d		/* 8.5.2.14 */
#define	TAS2770_TDM_CFG5_REG		0x0f		/* 8.5.2.16 */
#define	TAS2770_TDM_CFG6_REG		0x10		/* 8.5.2.17 */

/* Same layout on both parts. */
#define	TDM_CFG0_FRAME_START		__BIT(0)	/* 1: high to low */
#define	TDM_CFG1_RX_OFFSET		__BITS(5,1)
#define	TDM_CFG1_RX_EDGE		__BIT(0)	/* 1: falling */
#define	TDM_CFG4_TX_FILL		__BIT(4)	/* 1: Hi-Z, 0: zeros */
#define	TDM_CFG4_TX_OFFSET		__BITS(3,1)
#define	TDM_CFG4_TX_EDGE		__BIT(0)	/* 1: falling */
#define	TDM_CFG2_RX_SCFG		__BITS(5,4)
#define	 RX_SCFG_MONO_LEFT		1
#define	TDM_CFG2_RX_WLEN		__BITS(3,2)
#define	TDM_CFG2_RX_SLEN		__BITS(1,0)
#define	TDM_CFG3_RX_SLOT_L		__BITS(3,0)
#define	TDM_CFG5_VSNS_TX		__BIT(6)
#define	TDM_CFG5_VSNS_SLOT		__BITS(5,0)
#define	TDM_CFG6_ISNS_TX		__BIT(6)
#define	TDM_CFG6_ISNS_SLOT		__BITS(5,0)

/*
 * AMP_LEVEL: 00h is 11 dBV, 0.5 dB per step, 14h is 21 dBV and the rest
 * is reserved (TAS2764 8.9.7, TAS2770 8.5.2.4).
 */
#define	AMP_LEVEL_BASE_CDBV		1100
#define	AMP_LEVEL_STEP_CDB		50
#define	AMP_LEVEL_MAX			0x14

/*
 * DVC: 00h is 0 dB, -0.5 dB per step, C8h is -100 dB, anything above is
 * mute (TAS2764 8.4.2.3 and 8.9.30, TAS2770 8.5.2.6).
 */
#define	DVC_STEP_CDB			50
#define	DVC_MIN				0xc8
#define	DVC_MUTE			0xff

/*
 * TAS2764 6.5: release of software shutdown to a new assertion of it,
 * 1.5 ms minimum.  The TAS2770 data sheet gives no such minimum.  The
 * turn-off ramps (TAS2764 5.9 ms, TAS2770 4.7 ms typical) need the TDM
 * clocks, which the machine driver keeps running from attach on.
 */
#define	TAS2764_SHDN_MIN_US		1500

/* TAS2764 11, TAS2770 10: wait 1 ms after reset for the OTP to load. */
#define	TASAMP_RESET_DELAY_US		1000

struct tasamp_model {
	const char	*name;
	uint8_t		mode_mask;
	uint8_t		mode_active;
	uint8_t		mode_shutdown;
	uint8_t		sense_pd;
	uint8_t		amp_reg;
	uint8_t		amp_mask;
	uint8_t		dvc_reg;
	uint8_t		smode_reg;	/* 0: part has no safe mode */
	uint8_t		tdm_cfg0_reg;
	uint8_t		tdm_cfg1_reg;
	uint8_t		tdm_cfg2_reg;
	uint8_t		tdm_cfg3_reg;
	uint8_t		tdm_cfg4_reg;
	uint8_t		tdm_cfg5_reg;
	uint8_t		tdm_cfg6_reg;
	/* Least time from leaving software shutdown to entering it again. */
	u_int		shdn_min_us;
	/*
	 * Apple's parts are variants whose differences are not in the
	 * data sheets.  The TAS5770L is run as a TAS2770: the Linux
	 * maintainers, who have run it on Apple machines for years, state
	 * that it needs no handling of its own (cover letter of "ASoC:
	 * tas27{64,70}: improve support for Apple codec variants",
	 * February 2025); that is their word, not TI's.  The SN012776
	 * needs writes to undocumented registers whose reasons are only
	 * guessed at, so the amplifier is kept in shutdown on it; see
	 * tasamp_set_speaker_limit().
	 */
	bool		documented;
};

static const struct tasamp_model tas2764_model = {
	.name = "TAS2764",
	.mode_mask = TAS2764_MODE_MASK,
	.mode_active = TAS2764_MODE_ACTIVE,
	.mode_shutdown = TAS2764_MODE_SHUTDOWN,
	.sense_pd = MODE_ISNS_PD | MODE_VSNS_PD,
	.amp_reg = TAS2764_CHNL_0_REG,
	.amp_mask = TAS2764_AMP_LEVEL,
	.dvc_reg = TAS2764_DVC_REG,
	.smode_reg = TAS2764_MISC_CFG1_REG,
	.tdm_cfg0_reg = TAS2764_TDM_CFG0_REG,
	.tdm_cfg1_reg = TAS2764_TDM_CFG1_REG,
	.tdm_cfg2_reg = TAS2764_TDM_CFG2_REG,
	.tdm_cfg3_reg = TAS2764_TDM_CFG3_REG,
	.tdm_cfg4_reg = TAS2764_TDM_CFG4_REG,
	.tdm_cfg5_reg = TAS2764_TDM_CFG5_REG,
	.tdm_cfg6_reg = TAS2764_TDM_CFG6_REG,
	.shdn_min_us = TAS2764_SHDN_MIN_US,
	.documented = true,
};

static const struct tasamp_model sn012776_model = {
	.name = "SN012776",
	.mode_mask = TAS2764_MODE_MASK,
	.mode_active = TAS2764_MODE_ACTIVE,
	.mode_shutdown = TAS2764_MODE_SHUTDOWN,
	.sense_pd = MODE_ISNS_PD | MODE_VSNS_PD,
	.amp_reg = TAS2764_CHNL_0_REG,
	.amp_mask = TAS2764_AMP_LEVEL,
	.dvc_reg = TAS2764_DVC_REG,
	.smode_reg = TAS2764_MISC_CFG1_REG,
	.tdm_cfg0_reg = TAS2764_TDM_CFG0_REG,
	.tdm_cfg1_reg = TAS2764_TDM_CFG1_REG,
	.tdm_cfg2_reg = TAS2764_TDM_CFG2_REG,
	.tdm_cfg3_reg = TAS2764_TDM_CFG3_REG,
	.tdm_cfg4_reg = TAS2764_TDM_CFG4_REG,
	.tdm_cfg5_reg = TAS2764_TDM_CFG5_REG,
	.tdm_cfg6_reg = TAS2764_TDM_CFG6_REG,
	.shdn_min_us = TAS2764_SHDN_MIN_US,
	.documented = false,
};

static const struct tasamp_model tas2770_model = {
	.name = "TAS2770",
	.mode_mask = TAS2770_MODE_MASK,
	.mode_active = TAS2770_MODE_ACTIVE,
	.mode_shutdown = TAS2770_MODE_SHUTDOWN,
	.sense_pd = TAS2770_ISNS_PD | TAS2770_VSNS_PD,
	.amp_reg = TAS2770_PB_CFG0_REG,
	.amp_mask = TAS2770_AMP_LEVEL,
	.dvc_reg = TAS2770_PB_CFG2_REG,
	.smode_reg = 0,
	.tdm_cfg0_reg = TAS2770_TDM_CFG0_REG,
	.tdm_cfg1_reg = TAS2770_TDM_CFG1_REG,
	.tdm_cfg2_reg = TAS2770_TDM_CFG2_REG,
	.tdm_cfg3_reg = TAS2770_TDM_CFG3_REG,
	.tdm_cfg4_reg = TAS2770_TDM_CFG4_REG,
	.tdm_cfg5_reg = TAS2770_TDM_CFG5_REG,
	.tdm_cfg6_reg = TAS2770_TDM_CFG6_REG,
	.documented = true,
};

static const struct tasamp_model tas5770l_model = {
	.name = "TAS5770L",
	.mode_mask = TAS2770_MODE_MASK,
	.mode_active = TAS2770_MODE_ACTIVE,
	.mode_shutdown = TAS2770_MODE_SHUTDOWN,
	.sense_pd = TAS2770_ISNS_PD | TAS2770_VSNS_PD,
	.amp_reg = TAS2770_PB_CFG0_REG,
	.amp_mask = TAS2770_AMP_LEVEL,
	.dvc_reg = TAS2770_PB_CFG2_REG,
	.smode_reg = 0,
	.tdm_cfg0_reg = TAS2770_TDM_CFG0_REG,
	.tdm_cfg1_reg = TAS2770_TDM_CFG1_REG,
	.tdm_cfg2_reg = TAS2770_TDM_CFG2_REG,
	.tdm_cfg3_reg = TAS2770_TDM_CFG3_REG,
	.tdm_cfg4_reg = TAS2770_TDM_CFG4_REG,
	.tdm_cfg5_reg = TAS2770_TDM_CFG5_REG,
	.tdm_cfg6_reg = TAS2770_TDM_CFG6_REG,
	.documented = true,
};

/*
 * Apple's device trees list the variant first and the part it derives
 * from second, so the variant has to be matched ahead of the part.
 */
static const struct device_compatible_entry compat_data[] = {
	{ .compat = "ti,sn012776",	.data = &sn012776_model },
	{ .compat = "ti,tas5770l",	.data = &tas5770l_model },
	{ .compat = "ti,tas2764",	.data = &tas2764_model },
	{ .compat = "ti,tas2770",	.data = &tas2770_model },
	DEVICE_COMPAT_EOL
};

struct tasamp_softc {
	device_t		sc_dev;
	i2c_tag_t		sc_i2c;
	i2c_addr_t		sc_addr;
	int			sc_phandle;
	const struct tasamp_model *sc_model;
	struct fdtbus_gpio_pin	*sc_sdz;

	struct audio_dai_device	sc_dai;

	kmutex_t		sc_lock;	/* all below; before the bus */
	bool			sc_bus;		/* holding the I2C bus */
	bool			sc_fault;
	bool			sc_limited;	/* a limit has been set */
	struct audio_dai_speaker_limit sc_limit;
	int			sc_volume;	/* requested, cdB */
	bool			sc_running;	/* between open and close */
	bool			sc_active;	/* part out of shutdown */
	struct timeval		sc_active_at;	/*  since */
	uint32_t		sc_vsns_slot;
	uint32_t		sc_isns_slot;
	bool			sc_zero_fill;	/* ti,sdout-zero-fill */
};

static int	tasamp_match(device_t, cfdata_t, void *);
static void	tasamp_attach(device_t, device_t, void *);

CFATTACH_DECL_NEW(tasamp, sizeof(struct tasamp_softc),
    tasamp_match, tasamp_attach, NULL, NULL);

/*
 * Hardware shutdown.  Registers are lost and I2C stops answering
 * (8.5.1), so from here on every access fails and the fault stays.
 */
static void
tasamp_fault(struct tasamp_softc *sc, const char *why, uint8_t reg)
{

	KASSERT(mutex_owned(&sc->sc_lock));

	if (!sc->sc_fault) {
		device_printf(sc->sc_dev,
		    "%s at register 0x%02x, shutting down\n", why, reg);
	}
	sc->sc_fault = true;

	/*
	 * Software shutdown first when possible, so VBAT1S is discharged
	 * (TAS2764 11).  Its result does not matter: SDZ follows anyway.
	 */
	if (sc->sc_bus) {
		(void)iic_smbus_write_byte(sc->sc_i2c, sc->sc_addr,
		    TASAMP_MODE_REG, sc->sc_model->mode_shutdown, 0);
	}
	if (sc->sc_sdz != NULL)
		fdtbus_gpio_write(sc->sc_sdz, 0);
}

/*
 * Take the softc lock and then the bus.  Failing to get the bus is a
 * fault like any other: whatever was about to be written, possibly a
 * lower level, will not be.
 */
static int
tasamp_enter(struct tasamp_softc *sc)
{
	int error;

	mutex_enter(&sc->sc_lock);
	error = iic_acquire_bus(sc->sc_i2c, 0);
	if (error != 0) {
		tasamp_fault(sc, "cannot acquire bus", 0);
		mutex_exit(&sc->sc_lock);
		return error;
	}
	sc->sc_bus = true;
	return 0;
}

static void
tasamp_exit(struct tasamp_softc *sc)
{

	KASSERT(sc->sc_bus);
	sc->sc_bus = false;
	iic_release_bus(sc->sc_i2c, 0);
	mutex_exit(&sc->sc_lock);
}

/*
 * Read twice.  A value read here is written back with only some bits
 * changed, and I2C has no check of its own: a corrupted read would put
 * wrong bits into the part that the read back after the write cannot
 * see, since they are the bits that were written.
 */
static int
tasamp_read(struct tasamp_softc *sc, uint8_t reg, uint8_t *val)
{
	uint8_t again;
	int error;

	KASSERT(mutex_owned(&sc->sc_lock));
	KASSERT(sc->sc_bus);

	if (sc->sc_fault)
		return EIO;
	error = iic_smbus_read_byte(sc->sc_i2c, sc->sc_addr, reg, val, 0);
	if (error == 0) {
		error = iic_smbus_read_byte(sc->sc_i2c, sc->sc_addr, reg,
		    &again, 0);
	}
	if (error != 0) {
		tasamp_fault(sc, "read failed", reg);
		return error;
	}
	if (again != *val) {
		tasamp_fault(sc, "unstable read", reg);
		return EIO;
	}
	return 0;
}

/*
 * Write and read back.  Only for registers whose bits all read back as
 * written; SW_RESET self-clears and goes through iic directly.
 */
static int
tasamp_write(struct tasamp_softc *sc, uint8_t reg, uint8_t val)
{
	uint8_t back;
	int error;

	KASSERT(mutex_owned(&sc->sc_lock));
	KASSERT(sc->sc_bus);

	if (sc->sc_fault)
		return EIO;
	error = iic_smbus_write_byte(sc->sc_i2c, sc->sc_addr, reg, val, 0);
	if (error != 0) {
		tasamp_fault(sc, "write failed", reg);
		return error;
	}
	error = tasamp_read(sc, reg, &back);
	if (error != 0)
		return error;
	if (back != val) {
		tasamp_fault(sc, "read back mismatch", reg);
		return EIO;
	}
	return 0;
}

static int
tasamp_update(struct tasamp_softc *sc, uint8_t reg, uint8_t mask,
    uint8_t val)
{
	uint8_t old;
	int error;

	error = tasamp_read(sc, reg, &old);
	if (error != 0)
		return error;
	return tasamp_write(sc, reg, (old & ~mask) | (val & mask));
}

/*
 * Only this changes the mode, except tasamp_fault(), which shuts the
 * part down at once whatever the timing: silence comes first.
 */
static int
tasamp_set_mode(struct tasamp_softc *sc, uint8_t mode)
{
	const struct tasamp_model *m = sc->sc_model;
	struct timeval now;
	int64_t us;
	int error;

	if (mode == m->mode_shutdown && sc->sc_active && m->shdn_min_us != 0) {
		microuptime(&now);
		timersub(&now, &sc->sc_active_at, &now);
		us = (int64_t)now.tv_sec * 1000000 + now.tv_usec;
		if (us < m->shdn_min_us)
			delay(m->shdn_min_us - (u_int)us);
	}
	error = tasamp_update(sc, TASAMP_MODE_REG, m->mode_mask,
	    __SHIFTIN(mode, m->mode_mask));
	if (error != 0)
		return error;
	if (mode == m->mode_shutdown) {
		sc->sc_active = false;
	} else if (!sc->sc_active) {
		microuptime(&sc->sc_active_at);
		sc->sc_active = true;
	}
	return 0;
}

/*
 * Highest AMP_LEVEL code whose level does not exceed max_cdbv, or -1
 * if even the lowest does.
 */
static int
tasamp_amp_level(int max_cdbv)
{
	int code;

	if (max_cdbv < AMP_LEVEL_BASE_CDBV)
		return -1;
	code = (max_cdbv - AMP_LEVEL_BASE_CDBV) / AMP_LEVEL_STEP_CDB;
	return MIN(code, AMP_LEVEL_MAX);
}

/*
 * DVC code for an attenuation of cdb (0 or below), rounded towards
 * more attenuation.
 */
static uint8_t
tasamp_dvc(int cdb)
{
	int code;

	if (cdb > 0)
		cdb = 0;
	code = howmany(-cdb, DVC_STEP_CDB);
	return code > DVC_MIN ? DVC_MUTE : (uint8_t)code;
}

/*
 * Bring the registers in line with the limit and the requested volume.
 * Called with any change to either.
 */
static int
tasamp_apply(struct tasamp_softc *sc)
{
	const struct tasamp_model *m = sc->sc_model;
	const struct audio_dai_speaker_limit *l = &sc->sc_limit;
	bool quiet;
	int level, error;

	KASSERT(mutex_owned(&sc->sc_lock));

	if (sc->sc_fault)
		return EIO;

	level = sc->sc_limited ? tasamp_amp_level(l->amp_gain_max) : -1;
	quiet = !sc->sc_limited || l->locked;

	/*
	 * Order matters.  Going quieter, mute before anything else moves;
	 * going louder, the volume is raised last.
	 */
	if (quiet || level < 0 || !m->documented || !sc->sc_running) {
		error = tasamp_write(sc, m->dvc_reg, DVC_MUTE);
		if (error == 0 && m->smode_reg != 0) {
			error = tasamp_update(sc, m->smode_reg,
			    TAS2764_SMODE_EN, TAS2764_SMODE_EN);
		}
		if (error == 0 && (level < 0 || !m->documented ||
		    !sc->sc_running))
			error = tasamp_set_mode(sc, m->mode_shutdown);
		/* Without a usable limit, also the lowest output level. */
		if (error == 0) {
			error = tasamp_update(sc, m->amp_reg, m->amp_mask,
			    __SHIFTIN(MAX(level, 0), m->amp_mask));
		}
		return error;
	}

	error = tasamp_update(sc, m->amp_reg, m->amp_mask,
	    __SHIFTIN(level, m->amp_mask));
	if (error == 0 && m->smode_reg != 0)
		error = tasamp_update(sc, m->smode_reg, TAS2764_SMODE_EN, 0);
	if (error == 0)
		error = tasamp_set_mode(sc, m->mode_active);
	if (error == 0)
		error = tasamp_write(sc, m->dvc_reg, tasamp_dvc(sc->sc_volume));
	return error;
}

static int
tasamp_set_speaker_limit(audio_dai_tag_t dai,
    const struct audio_dai_speaker_limit *limit)
{
	struct tasamp_softc * const sc = audio_dai_private(dai);
	int error;

	if ((error = tasamp_enter(sc)) != 0)
		return error;
	if (!sc->sc_model->documented && !sc->sc_limited) {
		device_printf(sc->sc_dev, "%s differs from the data sheet "
		    "in undocumented ways; speaker output stays disabled\n",
		    sc->sc_model->name);
	}
	sc->sc_limit = *limit;
	sc->sc_limited = true;
	error = tasamp_apply(sc);
	tasamp_exit(sc);

	return error;
}

static int
tasamp_set_volume(audio_dai_tag_t dai, int cdb)
{
	struct tasamp_softc * const sc = audio_dai_private(dai);
	int error;

	if ((error = tasamp_enter(sc)) != 0)
		return error;
	sc->sc_volume = MIN(cdb, 0);
	error = tasamp_apply(sc);
	tasamp_exit(sc);

	return error;
}

static int
tasamp_set_tdm_slot(audio_dai_tag_t dai, uint32_t txmask, uint32_t rxmask,
    u_int slots, u_int width)
{
	struct tasamp_softc * const sc = audio_dai_private(dai);
	const struct tasamp_model *m = sc->sc_model;
	uint8_t len;
	int error;

	/*
	 * The transmit slots of the sense data are properties of the
	 * board and come from the device tree; txmask is not used.
	 */
	(void)txmask;

	/* One mono channel, RX_SLOT_L is four bits (8.9.16, 8.5.2.14). */
	if (popcount32(rxmask) != 1 || ffs32(rxmask) - 1 > 15 ||
	    ffs32(rxmask) > (int)slots)
		return EINVAL;

	/* RX_SLEN and RX_WLEN take the same three widths (8.9.14). */
	switch (width) {
	case 16:
		len = 0;
		break;
	case 24:
		len = 1;
		break;
	case 32:
		len = 2;
		break;
	default:
		return EINVAL;
	}

	if ((error = tasamp_enter(sc)) != 0)
		return error;
	error = tasamp_update(sc, m->tdm_cfg3_reg, TDM_CFG3_RX_SLOT_L,
	    __SHIFTIN(ffs32(rxmask) - 1, TDM_CFG3_RX_SLOT_L));
	if (error == 0) {
		error = tasamp_update(sc, m->tdm_cfg2_reg,
		    TDM_CFG2_RX_SCFG | TDM_CFG2_RX_WLEN | TDM_CFG2_RX_SLEN,
		    __SHIFTIN(RX_SCFG_MONO_LEFT, TDM_CFG2_RX_SCFG) |
		    __SHIFTIN(width == 16 ? 0 : (width == 24 ? 2 : 3),
			TDM_CFG2_RX_WLEN) |
		    __SHIFTIN(len, TDM_CFG2_RX_SLEN));
	}
	tasamp_exit(sc);

	return error;
}

/*
 * Frame and bit clock conventions of the formats are those of the I2S
 * bus specification (Philips, June 1996): data starts one bit clock
 * after the word select edge, word select low is the left channel, and
 * the transmitter changes data on the falling edge for the receiver to
 * latch on the rising one.  Left justified drops the one-clock offset
 * and has word select high for the left channel.  The part is always
 * the clock consumer here.
 */
static int
tasamp_set_format(audio_dai_tag_t dai, u_int format)
{
	struct tasamp_softc * const sc = audio_dai_private(dai);
	const struct tasamp_model *m = sc->sc_model;
	const u_int pol = __SHIFTOUT(format, AUDIO_DAI_POLARITY_MASK);
	bool frame_hl, bclk_inv;
	u_int offset;
	int error;

	switch (__SHIFTOUT(format, AUDIO_DAI_CLOCK_MASK)) {
	case AUDIO_DAI_CLOCK_CBS_CFS:		/* codec slave for both */
		break;
	default:
		return EINVAL;
	}
	switch (format & AUDIO_DAI_FORMAT_MASK) {
	case AUDIO_DAI_FORMAT_I2S:
		offset = 1;
		frame_hl = true;	/* left starts on WS falling */
		break;
	case AUDIO_DAI_FORMAT_LJ:
		offset = 0;
		frame_hl = false;	/* left starts on WS rising */
		break;
	default:
		return EINVAL;
	}
	if (AUDIO_DAI_POLARITY_F(pol))
		frame_hl = !frame_hl;
	bclk_inv = AUDIO_DAI_POLARITY_B(pol);

	if ((error = tasamp_enter(sc)) != 0)
		return error;
	error = tasamp_update(sc, m->tdm_cfg0_reg, TDM_CFG0_FRAME_START,
	    frame_hl ? TDM_CFG0_FRAME_START : 0);
	if (error == 0) {
		/* Receive on the rising edge, unless inverted. */
		error = tasamp_update(sc, m->tdm_cfg1_reg,
		    TDM_CFG1_RX_OFFSET | TDM_CFG1_RX_EDGE,
		    __SHIFTIN(offset, TDM_CFG1_RX_OFFSET) |
		    (bclk_inv ? TDM_CFG1_RX_EDGE : 0));
	}
	if (error == 0) {
		/* Transmit sense data on the falling edge, unless inverted. */
		error = tasamp_update(sc, m->tdm_cfg4_reg,
		    TDM_CFG4_TX_OFFSET | TDM_CFG4_TX_EDGE,
		    __SHIFTIN(offset, TDM_CFG4_TX_OFFSET) |
		    (bclk_inv ? 0 : TDM_CFG4_TX_EDGE));
	}
	tasamp_exit(sc);
	return error;
}

static int
tasamp_open(void *priv, int flags)
{
	struct tasamp_softc * const sc = priv;
	int error;

	if ((error = tasamp_enter(sc)) != 0)
		return error;
	sc->sc_running = true;
	error = tasamp_apply(sc);
	tasamp_exit(sc);

	return error;
}

static void
tasamp_close(void *priv)
{
	struct tasamp_softc * const sc = priv;

	if (tasamp_enter(sc) != 0)
		return;
	sc->sc_running = false;
	(void)tasamp_apply(sc);
	tasamp_exit(sc);
}

static const struct audio_hw_if tasamp_hw_if = {
	.open = tasamp_open,
	.close = tasamp_close,
};

static audio_dai_tag_t
tasamp_dai_get_tag(device_t dev, const void *data, size_t len)
{
	struct tasamp_softc * const sc = device_private(dev);

	if (len != 4)
		return NULL;

	return &sc->sc_dai;
}

static struct fdtbus_dai_controller_func tasamp_dai_funcs = {
	.get_tag = tasamp_dai_get_tag
};

/*
 * Reset, then leave the part silent: software shutdown, volume muted,
 * safe mode on, sense on and transmitting in the board's slots.
 */
static int
tasamp_init(struct tasamp_softc *sc)
{
	const struct tasamp_model *m = sc->sc_model;
	int error;

	KASSERT(mutex_owned(&sc->sc_lock));

	error = iic_smbus_write_byte(sc->sc_i2c, sc->sc_addr,
	    TASAMP_SW_RESET_REG, SW_RESET, 0);
	if (error != 0) {
		tasamp_fault(sc, "reset failed", TASAMP_SW_RESET_REG);
		return error;
	}
	delay(TASAMP_RESET_DELAY_US);

	/* Reset leaves both parts in software shutdown (8.9.6, 8.5.2.3). */
	if ((error = tasamp_write(sc, TASAMP_PAGE_REG, 0)) != 0 ||
	    (error = tasamp_apply(sc)) != 0)
		return error;

	if ((error = tasamp_update(sc, TASAMP_MODE_REG, m->sense_pd, 0)) != 0)
		return error;
	/*
	 * Unused transmit slots: zeros rather than Hi-Z where the board's
	 * tree asks, as for a single amplifier on the bus (TAS2764 8.4 and
	 * 8.9.17, TAS2770 Table 8-21 and 8.5.2.15; TX_FILL is bit 4 of
	 * TDM_CFG4 on both).  "ti,sdout-zero-fill" is in Apple's trees
	 * but in no binding; its reading here is the name's and TX_FILL's.
	 */
	if ((error = tasamp_update(sc, m->tdm_cfg4_reg, TDM_CFG4_TX_FILL,
	    sc->sc_zero_fill ? 0 : TDM_CFG4_TX_FILL)) != 0)
		return error;
	if ((error = tasamp_update(sc, m->tdm_cfg5_reg,
	    TDM_CFG5_VSNS_TX | TDM_CFG5_VSNS_SLOT,
	    TDM_CFG5_VSNS_TX |
	    __SHIFTIN(sc->sc_vsns_slot, TDM_CFG5_VSNS_SLOT))) != 0)
		return error;
	return tasamp_update(sc, m->tdm_cfg6_reg,
	    TDM_CFG6_ISNS_TX | TDM_CFG6_ISNS_SLOT,
	    TDM_CFG6_ISNS_TX |
	    __SHIFTIN(sc->sc_isns_slot, TDM_CFG6_ISNS_SLOT));
}

static int
tasamp_match(device_t parent, cfdata_t match, void *aux)
{
	struct i2c_attach_args *ia = aux;
	int match_result;

	if (iic_use_direct_match(ia, match, compat_data, &match_result))
		return match_result;

	/* This device is direct-config only */

	return 0;
}

static void
tasamp_attach(device_t parent, device_t self, void *aux)
{
	struct tasamp_softc * const sc = device_private(self);
	struct i2c_attach_args * const ia = aux;
	const struct device_compatible_entry *dce;
	int error;

	sc->sc_dev = self;
	sc->sc_phandle = devhandle_to_of(device_handle(self));
	sc->sc_i2c = ia->ia_tag;
	sc->sc_addr = ia->ia_addr;
	dce = iic_compatible_lookup(ia, compat_data);
	KASSERT(dce != NULL);
	sc->sc_model = dce->data;
	sc->sc_volume = 0;
	mutex_init(&sc->sc_lock, MUTEX_DEFAULT, IPL_NONE);

	aprint_naive("\n");
	aprint_normal(": TI %s speaker amplifier\n", sc->sc_model->name);

	/* SLOT fields are six bits wide (8.9.18, 8.5.2.16). */
	sc->sc_zero_fill = of_hasprop(sc->sc_phandle, "ti,sdout-zero-fill");
	if (of_getprop_uint32(sc->sc_phandle, "ti,vmon-slot-no",
	    &sc->sc_vsns_slot) != 0 ||
	    of_getprop_uint32(sc->sc_phandle, "ti,imon-slot-no",
	    &sc->sc_isns_slot) != 0 ||
	    sc->sc_vsns_slot > 63 || sc->sc_isns_slot > 63) {
		aprint_error_dev(self, "missing or bad sense slots\n");
		return;
	}

	sc->sc_sdz = fdtbus_gpio_acquire(sc->sc_phandle, "shutdown-gpios",
	    GPIO_PIN_OUTPUT);
	if (sc->sc_sdz != NULL) {
		fdtbus_gpio_write(sc->sc_sdz, 1);
		delay(TASAMP_RESET_DELAY_US);
	}

	if ((error = tasamp_enter(sc)) == 0) {
		error = tasamp_init(sc);
		tasamp_exit(sc);
	}
	if (error != 0) {
		aprint_error_dev(self, "init failed, error %d\n", error);
		return;
	}

	sc->sc_dai.dai_set_format = tasamp_set_format;
	sc->sc_dai.dai_set_tdm_slot = tasamp_set_tdm_slot;
	sc->sc_dai.dai_set_speaker_limit = tasamp_set_speaker_limit;
	sc->sc_dai.dai_set_volume = tasamp_set_volume;
	sc->sc_dai.dai_hw_if = &tasamp_hw_if;
	sc->sc_dai.dai_dev = self;
	sc->sc_dai.dai_priv = sc;
	fdtbus_register_dai_controller(self, sc->sc_phandle,
	    &tasamp_dai_funcs);
}
