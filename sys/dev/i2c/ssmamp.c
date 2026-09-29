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
 * Analog Devices SSM3515 mono class-D speaker amplifier.
 *
 * Written from the data sheet, SSM3515 Rev. A; table numbers below
 * refer to it.  The Japanese edition of the same revision was read
 * alongside; it is a translation and carries the same errors, so it is
 * not a second source.
 *
 * The part has no voltage or current sense, so nothing can watch the
 * speaker, and no shutdown pin: the only way to silence it is over
 * I2C.  The rules are those of tasamp(4):
 *
 *  - The amplifier stays in software power-down (SPWDN, Table 21)
 *    until a speaker limit has been set through
 *    audio_dai_set_speaker_limit().  There is no default limit.
 *
 *  - Every register write is read back.  Any I2C failure or mismatch
 *    latches a fault: the DAC is muted and the part powered down, and
 *    it stays there until reboot.  Its own fault recovery is set to
 *    manual (Table 32), so an overcurrent or overtemperature shutdown
 *    is not retried by the part behind the driver's back; retrying is
 *    the driver's discretion, not the data sheet's, and it never does.
 *
 *  - While the limit is locked, the DAC is muted whatever is asked for.
 *
 *  - The output for a full scale input never exceeds
 *    limit->amp_gain_max, and the limiter holds peaks to it as well.
 *    The DAC volume never goes above 0 dB, although the part has
 *    +24 dB (Table 24).
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/bitops.h>
#include <sys/device.h>
#include <sys/kernel.h>
#include <sys/mutex.h>
#include <sys/systm.h>

#include <dev/audio/audio_dai.h>

#include <dev/i2c/i2cvar.h>

#include <dev/fdt/fdtvar.h>

#define	SSM_PWR_CTRL_REG		0x00		/* Table 21 */
#define	 PWR_APWDN_EN			__BIT(7)
#define	 PWR_BSNS_PWDN			__BIT(6)
#define	 PWR_S_RST			__BIT(1)	/* write only */
#define	 PWR_SPWDN			__BIT(0)
#define	SSM_GAIN_CTRL_REG		0x01		/* Table 22 */
#define	 GAIN_ANA_GAIN			__BITS(1,0)
#define	SSM_DAC_CTRL_REG		0x02		/* Table 23 */
#define	 DAC_MUTE			__BIT(6)
#define	 DAC_FS				__BITS(2,0)
#define	  DAC_FS_32_48K			2
#define	SSM_DAC_VOL_REG			0x03		/* Table 24 */
#define	SSM_SAI_CTRL1_REG		0x04		/* Table 25 */
#define	 SAI1_BCLK_POL			__BIT(6)	/* 1: falling */
#define	 SAI1_TDM_BCLKS			__BITS(5,3)
#define	 SAI1_FSYNC_MODE		__BIT(2)	/* TDM 1: 50% */
#define	 SAI1_SDATA_FMT			__BIT(1)	/* 1: no delay */
#define	 SAI1_SAI_MODE			__BIT(0)	/* 1: TDM */
#define	SSM_SAI_CTRL2_REG		0x05		/* Table 26 */
#define	 SAI2_DATA_WIDTH		__BIT(7)	/* 1: 16 bits */
#define	 SAI2_AUTO_SLOT			__BIT(4)
#define	 SAI2_TDM_SLOT			__BITS(3,0)
#define	SSM_LIM_CTRL1_REG		0x07		/* Table 28 */
#define	 LIM1_VBAT_TRACK		__BIT(2)
#define	 LIM1_LIM_EN			__BITS(1,0)
#define	  LIM_EN_ON			1
#define	SSM_LIM_CTRL2_REG		0x08		/* Table 29 */
#define	 LIM2_LIM_THRES			__BITS(7,3)
#define	SSM_STATUS_REG			0x0a		/* Table 31 */
#define	SSM_FAULT_CTRL_REG		0x0b		/* Table 32 */
#define	 FAULT_MRCV			__BIT(5)	/* write only */
#define	 FAULT_ARCV_UV			__BIT(2)	/* 1: manual */
#define	 FAULT_ARCV_OT			__BIT(1)
#define	 FAULT_ARCV_OC			__BIT(0)

/*
 * Reset values of the registers that read back (Table 20), used to
 * recognise the part: it has no identification register.  0x06 and
 * 0x0a are measurements and are skipped.
 */
static const struct {
	uint8_t	reg;
	uint8_t	val;
} ssmamp_reset_values[] = {
	{ SSM_PWR_CTRL_REG,	0x81 },
	{ SSM_GAIN_CTRL_REG,	0x01 },
	{ SSM_DAC_CTRL_REG,	0x32 },
	{ SSM_DAC_VOL_REG,	0x40 },
	{ SSM_SAI_CTRL1_REG,	0x11 },
	{ SSM_SAI_CTRL2_REG,	0x00 },
	{ SSM_LIM_CTRL1_REG,	0xa4 },
	{ SSM_LIM_CTRL2_REG,	0x51 },
	{ 0x09,			0x22 },
	{ SSM_FAULT_CTRL_REG,	0x18 },
};

/*
 * The data sheet gives levels in volts peak: the output for a full
 * scale input at each ANA_GAIN (Specifications, Output Voltage Peak;
 * Table 22) and the limiter threshold (Table 29).  amp_gain_max is in
 * dBV, dB relative to 1 V rms.  For a full scale sine, rms is peak
 * over the square root of two; the values below are
 * 2000 log10(Vpeak / sqrt(2)), rounded up so that a level found at or
 * below a limit is never above it.  The conversion is ours; the data
 * sheet states neither dBV figure.
 */
static const int ssmamp_gain_cdbv[] = {
	1548,		/* 00:  8.4 V peak */
	1900,		/* 01: 12.6 V peak */
	1992,		/* 10: 14.0 V peak */
	2052,		/* 11: 15.0 V peak */
};

/* LIM_THRES codes 00000 to 11111, 15.0 V peak down to 1.0 V peak. */
static const int ssmamp_lim_cdbv[] = {
	2052, 2022, 1992, 1960, 1927, 1893, 1858, 1821,	/* 15.0 .. 11.5 */
	1782, 1742, 1699, 1655, 1608, 1558, 1532, 1506,	/* 11.0 ..  8.0 */
	1478, 1450, 1420, 1390, 1325, 1256, 1180, 1097,	/*  7.75 .. 5.0 */
	1006,  904,  788,  654,  495,  302,   52, -301,	/*  4.5 ..  1.0 */
};

/*
 * VOL: 40h is 0 dB, -0.375 dB per step, FEh is -71.25 dB and FFh is
 * mute (Table 24).  Codes below 40h are gain and are never written.
 */
#define	VOL_0DB				0x40
#define	VOL_STEP_MCDB			375	/* thousandths of a dB */
#define	VOL_MIN				0xfe
#define	VOL_MUTE			0xff

/*
 * Bit clocks per frame the part accepts at 32 kHz to 48 kHz
 * (Clocking).  48 kHz is the only rate this driver sets (DAC_FS).
 */
static const u_int ssmamp_bclk_ratios[] = {
	50, 64, 100, 128, 192, 200, 256, 384, 400, 512
};

struct ssmamp_softc {
	device_t		sc_dev;
	i2c_tag_t		sc_i2c;
	i2c_addr_t		sc_addr;
	int			sc_phandle;

	struct audio_dai_device	sc_dai;

	kmutex_t		sc_lock;	/* all below; before the bus */
	bool			sc_bus;		/* holding the I2C bus */
	bool			sc_fault;
	bool			sc_limited;	/* a limit has been set */
	struct audio_dai_speaker_limit sc_limit;
	int			sc_volume;	/* requested, cdB */
	bool			sc_running;	/* between open and close */
};

static int	ssmamp_match(device_t, cfdata_t, void *);
static void	ssmamp_attach(device_t, device_t, void *);

CFATTACH_DECL_NEW(ssmamp, sizeof(struct ssmamp_softc),
    ssmamp_match, ssmamp_attach, NULL, NULL);

static const struct device_compatible_entry compat_data[] = {
	{ .compat = "adi,ssm3515" },
	DEVICE_COMPAT_EOL
};

/*
 * Mute and power down, as far as the bus still lets us.  There is no
 * pin to fall back on: if I2C is gone, so is the last word.
 */
static void
ssmamp_fault(struct ssmamp_softc *sc, const char *why, uint8_t reg)
{

	KASSERT(mutex_owned(&sc->sc_lock));

	if (!sc->sc_fault) {
		device_printf(sc->sc_dev,
		    "%s at register 0x%02x, shutting down\n", why, reg);
	}
	sc->sc_fault = true;

	if (sc->sc_bus) {
		(void)iic_smbus_write_byte(sc->sc_i2c, sc->sc_addr,
		    SSM_DAC_VOL_REG, VOL_MUTE, 0);
		(void)iic_smbus_write_byte(sc->sc_i2c, sc->sc_addr,
		    SSM_PWR_CTRL_REG, PWR_APWDN_EN | PWR_SPWDN, 0);
	}
}

static int
ssmamp_enter(struct ssmamp_softc *sc)
{
	int error;

	mutex_enter(&sc->sc_lock);
	error = iic_acquire_bus(sc->sc_i2c, 0);
	if (error != 0) {
		ssmamp_fault(sc, "cannot acquire bus", 0);
		mutex_exit(&sc->sc_lock);
		return error;
	}
	sc->sc_bus = true;
	return 0;
}

static void
ssmamp_exit(struct ssmamp_softc *sc)
{

	KASSERT(sc->sc_bus);
	sc->sc_bus = false;
	iic_release_bus(sc->sc_i2c, 0);
	mutex_exit(&sc->sc_lock);
}

/* Read twice; see tasamp_read() for why. */
static int
ssmamp_read(struct ssmamp_softc *sc, uint8_t reg, uint8_t *val)
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
		ssmamp_fault(sc, "read failed", reg);
		return error;
	}
	if (again != *val) {
		ssmamp_fault(sc, "unstable read", reg);
		return EIO;
	}
	return 0;
}

/*
 * Write and read back.  Not for S_RST or MRCV, which are write only
 * (Tables 21, 32); neither is ever set through here.
 */
static int
ssmamp_write(struct ssmamp_softc *sc, uint8_t reg, uint8_t val)
{
	uint8_t back;
	int error;

	KASSERT(mutex_owned(&sc->sc_lock));
	KASSERT(sc->sc_bus);
	KASSERT(reg != SSM_PWR_CTRL_REG || (val & PWR_S_RST) == 0);
	KASSERT(reg != SSM_FAULT_CTRL_REG || (val & FAULT_MRCV) == 0);

	if (sc->sc_fault)
		return EIO;
	error = iic_smbus_write_byte(sc->sc_i2c, sc->sc_addr, reg, val, 0);
	if (error != 0) {
		ssmamp_fault(sc, "write failed", reg);
		return error;
	}
	error = ssmamp_read(sc, reg, &back);
	if (error != 0)
		return error;
	if (back != val) {
		ssmamp_fault(sc, "read back mismatch", reg);
		return EIO;
	}
	return 0;
}

static int
ssmamp_update(struct ssmamp_softc *sc, uint8_t reg, uint8_t mask,
    uint8_t val)
{
	uint8_t old;
	int error;

	error = ssmamp_read(sc, reg, &old);
	if (error != 0)
		return error;
	return ssmamp_write(sc, reg, (old & ~mask) | (val & mask));
}

/* Highest ANA_GAIN whose full scale is at or below max_cdbv, or -1. */
static int
ssmamp_gain(int max_cdbv)
{
	int code;

	for (code = __arraycount(ssmamp_gain_cdbv) - 1; code >= 0; code--) {
		if (ssmamp_gain_cdbv[code] <= max_cdbv)
			break;
	}
	return code;
}

/* Highest limiter threshold at or below max_cdbv, or -1. */
static int
ssmamp_lim_thres(int max_cdbv)
{
	u_int code;

	for (code = 0; code < __arraycount(ssmamp_lim_cdbv); code++) {
		if (ssmamp_lim_cdbv[code] <= max_cdbv)
			return code;
	}
	return -1;
}

/*
 * VOL code for an attenuation of cdb (0 or below), rounded towards
 * more attenuation.
 */
static uint8_t
ssmamp_vol(int cdb)
{
	int code;

	if (cdb > 0)
		cdb = 0;
	code = VOL_0DB + howmany(-cdb * 10, VOL_STEP_MCDB);
	return code > VOL_MIN ? VOL_MUTE : (uint8_t)code;
}

/*
 * Bring the registers in line with the limit and the requested volume.
 * Called with any change to either.
 */
static int
ssmamp_apply(struct ssmamp_softc *sc)
{
	const struct audio_dai_speaker_limit *l = &sc->sc_limit;
	int gain, thres, cap, error;
	uint8_t cur;
	bool quiet;

	KASSERT(mutex_owned(&sc->sc_lock));

	if (sc->sc_fault)
		return EIO;

	/*
	 * Below the lowest analog gain, the rest of the way down is taken
	 * off the DAC volume; the limiter stops at 1.0 V peak and is not
	 * relied on for that.
	 */
	if (sc->sc_limited) {
		gain = ssmamp_gain(l->amp_gain_max);
		cap = gain < 0 ? l->amp_gain_max - ssmamp_gain_cdbv[0] : 0;
		thres = ssmamp_lim_thres(l->amp_gain_max);
	} else {
		gain = -1;
		cap = 0;
		thres = -1;
	}
	quiet = !sc->sc_limited || l->locked;

	/*
	 * Order matters.  Going quieter, mute before anything else moves;
	 * going louder, unmute last.
	 */
	if (quiet || !sc->sc_running) {
		error = ssmamp_write(sc, SSM_DAC_VOL_REG, VOL_MUTE);
		if (error == 0) {
			error = ssmamp_update(sc, SSM_DAC_CTRL_REG, DAC_MUTE,
			    DAC_MUTE);
		}
		if (error == 0 && (!sc->sc_limited || !sc->sc_running)) {
			error = ssmamp_update(sc, SSM_PWR_CTRL_REG, PWR_SPWDN,
			    PWR_SPWDN);
		}
		/* Without a usable limit, also the lowest analog gain. */
		if (error == 0) {
			error = ssmamp_update(sc, SSM_GAIN_CTRL_REG,
			    GAIN_ANA_GAIN,
			    __SHIFTIN(MAX(gain, 0), GAIN_ANA_GAIN));
		}
		return error;
	}

	/*
	 * Playing.  Tighten the limiter first; move the analog gain down
	 * before the volume and up after it, so that no step passes
	 * through a level above both ends.  With the caps above the volume
	 * only tightens when the gain falls, so the other order would be
	 * safe too; this one stays safe if that changes.  Below the lowest
	 * threshold the volume cap alone holds the level, and the limiter
	 * is let go only once that cap is in.
	 */
	if (thres >= 0) {
		error = ssmamp_update(sc, SSM_LIM_CTRL2_REG, LIM2_LIM_THRES,
		    __SHIFTIN(thres, LIM2_LIM_THRES));
		/* LIM_EN 01 with a fixed threshold (Table 19). */
		if (error == 0) {
			error = ssmamp_update(sc, SSM_LIM_CTRL1_REG,
			    LIM1_VBAT_TRACK | LIM1_LIM_EN,
			    __SHIFTIN(LIM_EN_ON, LIM1_LIM_EN));
		}
		if (error != 0)
			return error;
	}
	if ((error = ssmamp_read(sc, SSM_GAIN_CTRL_REG, &cur)) != 0)
		return error;
	gain = MAX(gain, 0);
	if ((u_int)gain < __SHIFTOUT(cur, GAIN_ANA_GAIN)) {
		error = ssmamp_write(sc, SSM_GAIN_CTRL_REG,
		    (cur & ~GAIN_ANA_GAIN) | __SHIFTIN(gain, GAIN_ANA_GAIN));
	}
	if (error == 0) {
		error = ssmamp_write(sc, SSM_DAC_VOL_REG,
		    ssmamp_vol(MIN(sc->sc_volume, cap)));
	}
	if (error == 0 && (u_int)gain > __SHIFTOUT(cur, GAIN_ANA_GAIN)) {
		error = ssmamp_write(sc, SSM_GAIN_CTRL_REG,
		    (cur & ~GAIN_ANA_GAIN) | __SHIFTIN(gain, GAIN_ANA_GAIN));
	}
	if (error == 0 && thres < 0) {
		error = ssmamp_update(sc, SSM_LIM_CTRL1_REG,
		    LIM1_VBAT_TRACK | LIM1_LIM_EN, 0);
	}
	if (error == 0)
		error = ssmamp_update(sc, SSM_PWR_CTRL_REG, PWR_SPWDN, 0);
	if (error == 0)
		error = ssmamp_update(sc, SSM_DAC_CTRL_REG, DAC_MUTE, 0);
	return error;
}

static int
ssmamp_set_speaker_limit(audio_dai_tag_t dai,
    const struct audio_dai_speaker_limit *limit)
{
	struct ssmamp_softc * const sc = audio_dai_private(dai);
	int error;

	if ((error = ssmamp_enter(sc)) != 0)
		return error;
	sc->sc_limit = *limit;
	sc->sc_limited = true;
	error = ssmamp_apply(sc);
	ssmamp_exit(sc);

	return error;
}

static int
ssmamp_set_volume(audio_dai_tag_t dai, int cdb)
{
	struct ssmamp_softc * const sc = audio_dai_private(dai);
	int error;

	if ((error = ssmamp_enter(sc)) != 0)
		return error;
	sc->sc_volume = MIN(cdb, 0);
	error = ssmamp_apply(sc);
	ssmamp_exit(sc);

	return error;
}

/*
 * TDM with the part's own slot width (TDM_BCLKS) equal to the bus's,
 * one mono slot of the first sixteen (TDM_SLOT), and a frame length the
 * part accepts.  There is no sense data; txmask must be empty.
 */
static int
ssmamp_set_tdm_slot(audio_dai_tag_t dai, uint32_t txmask, uint32_t rxmask,
    u_int slots, u_int width)
{
	struct ssmamp_softc * const sc = audio_dai_private(dai);
	u_int bclks, i;
	int error;

	if (txmask != 0 || popcount32(rxmask) != 1 ||
	    ffs32(rxmask) - 1 > 15 || ffs32(rxmask) > (int)slots)
		return EINVAL;

	switch (width) {
	case 16:
		bclks = 0;
		break;
	case 24:
		bclks = 1;
		break;
	case 32:
		bclks = 2;
		break;
	case 48:
		bclks = 3;
		break;
	case 64:
		bclks = 4;
		break;
	default:
		return EINVAL;
	}
	for (i = 0; i < __arraycount(ssmamp_bclk_ratios); i++) {
		if (ssmamp_bclk_ratios[i] == slots * width)
			break;
	}
	if (i == __arraycount(ssmamp_bclk_ratios))
		return EINVAL;

	if ((error = ssmamp_enter(sc)) != 0)
		return error;
	error = ssmamp_update(sc, SSM_SAI_CTRL1_REG,
	    SAI1_TDM_BCLKS | SAI1_SAI_MODE,
	    __SHIFTIN(bclks, SAI1_TDM_BCLKS) | SAI1_SAI_MODE);
	if (error == 0) {
		/* 24-bit data fits any slot of 24 bits or more. */
		error = ssmamp_update(sc, SSM_SAI_CTRL2_REG,
		    SAI2_DATA_WIDTH | SAI2_AUTO_SLOT | SAI2_TDM_SLOT,
		    (width == 16 ? SAI2_DATA_WIDTH : 0) |
		    __SHIFTIN(ffs32(rxmask) - 1, SAI2_TDM_SLOT));
	}
	ssmamp_exit(sc);

	return error;
}

/*
 * In TDM mode a frame starts on the rising edge of FSYNC (TDM Operating
 * Mode); the data sheet says nothing different for the 50% FSYNC mode,
 * which is the one a word select clock is.  The I2S bus specification
 * starts the left channel on the falling edge of word select, so plain
 * I2S cannot be taken and I2S with an inverted frame can.  Left
 * justified starts on the rising edge already.  SDATA_FMT gives the
 * one-clock delay of I2S; BCLK_POL latches on the falling edge when the
 * bit clock is inverted.
 */
static int
ssmamp_set_format(audio_dai_tag_t dai, u_int format)
{
	struct ssmamp_softc * const sc = audio_dai_private(dai);
	const u_int pol = __SHIFTOUT(format, AUDIO_DAI_POLARITY_MASK);
	bool rising, delay;
	int error;

	if (__SHIFTOUT(format, AUDIO_DAI_CLOCK_MASK) != AUDIO_DAI_CLOCK_CBS_CFS)
		return EINVAL;
	switch (format & AUDIO_DAI_FORMAT_MASK) {
	case AUDIO_DAI_FORMAT_I2S:
		delay = true;
		rising = false;
		break;
	case AUDIO_DAI_FORMAT_LJ:
		delay = false;
		rising = true;
		break;
	default:
		return EINVAL;
	}
	if (AUDIO_DAI_POLARITY_F(pol))
		rising = !rising;
	if (!rising)
		return EINVAL;

	if ((error = ssmamp_enter(sc)) != 0)
		return error;
	error = ssmamp_update(sc, SSM_SAI_CTRL1_REG,
	    SAI1_BCLK_POL | SAI1_FSYNC_MODE | SAI1_SDATA_FMT,
	    (AUDIO_DAI_POLARITY_B(pol) ? SAI1_BCLK_POL : 0) |
	    SAI1_FSYNC_MODE | (delay ? 0 : SAI1_SDATA_FMT));
	ssmamp_exit(sc);
	return error;
}

/*
 * The DAC is muted or the part powered down before the bit clock
 * stops, as the data sheet asks for a quiet power-down (Pop and Click
 * Suppression): close comes before the clocks are halted.
 */
static int
ssmamp_open(void *priv, int flags)
{
	struct ssmamp_softc * const sc = priv;
	int error;

	if ((error = ssmamp_enter(sc)) != 0)
		return error;
	sc->sc_running = true;
	error = ssmamp_apply(sc);
	ssmamp_exit(sc);

	return error;
}

static void
ssmamp_close(void *priv)
{
	struct ssmamp_softc * const sc = priv;

	if (ssmamp_enter(sc) != 0)
		return;
	sc->sc_running = false;
	(void)ssmamp_apply(sc);
	ssmamp_exit(sc);
}

static const struct audio_hw_if ssmamp_hw_if = {
	.open = ssmamp_open,
	.close = ssmamp_close,
};

static audio_dai_tag_t
ssmamp_dai_get_tag(device_t dev, const void *data, size_t len)
{
	struct ssmamp_softc * const sc = device_private(dev);

	if (len != 4)
		return NULL;

	return &sc->sc_dai;
}

static struct fdtbus_dai_controller_func ssmamp_dai_funcs = {
	.get_tag = ssmamp_dai_get_tag
};

/*
 * Reset, check that every register holds its reset value, then leave
 * the part silent: powered down, muted, lowest gain, 48 kHz, and fault
 * recovery manual.  The data sheet gives no time for the reset to
 * complete; the reads that follow fail the attach if it has not, which
 * leaves the part in the power-down it resets to.
 */
static int
ssmamp_init(struct ssmamp_softc *sc)
{
	uint8_t val;
	u_int i;
	int error;

	KASSERT(mutex_owned(&sc->sc_lock));

	error = iic_smbus_write_byte(sc->sc_i2c, sc->sc_addr,
	    SSM_PWR_CTRL_REG, PWR_APWDN_EN | PWR_S_RST | PWR_SPWDN, 0);
	if (error != 0) {
		ssmamp_fault(sc, "reset failed", SSM_PWR_CTRL_REG);
		return error;
	}
	for (i = 0; i < __arraycount(ssmamp_reset_values); i++) {
		error = ssmamp_read(sc, ssmamp_reset_values[i].reg, &val);
		if (error != 0)
			return error;
		if (val != ssmamp_reset_values[i].val) {
			ssmamp_fault(sc, "not an SSM3515 after reset",
			    ssmamp_reset_values[i].reg);
			return ENXIO;
		}
	}

	if ((error = ssmamp_apply(sc)) != 0)
		return error;
	if ((error = ssmamp_update(sc, SSM_FAULT_CTRL_REG,
	    FAULT_ARCV_UV | FAULT_ARCV_OT | FAULT_ARCV_OC,
	    FAULT_ARCV_UV | FAULT_ARCV_OT | FAULT_ARCV_OC)) != 0)
		return error;
	return ssmamp_update(sc, SSM_DAC_CTRL_REG, DAC_FS,
	    __SHIFTIN(DAC_FS_32_48K, DAC_FS));
}

static int
ssmamp_match(device_t parent, cfdata_t match, void *aux)
{
	struct i2c_attach_args *ia = aux;
	int match_result;

	if (iic_use_direct_match(ia, match, compat_data, &match_result))
		return match_result;

	/* This device is direct-config only */

	return 0;
}

static void
ssmamp_attach(device_t parent, device_t self, void *aux)
{
	struct ssmamp_softc * const sc = device_private(self);
	struct i2c_attach_args * const ia = aux;
	int error;

	sc->sc_dev = self;
	sc->sc_phandle = devhandle_to_of(device_handle(self));
	sc->sc_i2c = ia->ia_tag;
	sc->sc_addr = ia->ia_addr;
	sc->sc_volume = 0;
	mutex_init(&sc->sc_lock, MUTEX_DEFAULT, IPL_NONE);

	aprint_naive("\n");
	aprint_normal(": ADI SSM3515 speaker amplifier\n");

	if ((error = ssmamp_enter(sc)) == 0) {
		error = ssmamp_init(sc);
		ssmamp_exit(sc);
	}
	if (error != 0) {
		aprint_error_dev(self, "init failed, error %d\n", error);
		return;
	}

	sc->sc_dai.dai_set_format = ssmamp_set_format;
	sc->sc_dai.dai_set_tdm_slot = ssmamp_set_tdm_slot;
	sc->sc_dai.dai_set_speaker_limit = ssmamp_set_speaker_limit;
	sc->sc_dai.dai_set_volume = ssmamp_set_volume;
	sc->sc_dai.dai_hw_if = &ssmamp_hw_if;
	sc->sc_dai.dai_dev = self;
	sc->sc_dai.dai_priv = sc;
	fdtbus_register_dai_controller(self, sc->sc_phandle,
	    &ssmamp_dai_funcs);
}
