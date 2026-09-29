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
 * Cirrus Logic CS42L42 headphone codec, and the CS42L83 of Apple
 * Silicon Macs: headphone playback from the audio serial port.
 *
 * Written from the data sheet, DS1083F8; section and example numbers
 * below refer to it.  The CS42L83 has no public data sheet; the Linux
 * driver runs it as a CS42L42 whose registers reset to different
 * values, so every register this driver depends on is written, never
 * assumed from reset.  Its device ID, 0x42A83, is also from there.
 *
 * The sequence is Example 5-1: slave mode, SCLK 12.288 MHz used as
 * MCLK, 48 kHz.  The machine driver must keep SCLK running from the
 * moment it reports it (set_sysclk) until detach, because stopping it
 * needs a switch back to the internal oscillator first (4.7.1.2).
 *
 * Headphones are loud: the full scale is set 6 dB down (7.13.1, as the
 * example does) and the volume starts at CSCODEC_INITIAL_CDB, muted
 * until opened.
 *
 * Plug presence is tip sense (4.14), polled: the part's interrupt line
 * is not used.  When a plug arrives and the headphones are not playing,
 * the headset type is found automatically as in Example 5-5 steps 10 to
 * 17 (4.13); load detection, from step 18 on, is not done.  Both are
 * reported by sysctl, hw.<dev>.plugged and hw.<dev>.headset.
 *
 * Opened for reading with a headset found (types 1 and 2), the headset
 * microphone is recorded: the HS bias in normal mode (7.9.5), the ADC
 * powered up, and channel 1 of the ASP transmitter driven in the slot
 * the machine driver gives (7.21).  No example of the data sheet covers
 * recording over the ASP: Ex. 5-3 does it over SoundWire and differs
 * only in powering up the ADC; the ASP settings are the register
 * descriptions'.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/bitops.h>
#include <sys/bus.h>
#include <sys/device.h>
#include <sys/file.h>
#include <sys/kernel.h>
#include <sys/callout.h>
#include <sys/mutex.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/workqueue.h>

#include <dev/audio/audio_dai.h>

#include <dev/i2c/i2cvar.h>

#include <dev/fdt/fdtvar.h>

/* Registers are page << 8 | offset; offset 0 of every page selects it. */
#define	CS_PAGE_REG		0x00
#define	CS_DEVID_AB		0x1001		/* 7.3.1-7.3.3 */
#define	CS_DEVID_CD		0x1002
#define	CS_DEVID_E		0x1003
#define	 CS42L42_ID		0x42a42
#define	 CS42L83_ID		0x42a83		/* Linux cs42l42.h */
#define	CS_SRC_CTL		0x1007		/* 4.21 in Ex. 5-1 */
#define	 SRC_CTL_EQ_BYPASS	__BIT(4)
#define	CS_MCLK_CTL		0x1009		/* 7.3.8 */
#define	 MCLK_CTL_INTERNAL_FS	__BIT(1)	/* MCLK/256 */
#define	CS_PWR_CTL1		0x1101		/* 7.4.1 */
#define	 PWR1_ASP_DAO_PDN	__BIT(7)
#define	 PWR1_ASP_DAI_PDN	__BIT(6)
#define	 PWR1_MIXER_PDN		__BIT(5)
#define	 PWR1_EQ_PDN		__BIT(4)
#define	 PWR1_HP_PDN		__BIT(3)
#define	 PWR1_ADC_PDN		__BIT(2)
#define	 PWR1_RSVD1		__BIT(1)	/* written as 1 in Ex. 5-1/5-2 */
#define	 PWR1_PDN_ALL		__BIT(0)
#define	CS_PWR_CTL2		0x1102		/* 7.4.2 */
#define	CS_HSDET_CTL1		0x111f		/* 7.4.11 */
#define	CS_HSDET_CTL2		0x1120		/* 7.4.12 */
#define	 HSDET_CTRL		__BITS(7,6)
#define	  HSDET_AUTO_DISABLED	2
#define	  HSDET_AUTO_ACTIVE	3
#define	CS_HSDET_STATUS		0x1124		/* 7.4.14 */
#define	 HSDET_TYPE		__BITS(1,0)	/* 00: type 1 .. 11: type 4 */
#define	CS_OSC_SWITCH		0x1107		/* 7.4.6 */
#define	 OSC_SCLK_PRESENT	__BIT(0)
#define	CS_OSC_STATUS		0x1109		/* 7.4.7 */
#define	 OSC_PDNB_STAT		__BIT(2)
#define	 OSC_SW_SEL_STAT	__BITS(1,0)
#define	  OSC_SEL_SCLK		2
#define	CS_MCLK_SRC		0x1201		/* 7.5.1: 0 = SCLK, /1 */
#define	CS_FSYNC_PW_LB		0x1203
#define	CS_FSYNC_P_LB		0x1205
#define	CS_FSYNC_P_UB		0x1206
#define	CS_ASP_CLK_CFG		0x1207		/* 7.5.7 */
#define	 ASP_SCLK_EN		__BIT(5)
#define	 ASP_SCPOL_IN_ADC	__BIT(3)	/* 1: launch on falling */
#define	 ASP_SCPOL_IN_DAC	__BIT(2)	/* 1: latch on rising */
#define	CS_ASP_FRM_CFG		0x1208		/* 7.5.8 */
#define	 ASP_STP		__BIT(4)	/* 1: frame starts low->high */
#define	 ASP_FSD		__BITS(2,0)	/* half SCLKs */
#define	CS_CODEC_INT_STATUS	0x1308		/* 7.6.6 */
#define	 HSDET_AUTO_DONE	__BIT(1)
#define	CS_CODEC_INT_MASK	0x131b		/* 7.6.18 */
#define	CS_PLL_CTL1		0x1501		/* 7.7.1 */
#define	 PLL_START		__BIT(0)
#define	CS_DAC_CTL1		0x1f01
#define	CS_DAC_CTL2		0x1f06		/* 7.12.2, values of Ex. 5-5 */
#define	CS_HP_CTL		0x2001		/* 7.13.1 */
#define	 HP_ANA_MUTE_B		__BIT(3)
#define	 HP_ANA_MUTE_A		__BIT(2)
#define	 HP_FULL_SCALE_VOL	__BIT(1)	/* -6 dB */
#define	 HP_RSVD0		__BIT(0)	/* written as 1 in Ex. 5-1 */
#define	CS_MIXER_CHA_VOL	0x2301		/* 7.15.1: -1 dB steps */
#define	CS_MIXER_ADC_VOL	0x2302
#define	CS_MIXER_CHB_VOL	0x2303
#define	 MIXER_VOL_MIN_DB	62
#define	 MIXER_VOL_MUTE		0x3f
#define	CS_SP_RX_CH_SEL		0x2501
#define	CS_SP_RX_ISOC		0x2502
#define	CS_SP_RX_FS		0x2503		/* 7.17.3 */
#define	 SP_RX_FS_48K		0x8c
#define	CS_SRC_SDIN_FS		0x2601		/* 0x40: autodetect */
#define	CS_SPDIF_CTL1		0x2801		/* 7.20.1 */
#define	 SPDIF_TX_PDN		__BIT(0)
#define	CS_ADC_CTL		0x1d01		/* 7.11.1 */
#define	CS_ADC_VOL		0x1d03		/* 7.11.3: 0 dB */
#define	CS_ADC_WNF_HPF		0x1d04		/* 7.11.4 */
#define	 ADC_WNF_HPF_DEFAULT	0x71		/* HPF on, as it must stay */
#define	CS_SP_TX_ISOC		0x2505		/* 7.17.5 */
#define	 SP_TX_ISOC_NATIVE	0x04		/* the default */
#define	CS_SP_TX_FS		0x2506		/* 7.17.6 */
#define	 SP_TX_FS_48K		0x0c
#define	CS_ASP_TX_EN		0x2901		/* 7.21.1 */
#define	 ASP_TX_EN		__BIT(0)
#define	CS_ASP_TX_CH_EN		0x2902		/* 7.21.2 */
#define	 ASP_TX_CH1_EN		__BIT(0)
#define	CS_ASP_TX_CH_RES	0x2903		/* 7.21.3 */
#define	 ASP_TX_RES_24		0x0a		/* both channels 24 bits */
#define	CS_ASP_TX_CH1_MSB	0x2904		/* 7.21.4 */
#define	CS_ASP_TX_CH1_LSB	0x2905		/* 7.21.5 */
#define	CS_HSBIAS_SENSE		0x1b70		/* 7.9.1 */
#define	 HSBIAS_SENSE_DEFAULT	0x03
#define	 TIP_SENSE_EN		__BIT(5)
#define	CS_TIP_SENSE_CTL2	0x1b73		/* 7.9.4 */
#define	 TIP_SENSE_CTRL		__BITS(7,6)
#define	  TIP_SENSE_SHORT_DET	3		/* weak pull-up on */
#define	 TIP_SENSE_INV		__BIT(5)
#define	 TIP_SENSE_DEBOUNCE	__BITS(1,0)
#define	  TIP_SENSE_DBNC_500MS	2		/* the default */
#define	CS_MISC_DET_CTL		0x1b74		/* 7.9.5 */
#define	 MISC_DET_DEFAULT	0x03		/* HSBIAS weak ground */
#define	 MISC_DET_HSBIAS_2V7	0x07		/* Ex. 5-5 11.4 */
#define	 MISC_DET_NORMAL_2V7	0x1f		/* DETECT_MODE 11: normal */
#define	CS_MIC_DET_CTL1		0x1b75		/* 7.9.6 */
#define	 LATCH_TO_VP		__BIT(7)
#define	 HS_DETECT_LEVEL_DEFAULT 0x1f
#define	CS_DET_STATUS1		0x1b77		/* 7.9.8 */
#define	 DET_TIP_SENSE		__BIT(7)	/* 1: plugged */
#define	CS_ASP_RX_EN		0x2a01
#define	 ASP_RX0_CH12_EN	0x0c		/* channels 1 and 2 */
#define	CS_ASP_RX_CH1_RES	0x2a02		/* 7.22.2: 0x02 = 24 bit */
#define	CS_ASP_RX_CH1_MSB	0x2a03
#define	CS_ASP_RX_CH1_LSB	0x2a04
#define	CS_ASP_RX_CH2_RES	0x2a05
#define	CS_ASP_RX_CH2_MSB	0x2a06
#define	CS_ASP_RX_CH2_LSB	0x2a07

#define	CSCODEC_SCLK_HZ		12288000	/* Ex. 5-1 */
#define	CSCODEC_RESET_WAIT_US	2500		/* Ex. 5-1 step 2 */
#define	CSCODEC_OSC_WAIT_US	200		/* >= 150, 4.7.1.1 */
#define	CSCODEC_HP_WAIT_US	10000		/* Ex. 5-1 step 11 */
#define	CSCODEC_INITIAL_CDB	(-3000)
/*
 * Ex. 5-5 11.5: t_startup + t_mb-rise at HSBIAS_RAMP 10, the default
 * (7.10.1): 36 + 25 ms.  Table 3-15 gives typical values only.
 */
#define	CSCODEC_HSBIAS_WAIT_MS	61
#define	CSCODEC_HSDET_WAIT_US	100		/* Ex. 5-5 11.8 */
/*
 * Waiting for HSDET_AUTO_DONE (Ex. 5-5 12.1): the data sheet gives
 * phases of HSDET_AUTO_TIME (10 us here) but no bound on their number;
 * the limit is ours.
 */
#define	CSCODEC_HSDET_DONE_US	10000
/*
 * Polling of plug presence.  A change is taken after two equal
 * samples, on top of the part's own unplug debounce; both the period
 * and the count are ours.
 */
#define	CSCODEC_POLL_MS		250

static const struct device_compatible_entry compat_data[] = {
	{ .compat = "cirrus,cs42l83",	.value = CS42L83_ID },
	{ .compat = "cirrus,cs42l42",	.value = CS42L42_ID },
	DEVICE_COMPAT_EOL
};

struct cscodec_softc {
	device_t		sc_dev;
	i2c_tag_t		sc_i2c;
	i2c_addr_t		sc_addr;
	int			sc_phandle;
	uint32_t		sc_id;
	struct fdtbus_gpio_pin	*sc_reset;

	struct audio_dai_device	sc_dai;

	kmutex_t		sc_lock;	/* all below; before the bus */
	int			sc_page;	/* selected, -1 unknown */
	bool			sc_ready;	/* Ex. 5-1 through step 5 */
	bool			sc_running;
	int			sc_volume;	/* cdB */
	uint8_t			sc_frm_cfg;	/* from set_format */
	uint8_t			sc_clk_pol;
	uint16_t		sc_bit_a, sc_bit_b;	/* from set_tdm_slot */
	int			sc_bit_tx;	/* mic, -1 none */
	bool			sc_recording;	/* opened for reading */
	bool			sc_ts_inv;	/* cirrus,ts-inv */
	bool			sc_plugged;	/* as last reported */
	bool			sc_sample;	/* last raw sample */
	bool			sc_typed;	/* sc_headset is current */
	u_int			sc_headset;	/* 1..4 of Table 4-22, 0: none */

	struct workqueue	*sc_wq;
	struct work		sc_work;
	callout_t		sc_poll;
	struct sysctllog	*sc_sysctllog;
	int			sc_sysctl_plugged, sc_sysctl_headset;
};

static int	cscodec_match(device_t, cfdata_t, void *);
static void	cscodec_attach(device_t, device_t, void *);

CFATTACH_DECL_NEW(cscodec, sizeof(struct cscodec_softc),
    cscodec_match, cscodec_attach, NULL, NULL);

/* Select the page of reg, then access its offset (4.16). */
static int
cscodec_page(struct cscodec_softc *sc, uint16_t reg)
{
	const int page = reg >> 8;
	int error;

	if (page == sc->sc_page)
		return 0;
	error = iic_smbus_write_byte(sc->sc_i2c, sc->sc_addr, CS_PAGE_REG,
	    page, 0);
	sc->sc_page = error == 0 ? page : -1;
	return error;
}

static int
cscodec_read(struct cscodec_softc *sc, uint16_t reg, uint8_t *val)
{
	int error;

	KASSERT(mutex_owned(&sc->sc_lock));
	if ((error = cscodec_page(sc, reg)) != 0)
		return error;
	return iic_smbus_read_byte(sc->sc_i2c, sc->sc_addr, reg & 0xff, val,
	    0);
}

static int
cscodec_write(struct cscodec_softc *sc, uint16_t reg, uint8_t val)
{
	int error;

	KASSERT(mutex_owned(&sc->sc_lock));
	if ((error = cscodec_page(sc, reg)) != 0)
		return error;
	return iic_smbus_write_byte(sc->sc_i2c, sc->sc_addr, reg & 0xff, val,
	    0);
}

static int
cscodec_enter(struct cscodec_softc *sc)
{
	int error;

	mutex_enter(&sc->sc_lock);
	if ((error = iic_acquire_bus(sc->sc_i2c, 0)) != 0)
		mutex_exit(&sc->sc_lock);
	return error;
}

static void
cscodec_exit(struct cscodec_softc *sc)
{

	iic_release_bus(sc->sc_i2c, 0);
	mutex_exit(&sc->sc_lock);
}

/* Mixer attenuation code for cdB: 1 dB steps, rounded down, or mute. */
static uint8_t
cscodec_vol(int cdb)
{
	int db;

	if (cdb > 0)
		cdb = 0;
	db = howmany(-cdb, 100);
	return db > MIXER_VOL_MIN_DB ? MIXER_VOL_MUTE : (uint8_t)db;
}

/*
 * Example 5-1 up to step 5, with the preconditions of its note: from
 * reset to SCLK enabled, headphone path still powered down.
 */
static int
cscodec_init(struct cscodec_softc *sc)
{
	uint8_t a, b, c, st;
	uint32_t id;
	int error;

	KASSERT(mutex_owned(&sc->sc_lock));

	/*
	 * Step 1: RESET is held low from attach, while SCLK started.
	 * The line's value is the pin level, RESET being active low, as
	 * the binding uses it (Apple marks it GPIO_ACTIVE_HIGH).
	 */
	if (sc->sc_reset != NULL)
		fdtbus_gpio_write(sc->sc_reset, 1);
	delay(CSCODEC_RESET_WAIT_US);		/* step 2 */
	sc->sc_page = -1;

	if ((error = cscodec_read(sc, CS_DEVID_AB, &a)) != 0 ||
	    (error = cscodec_read(sc, CS_DEVID_CD, &b)) != 0 ||
	    (error = cscodec_read(sc, CS_DEVID_E, &c)) != 0)
		return error;
	id = (uint32_t)a << 12 | (uint32_t)b << 4 | (c >> 4);
	if (id != sc->sc_id) {
		device_printf(sc->sc_dev, "device id %05x, expected %05x\n",
		    id, sc->sc_id);
		return ENXIO;
	}

#define	W(r, v) do {							\
	if ((error = cscodec_write(sc, (r), (v))) != 0)			\
		return error;						\
} while (0)
	/* Note to 5.1: PDN_ALL and SPDIF_TX_PDN set, PLL_START clear. */
	W(CS_PWR_CTL1, 0xff);
	W(CS_SPDIF_CTL1, SPDIF_TX_PDN);
	W(CS_PLL_CTL1, 0);

	W(CS_PWR_CTL2, 0x83);			/* step 3 */
	/*
	 * 4.1: the switch starts on a 0-to-1 transition of SCLK_PRESENT
	 * (7.4.6).  It resets to 0, but without a reset line the part may
	 * still have it set; go back to the oscillator first then, which
	 * takes the same 150 us.
	 */
	if ((error = cscodec_read(sc, CS_OSC_SWITCH, &st)) != 0)
		return error;
	if (st & OSC_SCLK_PRESENT) {
		W(CS_OSC_SWITCH, 0);
		delay(CSCODEC_OSC_WAIT_US);
	}
	W(CS_OSC_SWITCH, OSC_SCLK_PRESENT);
	/* No I2C for 150 us after the switch starts (4.7.1.1). */
	delay(CSCODEC_OSC_WAIT_US);
	if ((error = cscodec_read(sc, CS_OSC_STATUS, &st)) != 0)
		return error;
	/*
	 * 4.2: Ex. 5-1 gives 0x01 here, but 7.4.7 and 4.7.1 both make
	 * 01 "RCO selected" and 10 "SCLK selected"; the two agree, the
	 * example is taken to be wrong.
	 */
	if (__SHIFTOUT(st, OSC_SW_SEL_STAT) != OSC_SEL_SCLK ||
	    (st & OSC_PDNB_STAT) != 0) {
		device_printf(sc->sc_dev, "clock switch to SCLK not done "
		    "(status 0x%02x)\n", st);
		return EIO;
	}
	W(CS_MCLK_CTL, MCLK_CTL_INTERNAL_FS);	/* 4.3 */
	W(CS_MCLK_SRC, 0);			/* 4.4 */
	W(CS_FSYNC_P_LB, 0xff);			/* 4.5: 256 SCLKs */
	W(CS_FSYNC_P_UB, 0x00);			/* 4.6 */
	W(CS_FSYNC_PW_LB, 0x1f);		/* 4.7 */
	W(CS_ASP_CLK_CFG, sc->sc_clk_pol);	/* 4.8 */
	W(CS_ASP_FRM_CFG, sc->sc_frm_cfg);	/* 4.9 */
	W(CS_SP_RX_ISOC, 0x04);			/* 4.10 */
	W(CS_SP_RX_CH_SEL, 0x04);		/* 4.11 */
	W(CS_SP_RX_FS, SP_RX_FS_48K);		/* 4.12 */
	W(CS_ASP_RX_EN, 0x00);			/* 4.13 */
	W(CS_ASP_RX_CH1_RES, 0x02);		/* 4.14 */
	W(CS_ASP_RX_CH1_MSB, sc->sc_bit_a >> 8);	/* 4.15 */
	W(CS_ASP_RX_CH1_LSB, sc->sc_bit_a & 0xff);	/* 4.16 */
	W(CS_SRC_SDIN_FS, 0x40);		/* 4.17 */
	W(CS_ASP_RX_CH2_RES, 0x02);		/* 4.18 */
	W(CS_ASP_RX_CH2_MSB, sc->sc_bit_b >> 8);	/* 4.19 */
	W(CS_ASP_RX_CH2_LSB, sc->sc_bit_b & 0xff);	/* 4.20 */
	W(CS_SRC_CTL, SRC_CTL_EQ_BYPASS);	/* 4.21 */
	W(CS_ASP_CLK_CFG, ASP_SCLK_EN | sc->sc_clk_pol);	/* step 5 */
	/* Muted until opened. */
	W(CS_MIXER_CHA_VOL, MIXER_VOL_MUTE);
	W(CS_MIXER_ADC_VOL, MIXER_VOL_MUTE);
	W(CS_MIXER_CHB_VOL, MIXER_VOL_MUTE);
	W(CS_HP_CTL, HP_ANA_MUTE_B | HP_ANA_MUTE_A | HP_FULL_SCALE_VOL |
	    HP_RSVD0);

	/*
	 * Tip sense, 4.14.5 steps 1 to 3 and 5: the codec out of power
	 * down with every block still down (as Ex. 5-2 step 2 leaves it),
	 * the tip-sense front end on, VP latches transparent, and the
	 * circuit in short detect so that its pull-up holds an open pin
	 * high.  Ring sense (step 4) is not used.
	 *
	 * TIP_SENSE_INV comes from cirrus,ts-inv, whose binding gives 1 as
	 * "open when unplugged" (TS in 4.14.2) and 0 as "shorted to tip
	 * when unplugged" (ITS).  The data sheet does not say which pin
	 * level TIP_SENSE reports; with an open, pulled-up pin meaning
	 * unplugged for TS, the two agree if TIP_SENSE is the pin level
	 * inverted by TIP_SENSE_INV.  That reading is ours.
	 */
	W(CS_PWR_CTL1, 0xfe);
	W(CS_HSBIAS_SENSE, HSBIAS_SENSE_DEFAULT | TIP_SENSE_EN);
	W(CS_MIC_DET_CTL1, LATCH_TO_VP | HS_DETECT_LEVEL_DEFAULT);
	W(CS_TIP_SENSE_CTL2, __SHIFTIN(TIP_SENSE_SHORT_DET, TIP_SENSE_CTRL) |
	    (sc->sc_ts_inv ? TIP_SENSE_INV : 0) |
	    __SHIFTIN(TIP_SENSE_DBNC_500MS, TIP_SENSE_DEBOUNCE));
	return 0;
}

/*
 * Example 5-1 steps 6 to 11, after step 3 again: Ex. 5-2 step 3 leaves
 * SRC_PDN_OVERRIDE set with the DAC SRC powered down (7.4.2), and
 * without putting step 3 back every open after the first was silent.
 */
static int
cscodec_power_up(struct cscodec_softc *sc)
{
	const uint8_t vol = cscodec_vol(sc->sc_volume);
	int error;

	W(CS_PWR_CTL2, 0x83);			/* step 3 */
	W(CS_ASP_RX_EN, ASP_RX0_CH12_EN);	/* step 6, our two channels */
	W(CS_DAC_CTL1, 0x00);			/* step 7 */
	W(CS_MIXER_CHA_VOL, vol);		/* 8.1 */
	W(CS_MIXER_ADC_VOL, MIXER_VOL_MUTE);	/* 8.2 */
	W(CS_MIXER_CHB_VOL, vol);		/* 8.3 */
	W(CS_HP_CTL, HP_FULL_SCALE_VOL | HP_RSVD0);	/* step 9 */
	if (sc->sc_recording) {
		/* HS bias to normal mode with the path still down (7.9.5). */
		W(CS_MISC_DET_CTL, MISC_DET_NORMAL_2V7);
		W(CS_ADC_CTL, 0);
		W(CS_ADC_VOL, 0);
		W(CS_ADC_WNF_HPF, ADC_WNF_HPF_DEFAULT);
		W(CS_SP_TX_ISOC, SP_TX_ISOC_NATIVE);
		W(CS_SP_TX_FS, SP_TX_FS_48K);
		W(CS_ASP_TX_CH_RES, ASP_TX_RES_24);
		W(CS_ASP_TX_CH1_MSB, (uint8_t)(sc->sc_bit_tx >> 8));
		W(CS_ASP_TX_CH1_LSB, (uint8_t)(sc->sc_bit_tx & 0xff));
		W(CS_ASP_TX_CH_EN, ASP_TX_CH1_EN);
		W(CS_ASP_TX_EN, ASP_TX_EN);
	}
	/* Step 10, and with a recording, the ADC and the ASP output too. */
	W(CS_PWR_CTL1, (sc->sc_recording ? 0 : PWR1_ASP_DAO_PDN |
	    PWR1_ADC_PDN) | PWR1_EQ_PDN | PWR1_RSVD1);
	delay(CSCODEC_HP_WAIT_US);			/* step 11 */
	return 0;
}

/* Example 5-2 steps 1 to 3, leaving SCLK enabled (see the top). */
static int
cscodec_power_down(struct cscodec_softc *sc)
{
	int error;

	W(CS_MIXER_CHA_VOL, MIXER_VOL_MUTE);	/* 1.1 */
	W(CS_MIXER_ADC_VOL, MIXER_VOL_MUTE);	/* 1.2 */
	W(CS_MIXER_CHB_VOL, MIXER_VOL_MUTE);	/* 1.3 */
	W(CS_HP_CTL, HP_ANA_MUTE_B | HP_ANA_MUTE_A | HP_FULL_SCALE_VOL |
	    HP_RSVD0);				/* 1.4 */
	W(CS_ASP_RX_EN, 0x00);			/* 1.5 */
	if (sc->sc_recording) {
		W(CS_ASP_TX_EN, 0);		/* output back to Hi-Z */
		W(CS_ASP_TX_CH_EN, 0);
	}
	W(CS_PWR_CTL1, 0xfe);			/* step 2 */
	if (sc->sc_recording && sc->sc_headset != 1 && sc->sc_headset != 2)
		W(CS_MISC_DET_CTL, MISC_DET_DEFAULT);
	else if (sc->sc_recording)
		W(CS_MISC_DET_CTL, MISC_DET_HSBIAS_2V7);
	W(CS_PWR_CTL2, 0x8c);			/* step 3 */
	return 0;
#undef W
}

/*
 * Example 5-5 steps 11.2 to 17, from a codec closed as Ex. 5-2 leaves
 * it (11.1 and step 10 hold already; see cscodec_init()).  Steps 1 to 9
 * are the wake path, not used.  Returns the type of Table 4-22, or 0.
 * Drops the lock for the HSBIAS ramp; if the codec was opened
 * meanwhile, puts back what it changed and returns EBUSY.  *held says
 * whether the lock is held on return: false only if it could not be
 * taken again.
 */
static int
cscodec_detect_type(struct cscodec_softc *sc, u_int *type, bool *held)
{
	uint8_t pwr2, dac2, st;
	u_int waited;
	int error;

	KASSERT(mutex_owned(&sc->sc_lock));
	*type = 0;
	*held = true;

	if ((error = cscodec_read(sc, CS_PWR_CTL2, &pwr2)) != 0 ||
	    (error = cscodec_read(sc, CS_DAC_CTL2, &dac2)) != 0)
		return error;
#define	W(r, v) do {							\
	if ((error = cscodec_write(sc, (r), (v))) != 0)			\
		goto out;						\
} while (0)
	W(CS_PWR_CTL2, 0x87);			/* 11.2: FILT+ unclamped */
	W(CS_DAC_CTL2, 0x86);			/* 11.3 */
	W(CS_MISC_DET_CTL, MISC_DET_HSBIAS_2V7); /* 11.4 */
	cscodec_exit(sc);
	kpause("cshsbias", false, mstohz(CSCODEC_HSBIAS_WAIT_MS), NULL);
	if ((error = cscodec_enter(sc)) != 0) {
		*held = false;
		return error;
	}
	if (sc->sc_running) {
		error = EBUSY;			/* opened meanwhile */
		goto out;
	}
	W(CS_CODEC_INT_MASK, 0x01);		/* 11.6 */
	W(CS_HSDET_CTL2, __SHIFTIN(HSDET_AUTO_DISABLED, HSDET_CTRL)); /* 11.7 */
	delay(CSCODEC_HSDET_WAIT_US);		/* 11.8 */
	W(CS_HSDET_CTL1, 0x77);			/* 11.9 */
	W(CS_HSDET_CTL2, __SHIFTIN(HSDET_AUTO_ACTIVE, HSDET_CTRL)); /* 11.10 */
	for (waited = 0;; waited += CSCODEC_HSDET_WAIT_US) {	/* 12.1 */
		if ((error = cscodec_read(sc, CS_CODEC_INT_STATUS, &st)) != 0)
			goto out;
		if (st & HSDET_AUTO_DONE)
			break;
		if (waited >= CSCODEC_HSDET_DONE_US) {
			error = ETIMEDOUT;
			goto out;
		}
		delay(CSCODEC_HSDET_WAIT_US);
	}
	if ((error = cscodec_read(sc, CS_HSDET_STATUS, &st)) != 0)	/* 12.2 */
		goto out;
	*type = __SHIFTOUT(st, HSDET_TYPE) + 1;
	/*
	 * 13: types 1 to 3 set the switches themselves.  Type 4 is left as
	 * the automatic logic set it (Table 4-23: as type 1); the manual
	 * search of step 14 is not done.  Step 16 is for external
	 * switches, which Apple's boards do not have in their trees.
	 */
out:
	/* 12.3, also on the way out of a failure. */
	(void)cscodec_write(sc, CS_HSDET_CTL2,
	    __SHIFTIN(HSDET_AUTO_DISABLED, HSDET_CTRL));
	(void)cscodec_write(sc, CS_DAC_CTL2, error == 0 ? 0x02 : dac2); /* 17 */
	/* No mic, no bias: back to the weak ground it resets to. */
	if (error != 0 || (*type != 1 && *type != 2))
		(void)cscodec_write(sc, CS_MISC_DET_CTL, MISC_DET_DEFAULT);
	/* An open meanwhile set PWR_CTL2 for playback; it is its own. */
	if (error != EBUSY)
		(void)cscodec_write(sc, CS_PWR_CTL2, pwr2);
	return error;
#undef W
}

/* One sample of plug presence, and the type when a plug arrives. */
static void
cscodec_poll_work(struct work *wk, void *arg)
{
	struct cscodec_softc * const sc = arg;
	uint8_t st;
	bool now;
	u_int type;
	bool held;
	int error;

	if (cscodec_enter(sc) != 0)
		goto again;
	if (!sc->sc_ready || cscodec_read(sc, CS_DET_STATUS1, &st) != 0)
		goto out;
	now = (st & DET_TIP_SENSE) != 0;
	if (now != sc->sc_sample) {
		sc->sc_sample = now;		/* first of two */
		goto out;
	}
	if (now != sc->sc_plugged) {
		sc->sc_plugged = now;
		sc->sc_typed = false;
		sc->sc_headset = 0;
		if (!now)
			(void)cscodec_write(sc, CS_MISC_DET_CTL,
			    MISC_DET_DEFAULT);
	}
	if (sc->sc_plugged && !sc->sc_typed && !sc->sc_running) {
		error = cscodec_detect_type(sc, &type, &held);
		if (!held)
			goto again;
		if (error == EBUSY)
			goto out;		/* opened: try after close */
		sc->sc_headset = type;
		sc->sc_typed = true;
		if (error != 0) {
			device_printf(sc->sc_dev,
			    "headset type detection failed: %d\n", error);
		}
	}
out:
	cscodec_exit(sc);
again:
	callout_schedule(&sc->sc_poll, mstohz(CSCODEC_POLL_MS));
}

static void
cscodec_poll(void *arg)
{
	struct cscodec_softc * const sc = arg;

	workqueue_enqueue(sc->sc_wq, &sc->sc_work, NULL);
}

static int
cscodec_sysctl_state(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct cscodec_softc * const sc = node.sysctl_data;
	int val;

	mutex_enter(&sc->sc_lock);
	val = node.sysctl_num == sc->sc_sysctl_plugged ? sc->sc_plugged :
	    (int)sc->sc_headset;
	mutex_exit(&sc->sc_lock);
	node.sysctl_data = &val;
	return sysctl_lookup(SYSCTLFN_CALL(&node));
}

static void
cscodec_sysctl_attach(struct cscodec_softc *sc)
{
	const struct sysctlnode *root, *node;

	if (sysctl_createv(&sc->sc_sysctllog, 0, NULL, &root, 0,
	    CTLTYPE_NODE, device_xname(sc->sc_dev), NULL, NULL, 0, NULL, 0,
	    CTL_HW, CTL_CREATE, CTL_EOL) != 0)
		return;
	if (sysctl_createv(&sc->sc_sysctllog, 0, &root, &node, CTLFLAG_READONLY,
	    CTLTYPE_INT, "plugged", SYSCTL_DESCR("Headphone jack occupied"),
	    cscodec_sysctl_state, 0, (void *)sc, 0, CTL_CREATE, CTL_EOL) == 0)
		sc->sc_sysctl_plugged = node->sysctl_num;
	if (sysctl_createv(&sc->sc_sysctllog, 0, &root, &node, CTLFLAG_READONLY,
	    CTLTYPE_INT, "headset", SYSCTL_DESCR("Headset type: 0 none or "
	    "unknown, 1 mic on pin 4, 2 mic on pin 3, 3 no mic, 4 optical"),
	    cscodec_sysctl_state, 0, (void *)sc, 0, CTL_CREATE, CTL_EOL) == 0)
		sc->sc_sysctl_headset = node->sysctl_num;
}

static int
cscodec_set_sysclk(audio_dai_tag_t dai, u_int rate, int dir)
{
	struct cscodec_softc * const sc = audio_dai_private(dai);
	int error;

	/* Only the clocking of Example 5-1: SCLK as MCLK at 12.288 MHz. */
	if (rate != CSCODEC_SCLK_HZ || dir != AUDIO_DAI_CLOCK_IN)
		return EINVAL;
	if ((error = cscodec_enter(sc)) != 0)
		return error;
	error = cscodec_init(sc);
	sc->sc_ready = error == 0;
	cscodec_exit(sc);
	if (error != 0)
		device_printf(sc->sc_dev, "init failed: %d\n", error);
	else if (sc->sc_wq != NULL)
		callout_schedule(&sc->sc_poll, mstohz(CSCODEC_POLL_MS));
	return error;
}

/*
 * The frame conventions are those of the I2S bus specification (Philips,
 * June 1996), as in tasamp(4): I2S starts one bit clock after the word
 * select edge, on a falling edge for the left channel unless the frame
 * is inverted; data is latched on the rising edge unless the bit clock
 * is inverted.  The codec is always the clock slave.
 */
static int
cscodec_set_format(audio_dai_tag_t dai, u_int format)
{
	struct cscodec_softc * const sc = audio_dai_private(dai);
	const u_int pol = __SHIFTOUT(format, AUDIO_DAI_POLARITY_MASK);
	bool rising_start;
	u_int delay_half;

	if (__SHIFTOUT(format, AUDIO_DAI_CLOCK_MASK) != AUDIO_DAI_CLOCK_CBS_CFS)
		return EINVAL;
	switch (format & AUDIO_DAI_FORMAT_MASK) {
	case AUDIO_DAI_FORMAT_I2S:
		rising_start = false;	/* left starts on WS falling */
		delay_half = 2;		/* one SCLK: 010 (7.5.8) */
		break;
	case AUDIO_DAI_FORMAT_LJ:
		rising_start = true;
		delay_half = 0;
		break;
	default:
		return EINVAL;
	}
	if (AUDIO_DAI_POLARITY_F(pol))
		rising_start = !rising_start;

	mutex_enter(&sc->sc_lock);
	sc->sc_frm_cfg = (rising_start ? ASP_STP : 0) |
	    __SHIFTIN(delay_half, ASP_FSD);
	/*
	 * 7.5.7: with the bit clock inverted, latch on falling and launch
	 * on rising; otherwise the other way round, as the I2S bus
	 * specification has it.
	 */
	sc->sc_clk_pol = AUDIO_DAI_POLARITY_B(pol) ? 0 :
	    ASP_SCPOL_IN_DAC | ASP_SCPOL_IN_ADC;
	mutex_exit(&sc->sc_lock);
	return 0;
}

/*
 * Two receive slots: channel A in the first, B in the second.  At most
 * one transmit slot, for the microphone.
 */
static int
cscodec_set_tdm_slot(audio_dai_tag_t dai, uint32_t txmask, uint32_t rxmask,
    u_int slots, u_int width)
{
	struct cscodec_softc * const sc = audio_dai_private(dai);
	u_int a, b, t;

	if (popcount32(rxmask) != 2 || width == 0 || width > 32 ||
	    popcount32(txmask) > 1)
		return EINVAL;
	t = txmask != 0 ? (u_int)ffs32(txmask) - 1 : 0;
	if (txmask != 0 && (t >= slots || (t + 1) * width > 0x1ff))
		return EINVAL;
	a = ffs32(rxmask) - 1;
	b = ffs32(rxmask & ~__BIT(a)) - 1;
	if (b >= slots || (b + 1) * width > 0x1ff)	/* 9-bit bit start */
		return EINVAL;
	mutex_enter(&sc->sc_lock);
	sc->sc_bit_a = a * width;
	sc->sc_bit_b = b * width;
	sc->sc_bit_tx = txmask != 0 ? (int)(t * width) : -1;
	mutex_exit(&sc->sc_lock);
	return 0;
}

static int
cscodec_set_volume(audio_dai_tag_t dai, int cdb)
{
	struct cscodec_softc * const sc = audio_dai_private(dai);
	int error;

	if ((error = cscodec_enter(sc)) != 0)
		return error;
	sc->sc_volume = MIN(cdb, 0);
	if (sc->sc_running) {
		error = cscodec_write(sc, CS_MIXER_CHA_VOL,
		    cscodec_vol(sc->sc_volume));
		if (error == 0)
			error = cscodec_write(sc, CS_MIXER_CHB_VOL,
			    cscodec_vol(sc->sc_volume));
	}
	cscodec_exit(sc);
	return error;
}

static int
cscodec_open(void *priv, int flags)
{
	struct cscodec_softc * const sc = priv;
	int error;

	if ((error = cscodec_enter(sc)) != 0)
		return error;
	if (!sc->sc_ready) {
		error = ENXIO;
	} else if ((flags & FREAD) != 0 && (sc->sc_bit_tx < 0 ||
	    !sc->sc_typed || (sc->sc_headset != 1 && sc->sc_headset != 2))) {
		error = ENXIO;			/* no microphone to record */
	} else if (!sc->sc_running) {
		sc->sc_recording = (flags & FREAD) != 0;
		if ((error = cscodec_power_up(sc)) == 0)
			sc->sc_running = true;
	}
	cscodec_exit(sc);
	return error;
}

static void
cscodec_close(void *priv)
{
	struct cscodec_softc * const sc = priv;

	if (cscodec_enter(sc) != 0)
		return;
	if (sc->sc_running) {
		(void)cscodec_power_down(sc);
		sc->sc_running = false;
		sc->sc_recording = false;
	}
	cscodec_exit(sc);
}

static const struct audio_hw_if cscodec_hw_if = {
	.open = cscodec_open,
	.close = cscodec_close,
};

static audio_dai_tag_t
cscodec_dai_get_tag(device_t dev, const void *data, size_t len)
{
	struct cscodec_softc * const sc = device_private(dev);

	return len == 0 || len == 4 ? &sc->sc_dai : NULL;
}

static struct fdtbus_dai_controller_func cscodec_dai_funcs = {
	.get_tag = cscodec_dai_get_tag
};

static int
cscodec_match(device_t parent, cfdata_t match, void *aux)
{
	struct i2c_attach_args *ia = aux;
	int match_result;

	if (iic_use_direct_match(ia, match, compat_data, &match_result))
		return match_result;

	/* This device is direct-config only */

	return 0;
}

static void
cscodec_attach(device_t parent, device_t self, void *aux)
{
	struct cscodec_softc * const sc = device_private(self);
	struct i2c_attach_args * const ia = aux;
	const struct device_compatible_entry *dce;
	uint32_t inv = 0;

	sc->sc_dev = self;
	sc->sc_phandle = devhandle_to_of(device_handle(self));
	sc->sc_i2c = ia->ia_tag;
	sc->sc_addr = ia->ia_addr;
	dce = iic_compatible_lookup(ia, compat_data);
	KASSERT(dce != NULL);
	sc->sc_id = (uint32_t)dce->value;
	sc->sc_page = -1;
	sc->sc_volume = CSCODEC_INITIAL_CDB;
	/* Until told otherwise: I2S, bit A in slot 0, B in slot 1 of 32. */
	sc->sc_frm_cfg = __SHIFTIN(2, ASP_FSD);
	sc->sc_clk_pol = ASP_SCPOL_IN_DAC;
	sc->sc_bit_a = 0;
	sc->sc_bit_b = 32;
	sc->sc_bit_tx = -1;
	sc->sc_ts_inv = of_getprop_uint32(sc->sc_phandle, "cirrus,ts-inv",
	    &inv) == 0 && inv != 0;
	mutex_init(&sc->sc_lock, MUTEX_DEFAULT, IPL_NONE);
	callout_init(&sc->sc_poll, 0);
	callout_setfunc(&sc->sc_poll, cscodec_poll, sc);
	if (workqueue_create(&sc->sc_wq, device_xname(self), cscodec_poll_work,
	    sc, PRI_NONE, IPL_NONE, WQ_MPSAFE) != 0) {
		aprint_error(": can't create workqueue\n");
		sc->sc_wq = NULL;
	}

	aprint_naive("\n");
	aprint_normal(": Cirrus Logic CS42L%s headphone codec\n",
	    sc->sc_id == CS42L83_ID ? "83" : "42");

	/* Held in reset until SCLK runs (Ex. 5-1 step 1). */
	sc->sc_reset = fdtbus_gpio_acquire(sc->sc_phandle, "reset-gpios",
	    GPIO_PIN_OUTPUT);
	if (sc->sc_reset != NULL)
		fdtbus_gpio_write(sc->sc_reset, 0);

	sc->sc_dai.dai_set_sysclk = cscodec_set_sysclk;
	sc->sc_dai.dai_set_format = cscodec_set_format;
	sc->sc_dai.dai_set_tdm_slot = cscodec_set_tdm_slot;
	sc->sc_dai.dai_set_volume = cscodec_set_volume;
	sc->sc_dai.dai_hw_if = &cscodec_hw_if;
	sc->sc_dai.dai_dev = self;
	sc->sc_dai.dai_priv = sc;
	fdtbus_register_dai_controller(self, sc->sc_phandle, &cscodec_dai_funcs);
	cscodec_sysctl_attach(sc);
}
