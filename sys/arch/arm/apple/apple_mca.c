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
 * Apple MCA, the I2S/TDM serial audio block.
 *
 * There is no documentation.  Register layout and the order of
 * operations are facts from the Asahi Linux driver sound/soc/apple/mca.c
 * and the binding apple,mca.yaml; several bits are unnamed there too
 * and are kept as UNK.  Not run on hardware from NetBSD.
 *
 * The block is a set of identical clusters, each with a clock parent
 * (an NCO channel), a frame sync generator, four SERDES units (TX A/B,
 * RX A/B) and an I2S port.  A port can be fed clocks and data by any
 * cluster.  Streams here use TX A for playback and RX B for capture,
 * as Asahi does, and this MCA always provides the clocks.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/device.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/systm.h>

#include <dev/audio/audio_dai.h>

#include <dev/fdt/fdtvar.h>

#include <arm/apple/apple_mcavar.h>

#define	MCA_CLUSTER_STRIDE	0x4000
#define	MCA_MAX_CLUSTERS	6

/* Cluster registers. */
#define	MCA_STATUS		0x000
#define	 STATUS_MCLK_EN		__BIT(0)
#define	MCA_MCLK_CONF		0x004
#define	 MCLK_CONF_DIV		__BITS(11,8)
#define	MCA_SYNCGEN_STATUS	0x100
#define	 SYNCGEN_EN		__BIT(0)
#define	MCA_SYNCGEN_MCLK_SEL	0x104
#define	MCA_SYNCGEN_HI_PERIOD	0x108
#define	MCA_SYNCGEN_LO_PERIOD	0x10c
#define	MCA_PORT_ENABLES	0x600
#define	 PORT_ENABLES_CLOCKS	__BITS(2,1)
#define	 PORT_ENABLES_TX_DATA	__BIT(3)
#define	MCA_PORT_CLOCK_SEL	0x604
#define	 PORT_CLOCK_SEL		__BITS(11,8)
#define	MCA_PORT_DATA_SEL	0x608
#define	 PORT_DATA_SEL_TXA(cl)	(1U << ((cl) * 2))

/* SERDES units, relative to the cluster. */
#define	MCA_SERDES_TXA		0x300
#define	MCA_SERDES_RXB		0x400

/* SERDES registers, relative to the unit. */
#define	SERDES_STATUS		0x00
#define	 SERDES_STATUS_EN	__BIT(0)
#define	 SERDES_STATUS_RST	__BIT(1)
#define	SERDES_TX_CONF		0x04
#define	SERDES_RX_CONF		0x08
#define	 CONF_NCHANS		__BITS(3,0)
#define	 CONF_WIDTH		__BITS(8,4)
#define	  CONF_WIDTH_16		0x4
#define	  CONF_WIDTH_20		0x8
#define	  CONF_WIDTH_24		0xc
#define	  CONF_WIDTH_32		0x10
#define	 CONF_BCLK_POL		__BIT(10)
#define	 CONF_UNK1		__BIT(12)
#define	 CONF_UNK2		__BIT(13)
#define	 CONF_UNK3		__BIT(14)
#define	 CONF_NO_DATA_FEEDBACK	__BIT(15)
#define	 CONF_SYNC_SEL		__BITS(18,16)
#define	SERDES_TX_BITSTART	0x08
#define	SERDES_RX_BITSTART	0x0c
#define	SERDES_TX_SLOTMASK	0x0c	/* four words */
#define	SERDES_RX_SLOTMASK	0x10	/* two words */
#define	SERDES_RX_PORT		0x04

/* Switch registers. */
#define	MCA_DMA_ADAPTER_A(cl)	(0x8000 * (cl))
#define	MCA_DMA_ADAPTER_B(cl)	(0x8000 * (cl) + 0x4000)
#define	 ADAPTER_TX_LSB_PAD	__BITS(4,0)
#define	 ADAPTER_TX_NCHANS	__BITS(6,5)
#define	 ADAPTER_RX_MSB_PAD	__BITS(12,8)
#define	 ADAPTER_RX_NCHANS	__BITS(14,13)
#define	 ADAPTER_NCHANS		__BITS(22,20)

/*
 * Delays in the start sequence.  The reset bit clears in about 1 us by
 * Asahi's experiments; their code waits 50 us (its comment says 5).
 * The second wait "seems to be needed" before the DMA starts.
 */
#define	MCA_RESET_WAIT_US	50
#define	MCA_SETTLE_WAIT_US	100

struct apple_mca_softc;

struct apple_mca_port {
	struct apple_mca_softc	*mp_sc;
	u_int			mp_no;
	struct audio_dai_device	mp_dai;
};

struct apple_mca_stream {
	struct apple_mca_softc	*ms_sc;
	u_int			ms_fe;
	bool			ms_tx;
	uint32_t		ms_ports;
	bool			ms_configured;
	bool			ms_prepared;	/* under sc_lock */
	/*
	 * ms_running and the ring are under ms_intr_lock, a spin lock the
	 * DMA completion takes: halt must not race a completion that
	 * would queue one more block and restart the channel.  Order:
	 * sc_lock, ms_intr_lock, then the ADMAC's own.
	 */
	kmutex_t		ms_intr_lock;
	bool			ms_running;
	struct apple_mca_params	ms_params;
	struct fdtbus_dma	*ms_dma;
	struct fdtbus_dma_req	ms_req;
	bus_dma_segment_t	ms_seg;
	u_int			ms_frame_words;

	/* The ring: current block, wrapping at end. */
	bus_addr_t		ms_start, ms_end, ms_next;
	bus_size_t		ms_blksize;
	void			(*ms_intr)(void *);
	void			*ms_intrarg;
};

struct apple_mca_softc {
	device_t		sc_dev;
	int			sc_phandle;
	bus_space_tag_t		sc_bst;
	bus_space_handle_t	sc_bsh;		/* clusters */
	bus_space_handle_t	sc_swh;		/* switch */
	bus_dma_tag_t		sc_dmat;	/* through the ADMAC's DART */
	u_int			sc_nclusters;
	kmutex_t		sc_lock;	/* adaptive: streams, ports */

	/* Which stream uses each cluster, and who drives each port. */
	struct apple_mca_stream	*sc_fe[MCA_MAX_CLUSTERS][2];
	int			sc_port_driver[MCA_MAX_CLUSTERS];
	u_int			sc_port_users[MCA_MAX_CLUSTERS];
	u_int			sc_clk_users[MCA_MAX_CLUSTERS];

	struct apple_mca_port	sc_ports[MCA_MAX_CLUSTERS];
};

#define	CL_OFF(cl, reg)		((bus_size_t)(cl) * MCA_CLUSTER_STRIDE + (reg))
#define	CL_RD(sc, cl, reg) \
	bus_space_read_4((sc)->sc_bst, (sc)->sc_bsh, CL_OFF(cl, reg))
#define	CL_WR(sc, cl, reg, val) \
	bus_space_write_4((sc)->sc_bst, (sc)->sc_bsh, CL_OFF(cl, reg), (val))
#define	SW_WR(sc, reg, val) \
	bus_space_write_4((sc)->sc_bst, (sc)->sc_swh, (reg), (val))

static const struct device_compatible_entry compat_data[] = {
	{ .compat = "apple,mca" },
	DEVICE_COMPAT_EOL
};

static void
cl_modify(struct apple_mca_softc *sc, u_int cl, bus_size_t reg, uint32_t mask,
    uint32_t val)
{

	CL_WR(sc, cl, reg, (CL_RD(sc, cl, reg) & ~mask) | (val & mask));
}

static inline bus_size_t
serdes(const struct apple_mca_stream *ms)
{

	return ms->ms_tx ? MCA_SERDES_TXA : MCA_SERDES_RXB;
}

static inline bus_size_t
serdes_conf(const struct apple_mca_stream *ms)
{

	return serdes(ms) + (ms->ms_tx ? SERDES_TX_CONF : SERDES_RX_CONF);
}

int
apple_mca_dai_port(audio_dai_tag_t dai, device_t *dev, u_int *port)
{
	struct apple_mca_port *mp;

	if (dai == NULL || dai->dai_priv == NULL)
		return EINVAL;
	mp = dai->dai_priv;
	if (mp->mp_sc == NULL || &mp->mp_dai != dai)
		return EINVAL;
	*dev = mp->mp_sc->sc_dev;
	*port = mp->mp_no;
	return 0;
}

static void apple_mca_dma_done(void *);

int
apple_mca_stream_open(device_t dev, u_int fe, bool tx, uint32_t ports,
    struct apple_mca_stream **msp)
{
	struct apple_mca_softc * const sc = device_private(dev);
	struct apple_mca_stream *ms;
	char name[8];

	if (fe >= sc->sc_nclusters || ports == 0 ||
	    (ports & ~__BITS(sc->sc_nclusters - 1, 0)) != 0)
		return EINVAL;

	mutex_enter(&sc->sc_lock);
	if (sc->sc_fe[fe][tx] != NULL) {
		mutex_exit(&sc->sc_lock);
		return EBUSY;
	}
	ms = kmem_zalloc(sizeof(*ms), KM_SLEEP);
	mutex_init(&ms->ms_intr_lock, MUTEX_DEFAULT, IPL_AUDIO);
	ms->ms_sc = sc;
	ms->ms_fe = fe;
	ms->ms_tx = tx;
	ms->ms_ports = ports;
	sc->sc_fe[fe][tx] = ms;
	mutex_exit(&sc->sc_lock);

	/* Playback from TX A, capture into RX B, as named in dma-names. */
	snprintf(name, sizeof(name), tx ? "tx%ua" : "rx%ub", fe);
	ms->ms_dma = fdtbus_dma_get(sc->sc_phandle, name, apple_mca_dma_done,
	    ms);
	if (ms->ms_dma == NULL) {
		apple_mca_stream_close(ms);
		return ENXIO;
	}
	*msp = ms;
	return 0;
}

bus_dma_tag_t
apple_mca_stream_dmat(struct apple_mca_stream *ms)
{

	return ms->ms_sc->sc_dmat;
}

/*
 * Frame sync of cluster fe from the clocks arriving at port.  The
 * select value is the port plus 7 (mca.c: port + 6 + 1); 1..6 select
 * the clusters' own MCLKs.
 */
static void
mca_follow_on(struct apple_mca_softc *sc, u_int fe, u_int port)
{

	KASSERT(mutex_owned(&sc->sc_lock));
	fdtbus_powerdomain_enable_index(sc->sc_phandle, fe + 1);
	CL_WR(sc, fe, MCA_SYNCGEN_MCLK_SEL, port + 7);
	cl_modify(sc, fe, MCA_SYNCGEN_STATUS, SYNCGEN_EN, SYNCGEN_EN);
}

static void
mca_follow_off(struct apple_mca_softc *sc, u_int fe)
{

	KASSERT(mutex_owned(&sc->sc_lock));
	cl_modify(sc, fe, MCA_SYNCGEN_STATUS, SYNCGEN_EN, 0);
	fdtbus_powerdomain_disable_index(sc->sc_phandle, fe + 1);
}

/* Clocks from cluster fe: NCO, frame sync, MCLK.  Counted per cluster. */
static int
mca_clocks_on(struct apple_mca_softc *sc, u_int fe, u_int bclk_ratio,
    u_int rate)
{
	struct clk *clk;
	int error;

	KASSERT(mutex_owned(&sc->sc_lock));

	if (sc->sc_clk_users[fe]++ > 0)
		return 0;

	clk = fdtbus_clock_get_index(sc->sc_phandle, fe);
	if (clk == NULL) {
		error = ENXIO;
		goto fail;
	}
	/* Cluster power domains follow the general one in the list. */
	fdtbus_powerdomain_enable_index(sc->sc_phandle, fe + 1);

	/* FSYNC as even as the ratio allows. */
	CL_WR(sc, fe, MCA_SYNCGEN_HI_PERIOD, bclk_ratio / 2 - 1);
	CL_WR(sc, fe, MCA_SYNCGEN_LO_PERIOD, (bclk_ratio + 1) / 2 - 1);
	CL_WR(sc, fe, MCA_MCLK_CONF, __SHIFTIN(1, MCLK_CONF_DIV));
	if ((error = clk_set_rate(clk, bclk_ratio * rate)) != 0 ||
	    (error = clk_enable(clk)) != 0)
		goto fail;

	CL_WR(sc, fe, MCA_SYNCGEN_MCLK_SEL, fe + 1);
	cl_modify(sc, fe, MCA_SYNCGEN_STATUS, SYNCGEN_EN, SYNCGEN_EN);
	cl_modify(sc, fe, MCA_STATUS, STATUS_MCLK_EN, STATUS_MCLK_EN);
	return 0;

fail:
	sc->sc_clk_users[fe]--;
	return error;
}

static void
mca_clocks_off(struct apple_mca_softc *sc, u_int fe)
{
	struct clk *clk;

	KASSERT(mutex_owned(&sc->sc_lock));
	KASSERT(sc->sc_clk_users[fe] > 0);

	if (--sc->sc_clk_users[fe] > 0)
		return;
	cl_modify(sc, fe, MCA_SYNCGEN_STATUS, SYNCGEN_EN, 0);
	cl_modify(sc, fe, MCA_STATUS, STATUS_MCLK_EN, 0);
	if ((clk = fdtbus_clock_get_index(sc->sc_phandle, fe)) != NULL)
		clk_disable(clk);
	fdtbus_powerdomain_disable_index(sc->sc_phandle, fe + 1);
}

/* Keep the lowest n set bits of mask. */
static uint32_t
mca_crop(uint32_t mask, u_int n)
{
	uint32_t out = 0;

	while (mask != 0 && n-- > 0) {
		out |= mask & -mask;
		mask &= mask - 1;
	}
	return out;
}

int
apple_mca_stream_config(struct apple_mca_stream *ms,
    const struct apple_mca_params *mp)
{
	struct apple_mca_softc * const sc = ms->ms_sc;
	const u_int fe = ms->ms_fe;
	uint32_t conf, mask, width;
	u_int pad, bitstart, words;

	/* Checks first; nothing is written unless all pass. */
	switch (mp->mp_slot_width) {
	case 16:
		width = CONF_WIDTH_16;
		break;
	case 20:
		width = CONF_WIDTH_20;
		break;
	case 24:
		width = CONF_WIDTH_24;
		break;
	case 32:
		width = CONF_WIDTH_32;
		break;
	default:
		return EINVAL;
	}
	if (mp->mp_follow_port >= (int)sc->sc_nclusters ||
	    (mp->mp_follow_port >= 0 && ms->ms_tx))
		return EINVAL;
	if ((mp->mp_width != 16 && mp->mp_width != 24 && mp->mp_width != 32) ||
	    mp->mp_width > mp->mp_slot_width || mp->mp_rate == 0 ||
	    mp->mp_channels == 0 || mp->mp_slots == 0 || mp->mp_slots > 16 ||
	    popcount32(mp->mp_slot_mask) != mp->mp_channels ||
	    (mp->mp_slot_mask & ~__BITS(mp->mp_slots - 1, 0)) != 0)
		return EINVAL;

	/*
	 * Only inverted frame polarity works: I2S with an inverted frame,
	 * or left justified with a normal one.  BCLK_POL is set for a
	 * normal bit clock.
	 */
	conf = 0;
	switch (mp->mp_format & AUDIO_DAI_FORMAT_MASK) {
	case AUDIO_DAI_FORMAT_I2S:
		if (!AUDIO_DAI_POLARITY_F(__SHIFTOUT(mp->mp_format,
		    AUDIO_DAI_POLARITY_MASK)))
			return EINVAL;
		bitstart = 1;
		break;
	case AUDIO_DAI_FORMAT_LJ:
		if (AUDIO_DAI_POLARITY_F(__SHIFTOUT(mp->mp_format,
		    AUDIO_DAI_POLARITY_MASK)))
			return EINVAL;
		bitstart = 0;
		break;
	default:
		return EINVAL;
	}
	if (!AUDIO_DAI_POLARITY_B(__SHIFTOUT(mp->mp_format,
	    AUDIO_DAI_POLARITY_MASK)))
		conf |= CONF_BCLK_POL;

	mutex_enter(&sc->sc_lock);
	if (ms->ms_prepared) {
		mutex_exit(&sc->sc_lock);
		return EBUSY;
	}

	conf |= __SHIFTIN(mp->mp_slots - 1, CONF_NCHANS) |
	    __SHIFTIN(width, CONF_WIDTH) | __SHIFTIN(fe + 1, CONF_SYNC_SEL);
	if (ms->ms_tx)
		conf |= CONF_UNK1 | CONF_UNK2 | CONF_UNK3;
	else
		conf |= CONF_UNK1 | CONF_UNK2 | CONF_NO_DATA_FEEDBACK;
	cl_modify(sc, fe, serdes_conf(ms), CONF_NCHANS | CONF_WIDTH |
	    CONF_BCLK_POL | CONF_UNK1 | CONF_UNK2 | CONF_UNK3 |
	    CONF_NO_DATA_FEEDBACK | CONF_SYNC_SEL, conf);
	CL_WR(sc, fe, serdes(ms) + (ms->ms_tx ? SERDES_TX_BITSTART :
	    SERDES_RX_BITSTART), bitstart);

	/* Slot masks are written inverted: a set bit masks the slot out. */
	mask = mp->mp_slot_mask;
	if (ms->ms_tx) {
		CL_WR(sc, fe, serdes(ms) + SERDES_TX_SLOTMASK, 0xffffffff);
		CL_WR(sc, fe, serdes(ms) + SERDES_TX_SLOTMASK + 4,
		    ~mca_crop(mask, mp->mp_channels));
		CL_WR(sc, fe, serdes(ms) + SERDES_TX_SLOTMASK + 8, 0xffffffff);
		CL_WR(sc, fe, serdes(ms) + SERDES_TX_SLOTMASK + 12, ~mask);
	} else {
		CL_WR(sc, fe, serdes(ms) + SERDES_RX_SLOTMASK, 0xffffffff);
		CL_WR(sc, fe, serdes(ms) + SERDES_RX_SLOTMASK + 4,
		    ~mca_crop(mask, mp->mp_channels));
		CL_WR(sc, fe, serdes(ms) + SERDES_RX_PORT, ms->ms_ports);
	}

	/*
	 * DMA adapter.  Asahi notes the semantics are unclear; these are
	 * the values it writes: pads to 32 bits, and up to four channels.
	 */
	pad = 32 - mp->mp_width;
	words = MIN(mp->mp_channels, 4);
	SW_WR(sc, ms->ms_tx ? MCA_DMA_ADAPTER_A(fe) : MCA_DMA_ADAPTER_B(fe),
	    __SHIFTIN(words, ADAPTER_NCHANS) |
	    __SHIFTIN(2, ADAPTER_TX_NCHANS) | __SHIFTIN(2, ADAPTER_RX_NCHANS) |
	    __SHIFTIN(pad, ADAPTER_TX_LSB_PAD) |
	    __SHIFTIN(pad, ADAPTER_RX_MSB_PAD));

	/* The ADMAC can mark word positions for 1, 2 or 4 words a frame. */
	ms->ms_frame_words = words == 3 ? 2 : words;
	ms->ms_params = *mp;
	ms->ms_configured = true;
	mutex_exit(&sc->sc_lock);
	return 0;
}

/* Queue the next block of the ring with the ADMAC. */
static int
mca_queue_block(struct apple_mca_stream *ms)
{
	int error;

	KASSERT(mutex_owned(&ms->ms_intr_lock));

	ms->ms_seg.ds_addr = ms->ms_next;
	ms->ms_seg.ds_len = ms->ms_blksize;
	ms->ms_req.dreq_segs = &ms->ms_seg;
	ms->ms_req.dreq_nsegs = 1;
	error = fdtbus_dma_transfer(ms->ms_dma, &ms->ms_req);
	if (error == 0) {
		ms->ms_next += ms->ms_blksize;
		if (ms->ms_next >= ms->ms_end)
			ms->ms_next = ms->ms_start;
	}
	return error;
}

static void
apple_mca_dma_done(void *arg)
{
	struct apple_mca_stream * const ms = arg;
	void (*intr)(void *);
	void *intrarg;

	mutex_enter(&ms->ms_intr_lock);
	if (!ms->ms_running) {
		mutex_exit(&ms->ms_intr_lock);
		return;
	}
	(void)mca_queue_block(ms);
	intr = ms->ms_intr;
	intrarg = ms->ms_intrarg;
	mutex_exit(&ms->ms_intr_lock);

	/* The audio layer takes its own interrupt lock. */
	if (intr != NULL)
		intr(intrarg);
}

/*
 * Clocks and port routing.  May sleep: not from the audio layer's
 * locked callbacks.
 */
int
apple_mca_stream_prepare(struct apple_mca_stream *ms)
{
	struct apple_mca_softc * const sc = ms->ms_sc;
	const struct apple_mca_params *mp = &ms->ms_params;
	const u_int fe = ms->ms_fe;
	u_int p;
	int error;

	mutex_enter(&sc->sc_lock);
	if (!ms->ms_configured || ms->ms_prepared) {
		mutex_exit(&sc->sc_lock);
		return ms->ms_prepared ? 0 : EINVAL;
	}
	if (mp->mp_follow_port >= 0) {
		/* A follower touches neither the NCO nor the ports. */
		mca_follow_on(sc, fe, mp->mp_follow_port);
		ms->ms_prepared = true;
		mutex_exit(&sc->sc_lock);
		return 0;
	}
	/* A port takes clocks from one cluster at a time. */
	for (p = 0; p < sc->sc_nclusters; p++) {
		if ((ms->ms_ports & __BIT(p)) && sc->sc_port_driver[p] >= 0 &&
		    sc->sc_port_driver[p] != (int)fe) {
			mutex_exit(&sc->sc_lock);
			return EBUSY;
		}
	}
	error = mca_clocks_on(sc, fe, mp->mp_slots * mp->mp_slot_width,
	    mp->mp_rate);
	if (error != 0) {
		mutex_exit(&sc->sc_lock);
		return error;
	}
	for (p = 0; p < sc->sc_nclusters; p++) {
		if (ms->ms_ports & __BIT(p)) {
			sc->sc_port_driver[p] = fe;
			sc->sc_port_users[p]++;
		}
	}
	/* Route clocks, and for playback data, of each port from fe. */
	for (p = 0; p < sc->sc_nclusters; p++) {
		if ((ms->ms_ports & __BIT(p)) == 0)
			continue;
		if (ms->ms_tx) {
			CL_WR(sc, p, MCA_PORT_DATA_SEL, PORT_DATA_SEL_TXA(fe));
			cl_modify(sc, p, MCA_PORT_ENABLES, PORT_ENABLES_TX_DATA,
			    PORT_ENABLES_TX_DATA);
		}
		CL_WR(sc, p, MCA_PORT_CLOCK_SEL,
		    __SHIFTIN(fe + 1, PORT_CLOCK_SEL));
		cl_modify(sc, p, MCA_PORT_ENABLES, PORT_ENABLES_CLOCKS,
		    PORT_ENABLES_CLOCKS);
	}
	ms->ms_prepared = true;
	mutex_exit(&sc->sc_lock);
	return 0;
}

void
apple_mca_stream_unprepare(struct apple_mca_stream *ms)
{
	struct apple_mca_softc * const sc = ms->ms_sc;
	u_int p;

	apple_mca_stream_halt(ms);
	mutex_enter(&sc->sc_lock);
	if (!ms->ms_prepared) {
		mutex_exit(&sc->sc_lock);
		return;
	}
	if (ms->ms_params.mp_follow_port >= 0) {
		mca_follow_off(sc, ms->ms_fe);
		ms->ms_prepared = false;
		mutex_exit(&sc->sc_lock);
		return;
	}
	for (p = 0; p < sc->sc_nclusters; p++) {
		if ((ms->ms_ports & __BIT(p)) == 0)
			continue;
		if (ms->ms_tx) {
			cl_modify(sc, p, MCA_PORT_ENABLES, PORT_ENABLES_TX_DATA,
			    0);
			CL_WR(sc, p, MCA_PORT_DATA_SEL, 0);
		}
		KASSERT(sc->sc_port_users[p] > 0);
		if (--sc->sc_port_users[p] == 0) {
			cl_modify(sc, p, MCA_PORT_ENABLES, PORT_ENABLES_CLOCKS, 0);
			CL_WR(sc, p, MCA_PORT_CLOCK_SEL, 0);
			sc->sc_port_driver[p] = -1;
		}
	}
	mca_clocks_off(sc, ms->ms_fe);
	ms->ms_prepared = false;
	mutex_exit(&sc->sc_lock);
}

/*
 * Start the SERDES and the DMA.  Only register writes, busy waits and
 * spin locks: the audio layer calls this with its interrupt lock held.
 */
int
apple_mca_stream_start(struct apple_mca_stream *ms, bus_addr_t start,
    bus_size_t len, bus_size_t blksize, void (*intr)(void *), void *arg)
{
	struct apple_mca_softc * const sc = ms->ms_sc;
	const u_int fe = ms->ms_fe;
	int error;

	if (blksize == 0 || len < 2 * blksize || len % blksize != 0)
		return EINVAL;

	mutex_enter(&ms->ms_intr_lock);
	if (!ms->ms_prepared || ms->ms_running) {
		mutex_exit(&ms->ms_intr_lock);
		return ms->ms_running ? EBUSY : EINVAL;
	}

	/* Reset the SERDES with sync detached, then reattach it. */
	cl_modify(sc, fe, serdes_conf(ms), CONF_SYNC_SEL, 0);
	cl_modify(sc, fe, serdes_conf(ms), CONF_SYNC_SEL,
	    __SHIFTIN(7, CONF_SYNC_SEL));
	cl_modify(sc, fe, serdes(ms) + SERDES_STATUS,
	    SERDES_STATUS_EN | SERDES_STATUS_RST, SERDES_STATUS_RST);
	delay(MCA_RESET_WAIT_US);
	if (CL_RD(sc, fe, serdes(ms) + SERDES_STATUS) & SERDES_STATUS_RST)
		device_printf(sc->sc_dev, "cluster %u: SERDES stuck in reset\n",
		    fe);
	cl_modify(sc, fe, serdes_conf(ms), CONF_SYNC_SEL, 0);
	cl_modify(sc, fe, serdes_conf(ms), CONF_SYNC_SEL,
	    __SHIFTIN(fe + 1, CONF_SYNC_SEL));
	delay(MCA_SETTLE_WAIT_US);

	ms->ms_start = start;
	ms->ms_end = start + len;
	ms->ms_next = start;
	ms->ms_blksize = blksize;
	ms->ms_intr = intr;
	ms->ms_intrarg = arg;
	memset(&ms->ms_req, 0, sizeof(ms->ms_req));
	ms->ms_req.dreq_dir = ms->ms_tx ? FDT_DMA_WRITE : FDT_DMA_READ;
	ms->ms_req.dreq_dev_opt.opt_bus_width = 32;	/* adapter pads to 32 */
	ms->ms_req.dreq_data = &ms->ms_frame_words;
	ms->ms_req.dreq_datalen = sizeof(ms->ms_frame_words);

	/* Two blocks queued, so the ring never runs dry between blocks. */
	ms->ms_running = true;
	if ((error = mca_queue_block(ms)) == 0)
		error = mca_queue_block(ms);
	if (error != 0) {
		ms->ms_running = false;
		fdtbus_dma_halt(ms->ms_dma);
		mutex_exit(&ms->ms_intr_lock);
		return error;
	}
	cl_modify(sc, fe, serdes(ms) + SERDES_STATUS,
	    SERDES_STATUS_EN | SERDES_STATUS_RST, SERDES_STATUS_EN);
	mutex_exit(&ms->ms_intr_lock);
	return 0;
}

/* Spin-safe like start. */
void
apple_mca_stream_halt(struct apple_mca_stream *ms)
{
	struct apple_mca_softc * const sc = ms->ms_sc;

	mutex_enter(&ms->ms_intr_lock);
	if (ms->ms_running) {
		cl_modify(sc, ms->ms_fe, serdes(ms) + SERDES_STATUS,
		    SERDES_STATUS_EN, 0);
		ms->ms_running = false;
		fdtbus_dma_halt(ms->ms_dma);
	}
	mutex_exit(&ms->ms_intr_lock);
}

void
apple_mca_stream_close(struct apple_mca_stream *ms)
{
	struct apple_mca_softc * const sc = ms->ms_sc;

	apple_mca_stream_unprepare(ms);
	if (ms->ms_dma != NULL)
		fdtbus_dma_put(ms->ms_dma);

	mutex_enter(&sc->sc_lock);
	sc->sc_fe[ms->ms_fe][ms->ms_tx] = NULL;
	mutex_exit(&sc->sc_lock);
	mutex_destroy(&ms->ms_intr_lock);
	kmem_free(ms, sizeof(*ms));
}

static audio_dai_tag_t
apple_mca_dai_get_tag(device_t dev, const void *data, size_t len)
{
	struct apple_mca_softc * const sc = device_private(dev);
	u_int port;

	if (len != 4)
		return NULL;
	port = be32dec(data);
	if (port >= sc->sc_nclusters)
		return NULL;
	return &sc->sc_ports[port].mp_dai;
}

static struct fdtbus_dai_controller_func apple_mca_dai_funcs = {
	.get_tag = apple_mca_dai_get_tag
};

/* The ports carry no stream of their own; streams go through the API. */
static const struct audio_hw_if apple_mca_port_hw_if;

static int
apple_mca_match(device_t parent, cfdata_t cf, void *aux)
{
	struct fdt_attach_args * const faa = aux;

	return of_compatible_match(faa->faa_phandle, compat_data);
}

static void
apple_mca_attach(device_t parent, device_t self, void *aux)
{
	struct apple_mca_softc * const sc = device_private(self);
	struct fdt_attach_args * const faa = aux;
	const int phandle = faa->faa_phandle;
	bus_addr_t addr, swaddr;
	bus_size_t size, swsize;
	int dmac;
	u_int i;

	if (fdtbus_get_reg(phandle, 0, &addr, &size) != 0 ||
	    fdtbus_get_reg(phandle, 1, &swaddr, &swsize) != 0) {
		aprint_error(": couldn't get registers\n");
		return;
	}
	if (size < MCA_CLUSTER_STRIDE) {
		aprint_error(": register window too small\n");
		return;
	}

	sc->sc_dev = self;
	sc->sc_phandle = phandle;
	sc->sc_bst = faa->faa_bst;
	sc->sc_nclusters = MIN((size - MCA_CLUSTER_STRIDE) /
	    MCA_CLUSTER_STRIDE + 1, MCA_MAX_CLUSTERS);
	if (bus_space_map(sc->sc_bst, addr, size, 0, &sc->sc_bsh) != 0 ||
	    bus_space_map(sc->sc_bst, swaddr, swsize, 0, &sc->sc_swh) != 0) {
		aprint_error(": couldn't map registers\n");
		return;
	}

	/*
	 * Buffers are fetched by the ADMAC, behind its DART, so they are
	 * loaded with the tag of the ADMAC's node, not ours.
	 */
	dmac = fdtbus_get_phandle(phandle, "dmas");
	if (dmac <= 0) {
		aprint_error(": no dmas\n");
		return;
	}
	sc->sc_dmat = fdtbus_iommu_map(dmac, 0, faa->faa_dmat);

	mutex_init(&sc->sc_lock, MUTEX_DEFAULT, IPL_NONE);
	for (i = 0; i < MCA_MAX_CLUSTERS; i++)
		sc->sc_port_driver[i] = -1;

	/* The first power domain is for register access. */
	fdtbus_powerdomain_enable_index(phandle, 0);

	aprint_naive("\n");
	aprint_normal(": Apple MCA, %u clusters\n", sc->sc_nclusters);

	for (i = 0; i < sc->sc_nclusters; i++) {
		struct apple_mca_port * const mp = &sc->sc_ports[i];

		mp->mp_sc = sc;
		mp->mp_no = i;
		mp->mp_dai.dai_hw_if = &apple_mca_port_hw_if;
		mp->mp_dai.dai_dev = self;
		mp->mp_dai.dai_priv = mp;
	}
	fdtbus_register_dai_controller(self, phandle, &apple_mca_dai_funcs);
}

CFATTACH_DECL_NEW(apple_mca, sizeof(struct apple_mca_softc),
	apple_mca_match, apple_mca_attach, NULL, NULL);
