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
 * Apple ADMAC, the audio DMA controller.
 *
 * There is no documentation.  Register offsets, fields and the order of
 * operations are facts taken from the Asahi Linux driver
 * drivers/dma/apple-admac.c and the binding apple,admac.yaml; the code
 * is written for NetBSD's fdtbus DMA interface and has not been run on
 * hardware.
 *
 * Channels are hard-wired by parity: even channels move memory to the
 * device, odd ones device to memory.  Each has a ring of four
 * descriptors (address, length, flags) written through one register,
 * and a ring of four reports that the controller fills as descriptors
 * complete.  One fdtbus_dma_transfer() is one descriptor; a consumer
 * that wants no gaps keeps at least two queued.  Each channel buffers
 * through a carve-out of the controller's SRAM, allocated here in 2 KiB
 * blocks.
 *
 * The controller sits behind a DART; buffers must be loaded with the
 * tag fdtbus_iommu_map() gives for this node, not the consumer's.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/device.h>
#include <sys/intr.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/systm.h>

#include <dev/fdt/fdtvar.h>

#define	ADMAC_NCHANNELS_MAX	64
#define	ADMAC_NIRQ		4
#define	ADMAC_RING_SLOTS	4
#define	ADMAC_SRAM_BLOCK	2048

#define	ADMAC_TX_START		0x0000
#define	ADMAC_TX_STOP		0x0004
#define	ADMAC_RX_START		0x0008
#define	ADMAC_RX_STOP		0x000c
#define	ADMAC_TX_INTSTATE(i)	(0x0030 + (i) * 4)
#define	ADMAC_RX_INTSTATE(i)	(0x0040 + (i) * 4)
#define	ADMAC_GLOBAL_INTSTATE(i) (0x0050 + (i) * 4)
#define	ADMAC_TX_SRAM_SIZE	0x0094
#define	ADMAC_RX_SRAM_SIZE	0x0098

#define	ADMAC_CHAN(ch)		(0x8000 + (ch) * 0x200)
#define	ADMAC_CHAN_CTL(ch)	(ADMAC_CHAN(ch) + 0x00)
#define	 CHAN_CTL_RST_RINGS	__BIT(0)
#define	ADMAC_CHAN_INTSTATUS(ch, i) (ADMAC_CHAN(ch) + 0x10 + (i) * 4)
#define	ADMAC_CHAN_INTMASK(ch, i) (ADMAC_CHAN(ch) + 0x20 + (i) * 4)
#define	 STATUS_DESC_DONE	__BIT(0)
#define	 STATUS_ERR		__BIT(6)
#define	ADMAC_BUS_WIDTH(ch)	(ADMAC_CHAN(ch) + 0x40)
#define	 BUS_WIDTH_WORD		__BITS(3,0)
#define	  BUS_WIDTH_WORD_8	0
#define	  BUS_WIDTH_WORD_16	1
#define	  BUS_WIDTH_WORD_32	2
#define	 BUS_WIDTH_FRAME	__BITS(7,4)
#define	  BUS_WIDTH_FRAME_1	0
#define	  BUS_WIDTH_FRAME_2	1
#define	  BUS_WIDTH_FRAME_4	2
#define	ADMAC_SRAM_CARVEOUT(ch)	(ADMAC_CHAN(ch) + 0x50)
#define	 CARVEOUT_SIZE		__BITS(31,16)
#define	 CARVEOUT_BASE		__BITS(15,0)
#define	ADMAC_FIFOCTL(ch)	(ADMAC_CHAN(ch) + 0x54)
#define	 FIFOCTL_LIMIT		__BITS(31,16)
#define	 FIFOCTL_THRESHOLD	__BITS(15,0)
#define	ADMAC_DESC_RING(ch)	(ADMAC_CHAN(ch) + 0x70)
#define	ADMAC_REPORT_RING(ch)	(ADMAC_CHAN(ch) + 0x74)
#define	 RING_EMPTY		__BIT(8)
#define	 RING_FULL		__BIT(9)
#define	 RING_ERR		__BIT(10)

#define	ADMAC_DESC_WRITE(ch)	(0x10000 + ((ch) / 2) * 4 + ((ch) & 1) * 0x4000)
#define	ADMAC_REPORT_READ(ch)	(0x10100 + ((ch) / 2) * 4 + ((ch) & 1) * 0x4000)
#define	 DESC_FLAG_NOTIFY	__BIT(16)

struct apple_admac_softc;

struct apple_admac_chan {
	struct apple_admac_softc *ac_sc;
	u_int			ac_no;
	bool			ac_busy;	/* acquired */
	bool			ac_running;
	uint32_t		ac_carveout;
	void			(*ac_cb)(void *);
	void			*ac_cbarg;
};

struct apple_admac_softc {
	device_t		sc_dev;
	bus_space_tag_t		sc_bst;
	bus_space_handle_t	sc_bsh;
	int			sc_phandle;
	void			*sc_ih;
	u_int			sc_irq;		/* which of the four outputs */

	kmutex_t		sc_lock;	/* spin, IPL_AUDIO */
	uint64_t		sc_sram_used[2];	/* tx, rx: 2K blocks */
	u_int			sc_nchan;
	struct apple_admac_chan	sc_chan[ADMAC_NCHANNELS_MAX];
};

#define	RD4(sc, reg) \
	bus_space_read_4((sc)->sc_bst, (sc)->sc_bsh, (reg))
#define	WR4(sc, reg, val) \
	bus_space_write_4((sc)->sc_bst, (sc)->sc_bsh, (reg), (val))

static const struct device_compatible_entry compat_data[] = {
	/* t603x need an extra register set; not handled, so not matched. */
	{ .compat = "apple,t8103-admac" },
	{ .compat = "apple,t8112-admac" },
	{ .compat = "apple,t6000-admac" },
	DEVICE_COMPAT_EOL
};

static inline bool
admac_is_tx(u_int ch)
{

	return (ch & 1) == 0;
}

/* One 2 KiB block of the direction's SRAM, or 0 if none is free. */
static uint32_t
admac_sram_alloc(struct apple_admac_softc *sc, u_int ch)
{
	const u_int dir = admac_is_tx(ch) ? 0 : 1;
	uint32_t size;
	u_int i, nblocks;

	size = RD4(sc, admac_is_tx(ch) ? ADMAC_TX_SRAM_SIZE :
	    ADMAC_RX_SRAM_SIZE);
	/* CARVEOUT fields are 16 bits, so at most 64 KiB is usable. */
	nblocks = MIN(size, 0x10000) / ADMAC_SRAM_BLOCK;
	for (i = 0; i < nblocks; i++) {
		if ((sc->sc_sram_used[dir] & __BIT(i)) == 0) {
			sc->sc_sram_used[dir] |= __BIT(i);
			return __SHIFTIN(i * ADMAC_SRAM_BLOCK, CARVEOUT_BASE) |
			    __SHIFTIN(ADMAC_SRAM_BLOCK, CARVEOUT_SIZE);
		}
	}
	return 0;
}

static void
admac_sram_free(struct apple_admac_softc *sc, u_int ch, uint32_t carveout)
{
	const u_int dir = admac_is_tx(ch) ? 0 : 1;

	sc->sc_sram_used[dir] &=
	    ~__BIT(__SHIFTOUT(carveout, CARVEOUT_BASE) / ADMAC_SRAM_BLOCK);
}

static void
admac_reset_rings(struct apple_admac_softc *sc, u_int ch)
{

	WR4(sc, ADMAC_CHAN_CTL(ch), CHAN_CTL_RST_RINGS);
	WR4(sc, ADMAC_CHAN_CTL(ch), 0);
}

static void
admac_stop(struct apple_admac_softc *sc, u_int ch)
{

	WR4(sc, admac_is_tx(ch) ? ADMAC_TX_STOP : ADMAC_RX_STOP,
	    __BIT(ch / 2));
}

static void
admac_start(struct apple_admac_softc *sc, u_int ch)
{

	WR4(sc, ADMAC_CHAN_INTSTATUS(ch, sc->sc_irq),
	    STATUS_DESC_DONE | STATUS_ERR);
	WR4(sc, ADMAC_CHAN_INTMASK(ch, sc->sc_irq),
	    STATUS_DESC_DONE | STATUS_ERR);
	WR4(sc, admac_is_tx(ch) ? ADMAC_TX_START : ADMAC_RX_START,
	    __BIT(ch / 2));
}

static void *
apple_admac_acquire(device_t dev, const void *data, size_t len,
    void (*cb)(void *), void *cbarg)
{
	struct apple_admac_softc * const sc = device_private(dev);
	struct apple_admac_chan *ac;
	uint32_t carveout;
	u_int ch;

	if (len != 4)
		return NULL;
	ch = be32dec(data);
	if (ch >= sc->sc_nchan)
		return NULL;
	ac = &sc->sc_chan[ch];

	mutex_enter(&sc->sc_lock);
	if (ac->ac_busy || (carveout = admac_sram_alloc(sc, ch)) == 0) {
		mutex_exit(&sc->sc_lock);
		return NULL;
	}
	ac->ac_busy = true;
	ac->ac_running = false;
	ac->ac_carveout = carveout;
	ac->ac_cb = cb;
	ac->ac_cbarg = cbarg;
	WR4(sc, ADMAC_SRAM_CARVEOUT(ch), carveout);
	mutex_exit(&sc->sc_lock);

	return ac;
}

static void
apple_admac_halt(device_t dev, void *priv)
{
	struct apple_admac_softc * const sc = device_private(dev);
	struct apple_admac_chan * const ac = priv;

	mutex_enter(&sc->sc_lock);
	admac_stop(sc, ac->ac_no);
	admac_reset_rings(sc, ac->ac_no);
	WR4(sc, ADMAC_CHAN_INTMASK(ac->ac_no, sc->sc_irq), 0);
	ac->ac_running = false;
	mutex_exit(&sc->sc_lock);
}

static void
apple_admac_release(device_t dev, void *priv)
{
	struct apple_admac_softc * const sc = device_private(dev);
	struct apple_admac_chan * const ac = priv;

	apple_admac_halt(dev, priv);
	mutex_enter(&sc->sc_lock);
	admac_sram_free(sc, ac->ac_no, ac->ac_carveout);
	ac->ac_busy = false;
	ac->ac_cb = NULL;
	mutex_exit(&sc->sc_lock);
}

/*
 * Bus width in bits, and through dreq_data an optional u_int giving the
 * words per frame (1, 2 or 4): the controller signals word position in
 * the frame to the peripheral.
 */
static int
admac_config(struct apple_admac_softc *sc, u_int ch,
    const struct fdtbus_dma_req *req)
{
	u_int width, frame, words;
	uint32_t bw;

	switch (req->dreq_dev_opt.opt_bus_width) {
	case 8:
		width = BUS_WIDTH_WORD_8;
		break;
	case 16:
		width = BUS_WIDTH_WORD_16;
		break;
	case 32:
		width = BUS_WIDTH_WORD_32;
		break;
	default:
		return EINVAL;
	}
	words = 1;
	if (req->dreq_data != NULL) {
		if (req->dreq_datalen != sizeof(u_int))
			return EINVAL;
		words = *(const u_int *)req->dreq_data;
	}
	switch (words) {
	case 1:
		frame = BUS_WIDTH_FRAME_1;
		break;
	case 2:
		frame = BUS_WIDTH_FRAME_2;
		break;
	case 4:
		frame = BUS_WIDTH_FRAME_4;
		break;
	default:
		return EINVAL;
	}

	bw = RD4(sc, ADMAC_BUS_WIDTH(ch)) & ~(BUS_WIDTH_WORD | BUS_WIDTH_FRAME);
	WR4(sc, ADMAC_BUS_WIDTH(ch), bw | __SHIFTIN(width, BUS_WIDTH_WORD) |
	    __SHIFTIN(frame, BUS_WIDTH_FRAME));

	/*
	 * FIFO limit and trigger threshold, in bytes.  The Asahi driver
	 * calls its values more or less arbitrary; they are used as is.
	 */
	WR4(sc, ADMAC_FIFOCTL(ch),
	    __SHIFTIN(0x30 * (req->dreq_dev_opt.opt_bus_width / 8),
		FIFOCTL_LIMIT) |
	    __SHIFTIN(0x18 * (req->dreq_dev_opt.opt_bus_width / 8),
		FIFOCTL_THRESHOLD));
	return 0;
}

static int
apple_admac_transfer(device_t dev, void *priv, struct fdtbus_dma_req *req)
{
	struct apple_admac_softc * const sc = device_private(dev);
	struct apple_admac_chan * const ac = priv;
	const u_int ch = ac->ac_no;
	bus_addr_t addr;
	bus_size_t len;
	int error;

	if (req->dreq_nsegs != 1 ||
	    (req->dreq_dir == FDT_DMA_WRITE) != admac_is_tx(ch))
		return EINVAL;
	addr = req->dreq_segs[0].ds_addr;
	len = req->dreq_segs[0].ds_len;
	if (len == 0 || len > UINT32_MAX)
		return EINVAL;

	mutex_enter(&sc->sc_lock);
	if (!ac->ac_running) {
		if ((error = admac_config(sc, ch, req)) != 0) {
			mutex_exit(&sc->sc_lock);
			return error;
		}
		admac_reset_rings(sc, ch);
	} else if (RD4(sc, ADMAC_DESC_RING(ch)) & RING_FULL) {
		mutex_exit(&sc->sc_lock);
		return EBUSY;
	}

	/* Four writes to the same register make one descriptor. */
	WR4(sc, ADMAC_DESC_WRITE(ch), BUS_ADDR_LO32(addr));
	WR4(sc, ADMAC_DESC_WRITE(ch), BUS_ADDR_HI32(addr));
	WR4(sc, ADMAC_DESC_WRITE(ch), (uint32_t)len);
	WR4(sc, ADMAC_DESC_WRITE(ch), DESC_FLAG_NOTIFY);

	if (!ac->ac_running) {
		admac_start(sc, ch);
		ac->ac_running = true;
	}
	mutex_exit(&sc->sc_lock);
	return 0;
}

static const struct fdtbus_dma_controller_func apple_admac_dma_funcs = {
	.acquire = apple_admac_acquire,
	.release = apple_admac_release,
	.transfer = apple_admac_transfer,
	.halt = apple_admac_halt,
};

/* Take the completed reports; each is one finished descriptor. */
static u_int
admac_drain(struct apple_admac_softc *sc, u_int ch)
{
	u_int n, i;

	for (n = 0; n < ADMAC_RING_SLOTS; n++) {
		if (RD4(sc, ADMAC_REPORT_RING(ch)) & RING_EMPTY)
			break;
		/* A report is four words: count low, count high, ?, flags. */
		for (i = 0; i < 4; i++)
			(void)RD4(sc, ADMAC_REPORT_READ(ch));
	}
	return n;
}

static u_int
admac_chan_intr(struct apple_admac_softc *sc, u_int ch)
{
	uint32_t cause;
	u_int done = 0;

	cause = RD4(sc, ADMAC_CHAN_INTSTATUS(ch, sc->sc_irq));
	if (cause & STATUS_ERR) {
		bool known = false;

		if (RD4(sc, ADMAC_DESC_RING(ch)) & RING_ERR) {
			WR4(sc, ADMAC_DESC_RING(ch), RING_ERR);
			known = true;
		}
		if (RD4(sc, ADMAC_REPORT_RING(ch)) & RING_ERR) {
			WR4(sc, ADMAC_REPORT_RING(ch), RING_ERR);
			known = true;
		}
		if (!known) {
			/* Unknown cause: stop it from storming. */
			device_printf(sc->sc_dev,
			    "channel %u: unknown error, masked\n", ch);
			WR4(sc, ADMAC_CHAN_INTMASK(ch, sc->sc_irq),
			    RD4(sc, ADMAC_CHAN_INTMASK(ch, sc->sc_irq)) &
			    ~STATUS_ERR);
		}
	}
	if (cause & STATUS_DESC_DONE) {
		WR4(sc, ADMAC_CHAN_INTSTATUS(ch, sc->sc_irq), STATUS_DESC_DONE);
		done = admac_drain(sc, ch);
	}
	return done;
}

static int
apple_admac_intr(void *arg)
{
	struct apple_admac_softc * const sc = arg;
	struct {
		void	(*cb)(void *);
		void	*arg;
		u_int	n;
	} done[ADMAC_NCHANNELS_MAX];
	uint32_t tx, rx, global;
	u_int ch, n;

	mutex_enter(&sc->sc_lock);
	tx = RD4(sc, ADMAC_TX_INTSTATE(sc->sc_irq));
	rx = RD4(sc, ADMAC_RX_INTSTATE(sc->sc_irq));
	global = RD4(sc, ADMAC_GLOBAL_INTSTATE(sc->sc_irq));
	if (tx == 0 && rx == 0 && global == 0) {
		mutex_exit(&sc->sc_lock);
		return 0;
	}
	/* Bit n of TX state is channel 2n, of RX state channel 2n + 1. */
	for (ch = 0; ch < sc->sc_nchan; ch++) {
		const uint32_t state = admac_is_tx(ch) ? tx : rx;

		done[ch].n = (state & __BIT(ch / 2)) ?
		    admac_chan_intr(sc, ch) : 0;
		/* Taken under the lock: release() may clear them. */
		done[ch].cb = sc->sc_chan[ch].ac_cb;
		done[ch].arg = sc->sc_chan[ch].ac_cbarg;
	}
	if (global != 0) {
		device_printf(sc->sc_dev, "unknown global interrupt 0x%x\n",
		    global);
		WR4(sc, ADMAC_GLOBAL_INTSTATE(sc->sc_irq), 0xffffffff);
	}
	mutex_exit(&sc->sc_lock);

	/* Callbacks queue the next descriptor, so not under our lock. */
	for (ch = 0; ch < sc->sc_nchan; ch++) {
		for (n = 0; n < done[ch].n && done[ch].cb != NULL; n++)
			done[ch].cb(done[ch].arg);
	}
	return 1;
}

static int
apple_admac_match(device_t parent, cfdata_t cf, void *aux)
{
	struct fdt_attach_args * const faa = aux;

	return of_compatible_match(faa->faa_phandle, compat_data);
}

static void
apple_admac_attach(device_t parent, device_t self, void *aux)
{
	struct apple_admac_softc * const sc = device_private(self);
	struct fdt_attach_args * const faa = aux;
	const int phandle = faa->faa_phandle;
	bus_addr_t addr;
	bus_size_t size;
	uint32_t nchan;
	u_int i;

	if (fdtbus_get_reg(phandle, 0, &addr, &size) != 0) {
		aprint_error(": couldn't get registers\n");
		return;
	}
	if (of_getprop_uint32(phandle, "dma-channels", &nchan) != 0 ||
	    nchan == 0 || nchan > ADMAC_NCHANNELS_MAX) {
		aprint_error(": missing or bad dma-channels\n");
		return;
	}

	sc->sc_dev = self;
	sc->sc_phandle = phandle;
	sc->sc_bst = faa->faa_bst;
	sc->sc_nchan = nchan;
	if (bus_space_map(sc->sc_bst, addr, size, 0, &sc->sc_bsh) != 0) {
		aprint_error(": couldn't map registers\n");
		return;
	}
	mutex_init(&sc->sc_lock, MUTEX_DEFAULT, IPL_AUDIO);
	for (i = 0; i < nchan; i++) {
		sc->sc_chan[i].ac_sc = sc;
		sc->sc_chan[i].ac_no = i;
	}

	/*
	 * The binding has a reset as well, but apple_pmgr does not provide
	 * resets; the power domain is enabled and the block left as the
	 * firmware set it up.
	 */
	fdtbus_powerdomain_enable(phandle);

	aprint_naive("\n");
	aprint_normal(": Apple ADMAC, %u channels\n", nchan);

	/*
	 * Four interrupt outputs, of which a machine wires some; the
	 * unwired ones are <0> in interrupts-extended.  Use the first
	 * that establishes.
	 */
	for (i = 0; i < ADMAC_NIRQ; i++) {
		char intrstr[128];

		if (!fdtbus_intr_str(phandle, i, intrstr, sizeof(intrstr)))
			continue;
		sc->sc_ih = fdtbus_intr_establish_xname(phandle, i, IPL_AUDIO,
		    FDT_INTR_MPSAFE, apple_admac_intr, sc, device_xname(self));
		if (sc->sc_ih != NULL) {
			sc->sc_irq = i;
			aprint_normal_dev(self, "interrupting on %s (output %u)\n",
			    intrstr, i);
			break;
		}
	}
	if (sc->sc_ih == NULL) {
		aprint_error_dev(self, "couldn't establish an interrupt\n");
		return;
	}

	/* Nothing running, nothing interrupting, until acquired. */
	for (i = 0; i < nchan; i++) {
		admac_stop(sc, i);
		WR4(sc, ADMAC_CHAN_INTMASK(i, sc->sc_irq), 0);
	}

	fdtbus_register_dma_controller(self, phandle, &apple_admac_dma_funcs);
}

CFATTACH_DECL_NEW(apple_admac, sizeof(struct apple_admac_softc),
	apple_admac_match, apple_admac_attach, NULL, NULL);
