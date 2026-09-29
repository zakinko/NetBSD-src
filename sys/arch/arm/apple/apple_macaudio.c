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
 * Sound on Apple Silicon Macs ("apple,macaudio"): the speaker array.
 *
 * The speakers have no protection of their own and fail in seconds if
 * driven hard.  Protection is a userland daemon (speakersafetyd) that
 * models their temperature from the amplifiers' voltage and current
 * sense and turns them down.  The kernel side of the arrangement:
 *
 *  - Every amplifier gets a limit it enforces itself (tasamp(4)): an
 *    output level cap for the machine, and a lock that holds the
 *    volume at mute.  The lock starts closed.
 *
 *  - The daemon opens it by writing SPEAKER_UNLOCK_MAGIC to
 *    hw.<dev>.speaker_unlock, and must keep writing it: while playing,
 *    250 ms without a write closes the lock again.  A daemon that dies
 *    or hangs leaves the speakers muted.
 *
 *  - Per-speaker volume, which the daemon lowers as the speakers heat,
 *    is hw.<dev>.speaker.<name>.volume in hundredths of a dB.  Only
 *    root can write these.  User volume stays in the audio layer.
 *
 *  - Machines on which the upstream work has not validated a model get
 *    no speaker output at all.
 *
 * The numbers per machine, the timeout and the magic are facts from the
 * Asahi Linux machine driver sound/soc/apple/macaudio.c; the magic is
 * also what speakersafetyd writes.  The TDM layout follows the same
 * driver.
 *
 * The amplifiers' voltage and current sense comes back on the speaker
 * ports and is recorded by a second, capture-only audio device: 16-bit,
 * two channels per speaker, current first, in the order of the codec
 * list (the amplifiers' 8-bit TX slots put them in consecutive 16-bit
 * slots; TAS2764 8.4.1).  It flows only while the speaker clocks run.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/bitops.h>
#include <sys/bus.h>
#include <sys/callout.h>
#include <sys/device.h>
#include <sys/file.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/workqueue.h>

#include <dev/audio/audio_dai.h>
#include <dev/audio/audio_if.h>

#include <dev/fdt/fdtvar.h>

#include <arm/apple/apple_mcavar.h>

#define	SPEAKER_UNLOCK_MAGIC	0xdec1be15
#define	SPEAKER_LOCK_TIMEOUT_MS	250

#define	MACAUDIO_SLOT_WIDTH	32
#define	MACAUDIO_SPEAKER_BCLK	256	/* bit clocks per frame */
#define	MACAUDIO_SPEAKER_FE	1	/* Asahi's "Secondary" frontend */
#define	MACAUDIO_MAX_BCLK_HZ	24576000	/* TAS2764 limit */
#define	MACAUDIO_MAX_CODECS	8
#define	MACAUDIO_MAX_PORTS	2

/*
 * Per machine: whether upstream considers the speaker model safe to
 * drive, and the amplifier output level cap in AMP_LEVEL steps
 * (11 dBV + 0.5 dB per step).  From macaudio.c.
 */
struct macaudio_machine {
	bool	enable;
	u_int	gain_step;
};

static const struct macaudio_machine j180 = { false, 10 };
static const struct macaudio_machine j274 = { true, 20 };
static const struct macaudio_machine j293 = { true, 15 };
static const struct macaudio_machine j313 = { true, 10 };
static const struct macaudio_machine j314 = { true, 15 };
/*
 * j375/j473 share a structure upstream with 20 steps, while its own
 * table comment gives j375 as 15; for a cap the smaller is taken.
 */
static const struct macaudio_machine j375 = { true, 15 };
static const struct macaudio_machine j413 = { true, 15 };
static const struct macaudio_machine j45x = { false, 9 };
static const struct macaudio_machine j473 = { true, 20 };
static const struct macaudio_machine j493 = { true, 15 };

static const struct device_compatible_entry compat_data[] = {
	{ .compat = "apple,j180-macaudio",	.data = &j180 },
	{ .compat = "apple,j274-macaudio",	.data = &j274 },
	{ .compat = "apple,j293-macaudio",	.data = &j293 },
	{ .compat = "apple,j313-macaudio",	.data = &j313 },
	{ .compat = "apple,j314-macaudio",	.data = &j314 },
	{ .compat = "apple,j316-macaudio",	.data = &j314 },
	{ .compat = "apple,j375-macaudio",	.data = &j375 },
	{ .compat = "apple,j413-macaudio",	.data = &j413 },
	{ .compat = "apple,j415-macaudio",	.data = &j314 },
	{ .compat = "apple,j456-macaudio",	.data = &j45x },
	{ .compat = "apple,j473-macaudio",	.data = &j473 },
	{ .compat = "apple,j493-macaudio",	.data = &j493 },
	DEVICE_COMPAT_EOL
};

/* Machines matched only by the generic string get no speakers. */
static const struct device_compatible_entry compat_generic[] = {
	{ .compat = "apple,macaudio" },
	DEVICE_COMPAT_EOL
};

struct macaudio_softc;

struct macaudio_codec {
	struct macaudio_softc	*mc_sc;
	audio_dai_tag_t		mc_dai;
	char			mc_name[32];	/* sysctl-safe */
	int			mc_volume;	/* cdB, set by the daemon */
};

struct macaudio_dma {
	LIST_ENTRY(macaudio_dma) md_list;
	bus_dmamap_t		md_map;
	bus_dma_segment_t	md_seg;
	void			*md_kva;
	size_t			md_size;
};

struct macaudio_softc;

LIST_HEAD(macaudio_dmalist, macaudio_dma);

/* The sense capture device. */
struct macaudio_sense {
	struct macaudio_softc	*se_sc;
	kmutex_t		se_lock;
	kmutex_t		se_intr_lock;
	struct apple_mca_stream	*se_stream;
	bus_dma_tag_t		se_dmat;
	struct macaudio_dmalist	se_dmalist;
	void			(*se_rintr)(void *);
	void			*se_rintrarg;
	u_int			se_channels;
};

/*
 * The headphone jack: its own audio device, no lock (nothing to
 * protect but ears, which the codec's starting volume looks after).
 */
struct macaudio_hp {
	struct macaudio_softc	*hp_sc;
	kmutex_t		hp_lock;
	kmutex_t		hp_intr_lock;
	audio_dai_tag_t		hp_codec;
	struct apple_mca_stream	*hp_stream;
	bus_dma_tag_t		hp_dmat;
	struct macaudio_dmalist	hp_dmalist;
	void			(*hp_pintr)(void *);
	void			*hp_pintrarg;
	/* The headset microphone, on the same port's receiver. */
	struct apple_mca_stream	*hp_rstream;
	bus_dma_tag_t		hp_rdmat;
	struct macaudio_dmalist	hp_rdmalist;
	void			(*hp_rintr)(void *);
	void			*hp_rintrarg;
	/* Under the softc's sc_intr_lock, for the work. */
	int			hp_flags;	/* FREAD|FWRITE open, 0 closed */
	u_int			hp_level;	/* mixer, 0..255 */
	bool			hp_level_dirty;
	/* Under sc_cfg_lock. */
	int			hp_codec_flags;	/* as the codec is open */
};

struct macaudio_softc {
	device_t		sc_dev;
	int			sc_phandle;
	const struct macaudio_machine *sc_machine;

	/*
	 * sc_lock and sc_intr_lock belong to the audio layer: nothing that
	 * sleeps may happen under them, and it calls open, close, trigger
	 * and halt with both held (audio.c).  Everything that talks to the
	 * amplifiers over I2C therefore runs in sc_wq under sc_cfg_lock.
	 */
	kmutex_t		sc_lock;
	kmutex_t		sc_intr_lock;	/* spin, IPL_SCHED */
	kmutex_t		sc_cfg_lock;	/* adaptive: limits, amps */

	device_t		sc_mca;
	uint32_t		sc_ports;
	u_int			sc_ncodecs;
	struct macaudio_codec	sc_codecs[MACAUDIO_MAX_CODECS];
	u_int			sc_channels;
	uint32_t		sc_slot_mask;
	u_int			sc_rate;

	struct apple_mca_stream	*sc_stream;
	bus_dma_tag_t		sc_dmat;
	struct macaudio_dmalist	sc_dmalist;
	struct macaudio_sense	sc_sense;
	bool			sc_has_sense;
	struct macaudio_hp	sc_hp;
	bool			sc_has_hp;
	void			(*sc_pintr)(void *);
	void			*sc_pintrarg;

	/* Under sc_intr_lock: what the audio layer last asked for. */
	bool			sc_open;
	bool			sc_playing;
	bool			sc_work_queued;

	/*
	 * Under sc_cfg_lock.  The lock stays open for at most
	 * SPEAKER_LOCK_TIMEOUT_MS of playback after the last unlock
	 * write: the clock runs only while playing (sc_timing), with
	 * sc_deadline the absolute expiry then, and sc_remaining what is
	 * left while stopped.  Playback that starts long after the last
	 * write gets only what was left, never a fresh period.
	 */
	bool			sc_amps_running;
	bool			sc_unlocked;
	bool			sc_timing;
	int			sc_deadline;	/* ticks, while sc_timing */
	int			sc_remaining;	/* ticks, while !sc_timing */

	callout_t		sc_lock_callout;
	struct workqueue	*sc_wq;
	struct work		sc_work;

	struct sysctllog	*sc_sysctllog;
	char			sc_compatible[32];	/* machine, for the daemon */
	char			sc_sense_audio[16];	/* its capture device */
};

static int	macaudio_match(device_t, cfdata_t, void *);
static void	macaudio_attach(device_t, device_t, void *);

CFATTACH_DECL_NEW(apple_macaudio, sizeof(struct macaudio_softc),
    macaudio_match, macaudio_attach, NULL, NULL);

/* Level cap for the machine, cdBV. */
static int
macaudio_amp_cap(const struct macaudio_softc *sc)
{

	return 1100 + 50 * (int)sc->sc_machine->gain_step;
}

/*
 * Push the lock state and the volumes to every amplifier.  An amplifier
 * that fails shuts itself down (tasamp(4)); the error is returned so
 * the caller knows, but nothing here can make it louder.
 */
static int
macaudio_apply_limits(struct macaudio_softc *sc)
{
	struct audio_dai_speaker_limit lim;
	int error = 0, e;
	u_int i;

	KASSERT(mutex_owned(&sc->sc_cfg_lock));

	lim.locked = !sc->sc_unlocked;
	lim.amp_gain_max = macaudio_amp_cap(sc);
	for (i = 0; i < sc->sc_ncodecs; i++) {
		struct macaudio_codec * const mc = &sc->sc_codecs[i];

		/* Volume first when locking is not the change; see tasamp. */
		e = audio_dai_set_speaker_limit(mc->mc_dai, &lim);
		if (e == 0)
			e = audio_dai_set_volume(mc->mc_dai, mc->mc_volume);
		if (e != 0 && error == 0)
			error = e;
	}
	return error;
}

/*
 * The one place that reconciles the amplifiers with what the audio
 * layer and the daemon want: runs the amplifiers while open, closes an
 * expired lock, and re-arms the timer.  In the workqueue, so it may
 * sleep on I2C.
 */
static void
macaudio_work(struct work *wk, void *arg)
{
	struct macaudio_softc * const sc = arg;
	bool open, playing;
	u_int i;
	int left;

	mutex_enter(&sc->sc_intr_lock);
	sc->sc_work_queued = false;
	open = sc->sc_open;
	playing = sc->sc_playing;
	mutex_exit(&sc->sc_intr_lock);

	/* Headphones: codec power follows the device, volume on request. */
	if (sc->sc_has_hp) {
		struct macaudio_hp * const hp = &sc->sc_hp;
		bool dirty;
		u_int level;
		int hflags;

		mutex_enter(&sc->sc_intr_lock);
		hflags = hp->hp_flags;
		dirty = hp->hp_level_dirty;
		level = hp->hp_level;
		hp->hp_level_dirty = false;
		mutex_exit(&sc->sc_intr_lock);

		/*
		 * The codec powers the microphone path only when opened for
		 * reading, so a change of mode reopens it.  Without a
		 * headset to record, reading gives silence and playback
		 * goes on.
		 */
		mutex_enter(&sc->sc_cfg_lock);
		if (hflags != hp->hp_codec_flags) {
			if (hp->hp_codec_flags != 0)
				audio_dai_close(hp->hp_codec);
			hp->hp_codec_flags = 0;
			if (hflags != 0) {
				if (audio_dai_open(hp->hp_codec,
				    hflags | FWRITE) != 0)
					(void)audio_dai_open(hp->hp_codec,
					    FWRITE);
				hp->hp_codec_flags = hflags;
			}
		}
		if (dirty) {
			/* 0..255 onto -62..0 dB; 0 mutes. */
			(void)audio_dai_set_volume(hp->hp_codec, level == 0 ?
			    -12000 : -(int)(255 - level) * 6200 / 255);
		}
		mutex_exit(&sc->sc_cfg_lock);
	}

	mutex_enter(&sc->sc_cfg_lock);
	if (open != sc->sc_amps_running) {
		for (i = 0; i < sc->sc_ncodecs; i++) {
			if (open)
				(void)audio_dai_open(sc->sc_codecs[i].mc_dai,
				    FWRITE);
			else
				audio_dai_close(sc->sc_codecs[i].mc_dai);
		}
		sc->sc_amps_running = open;
	}
	if (playing && !sc->sc_timing) {
		sc->sc_deadline = getticks() + sc->sc_remaining;
		sc->sc_timing = true;
	} else if (!playing && sc->sc_timing) {
		sc->sc_remaining = MAX(sc->sc_deadline - getticks(), 0);
		sc->sc_timing = false;
	}
	if (sc->sc_unlocked && sc->sc_timing) {
		left = sc->sc_deadline - getticks();
		if (left <= 0) {
			sc->sc_unlocked = false;
			sc->sc_remaining = 0;
			device_printf(sc->sc_dev,
			    "speaker lock timed out, muting\n");
			(void)macaudio_apply_limits(sc);
			callout_stop(&sc->sc_lock_callout);
		} else {
			callout_schedule(&sc->sc_lock_callout, left);
		}
	} else {
		callout_stop(&sc->sc_lock_callout);
	}
	mutex_exit(&sc->sc_cfg_lock);
}

/* Queue the work; safe from any context, including under spin locks. */
static void
macaudio_kick(struct macaudio_softc *sc)
{

	KASSERT(mutex_owned(&sc->sc_intr_lock));

	if (!sc->sc_work_queued) {
		sc->sc_work_queued = true;
		workqueue_enqueue(sc->sc_wq, &sc->sc_work, NULL);
	}
}

static void
macaudio_lock_expire(void *arg)
{
	struct macaudio_softc * const sc = arg;

	mutex_enter(&sc->sc_intr_lock);
	macaudio_kick(sc);
	mutex_exit(&sc->sc_intr_lock);
}

static int
macaudio_sysctl_unlock(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct macaudio_softc * const sc = node.sysctl_data;
	int val, error;

	mutex_enter(&sc->sc_cfg_lock);
	val = sc->sc_unlocked;
	mutex_exit(&sc->sc_cfg_lock);
	node.sysctl_data = &val;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error || newp == NULL)
		return error;
	if ((uint32_t)val != SPEAKER_UNLOCK_MAGIC)
		return EINVAL;

	mutex_enter(&sc->sc_cfg_lock);
	sc->sc_remaining = mstohz(SPEAKER_LOCK_TIMEOUT_MS);
	sc->sc_deadline = getticks() + sc->sc_remaining;
	if (!sc->sc_unlocked) {
		sc->sc_unlocked = true;
		error = macaudio_apply_limits(sc);
	}
	mutex_exit(&sc->sc_cfg_lock);

	/* Let the work re-arm the timer against the new deadline. */
	mutex_enter(&sc->sc_intr_lock);
	macaudio_kick(sc);
	mutex_exit(&sc->sc_intr_lock);
	return error;
}

static int
macaudio_sysctl_volume(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct macaudio_codec * const mc = node.sysctl_data;
	struct macaudio_softc * const sc = mc->mc_sc;
	int val, error;

	mutex_enter(&sc->sc_cfg_lock);
	val = mc->mc_volume;
	mutex_exit(&sc->sc_cfg_lock);
	node.sysctl_data = &val;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error || newp == NULL)
		return error;
	if (val > 0 || val < -12000)
		return EINVAL;

	mutex_enter(&sc->sc_cfg_lock);
	mc->mc_volume = val;
	error = audio_dai_set_volume(mc->mc_dai, val);
	mutex_exit(&sc->sc_cfg_lock);
	return error;
}

static void
macaudio_sysctl_init(struct macaudio_softc *sc)
{
	const struct sysctlnode *root, *spk, *node;
	static int cap_dummy;
	u_int i;

	if (sysctl_createv(&sc->sc_sysctllog, 0, NULL, &root, 0,
	    CTLTYPE_NODE, device_xname(sc->sc_dev),
	    SYSCTL_DESCR("Apple Mac audio"), NULL, 0, NULL, 0,
	    CTL_HW, CTL_CREATE, CTL_EOL) != 0)
		return;
	sysctl_createv(&sc->sc_sysctllog, 0, &root, NULL, CTLFLAG_READWRITE,
	    CTLTYPE_INT, "speaker_unlock",
	    SYSCTL_DESCR("Write the magic to open the speaker lock for "
		"250 ms of playback; reads 1 while open"),
	    macaudio_sysctl_unlock, 0, (void *)sc, 0, CTL_CREATE, CTL_EOL);
	sysctl_createv(&sc->sc_sysctllog, 0, &root, NULL, CTLFLAG_READONLY,
	    CTLTYPE_INT, "speaker_rate",
	    SYSCTL_DESCR("Speaker sample rate, 0 when idle"),
	    NULL, 0, &sc->sc_rate, 0, CTL_CREATE, CTL_EOL);
	cap_dummy = macaudio_amp_cap(sc);
	sysctl_createv(&sc->sc_sysctllog, 0, &root, NULL,
	    CTLFLAG_READONLY | CTLFLAG_IMMEDIATE, CTLTYPE_INT, "amp_gain_max",
	    SYSCTL_DESCR("Amplifier output level cap, cdBV"),
	    NULL, cap_dummy, NULL, 0, CTL_CREATE, CTL_EOL);
	/* What speakersafetyd needs to find its configuration and data. */
	sysctl_createv(&sc->sc_sysctllog, 0, &root, NULL, CTLFLAG_READONLY,
	    CTLTYPE_STRING, "compatible",
	    SYSCTL_DESCR("Machine, as the first device tree compatible"),
	    NULL, 0, sc->sc_compatible, 0, CTL_CREATE, CTL_EOL);
	sysctl_createv(&sc->sc_sysctllog, 0, &root, NULL, CTLFLAG_READONLY,
	    CTLTYPE_STRING, "sense_audio",
	    SYSCTL_DESCR("Audio device recording the speaker sense"),
	    NULL, 0, sc->sc_sense_audio, 0, CTL_CREATE, CTL_EOL);
	if (sysctl_createv(&sc->sc_sysctllog, 0, &root, &spk, 0,
	    CTLTYPE_NODE, "speaker", SYSCTL_DESCR("Speakers"),
	    NULL, 0, NULL, 0, CTL_CREATE, CTL_EOL) != 0)
		return;
	for (i = 0; i < sc->sc_ncodecs; i++) {
		struct macaudio_codec * const mc = &sc->sc_codecs[i];

		if (sysctl_createv(&sc->sc_sysctllog, 0, &spk, &node, 0,
		    CTLTYPE_NODE, mc->mc_name, NULL, NULL, 0, NULL, 0,
		    CTL_CREATE, CTL_EOL) != 0)
			continue;
		sysctl_createv(&sc->sc_sysctllog, 0, &node, NULL,
		    CTLFLAG_READWRITE, CTLTYPE_INT, "volume",
		    SYSCTL_DESCR("Speaker volume, cdB, 0 or below"),
		    macaudio_sysctl_volume, 0, (void *)mc, 0, CTL_CREATE,
		    CTL_EOL);
	}
}

/* ---- audio(4) ---- */

static void
macaudio_pintr(void *arg)
{
	struct macaudio_softc * const sc = arg;

	mutex_enter(&sc->sc_intr_lock);
	if (sc->sc_pintr != NULL)
		sc->sc_pintr(sc->sc_pintrarg);
	mutex_exit(&sc->sc_intr_lock);
}

/*
 * The stream was set up at attach; the amplifiers follow in the work,
 * since they need I2C.  tasamp keeps them muted until then, and when
 * closing the MCA has already stopped the signal.
 */
static int
macaudio_open(void *priv, int flags)
{
	struct macaudio_softc * const sc = priv;

	if ((flags & FWRITE) == 0)
		return ENXIO;
	sc->sc_open = true;
	macaudio_kick(sc);
	return 0;
}

static void
macaudio_close(void *priv)
{
	struct macaudio_softc * const sc = priv;

	sc->sc_open = false;
	macaudio_kick(sc);
}

static int
macaudio_query_format(void *priv, audio_format_query_t *afp)
{
	struct macaudio_softc * const sc = priv;
	struct audio_format fmt;

	memset(&fmt, 0, sizeof(fmt));
	fmt.mode = AUMODE_PLAY;
	fmt.encoding = AUDIO_ENCODING_SLINEAR_LE;
	fmt.validbits = 32;
	fmt.precision = 32;
	fmt.channels = sc->sc_channels;
	fmt.channel_mask = AUFMT_UNKNOWN_POSITION;
	fmt.frequency_type = 1;
	fmt.frequency[0] = 48000;
	return audio_query_format(&fmt, 1, afp);
}

static int
macaudio_set_format(void *priv, int setmode, const audio_params_t *play,
    const audio_params_t *rec, audio_filter_reg_t *pfil,
    audio_filter_reg_t *rfil)
{

	/* One format, fixed at open. */
	return 0;
}

static int
macaudio_round_blocksize(void *priv, int bs, int mode,
    const audio_params_t *param)
{

	/* Whole frames of 8 32-bit slots, and at least the Asahi minimum. */
	bs = rounddown(bs, 32);
	return MAX(bs, 256);
}

static void *
macaudio_dma_alloc(bus_dma_tag_t dmat, struct macaudio_dmalist *list,
    size_t size)
{
	struct macaudio_dma *md;
	int nsegs;

	if (dmat == NULL)
		return NULL;
	md = kmem_zalloc(sizeof(*md), KM_SLEEP);
	md->md_size = size;
	if (bus_dmamem_alloc(dmat, size, PAGE_SIZE, 0, &md->md_seg, 1,
	    &nsegs, BUS_DMA_WAITOK) != 0)
		goto free;
	if (bus_dmamem_map(dmat, &md->md_seg, nsegs, size, &md->md_kva,
	    BUS_DMA_WAITOK | BUS_DMA_COHERENT) != 0)
		goto dmafree;
	if (bus_dmamap_create(dmat, size, 1, size, 0, BUS_DMA_WAITOK,
	    &md->md_map) != 0)
		goto unmap;
	if (bus_dmamap_load(dmat, md->md_map, md->md_kva, size, NULL,
	    BUS_DMA_WAITOK) != 0)
		goto destroy;
	LIST_INSERT_HEAD(list, md, md_list);
	return md->md_kva;

destroy:
	bus_dmamap_destroy(dmat, md->md_map);
unmap:
	bus_dmamem_unmap(dmat, md->md_kva, size);
dmafree:
	bus_dmamem_free(dmat, &md->md_seg, 1);
free:
	kmem_free(md, sizeof(*md));
	return NULL;
}

static struct macaudio_dma *
macaudio_dma_find(struct macaudio_dmalist *list, void *kva)
{
	struct macaudio_dma *md;

	LIST_FOREACH(md, list, md_list) {
		if (md->md_kva == kva)
			return md;
	}
	return NULL;
}

static void
macaudio_dma_free(bus_dma_tag_t dmat, struct macaudio_dmalist *list,
    void *addr)
{
	struct macaudio_dma *md;

	if ((md = macaudio_dma_find(list, addr)) == NULL)
		return;
	LIST_REMOVE(md, md_list);
	bus_dmamap_unload(dmat, md->md_map);
	bus_dmamap_destroy(dmat, md->md_map);
	bus_dmamem_unmap(dmat, md->md_kva, md->md_size);
	bus_dmamem_free(dmat, &md->md_seg, 1);
	kmem_free(md, sizeof(*md));
}

static void *
macaudio_allocm(void *priv, int dir, size_t size)
{
	struct macaudio_softc * const sc = priv;

	return macaudio_dma_alloc(sc->sc_dmat, &sc->sc_dmalist, size);
}

static void
macaudio_freem(void *priv, void *addr, size_t size)
{
	struct macaudio_softc * const sc = priv;

	macaudio_dma_free(sc->sc_dmat, &sc->sc_dmalist, addr);
}

static int
macaudio_get_props(void *priv)
{

	return AUDIO_PROP_PLAYBACK;
}

static int
macaudio_trigger_output(void *priv, void *start, void *end, int blksize,
    void (*intr)(void *), void *intrarg, const audio_params_t *params)
{
	struct macaudio_softc * const sc = priv;
	struct macaudio_dma *md;
	int error;

	md = macaudio_dma_find(&sc->sc_dmalist, start);
	if (md == NULL || sc->sc_stream == NULL)
		return EINVAL;

	sc->sc_pintr = intr;
	sc->sc_pintrarg = intrarg;
	error = apple_mca_stream_start(sc->sc_stream,
	    md->md_map->dm_segs[0].ds_addr, (char *)end - (char *)start,
	    blksize, macaudio_pintr, sc);
	if (error != 0)
		return error;
	sc->sc_playing = true;
	sc->sc_rate = 48000;
	macaudio_kick(sc);
	return 0;
}

static int
macaudio_halt_output(void *priv)
{
	struct macaudio_softc * const sc = priv;

	if (sc->sc_stream != NULL)
		apple_mca_stream_halt(sc->sc_stream);
	sc->sc_pintr = NULL;
	sc->sc_playing = false;
	sc->sc_rate = 0;
	macaudio_kick(sc);
	return 0;
}

static int
macaudio_getdev(void *priv, struct audio_device *adev)
{

	snprintf(adev->name, sizeof(adev->name), "Apple");
	snprintf(adev->version, sizeof(adev->version), "");
	snprintf(adev->config, sizeof(adev->config), "macaudio");
	return 0;
}

static int
macaudio_query_devinfo(void *priv, mixer_devinfo_t *di)
{

	return ENXIO;
}

static int
macaudio_port(void *priv, mixer_ctrl_t *mc)
{

	return ENXIO;
}

static void
macaudio_get_locks(void *priv, kmutex_t **intr, kmutex_t **thread)
{
	struct macaudio_softc * const sc = priv;

	*intr = &sc->sc_intr_lock;
	*thread = &sc->sc_lock;
}

static const struct audio_hw_if macaudio_hw_if = {
	.open = macaudio_open,
	.close = macaudio_close,
	.query_format = macaudio_query_format,
	.set_format = macaudio_set_format,
	.round_blocksize = macaudio_round_blocksize,
	.allocm = macaudio_allocm,
	.freem = macaudio_freem,
	.get_props = macaudio_get_props,
	.trigger_output = macaudio_trigger_output,
	.halt_output = macaudio_halt_output,
	.getdev = macaudio_getdev,
	.query_devinfo = macaudio_query_devinfo,
	.set_port = macaudio_port,
	.get_port = macaudio_port,
	.get_locks = macaudio_get_locks,
};

/* ---- the sense capture device ---- */

static void
macaudio_rintr(void *arg)
{
	struct macaudio_sense * const se = arg;

	mutex_enter(&se->se_intr_lock);
	if (se->se_rintr != NULL)
		se->se_rintr(se->se_rintrarg);
	mutex_exit(&se->se_intr_lock);
}

static int
macaudio_sense_open(void *priv, int flags)
{

	return (flags & FWRITE) != 0 ? ENXIO : 0;
}

static void
macaudio_sense_close(void *priv)
{
}

static int
macaudio_sense_query_format(void *priv, audio_format_query_t *afp)
{
	struct macaudio_sense * const se = priv;
	struct audio_format fmt;

	memset(&fmt, 0, sizeof(fmt));
	fmt.mode = AUMODE_RECORD;
	fmt.encoding = AUDIO_ENCODING_SLINEAR_LE;
	fmt.validbits = 16;
	fmt.precision = 16;
	fmt.channels = se->se_channels;
	fmt.channel_mask = AUFMT_UNKNOWN_POSITION;
	fmt.frequency_type = 1;
	fmt.frequency[0] = 48000;
	return audio_query_format(&fmt, 1, afp);
}

static int
macaudio_sense_round_blocksize(void *priv, int bs, int mode,
    const audio_params_t *param)
{
	struct macaudio_sense * const se = priv;
	const int frame = 2 * se->se_channels;

	bs = rounddown(bs, frame);
	return MAX(bs, roundup(256, frame));
}

static void *
macaudio_sense_allocm(void *priv, int dir, size_t size)
{
	struct macaudio_sense * const se = priv;

	return macaudio_dma_alloc(se->se_dmat, &se->se_dmalist, size);
}

static void
macaudio_sense_freem(void *priv, void *addr, size_t size)
{
	struct macaudio_sense * const se = priv;

	macaudio_dma_free(se->se_dmat, &se->se_dmalist, addr);
}

static int
macaudio_sense_get_props(void *priv)
{

	return AUDIO_PROP_CAPTURE;
}

static int
macaudio_sense_trigger_input(void *priv, void *start, void *end, int blksize,
    void (*intr)(void *), void *intrarg, const audio_params_t *params)
{
	struct macaudio_sense * const se = priv;
	struct macaudio_dma *md;

	if ((md = macaudio_dma_find(&se->se_dmalist, start)) == NULL)
		return EINVAL;
	se->se_rintr = intr;
	se->se_rintrarg = intrarg;
	return apple_mca_stream_start(se->se_stream,
	    md->md_map->dm_segs[0].ds_addr, (char *)end - (char *)start,
	    blksize, macaudio_rintr, se);
}

static int
macaudio_sense_halt_input(void *priv)
{
	struct macaudio_sense * const se = priv;

	apple_mca_stream_halt(se->se_stream);
	se->se_rintr = NULL;
	return 0;
}

static int
macaudio_sense_getdev(void *priv, struct audio_device *adev)
{

	snprintf(adev->name, sizeof(adev->name), "Apple");
	snprintf(adev->version, sizeof(adev->version), "");
	snprintf(adev->config, sizeof(adev->config), "speaker sense");
	return 0;
}

static void
macaudio_sense_get_locks(void *priv, kmutex_t **intr, kmutex_t **thread)
{
	struct macaudio_sense * const se = priv;

	*intr = &se->se_intr_lock;
	*thread = &se->se_lock;
}

static const struct audio_hw_if macaudio_sense_hw_if = {
	.open = macaudio_sense_open,
	.close = macaudio_sense_close,
	.query_format = macaudio_sense_query_format,
	.set_format = macaudio_set_format,
	.round_blocksize = macaudio_sense_round_blocksize,
	.allocm = macaudio_sense_allocm,
	.freem = macaudio_sense_freem,
	.get_props = macaudio_sense_get_props,
	.trigger_input = macaudio_sense_trigger_input,
	.halt_input = macaudio_sense_halt_input,
	.getdev = macaudio_sense_getdev,
	.query_devinfo = macaudio_query_devinfo,
	.set_port = macaudio_port,
	.get_port = macaudio_port,
	.get_locks = macaudio_sense_get_locks,
};

/*
 * Cluster 2 records, following the clocks of the first speaker port,
 * the input lines of all speaker ports: Asahi's "Speaker Sense"
 * frontend (mca-pcm-2), 16 slots of 16 bits, the low 2 x speakers used.
 */
#define	MACAUDIO_SENSE_FE	2
#define	MACAUDIO_SENSE_SLOTS	16

static int
macaudio_sense_setup(struct macaudio_softc *sc)
{
	struct macaudio_sense * const se = &sc->sc_sense;
	struct apple_mca_params mp;
	int error;

	se->se_sc = sc;
	se->se_channels = 2 * sc->sc_ncodecs;
	if (se->se_channels > MACAUDIO_SENSE_SLOTS)
		return EINVAL;
	mutex_init(&se->se_lock, MUTEX_DEFAULT, IPL_NONE);
	mutex_init(&se->se_intr_lock, MUTEX_DEFAULT, IPL_SCHED);
	LIST_INIT(&se->se_dmalist);

	error = apple_mca_stream_open(sc->sc_mca, MACAUDIO_SENSE_FE, false,
	    sc->sc_ports, &se->se_stream);
	if (error != 0)
		return error;
	memset(&mp, 0, sizeof(mp));
	mp.mp_rate = 48000;
	mp.mp_width = 16;
	mp.mp_channels = se->se_channels;
	mp.mp_slots = MACAUDIO_SENSE_SLOTS;
	mp.mp_slot_width = 16;
	mp.mp_slot_mask = __BITS(se->se_channels - 1, 0);
	mp.mp_format = AUDIO_DAI_FORMAT_I2S |
	    __SHIFTIN(AUDIO_DAI_POLARITY_IB_IF, AUDIO_DAI_POLARITY_MASK);
	mp.mp_follow_port = ffs32(sc->sc_ports) - 1;
	if ((error = apple_mca_stream_config(se->se_stream, &mp)) != 0 ||
	    (error = apple_mca_stream_prepare(se->se_stream)) != 0) {
		apple_mca_stream_close(se->se_stream);
		se->se_stream = NULL;
		return error;
	}
	se->se_dmat = apple_mca_stream_dmat(se->se_stream);
	return 0;
}

/* ---- the headphone device ---- */

static void
macaudio_hp_pintr(void *arg)
{
	struct macaudio_hp * const hp = arg;

	mutex_enter(&hp->hp_intr_lock);
	if (hp->hp_pintr != NULL)
		hp->hp_pintr(hp->hp_pintrarg);
	mutex_exit(&hp->hp_intr_lock);
}

static int
macaudio_hp_open(void *priv, int flags)
{
	struct macaudio_hp * const hp = priv;
	struct macaudio_softc * const sc = hp->hp_sc;

	if ((flags & FREAD) != 0 && hp->hp_rstream == NULL)
		return ENXIO;
	/* Order: this device's intr lock, then sc_intr_lock; never back. */
	mutex_enter(&sc->sc_intr_lock);
	hp->hp_flags = flags & (FREAD | FWRITE);
	macaudio_kick(sc);
	mutex_exit(&sc->sc_intr_lock);
	return 0;
}

static void
macaudio_hp_close(void *priv)
{
	struct macaudio_hp * const hp = priv;
	struct macaudio_softc * const sc = hp->hp_sc;

	mutex_enter(&sc->sc_intr_lock);
	hp->hp_flags = 0;
	macaudio_kick(sc);
	mutex_exit(&sc->sc_intr_lock);
}

/* Stereo out; the microphone in, one channel of the same frames. */
static int
macaudio_hp_query_format(void *priv, audio_format_query_t *afp)
{
	struct macaudio_hp * const hp = priv;
	struct audio_format fmt[2];

	memset(fmt, 0, sizeof(fmt));
	fmt[0].mode = AUMODE_PLAY;
	fmt[0].encoding = AUDIO_ENCODING_SLINEAR_LE;
	fmt[0].validbits = 32;
	fmt[0].precision = 32;
	fmt[0].channels = 2;
	fmt[0].channel_mask = AUFMT_STEREO;
	fmt[0].frequency_type = 1;
	fmt[0].frequency[0] = 48000;
	fmt[1] = fmt[0];
	fmt[1].mode = AUMODE_RECORD;
	fmt[1].channels = 1;
	fmt[1].channel_mask = AUFMT_MONAURAL;
	return audio_query_format(fmt, hp->hp_rstream != NULL ? 2 : 1, afp);
}

static void *
macaudio_hp_allocm(void *priv, int dir, size_t size)
{
	struct macaudio_hp * const hp = priv;

	if (dir == AUMODE_RECORD)
		return macaudio_dma_alloc(hp->hp_rdmat, &hp->hp_rdmalist, size);
	return macaudio_dma_alloc(hp->hp_dmat, &hp->hp_dmalist, size);
}

static void
macaudio_hp_freem(void *priv, void *addr, size_t size)
{
	struct macaudio_hp * const hp = priv;

	/* Each list skips an address it does not hold. */
	macaudio_dma_free(hp->hp_dmat, &hp->hp_dmalist, addr);
	macaudio_dma_free(hp->hp_rdmat, &hp->hp_rdmalist, addr);
}

static int
macaudio_hp_trigger_output(void *priv, void *start, void *end, int blksize,
    void (*intr)(void *), void *intrarg, const audio_params_t *params)
{
	struct macaudio_hp * const hp = priv;
	struct macaudio_dma *md;

	if ((md = macaudio_dma_find(&hp->hp_dmalist, start)) == NULL)
		return EINVAL;
	hp->hp_pintr = intr;
	hp->hp_pintrarg = intrarg;
	return apple_mca_stream_start(hp->hp_stream,
	    md->md_map->dm_segs[0].ds_addr, (char *)end - (char *)start,
	    blksize, macaudio_hp_pintr, hp);
}

static int
macaudio_hp_halt_output(void *priv)
{
	struct macaudio_hp * const hp = priv;

	apple_mca_stream_halt(hp->hp_stream);
	hp->hp_pintr = NULL;
	return 0;
}

static void
macaudio_hp_rintr(void *arg)
{
	struct macaudio_hp * const hp = arg;

	mutex_enter(&hp->hp_intr_lock);
	if (hp->hp_rintr != NULL)
		hp->hp_rintr(hp->hp_rintrarg);
	mutex_exit(&hp->hp_intr_lock);
}

static int
macaudio_hp_trigger_input(void *priv, void *start, void *end, int blksize,
    void (*intr)(void *), void *intrarg, const audio_params_t *params)
{
	struct macaudio_hp * const hp = priv;
	struct macaudio_dma *md;

	if (hp->hp_rstream == NULL ||
	    (md = macaudio_dma_find(&hp->hp_rdmalist, start)) == NULL)
		return EINVAL;
	hp->hp_rintr = intr;
	hp->hp_rintrarg = intrarg;
	return apple_mca_stream_start(hp->hp_rstream,
	    md->md_map->dm_segs[0].ds_addr, (char *)end - (char *)start,
	    blksize, macaudio_hp_rintr, hp);
}

static int
macaudio_hp_halt_input(void *priv)
{
	struct macaudio_hp * const hp = priv;

	if (hp->hp_rstream != NULL)
		apple_mca_stream_halt(hp->hp_rstream);
	hp->hp_rintr = NULL;
	return 0;
}

static int
macaudio_hp_get_props(void *priv)
{
	struct macaudio_hp * const hp = priv;

	return AUDIO_PROP_PLAYBACK | (hp->hp_rstream != NULL ?
	    AUDIO_PROP_CAPTURE | AUDIO_PROP_FULLDUPLEX |
	    AUDIO_PROP_INDEPENDENT : 0);
}

static int
macaudio_hp_getdev(void *priv, struct audio_device *adev)
{

	snprintf(adev->name, sizeof(adev->name), "Apple");
	snprintf(adev->version, sizeof(adev->version), "");
	snprintf(adev->config, sizeof(adev->config), "headphones");
	return 0;
}

enum { HP_MIX_OUTPUTS, HP_MIX_LEVEL, HP_MIX_COUNT };

static int
macaudio_hp_query_devinfo(void *priv, mixer_devinfo_t *di)
{

	switch (di->index) {
	case HP_MIX_OUTPUTS:
		di->type = AUDIO_MIXER_CLASS;
		di->mixer_class = HP_MIX_OUTPUTS;
		di->next = di->prev = AUDIO_MIXER_LAST;
		strlcpy(di->label.name, AudioCoutputs, sizeof(di->label.name));
		return 0;
	case HP_MIX_LEVEL:
		di->type = AUDIO_MIXER_VALUE;
		di->mixer_class = HP_MIX_OUTPUTS;
		di->next = di->prev = AUDIO_MIXER_LAST;
		strlcpy(di->label.name, AudioNheadphone, sizeof(di->label.name));
		di->un.v.num_channels = 1;
		di->un.v.delta = 255 / 62;
		strlcpy(di->un.v.units.name, AudioNvolume,
		    sizeof(di->un.v.units.name));
		return 0;
	default:
		return ENXIO;
	}
}

static int
macaudio_hp_set_port(void *priv, mixer_ctrl_t *mc)
{
	struct macaudio_hp * const hp = priv;
	struct macaudio_softc * const sc = hp->hp_sc;

	if (mc->dev != HP_MIX_LEVEL || mc->type != AUDIO_MIXER_VALUE ||
	    mc->un.value.num_channels != 1)
		return EINVAL;
	/* The codec is on I2C, which sleeps: the work writes it. */
	mutex_enter(&sc->sc_intr_lock);
	hp->hp_level = mc->un.value.level[AUDIO_MIXER_LEVEL_MONO];
	hp->hp_level_dirty = true;
	macaudio_kick(sc);
	mutex_exit(&sc->sc_intr_lock);
	return 0;
}

static int
macaudio_hp_get_port(void *priv, mixer_ctrl_t *mc)
{
	struct macaudio_hp * const hp = priv;

	if (mc->dev != HP_MIX_LEVEL)
		return EINVAL;
	mc->type = AUDIO_MIXER_VALUE;
	mc->un.value.num_channels = 1;
	mc->un.value.level[AUDIO_MIXER_LEVEL_MONO] = hp->hp_level;
	return 0;
}

static void
macaudio_hp_get_locks(void *priv, kmutex_t **intr, kmutex_t **thread)
{
	struct macaudio_hp * const hp = priv;

	*intr = &hp->hp_intr_lock;
	*thread = &hp->hp_lock;
}

static const struct audio_hw_if macaudio_hp_hw_if = {
	.open = macaudio_hp_open,
	.close = macaudio_hp_close,
	.query_format = macaudio_hp_query_format,
	.set_format = macaudio_set_format,
	.round_blocksize = macaudio_round_blocksize,
	.allocm = macaudio_hp_allocm,
	.freem = macaudio_hp_freem,
	.get_props = macaudio_hp_get_props,
	.trigger_output = macaudio_hp_trigger_output,
	.halt_output = macaudio_hp_halt_output,
	.trigger_input = macaudio_hp_trigger_input,
	.halt_input = macaudio_hp_halt_input,
	.getdev = macaudio_hp_getdev,
	.query_devinfo = macaudio_hp_query_devinfo,
	.set_port = macaudio_hp_set_port,
	.get_port = macaudio_hp_get_port,
	.get_locks = macaudio_hp_get_locks,
};

/*
 * The headphone link: one MCA port, one codec.  Cluster 0 is the
 * frontend (Asahi's "Primary").  Upstream runs it at 64 bit clocks a
 * frame only because its codec driver had no TDM; here it is 256, 32
 * bits x 8 slots, the codec's documented slave clocking (CS42L42
 * Example 5-1: SCLK 12.288 MHz at 48 kHz), left and right in slots 0
 * and 1.  The clocks run from here on: the codec may not lose SCLK
 * without switching back to its oscillator first.  The headset
 * microphone comes back on the same port, in slot 0 of the receiver:
 * the device tree has one link for both directions.  Without it the
 * device only plays.
 */
#define	MACAUDIO_HP_FE		0
#define	MACAUDIO_HP_SLOTS	8

static int
macaudio_hp_setup(struct macaudio_softc *sc, int link)
{
	struct macaudio_hp * const hp = &sc->sc_hp;
	struct apple_mca_params mp;
	audio_dai_tag_t dai;
	device_t mca;
	u_int port;
	int cpu, codec, error;
	uint32_t fmt;

	cpu = of_find_firstchild_byname(link, "cpu");
	codec = of_find_firstchild_byname(link, "codec");
	if (cpu <= 0 || codec <= 0)
		return ENXIO;
	dai = fdtbus_dai_acquire_index(cpu, "sound-dai", 0);
	if (dai == NULL || apple_mca_dai_port(dai, &mca, &port) != 0)
		return ENXIO;
	hp->hp_codec = fdtbus_dai_acquire_index(codec, "sound-dai", 0);
	if (hp->hp_codec == NULL)
		return ENXIO;

	hp->hp_sc = sc;
	hp->hp_level = 255 * (6200 - 3000) / 6200;	/* the codec's -30 dB */
	mutex_init(&hp->hp_lock, MUTEX_DEFAULT, IPL_NONE);
	mutex_init(&hp->hp_intr_lock, MUTEX_DEFAULT, IPL_SCHED);
	LIST_INIT(&hp->hp_dmalist);
	LIST_INIT(&hp->hp_rdmalist);

	if ((error = apple_mca_stream_open(mca, MACAUDIO_HP_FE, true,
	    __BIT(port), &hp->hp_stream)) != 0)
		return error;
	memset(&mp, 0, sizeof(mp));
	mp.mp_rate = 48000;
	mp.mp_width = 32;
	mp.mp_channels = 2;
	mp.mp_slots = MACAUDIO_HP_SLOTS;
	mp.mp_slot_width = MACAUDIO_SLOT_WIDTH;
	mp.mp_slot_mask = 0x3;
	mp.mp_format = AUDIO_DAI_FORMAT_I2S |
	    __SHIFTIN(AUDIO_DAI_POLARITY_IB_IF, AUDIO_DAI_POLARITY_MASK);
	mp.mp_follow_port = -1;
	fmt = mp.mp_format |
	    __SHIFTIN(AUDIO_DAI_CLOCK_CBS_CFS, AUDIO_DAI_CLOCK_MASK);
	if ((error = apple_mca_stream_config(hp->hp_stream, &mp)) != 0 ||
	    (error = audio_dai_set_format(hp->hp_codec, fmt)) != 0 ||
	    (error = audio_dai_set_tdm_slot(hp->hp_codec, 0x1, 0x3,
	    MACAUDIO_HP_SLOTS, MACAUDIO_SLOT_WIDTH)) != 0 ||
	    (error = apple_mca_stream_prepare(hp->hp_stream)) != 0)
		goto fail;
	hp->hp_dmat = apple_mca_stream_dmat(hp->hp_stream);

	mp.mp_channels = 1;
	mp.mp_slot_mask = 0x1;
	if (apple_mca_stream_open(mca, MACAUDIO_HP_FE, false, __BIT(port),
	    &hp->hp_rstream) == 0) {
		if (apple_mca_stream_config(hp->hp_rstream, &mp) != 0 ||
		    apple_mca_stream_prepare(hp->hp_rstream) != 0) {
			apple_mca_stream_close(hp->hp_rstream);
			hp->hp_rstream = NULL;
		} else {
			hp->hp_rdmat = apple_mca_stream_dmat(hp->hp_rstream);
		}
	}

	/* SCLK now runs: the codec may start (Ex. 5-1 needs it first). */
	if ((error = audio_dai_set_sysclk(hp->hp_codec,
	    MACAUDIO_HP_SLOTS * MACAUDIO_SLOT_WIDTH * 48000,
	    AUDIO_DAI_CLOCK_IN)) != 0)
		goto fail;
	return 0;

fail:
	apple_mca_stream_close(hp->hp_stream);
	hp->hp_stream = NULL;
	return error;
}

static bool
macaudio_is_headphones(int link)
{
	const char *name = fdtbus_get_string(link, "link-name");

	return name != NULL && strncmp(name, "Headphone", 9) == 0;
}

/* ---- attach ---- */

/* "Left Front" -> "left_front", for sysctl. */
static void
macaudio_sysctl_name(char *dst, size_t len, const char *src, u_int idx)
{
	size_t i;

	if (src == NULL || *src == '\0') {
		snprintf(dst, len, "spk%u", idx);
		return;
	}
	for (i = 0; i + 1 < len && src[i] != '\0'; i++) {
		const char c = src[i];

		dst[i] = (c >= 'A' && c <= 'Z') ? c - 'A' + 'a' :
		    ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) ? c :
		    '_';
	}
	dst[i] = '\0';
}

/*
 * Name the speakers after their amplifiers' sound-name-prefix.  A lone
 * speaker without one is "mono": speakersafetyd calls it "Mono" and
 * leaves the prefix off its controls (src/types.rs, Mixer::new), and
 * its configuration for the Mac mini (j274), whose one amplifier has
 * no prefix, names it so.  Before this it was "spk0", which the daemon
 * never found, so the speaker was never unlocked.
 */
static void
macaudio_name_speakers(struct macaudio_softc *sc, const char *const *prefix,
    u_int n)
{
	u_int i;

	for (i = 0; i < n; i++) {
		macaudio_sysctl_name(sc->sc_codecs[i].mc_name,
		    sizeof(sc->sc_codecs[i].mc_name), prefix[i], i);
	}
	if (n == 1 && (prefix[0] == NULL || *prefix[0] == '\0')) {
		strlcpy(sc->sc_codecs[0].mc_name, "mono",
		    sizeof(sc->sc_codecs[0].mc_name));
	}
}

static bool
macaudio_is_speakers(int link)
{
	const char *name = fdtbus_get_string(link, "link-name");

	return name != NULL &&
	    (strcmp(name, "Speaker") == 0 || strcmp(name, "Speakers") == 0);
}

/*
 * The speaker link: one or two MCA ports, codecs listed per port in
 * order.  Slots follow Asahi: channel pairs interleave, the first
 * port's codecs take the even slots and the second port's the odd.
 */
static int
macaudio_setup_speakers(struct macaudio_softc *sc, int link)
{
	int cpu, codec, n, nports;
	u_int i, per_port, left, right, port_mask[MACAUDIO_MAX_PORTS];
	const char *prefix[MACAUDIO_MAX_CODECS];
	uint32_t fmt;

	cpu = of_find_firstchild_byname(link, "cpu");
	codec = of_find_firstchild_byname(link, "codec");
	if (cpu <= 0 || codec <= 0)
		return ENXIO;

	for (nports = 0; nports < MACAUDIO_MAX_PORTS; nports++) {
		audio_dai_tag_t dai;
		device_t mca;
		u_int port;

		dai = fdtbus_dai_acquire_index(cpu, "sound-dai", nports);
		if (dai == NULL)
			break;
		if (apple_mca_dai_port(dai, &mca, &port) != 0 ||
		    (sc->sc_mca != NULL && sc->sc_mca != mca))
			return ENXIO;
		sc->sc_mca = mca;
		sc->sc_ports |= __BIT(port);
	}
	for (n = 0; n < MACAUDIO_MAX_CODECS; n++) {
		struct macaudio_codec * const mc = &sc->sc_codecs[n];
		audio_dai_tag_t dai;
		int ph;

		dai = fdtbus_dai_acquire_index(codec, "sound-dai", n);
		if (dai == NULL)
			break;
		mc->mc_sc = sc;
		mc->mc_dai = dai;
		ph = devhandle_to_of(device_handle(audio_dai_device(dai)));
		prefix[n] = fdtbus_get_string(ph, "sound-name-prefix");
	}
	if (nports == 0 || n == 0 || n % nports != 0)
		return ENXIO;
	macaudio_name_speakers(sc, prefix, n);
	sc->sc_ncodecs = n;
	per_port = n / nports;

	/* One channel per speaker; a lone speaker gets two to downmix. */
	sc->sc_channels = MAX(n, 2);
	left = 0;
	for (i = 0; i < sc->sc_channels; i += 2)
		left = left << 2 | 1;
	right = left << 1;
	port_mask[0] = nports == 2 ? left : left | right;
	port_mask[1] = right;
	sc->sc_slot_mask = left | right;

	/* I2S, both clocks inverted, the MCA drives them. */
	fmt = AUDIO_DAI_FORMAT_I2S |
	    __SHIFTIN(AUDIO_DAI_POLARITY_IB_IF, AUDIO_DAI_POLARITY_MASK) |
	    __SHIFTIN(AUDIO_DAI_CLOCK_CBS_CFS, AUDIO_DAI_CLOCK_MASK);
	for (i = 0; i < sc->sc_ncodecs; i++) {
		struct macaudio_codec * const mc = &sc->sc_codecs[i];
		uint32_t *mask = &port_mask[i / per_port];
		const uint32_t slot = *mask & -*mask;
		int error;

		*mask &= ~slot;
		if (slot == 0)
			return ENXIO;
		if ((error = audio_dai_set_format(mc->mc_dai, fmt)) != 0 ||
		    (error = audio_dai_set_tdm_slot(mc->mc_dai, 0, slot,
		    MACAUDIO_SPEAKER_BCLK / MACAUDIO_SLOT_WIDTH,
		    MACAUDIO_SLOT_WIDTH)) != 0)
			return error;
	}
	return 0;
}

/* Open, configure and clock the speaker stream once, at attach. */
static int
macaudio_stream_setup(struct macaudio_softc *sc)
{
	struct apple_mca_params mp;
	int error;

	error = apple_mca_stream_open(sc->sc_mca, MACAUDIO_SPEAKER_FE, true,
	    sc->sc_ports, &sc->sc_stream);
	if (error != 0)
		return error;
	memset(&mp, 0, sizeof(mp));
	mp.mp_rate = 48000;
	mp.mp_width = 32;
	mp.mp_channels = sc->sc_channels;
	mp.mp_slots = MACAUDIO_SPEAKER_BCLK / MACAUDIO_SLOT_WIDTH;
	mp.mp_slot_width = MACAUDIO_SLOT_WIDTH;
	mp.mp_slot_mask = sc->sc_slot_mask;
	mp.mp_format = AUDIO_DAI_FORMAT_I2S |
	    __SHIFTIN(AUDIO_DAI_POLARITY_IB_IF, AUDIO_DAI_POLARITY_MASK);
	mp.mp_follow_port = -1;		/* the speaker stream makes the clocks */
	if ((error = apple_mca_stream_config(sc->sc_stream, &mp)) != 0 ||
	    (error = apple_mca_stream_prepare(sc->sc_stream)) != 0) {
		apple_mca_stream_close(sc->sc_stream);
		sc->sc_stream = NULL;
		return error;
	}
	sc->sc_dmat = apple_mca_stream_dmat(sc->sc_stream);
	return 0;
}

static int
macaudio_match(device_t parent, cfdata_t cf, void *aux)
{
	struct fdt_attach_args * const faa = aux;

	return of_compatible_match(faa->faa_phandle, compat_generic);
}

static void
macaudio_attach(device_t parent, device_t self, void *aux)
{
	struct macaudio_softc * const sc = device_private(self);
	struct fdt_attach_args * const faa = aux;
	const struct device_compatible_entry *dce;
	int child, error;

	sc->sc_dev = self;
	sc->sc_phandle = faa->faa_phandle;
	mutex_init(&sc->sc_lock, MUTEX_DEFAULT, IPL_NONE);
	mutex_init(&sc->sc_intr_lock, MUTEX_DEFAULT, IPL_SCHED);
	mutex_init(&sc->sc_cfg_lock, MUTEX_DEFAULT, IPL_NONE);
	LIST_INIT(&sc->sc_dmalist);
	callout_init(&sc->sc_lock_callout, CALLOUT_MPSAFE);
	callout_setfunc(&sc->sc_lock_callout, macaudio_lock_expire, sc);

	aprint_naive("\n");
	aprint_normal(": Apple Mac audio\n");

	if (workqueue_create(&sc->sc_wq, device_xname(self), macaudio_work,
	    sc, PRI_NONE, IPL_NONE, WQ_MPSAFE) != 0) {
		aprint_error_dev(self, "couldn't create workqueue\n");
		return;
	}

	/* Headphones do not depend on the speaker safety table. */
	for (child = OF_child(sc->sc_phandle); child; child = OF_peer(child)) {
		if (!macaudio_is_headphones(child))
			continue;
		if ((error = macaudio_hp_setup(sc, child)) != 0) {
			aprint_error_dev(self, "headphone setup failed: %d\n",
			    error);
			break;
		}
		sc->sc_has_hp = true;
		audio_attach_mi(&macaudio_hp_hw_if, &sc->sc_hp, self);
		break;
	}

	dce = of_compatible_lookup(sc->sc_phandle, compat_data);
	if (dce == NULL || !((const struct macaudio_machine *)dce->data)->enable) {
		aprint_normal_dev(self, "speaker safety not established for "
		    "this model; speakers disabled\n");
		return;
	}
	sc->sc_machine = dce->data;
	{
		const char *compat = fdtbus_get_string(OF_finddevice("/"),
		    "compatible");

		strlcpy(sc->sc_compatible, compat != NULL ? compat : "",
		    sizeof(sc->sc_compatible));
	}

	for (child = OF_child(sc->sc_phandle); child; child = OF_peer(child)) {
		if (macaudio_is_speakers(child))
			break;
	}
	if (child == 0) {
		aprint_normal_dev(self, "no speaker link\n");
		return;
	}
	if ((error = macaudio_setup_speakers(sc, child)) != 0) {
		aprint_error_dev(self, "speaker link setup failed: %d\n", error);
		return;
	}
	/* Locked from the start: the daemon has to open it. */
	mutex_enter(&sc->sc_cfg_lock);
	error = macaudio_apply_limits(sc);
	mutex_exit(&sc->sc_cfg_lock);
	if (error != 0) {
		aprint_error_dev(self, "couldn't limit amplifiers: %d; "
		    "speakers disabled\n", error);
		return;
	}
	aprint_normal_dev(self, "%u speakers, %u channels, level cap "
	    "%d.%02d dBV, locked\n", sc->sc_ncodecs, sc->sc_channels,
	    macaudio_amp_cap(sc) / 100, macaudio_amp_cap(sc) % 100);

	if ((error = macaudio_stream_setup(sc)) != 0) {
		aprint_error_dev(self, "couldn't set up the stream: %d\n",
		    error);
		return;
	}

	audio_attach_mi(&macaudio_hw_if, sc, self);

	/*
	 * Without sense data speakersafetyd cannot run, the lock is never
	 * opened and the speakers stay muted; so a failure here is
	 * reported and otherwise harmless.
	 */
	if ((error = macaudio_sense_setup(sc)) != 0) {
		aprint_error_dev(self, "no speaker sense capture: %d\n", error);
		macaudio_sysctl_init(sc);
		return;
	}
	sc->sc_has_sense = true;
	{
		device_t adev;

		adev = audio_attach_mi(&macaudio_sense_hw_if, &sc->sc_sense,
		    self);
		if (adev != NULL)
			strlcpy(sc->sc_sense_audio, device_xname(adev),
			    sizeof(sc->sc_sense_audio));
	}
	macaudio_sysctl_init(sc);
}
