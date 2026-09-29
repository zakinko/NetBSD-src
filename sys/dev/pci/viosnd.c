/*	$NetBSD$	*/

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
 * Virtio sound device.
 *
 * Written from the Virtual I/O Device (VIRTIO) Version 1.3 specification
 * (OASIS, 2023), 5.14; section numbers below refer to it.
 *
 * One output and one input PCM stream, the first of each the device
 * reports, driven by messages on the tx and rx queues (5.14.6.8): the
 * shared memory transports are placeholders in the specification.
 * The completion of each message, one period long, is taken as the
 * period having elapsed, as 5.14.6.8 allows.  Jacks, channel maps and
 * control elements are not used; their queries in the initialization
 * sequence of 5.14.5 are skipped.
 *
 * audio(4) calls trigger and halt with its interrupt lock held, so the
 * stream commands they need (5.14.6.6.1) are queued without waiting;
 * the control queue is serviced in order, and replies are checked when
 * the next command is queued.  Only the stream queries at attach wait
 * for their reply.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/audioio.h>
#include <sys/bus.h>
#include <sys/condvar.h>
#include <sys/device.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/systm.h>

#include <dev/audio/audio_if.h>

#include <dev/pci/virtioreg.h>
#include <dev/pci/virtiovar.h>

/* 5.14.2 */
#define	VIOSND_VQ_CONTROL	0
#define	VIOSND_VQ_EVENT		1
#define	VIOSND_VQ_TX		2
#define	VIOSND_VQ_RX		3
#define	VIOSND_NVQS		4

/* 5.14.4 */
#define	VIOSND_CONFIG_JACKS	0
#define	VIOSND_CONFIG_STREAMS	4
#define	VIOSND_CONFIG_CHMAPS	8

/* 5.14.6 */
#define	VIRTIO_SND_R_PCM_INFO		0x0100
#define	VIRTIO_SND_R_PCM_SET_PARAMS	0x0101
#define	VIRTIO_SND_R_PCM_PREPARE	0x0102
#define	VIRTIO_SND_R_PCM_RELEASE	0x0103
#define	VIRTIO_SND_R_PCM_START		0x0104
#define	VIRTIO_SND_R_PCM_STOP		0x0105
#define	VIRTIO_SND_EVT_PCM_XRUN		0x1101
#define	VIRTIO_SND_S_OK			0x8000
#define	VIRTIO_SND_D_OUTPUT		0
#define	VIRTIO_SND_D_INPUT		1

/* 5.14.6.6.2 */
#define	VIRTIO_SND_PCM_FMT_S16		5
#define	VIRTIO_SND_PCM_FMT_S32		17

static const u_int viosnd_rates[] = {	/* VIRTIO_SND_PCM_RATE_* order */
	5512, 8000, 11025, 16000, 22050, 32000, 44100, 48000,
	64000, 88200, 96000, 176400, 192000, 384000
};

struct virtio_snd_hdr {
	uint32_t	code;
} __packed;

struct virtio_snd_event {		/* 5.14.6 */
	struct virtio_snd_hdr hdr;
	uint32_t	data;
} __packed;

struct virtio_snd_query_info {		/* 5.14.6.1 */
	struct virtio_snd_hdr hdr;
	uint32_t	start_id;
	uint32_t	count;
	uint32_t	size;
} __packed;

struct virtio_snd_pcm_info {		/* 5.14.6.6.2 */
	uint32_t	hda_fn_nid;
	uint32_t	features;
	uint64_t	formats;
	uint64_t	rates;
	uint8_t		direction;
	uint8_t		channels_min;
	uint8_t		channels_max;
	uint8_t		padding[5];
} __packed;

struct virtio_snd_pcm_hdr {		/* 5.14.6.6 */
	struct virtio_snd_hdr hdr;
	uint32_t	stream_id;
} __packed;

struct virtio_snd_pcm_set_params {	/* 5.14.6.6.3 */
	struct virtio_snd_pcm_hdr hdr;
	uint32_t	buffer_bytes;
	uint32_t	period_bytes;
	uint32_t	features;
	uint8_t		channels;
	uint8_t		format;
	uint8_t		rate;
	uint8_t		padding;
} __packed;

struct virtio_snd_pcm_xfer {		/* 5.14.6.8 */
	uint32_t	stream_id;
} __packed;

struct virtio_snd_pcm_status {
	uint32_t	status;
	uint32_t	latency_bytes;
} __packed;

CTASSERT(sizeof(struct virtio_snd_pcm_info) == 32);
CTASSERT(sizeof(struct virtio_snd_pcm_set_params) == 24);

#define	VIOSND_MAX_STREAMS	32	/* read at attach; more are ignored */
#define	VIOSND_NCTL		16	/* control messages in flight */
#define	VIOSND_NEVENT		8
#define	VIOSND_NIO		4	/* periods queued ahead, per stream */
#define	VIOSND_CTL_WAIT_MS	1000	/* attach queries, polled; ours */
#define	VIOSND_MAXSEG		(64 * 1024)	/* a period, at most */
#define	VIOSND_DRAIN_WAIT_MS	100	/* freeing a ring; ours */
#define	VIOSND_DRAIN_WAITS	20

/* Driver memory shared with the device, one DMA allocation. */
struct viosnd_shm {
	struct viosnd_ctl {
		struct virtio_snd_pcm_set_params req;	/* largest request */
		struct virtio_snd_hdr resp;
	} ctl[VIOSND_NCTL];
	struct virtio_snd_query_info info_req;
	struct virtio_snd_hdr info_resp;
	struct virtio_snd_pcm_info info[VIOSND_MAX_STREAMS];
	struct virtio_snd_event event[VIOSND_NEVENT];
	struct viosnd_io {
		struct virtio_snd_pcm_xfer xfer;
		struct virtio_snd_pcm_status status;
	} io[2][VIOSND_NIO];
};

struct viosnd_dma {
	void		*vd_kva;
	size_t		vd_size;
	bus_dma_segment_t vd_seg;
	bus_dmamap_t	vd_map;
};

struct viosnd_stream {
	int		vs_id;		/* -1: none */
	u_int		vs_dir;		/* VIRTIO_SND_D_* */
	struct virtio_snd_pcm_info vs_info;
	struct audio_format vs_formats[2];
	u_int		vs_nformats;
	/* set_format */
	uint8_t		vs_format, vs_rate, vs_channels;
	/* running */
	struct viosnd_dma *vs_ring;
	bool		vs_running;
	u_int		vs_epoch;	/* of the current trigger */
	size_t		vs_blksize, vs_bufsize;
	size_t		vs_next;	/* next period to queue, offset */
	u_int		vs_queued;
	u_int		vs_inflight;	/* messages kept out */
	void		(*vs_intr)(void *);
	void		*vs_intrarg;
};

struct viosnd_softc {
	device_t		sc_dev;
	struct virtio_softc	*sc_virtio;
	struct virtqueue	sc_vq[VIOSND_NVQS];
	bus_dma_tag_t		sc_dmat;

	kmutex_t		sc_lock;	/* audio thread lock */
	kmutex_t		sc_intr_lock;	/* audio intr lock, the rest */

	struct viosnd_dma	sc_shmdma;
	struct viosnd_shm	*sc_shm;
	bool			sc_ctl_busy[VIOSND_NCTL];
	bool			sc_io_busy[2][VIOSND_NIO];
	u_int			sc_io_epoch[2][VIOSND_NIO];
	u_int			sc_io_stale[2];	/* earlier triggers' */
	kcondvar_t		sc_io_cv;	/* all messages back */
	int			sc_info_slot;	/* -1: none waiting */
	bool			sc_info_done;
	/*
	 * Which shared memory entry each queue slot carries: slots are
	 * descriptor indices, any of vq_num, and entries are few.
	 */
	int			*sc_slot_entry[VIOSND_NVQS];

	struct viosnd_stream	sc_stream[2];	/* [dir] */
	struct viosnd_dma	*sc_dmas[4];
};

static int	viosnd_match(device_t, cfdata_t, void *);
static void	viosnd_stop(struct viosnd_softc *, struct viosnd_stream *);
static void	viosnd_attach(device_t, device_t, void *);

CFATTACH_DECL_NEW(viosnd, sizeof(struct viosnd_softc),
    viosnd_match, viosnd_attach, NULL, NULL);

#define	SHM_OFF(field)	((bus_addr_t)offsetof(struct viosnd_shm, field))

static void
viosnd_shm_sync(struct viosnd_softc *sc, bus_addr_t off, bus_size_t len,
    int ops)
{

	bus_dmamap_sync(sc->sc_dmat, sc->sc_shmdma.vd_map, off, len, ops);
}

static int
viosnd_dma_alloc(struct viosnd_softc *sc, struct viosnd_dma *vd, size_t size)
{
	int nsegs, error;

	vd->vd_size = size;
	error = bus_dmamem_alloc(sc->sc_dmat, size, PAGE_SIZE, 0, &vd->vd_seg,
	    1, &nsegs, BUS_DMA_WAITOK);
	if (error)
		return error;
	error = bus_dmamem_map(sc->sc_dmat, &vd->vd_seg, 1, size, &vd->vd_kva,
	    BUS_DMA_WAITOK | BUS_DMA_COHERENT);
	if (error)
		goto free;
	error = bus_dmamap_create(sc->sc_dmat, size, 1, size, 0,
	    BUS_DMA_WAITOK, &vd->vd_map);
	if (error)
		goto unmap;
	error = bus_dmamap_load(sc->sc_dmat, vd->vd_map, vd->vd_kva, size,
	    NULL, BUS_DMA_WAITOK);
	if (error)
		goto destroy;
	return 0;
destroy:
	bus_dmamap_destroy(sc->sc_dmat, vd->vd_map);
unmap:
	bus_dmamem_unmap(sc->sc_dmat, vd->vd_kva, size);
free:
	bus_dmamem_free(sc->sc_dmat, &vd->vd_seg, 1);
	return error;
}

static void
viosnd_dma_free(struct viosnd_softc *sc, struct viosnd_dma *vd)
{

	bus_dmamap_unload(sc->sc_dmat, vd->vd_map);
	bus_dmamap_destroy(sc->sc_dmat, vd->vd_map);
	bus_dmamem_unmap(sc->sc_dmat, vd->vd_kva, vd->vd_size);
	bus_dmamem_free(sc->sc_dmat, &vd->vd_seg, 1);
}

/* ---- control queue ---- */

/*
 * Take back what the device finished.  Stream commands are not waited
 * for; a failure is reported here, the stream is not stopped by it:
 * audio(4) sees the silence and nothing is left running.
 */
static int
viosnd_ctl_done(struct virtqueue *vq)
{
	struct virtio_softc *vsc = vq->vq_owner;
	struct viosnd_softc *sc = device_private(virtio_child(vsc));
	int slot, len, i;
	uint32_t code, status;

	mutex_enter(&sc->sc_intr_lock);
	while (virtio_dequeue(vsc, vq, &slot, &len) == 0) {
		if (slot == sc->sc_info_slot) {
			viosnd_shm_sync(sc, SHM_OFF(info_req),
			    sizeof(sc->sc_shm->info_req) +
			    sizeof(sc->sc_shm->info_resp) +
			    sizeof(sc->sc_shm->info), BUS_DMASYNC_POSTREAD);
			sc->sc_info_slot = -1;
			sc->sc_info_done = true;
		} else {
			i = sc->sc_slot_entry[VIOSND_VQ_CONTROL][slot];
			viosnd_shm_sync(sc, SHM_OFF(ctl[i]),
			    sizeof(struct viosnd_ctl), BUS_DMASYNC_POSTREAD);
			code = le32toh(sc->sc_shm->ctl[i].req.hdr.hdr.code);
			status = le32toh(sc->sc_shm->ctl[i].resp.code);
			if (status != VIRTIO_SND_S_OK) {
				device_printf(sc->sc_dev,
				    "command 0x%04x failed: 0x%04x\n",
				    code, status);
			}
			sc->sc_ctl_busy[i] = false;
		}
		virtio_dequeue_commit(vsc, vq, slot);
	}
	mutex_exit(&sc->sc_intr_lock);
	return 1;
}

/* Queue a stream command (5.14.6.6); len is the request's size. */
static int
viosnd_ctl_queue(struct viosnd_softc *sc, const void *req, size_t len)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	struct virtqueue *vq = &sc->sc_vq[VIOSND_VQ_CONTROL];
	struct viosnd_ctl *c;
	int slot, i, error;

	KASSERT(mutex_owned(&sc->sc_intr_lock));
	KASSERT(len <= sizeof(c->req));

	for (i = 0; i < VIOSND_NCTL && sc->sc_ctl_busy[i]; i++)
		continue;
	if (i == VIOSND_NCTL)
		return EBUSY;
	if ((error = virtio_enqueue_prep(vsc, vq, &slot)) != 0)
		return error;
	if ((error = virtio_enqueue_reserve(vsc, vq, slot, 2)) != 0)
		return error;
	sc->sc_slot_entry[VIOSND_VQ_CONTROL][slot] = i;
	c = &sc->sc_shm->ctl[i];
	memset(c, 0, sizeof(*c));
	memcpy(&c->req, req, len);
	viosnd_shm_sync(sc, SHM_OFF(ctl[i]), sizeof(*c),
	    BUS_DMASYNC_PREWRITE | BUS_DMASYNC_PREREAD);
	virtio_enqueue_p(vsc, vq, slot, sc->sc_shmdma.vd_map,
	    SHM_OFF(ctl[i].req), len, true);
	virtio_enqueue_p(vsc, vq, slot, sc->sc_shmdma.vd_map,
	    SHM_OFF(ctl[i].resp), sizeof(c->resp), false);
	sc->sc_ctl_busy[i] = true;
	virtio_enqueue_commit(vsc, vq, slot, true);
	return 0;
}

static int
viosnd_pcm_cmd(struct viosnd_softc *sc, struct viosnd_stream *vs,
    uint32_t code)
{
	struct virtio_snd_pcm_hdr req;

	req.hdr.code = htole32(code);
	req.stream_id = htole32(vs->vs_id);
	return viosnd_ctl_queue(sc, &req, sizeof(req));
}

/* VIRTIO_SND_R_PCM_INFO for streams 0..n-1, waiting for the reply. */
static int
viosnd_query_streams(struct viosnd_softc *sc, u_int n)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	struct virtqueue *vq = &sc->sc_vq[VIOSND_VQ_CONTROL];
	struct viosnd_shm *shm = sc->sc_shm;
	int slot, error;
	u_int i;

	mutex_enter(&sc->sc_intr_lock);
	if ((error = virtio_enqueue_prep(vsc, vq, &slot)) != 0 ||
	    (error = virtio_enqueue_reserve(vsc, vq, slot, 2)) != 0) {
		mutex_exit(&sc->sc_intr_lock);
		return error;
	}
	/* 5.14.6.1, 5.14.6.2: count items of size bytes, and room for them. */
	memset(&shm->info_req, 0, sizeof(shm->info_req) +
	    sizeof(shm->info_resp) + sizeof(shm->info));
	shm->info_req.hdr.code = htole32(VIRTIO_SND_R_PCM_INFO);
	shm->info_req.start_id = htole32(0);
	shm->info_req.count = htole32(n);
	shm->info_req.size = htole32(sizeof(struct virtio_snd_pcm_info));
	viosnd_shm_sync(sc, SHM_OFF(info_req), sizeof(shm->info_req) +
	    sizeof(shm->info_resp) + sizeof(shm->info),
	    BUS_DMASYNC_PREWRITE | BUS_DMASYNC_PREREAD);
	virtio_enqueue_p(vsc, vq, slot, sc->sc_shmdma.vd_map,
	    SHM_OFF(info_req), sizeof(shm->info_req), true);
	virtio_enqueue_p(vsc, vq, slot, sc->sc_shmdma.vd_map,
	    SHM_OFF(info_resp), sizeof(shm->info_resp) +
	    n * sizeof(struct virtio_snd_pcm_info), false);
	sc->sc_info_slot = slot;
	sc->sc_info_done = false;
	virtio_enqueue_commit(vsc, vq, slot, true);
	/*
	 * Attach runs cold, where sleeping is not possible: poll, taking
	 * the reply ourselves if the interrupt has not.
	 */
	for (i = 0; !sc->sc_info_done && i < VIOSND_CTL_WAIT_MS; i++) {
		mutex_exit(&sc->sc_intr_lock);
		delay(1000);
		(void)viosnd_ctl_done(vq);
		mutex_enter(&sc->sc_intr_lock);
	}
	if (!sc->sc_info_done) {
		sc->sc_info_slot = -1;
		error = ETIMEDOUT;
	} else if (le32toh(shm->info_resp.code) != VIRTIO_SND_S_OK)
		error = EIO;
	mutex_exit(&sc->sc_intr_lock);
	return error;
}

/* ---- event queue ---- */

static void
viosnd_event_post(struct viosnd_softc *sc, u_int i)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	struct virtqueue *vq = &sc->sc_vq[VIOSND_VQ_EVENT];
	int slot;

	if (virtio_enqueue_prep(vsc, vq, &slot) != 0)
		return;
	if (virtio_enqueue_reserve(vsc, vq, slot, 1) != 0)
		return;
	sc->sc_slot_entry[VIOSND_VQ_EVENT][slot] = i;
	/* 5.14.5.1: device-writable only, at least an event's size. */
	viosnd_shm_sync(sc, SHM_OFF(event[i]), sizeof(struct virtio_snd_event),
	    BUS_DMASYNC_PREREAD);
	virtio_enqueue_p(vsc, vq, slot, sc->sc_shmdma.vd_map,
	    SHM_OFF(event[i]), sizeof(struct virtio_snd_event), false);
	virtio_enqueue_commit(vsc, vq, slot, true);
}

static int
viosnd_event_done(struct virtqueue *vq)
{
	struct virtio_softc *vsc = vq->vq_owner;
	struct viosnd_softc *sc = device_private(virtio_child(vsc));
	int slot, len;
	u_int i;

	mutex_enter(&sc->sc_intr_lock);
	while (virtio_dequeue(vsc, vq, &slot, &len) == 0) {
		i = sc->sc_slot_entry[VIOSND_VQ_EVENT][slot];
		virtio_dequeue_commit(vsc, vq, slot);
		viosnd_shm_sync(sc, SHM_OFF(event[i]),
		    sizeof(struct virtio_snd_event), BUS_DMASYNC_POSTREAD);
		if (le32toh(sc->sc_shm->event[i].hdr.code) ==
		    VIRTIO_SND_EVT_PCM_XRUN) {
			device_printf(sc->sc_dev, "stream %u: xrun\n",
			    le32toh(sc->sc_shm->event[i].data));
		}
		viosnd_event_post(sc, i);
	}
	mutex_exit(&sc->sc_intr_lock);
	return 1;
}

/* ---- PCM I/O ---- */

/* Queue the next period of vs's ring (5.14.6.8.1, 5.14.6.8.2). */
static int
viosnd_io_queue(struct viosnd_softc *sc, struct viosnd_stream *vs)
{
	struct virtio_softc *vsc = sc->sc_virtio;
	const bool out = vs->vs_dir == VIRTIO_SND_D_OUTPUT;
	struct virtqueue *vq = &sc->sc_vq[out ? VIOSND_VQ_TX : VIOSND_VQ_RX];
	struct viosnd_io *io;
	int slot, error;
	u_int i;

	KASSERT(mutex_owned(&sc->sc_intr_lock));

	for (i = 0; i < VIOSND_NIO && sc->sc_io_busy[vs->vs_dir][i]; i++)
		continue;
	if (i == VIOSND_NIO)
		return EBUSY;
	if ((error = virtio_enqueue_prep(vsc, vq, &slot)) != 0)
		return error;
	if ((error = virtio_enqueue_reserve(vsc, vq, slot, 3)) != 0)
		return error;
	sc->sc_slot_entry[vq->vq_index][slot] = i;
	sc->sc_io_busy[vs->vs_dir][i] = true;
	sc->sc_io_epoch[vs->vs_dir][i] = vs->vs_epoch;
	io = &sc->sc_shm->io[vs->vs_dir][i];
	io->xfer.stream_id = htole32(vs->vs_id);
	io->status.status = 0;
	viosnd_shm_sync(sc, SHM_OFF(io[vs->vs_dir][i]), sizeof(*io),
	    BUS_DMASYNC_PREWRITE | BUS_DMASYNC_PREREAD);
	bus_dmamap_sync(sc->sc_dmat, vs->vs_ring->vd_map, vs->vs_next,
	    vs->vs_blksize, out ? BUS_DMASYNC_PREWRITE : BUS_DMASYNC_PREREAD);
	virtio_enqueue_p(vsc, vq, slot, sc->sc_shmdma.vd_map,
	    SHM_OFF(io[vs->vs_dir][i].xfer), sizeof(io->xfer), true);
	virtio_enqueue_p(vsc, vq, slot, vs->vs_ring->vd_map, vs->vs_next,
	    vs->vs_blksize, out);
	virtio_enqueue_p(vsc, vq, slot, sc->sc_shmdma.vd_map,
	    SHM_OFF(io[vs->vs_dir][i].status), sizeof(io->status), false);
	virtio_enqueue_commit(vsc, vq, slot, true);
	vs->vs_next = (vs->vs_next + vs->vs_blksize) % vs->vs_bufsize;
	vs->vs_queued++;
	return 0;
}

static int
viosnd_io_done(struct virtqueue *vq)
{
	struct virtio_softc *vsc = vq->vq_owner;
	struct viosnd_softc *sc = device_private(virtio_child(vsc));
	const u_int dir = vq->vq_index == VIOSND_VQ_TX ? VIRTIO_SND_D_OUTPUT :
	    VIRTIO_SND_D_INPUT;
	struct viosnd_stream *vs = &sc->sc_stream[dir];
	int slot, len;

	mutex_enter(&sc->sc_intr_lock);
	while (virtio_dequeue(vsc, vq, &slot, &len) == 0) {
		const u_int e = sc->sc_slot_entry[vq->vq_index][slot];

		sc->sc_io_busy[dir][e] = false;
		virtio_dequeue_commit(vsc, vq, slot);
		if (sc->sc_io_epoch[dir][e] != vs->vs_epoch) {
			/* An earlier trigger's, stopped before it came back. */
			KASSERT(sc->sc_io_stale[dir] > 0);
			if (--sc->sc_io_stale[dir] == 0)
				cv_broadcast(&sc->sc_io_cv);
			continue;
		}
		KASSERT(vs->vs_queued > 0);
		if (--vs->vs_queued == 0)
			cv_broadcast(&sc->sc_io_cv);
		if (!vs->vs_running)
			continue;	/* after halt: only drained */
		/* One period elapsed: tell audio(4), keep the queue full. */
		if (vs->vs_intr != NULL)
			vs->vs_intr(vs->vs_intrarg);
		if (vs->vs_running)
			(void)viosnd_io_queue(sc, vs);
	}
	mutex_exit(&sc->sc_intr_lock);
	return 1;
}

/* ---- audio(4) ---- */

static int
viosnd_query_format(void *priv, audio_format_query_t *afp)
{
	struct viosnd_softc *sc = priv;
	struct audio_format fmts[4];
	u_int n = 0, d, i;

	for (d = 0; d < 2; d++) {
		struct viosnd_stream *vs = &sc->sc_stream[d];

		for (i = 0; vs->vs_id >= 0 && i < vs->vs_nformats; i++)
			fmts[n++] = vs->vs_formats[i];
	}
	return audio_query_format(fmts, n, afp);
}

static int
viosnd_set_one(struct viosnd_stream *vs, const audio_params_t *p)
{
	u_int r;

	if (vs->vs_id < 0 || p == NULL)
		return 0;
	for (r = 0; r < __arraycount(viosnd_rates); r++) {
		if (viosnd_rates[r] == p->sample_rate)
			break;
	}
	if (r == __arraycount(viosnd_rates))
		return EINVAL;
	vs->vs_rate = r;
	vs->vs_format = p->precision == 16 ? VIRTIO_SND_PCM_FMT_S16 :
	    VIRTIO_SND_PCM_FMT_S32;
	vs->vs_channels = p->channels;
	return 0;
}

static int
viosnd_set_format(void *priv, int setmode, const audio_params_t *play,
    const audio_params_t *rec, audio_filter_reg_t *pfil,
    audio_filter_reg_t *rfil)
{
	struct viosnd_softc *sc = priv;
	int error;

	if ((setmode & AUMODE_PLAY) &&
	    (error = viosnd_set_one(&sc->sc_stream[VIRTIO_SND_D_OUTPUT],
	    play)) != 0)
		return error;
	if ((setmode & AUMODE_RECORD) &&
	    (error = viosnd_set_one(&sc->sc_stream[VIRTIO_SND_D_INPUT],
	    rec)) != 0)
		return error;
	return 0;
}

static int
viosnd_round_blocksize(void *priv, int bs, int mode,
    const audio_params_t *param)
{

	/* Whole frames of up to 8 channels of 32 bits. */
	return MAX(rounddown(bs, 32), 32);
}

static void *
viosnd_allocm(void *priv, int dir, size_t size)
{
	struct viosnd_softc *sc = priv;
	struct viosnd_dma *vd;
	u_int i;

	vd = kmem_zalloc(sizeof(*vd), KM_SLEEP);
	if (viosnd_dma_alloc(sc, vd, size) != 0) {
		kmem_free(vd, sizeof(*vd));
		return NULL;
	}
	for (i = 0; i < __arraycount(sc->sc_dmas); i++) {
		if (sc->sc_dmas[i] == NULL) {
			sc->sc_dmas[i] = vd;
			return vd->vd_kva;
		}
	}
	viosnd_dma_free(sc, vd);
	kmem_free(vd, sizeof(*vd));
	return NULL;
}

/*
 * Messages out with the device point into the ring: wait for them
 * before freeing it.  The bound is ours.
 */
static void
viosnd_io_drain(struct viosnd_softc *sc)
{
	u_int d, tries;

	mutex_enter(&sc->sc_intr_lock);
	for (tries = 0; tries < VIOSND_DRAIN_WAITS; tries++) {
		for (d = 0; d < 2; d++) {
			if (sc->sc_stream[d].vs_queued != 0 ||
			    sc->sc_io_stale[d] != 0)
				break;
		}
		if (d == 2)
			break;
		(void)cv_timedwait(&sc->sc_io_cv, &sc->sc_intr_lock,
		    mstohz(VIOSND_DRAIN_WAIT_MS));
	}
	mutex_exit(&sc->sc_intr_lock);
}

static void
viosnd_freem(void *priv, void *addr, size_t size)
{
	struct viosnd_softc *sc = priv;
	u_int i;

	viosnd_io_drain(sc);
	for (i = 0; i < __arraycount(sc->sc_dmas); i++) {
		struct viosnd_dma *vd = sc->sc_dmas[i];

		if (vd != NULL && vd->vd_kva == addr) {
			viosnd_dma_free(sc, vd);
			kmem_free(vd, sizeof(*vd));
			sc->sc_dmas[i] = NULL;
			return;
		}
	}
}

static int
viosnd_get_props(void *priv)
{
	struct viosnd_softc *sc = priv;
	int props = 0;

	if (sc->sc_stream[VIRTIO_SND_D_OUTPUT].vs_id >= 0)
		props |= AUDIO_PROP_PLAYBACK;
	if (sc->sc_stream[VIRTIO_SND_D_INPUT].vs_id >= 0)
		props |= AUDIO_PROP_CAPTURE;
	if (props == (AUDIO_PROP_PLAYBACK | AUDIO_PROP_CAPTURE))
		props |= AUDIO_PROP_FULLDUPLEX | AUDIO_PROP_INDEPENDENT;
	return props;
}

/* 5.14.6.6.1: stop, then release. */
static void
viosnd_stop(struct viosnd_softc *sc, struct viosnd_stream *vs)
{

	KASSERT(mutex_owned(&sc->sc_intr_lock));

	(void)viosnd_pcm_cmd(sc, vs, VIRTIO_SND_R_PCM_STOP);
	(void)viosnd_pcm_cmd(sc, vs, VIRTIO_SND_R_PCM_RELEASE);
}

/*
 * 5.14.6.6.1: set parameters, prepare, for output queue data ahead,
 * then start.
 */
static int
viosnd_trigger(struct viosnd_softc *sc, struct viosnd_stream *vs,
    void *start, void *end, int blksize, void (*intr)(void *), void *arg)
{
	struct virtio_snd_pcm_set_params p;
	u_int i;
	int error;

	KASSERT(mutex_owned(&sc->sc_intr_lock));

	vs->vs_ring = NULL;
	for (i = 0; i < __arraycount(sc->sc_dmas); i++) {
		if (sc->sc_dmas[i] != NULL && sc->sc_dmas[i]->vd_kva == start)
			vs->vs_ring = sc->sc_dmas[i];
	}
	if (vs->vs_id < 0 || vs->vs_ring == NULL)
		return EINVAL;
	vs->vs_bufsize = (char *)end - (char *)start;
	vs->vs_blksize = blksize;
	/* 5.14.6.6.3.2: period_bytes divides buffer_bytes. */
	if (blksize <= 0 || vs->vs_bufsize % blksize != 0)
		return EINVAL;
	/*
	 * Messages of the previous trigger may still be out; from here on
	 * their completions are not periods of this one.  Before, the
	 * count was reset and they were taken as elapsed periods.
	 */
	sc->sc_io_stale[vs->vs_dir] += vs->vs_queued;
	vs->vs_epoch++;
	vs->vs_next = 0;
	vs->vs_queued = 0;
	vs->vs_intr = intr;
	vs->vs_intrarg = arg;

	memset(&p, 0, sizeof(p));
	p.hdr.hdr.code = htole32(VIRTIO_SND_R_PCM_SET_PARAMS);
	p.hdr.stream_id = htole32(vs->vs_id);
	p.buffer_bytes = htole32(vs->vs_bufsize);
	p.period_bytes = htole32(blksize);
	p.features = 0;			/* messages, with notifications */
	p.channels = vs->vs_channels;
	p.format = vs->vs_format;
	p.rate = vs->vs_rate;
	if ((error = viosnd_ctl_queue(sc, &p, sizeof(p))) != 0 ||
	    (error = viosnd_pcm_cmd(sc, vs, VIRTIO_SND_R_PCM_PREPARE)) != 0)
		return error;
	vs->vs_running = true;
	/*
	 * Output pre-buffers; input queues empty buffers (5.14.6.8.2.2).
	 * At most one block fewer than the ring holds is out at a time:
	 * audio(4) fills the block after next in the interrupt for a block
	 * (audio_pintr), so the block a whole ring ahead still holds old
	 * samples.  With the ring's every block out, each completion queued
	 * that stale block; QEMU reads a message only when it comes to it,
	 * which hid this until the last block of a sound, never refilled,
	 * went out missing.
	 */
	vs->vs_inflight = MAX(1, MIN(VIOSND_NIO,
	    vs->vs_bufsize / blksize - 1));
	for (i = 0; i < vs->vs_inflight; i++) {
		if ((error = viosnd_io_queue(sc, vs)) != 0)
			break;
	}
	if (error == 0)
		error = viosnd_pcm_cmd(sc, vs, VIRTIO_SND_R_PCM_START);
	if (error != 0)
		vs->vs_running = false;
	return error;
}

static int
viosnd_halt(struct viosnd_softc *sc, struct viosnd_stream *vs)
{

	KASSERT(mutex_owned(&sc->sc_intr_lock));

	if (!vs->vs_running)
		return 0;
	vs->vs_running = false;
	vs->vs_intr = NULL;
	viosnd_stop(sc, vs);
	return 0;
}

static int
viosnd_trigger_output(void *priv, void *start, void *end, int blksize,
    void (*intr)(void *), void *arg, const audio_params_t *param)
{
	struct viosnd_softc *sc = priv;

	return viosnd_trigger(sc, &sc->sc_stream[VIRTIO_SND_D_OUTPUT],
	    start, end, blksize, intr, arg);
}

static int
viosnd_trigger_input(void *priv, void *start, void *end, int blksize,
    void (*intr)(void *), void *arg, const audio_params_t *param)
{
	struct viosnd_softc *sc = priv;

	return viosnd_trigger(sc, &sc->sc_stream[VIRTIO_SND_D_INPUT],
	    start, end, blksize, intr, arg);
}

static int
viosnd_halt_output(void *priv)
{
	struct viosnd_softc *sc = priv;

	return viosnd_halt(sc, &sc->sc_stream[VIRTIO_SND_D_OUTPUT]);
}

static int
viosnd_halt_input(void *priv)
{
	struct viosnd_softc *sc = priv;

	return viosnd_halt(sc, &sc->sc_stream[VIRTIO_SND_D_INPUT]);
}

static int
viosnd_getdev(void *priv, struct audio_device *adev)
{

	strlcpy(adev->name, "Virtio", sizeof(adev->name));
	strlcpy(adev->version, "1.3", sizeof(adev->version));
	strlcpy(adev->config, "viosnd", sizeof(adev->config));
	return 0;
}

static int
viosnd_query_devinfo(void *priv, mixer_devinfo_t *di)
{

	return ENXIO;
}

static int
viosnd_port(void *priv, mixer_ctrl_t *mc)
{

	return ENXIO;
}

static void
viosnd_get_locks(void *priv, kmutex_t **intr, kmutex_t **thread)
{
	struct viosnd_softc *sc = priv;

	*intr = &sc->sc_intr_lock;
	*thread = &sc->sc_lock;
}

static const struct audio_hw_if viosnd_hw_if = {
	.query_format = viosnd_query_format,
	.set_format = viosnd_set_format,
	.round_blocksize = viosnd_round_blocksize,
	.allocm = viosnd_allocm,
	.freem = viosnd_freem,
	.get_props = viosnd_get_props,
	.trigger_output = viosnd_trigger_output,
	.trigger_input = viosnd_trigger_input,
	.halt_output = viosnd_halt_output,
	.halt_input = viosnd_halt_input,
	.getdev = viosnd_getdev,
	.query_devinfo = viosnd_query_devinfo,
	.set_port = viosnd_port,
	.get_port = viosnd_port,
	.get_locks = viosnd_get_locks,
};

/* ---- attach ---- */

/*
 * What audio(4) is offered of a stream: signed 16 and 32 bit little
 * endian if the device has them, stereo if it can, at its rates.
 */
static void
viosnd_stream_formats(struct viosnd_stream *vs)
{
	const struct virtio_snd_pcm_info *pi = &vs->vs_info;
	const uint64_t formats = le64toh(pi->formats);
	const uint64_t rates = le64toh(pi->rates);
	struct audio_format f;
	u_int r, ch;

	memset(&f, 0, sizeof(f));
	f.mode = vs->vs_dir == VIRTIO_SND_D_OUTPUT ? AUMODE_PLAY :
	    AUMODE_RECORD;
	f.encoding = AUDIO_ENCODING_SLINEAR_LE;
	ch = MIN(2, pi->channels_max);
	if (ch < pi->channels_min || ch == 0)
		return;
	f.channels = ch;
	f.channel_mask = ch == 1 ? AUFMT_MONAURAL : AUFMT_STEREO;
	for (r = 0; r < __arraycount(viosnd_rates) &&
	    f.frequency_type < AUFMT_MAX_FREQUENCIES; r++) {
		if (rates & __BIT(r))
			f.frequency[f.frequency_type++] = viosnd_rates[r];
	}
	if (f.frequency_type == 0)
		return;
	if (formats & __BIT(VIRTIO_SND_PCM_FMT_S16)) {
		f.validbits = f.precision = 16;
		vs->vs_formats[vs->vs_nformats++] = f;
	}
	if (formats & __BIT(VIRTIO_SND_PCM_FMT_S32)) {
		f.validbits = f.precision = 32;
		vs->vs_formats[vs->vs_nformats++] = f;
	}
}

static int
viosnd_match(device_t parent, cfdata_t match, void *aux)
{
	struct virtio_attach_args *va = aux;

	return va->sc_childdevid == VIRTIO_DEVICE_ID_SOUND;
}

static void
viosnd_attach(device_t parent, device_t self, void *aux)
{
	struct viosnd_softc *sc = device_private(self);
	struct virtio_softc *vsc = device_private(parent);
	u_int nstreams, i, d;

	if (virtio_child(vsc) != NULL)
		panic("already attached to something else");
	sc->sc_dev = self;
	sc->sc_virtio = vsc;
	sc->sc_dmat = virtio_dmat(vsc);
	sc->sc_info_slot = -1;
	mutex_init(&sc->sc_lock, MUTEX_DEFAULT, IPL_NONE);
	mutex_init(&sc->sc_intr_lock, MUTEX_DEFAULT, IPL_AUDIO);
	cv_init(&sc->sc_io_cv, "viosndio");
	for (d = 0; d < 2; d++) {
		sc->sc_stream[d].vs_id = -1;
		sc->sc_stream[d].vs_dir = d;
	}

	/* 5.14 is a VIRTIO 1.x device; its fields are little endian. */
	virtio_child_attach_start(vsc, self, IPL_AUDIO, VIRTIO_F_VERSION_1,
	    VIRTIO_COMMON_FLAG_BITS);

	if (viosnd_dma_alloc(sc, &sc->sc_shmdma, sizeof(struct viosnd_shm))) {
		aprint_error_dev(self, "can't allocate shared memory\n");
		goto failed;
	}
	sc->sc_shm = sc->sc_shmdma.vd_kva;
	memset(sc->sc_shm, 0, sizeof(*sc->sc_shm));

	virtio_init_vq_vqdone(vsc, &sc->sc_vq[VIOSND_VQ_CONTROL],
	    VIOSND_VQ_CONTROL, viosnd_ctl_done);
	virtio_init_vq_vqdone(vsc, &sc->sc_vq[VIOSND_VQ_EVENT],
	    VIOSND_VQ_EVENT, viosnd_event_done);
	virtio_init_vq_vqdone(vsc, &sc->sc_vq[VIOSND_VQ_TX],
	    VIOSND_VQ_TX, viosnd_io_done);
	virtio_init_vq_vqdone(vsc, &sc->sc_vq[VIOSND_VQ_RX],
	    VIOSND_VQ_RX, viosnd_io_done);
	if (virtio_alloc_vq(vsc, &sc->sc_vq[VIOSND_VQ_CONTROL], VIOSND_MAXSEG, 2,
	    "control") != 0 ||
	    virtio_alloc_vq(vsc, &sc->sc_vq[VIOSND_VQ_EVENT], VIOSND_MAXSEG, 1,
	    "event") != 0 ||
	    virtio_alloc_vq(vsc, &sc->sc_vq[VIOSND_VQ_TX], VIOSND_MAXSEG, 3,
	    "tx") != 0 ||
	    virtio_alloc_vq(vsc, &sc->sc_vq[VIOSND_VQ_RX], VIOSND_MAXSEG, 3,
	    "rx") != 0) {
		aprint_error_dev(self, "can't allocate virtqueues\n");
		goto failed;
	}
	for (i = 0; i < VIOSND_NVQS; i++) {
		sc->sc_slot_entry[i] = kmem_zalloc(sc->sc_vq[i].vq_num *
		    sizeof(int), KM_SLEEP);
	}
	if (virtio_child_attach_finish(vsc, sc->sc_vq, VIOSND_NVQS, NULL,
	    VIRTIO_F_INTR_MPSAFE) != 0)
		goto failed;

	nstreams = virtio_read_device_config_le_4(vsc, VIOSND_CONFIG_STREAMS);
	aprint_normal_dev(self, "%u jacks, %u streams, %u channel maps\n",
	    virtio_read_device_config_le_4(vsc, VIOSND_CONFIG_JACKS),
	    nstreams,
	    virtio_read_device_config_le_4(vsc, VIOSND_CONFIG_CHMAPS));
	nstreams = MIN(nstreams, VIOSND_MAX_STREAMS);

	/* 5.14.5 step 6, 5.14.5.1. */
	mutex_enter(&sc->sc_intr_lock);
	for (i = 0; i < VIOSND_NEVENT; i++)
		viosnd_event_post(sc, i);
	mutex_exit(&sc->sc_intr_lock);

	if (nstreams == 0 || viosnd_query_streams(sc, nstreams) != 0) {
		aprint_error_dev(self, "can't read the streams\n");
		return;
	}
	for (i = 0; i < nstreams; i++) {
		const struct virtio_snd_pcm_info *pi = &sc->sc_shm->info[i];
		struct viosnd_stream *vs;

		if (pi->direction > VIRTIO_SND_D_INPUT)
			continue;
		vs = &sc->sc_stream[pi->direction];
		if (vs->vs_id >= 0)
			continue;		/* the first of each */
		vs->vs_info = *pi;
		viosnd_stream_formats(vs);
		if (vs->vs_nformats > 0)
			vs->vs_id = i;
	}
	if (sc->sc_stream[0].vs_id < 0 && sc->sc_stream[1].vs_id < 0) {
		aprint_error_dev(self, "no stream in a format we use\n");
		return;
	}
	audio_attach_mi(&viosnd_hw_if, sc, self);
	return;

failed:
	virtio_child_attach_failed(vsc);
}
