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

#ifndef _ARM_APPLE_APPLE_MCAVAR_H_
#define _ARM_APPLE_APPLE_MCAVAR_H_

#include <sys/bus.h>

/*
 * Streams through the MCA, for the machine driver.
 *
 * A stream runs in one cluster (the frontend) and drives one or more
 * I2S ports (portmask), which need not be the cluster's own: on the
 * j293 one cluster feeds the speaker amplifiers on two ports.  The
 * MCA provides BCLK and FSYNC.
 */
struct apple_mca_stream;

struct apple_mca_params {
	u_int		mp_rate;	/* frames per second */
	u_int		mp_width;	/* sample bits: 16, 24 or 32 */
	u_int		mp_channels;	/* in memory, interleaved */
	u_int		mp_slots;	/* per frame on the wire */
	u_int		mp_slot_width;	/* bits: 16, 20, 24 or 32 */
	uint32_t	mp_slot_mask;	/* slots used, mp_channels bits set */
	u_int		mp_format;	/* AUDIO_DAI_FORMAT_* | POLARITY */
	/*
	 * -1: this stream's cluster makes the clocks.  Otherwise the port
	 * whose clocks it follows, as made by another stream; capture of
	 * the amplifiers' sense data runs this way, on the speaker clocks.
	 */
	int		mp_follow_port;
};

struct audio_dai_device;
int	apple_mca_dai_port(struct audio_dai_device *, device_t *, u_int *);

int	apple_mca_stream_open(device_t, u_int, bool, uint32_t,
	    struct apple_mca_stream **);
void	apple_mca_stream_close(struct apple_mca_stream *);
bus_dma_tag_t apple_mca_stream_dmat(struct apple_mca_stream *);
int	apple_mca_stream_config(struct apple_mca_stream *,
	    const struct apple_mca_params *);
int	apple_mca_stream_prepare(struct apple_mca_stream *);
void	apple_mca_stream_unprepare(struct apple_mca_stream *);
/* start and halt are safe with spin locks held; the rest may sleep. */
int	apple_mca_stream_start(struct apple_mca_stream *, bus_addr_t,
	    bus_size_t, bus_size_t, void (*)(void *), void *);
void	apple_mca_stream_halt(struct apple_mca_stream *);

#endif /* !_ARM_APPLE_APPLE_MCAVAR_H_ */
