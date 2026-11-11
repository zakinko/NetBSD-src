/*	$NetBSD$	*/

/*-
 * Copyright (c) 2026 Showta Ishizaki
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * The TLS 1.3 record layer of RPC-with-TLS, RFC 9289, over mbufs.  The
 * handshake was done in userland by rpc.tlsservd(8); what comes here is
 * the pair of application traffic secrets, and every record after the
 * handshake is the kernel's: application data, KeyUpdate, alerts.
 *
 * One receiver and one sender at a time, as oncrpc_svc.c guarantees with
 * XP_RECEIVING and XP_SENDING: the receive side touches tc_rx and the
 * reassembly, the send side tc_tx and tc_wbuf, and nothing is shared.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/mbuf.h>
#include <sys/systm.h>

#include <crypto/aes/aes.h>

#include <oncrpc/oncrpc.h>
#include <oncrpc/oncrpc_tls.h>
#include <oncrpc/tls13_crypto.h>

/* RFC 8446 s4, HandshakeType */
#define	TLS13_HS_KEY_UPDATE	24
/* RFC 8446 s4.6.3, KeyUpdateRequest */
#define	TLS13_KU_NOT_REQUESTED	0
#define	TLS13_KU_REQUESTED	1
#define	TLS13_HSHDRLEN		4	/* msg_type, uint24 length, s4 */

/*
 * RFC 8446 s5.5: no more than 2^24.5 full-size records under one AES-GCM
 * key.  The sender rekeys well before, at 2^24.
 */
#define	TLS13_GCM_REKEY		(1ULL << 24)

#define	TC_RECMAX	(TLS13_HDRLEN + TLS13_MAXCIPHER)

struct oncrpc_tlsconn {
	struct tls13_dir tc_rx;		/* the client's, receive side */
	struct tls13_dir tc_tx;		/* the server's, send side */
	struct mbuf	*tc_raw;	/* received, not yet a whole record */
	u_int		 tc_rawlen;
	bool		 tc_closed;	/* close_notify received, s6.1 */
	uint8_t		*tc_rbuf;	/* TC_RECMAX, receive side */
	uint8_t		*tc_wbuf;	/* TC_RECMAX, send side */
	uint8_t		 tc_exporter[ONCRPC_TLS_EXPORTERLEN];
	uint8_t		 tc_flags;
};

struct oncrpc_tlsconn *
oncrpc_tlsconn_create(const struct oncrpc_tls_params *p, int *errorp)
{
	struct oncrpc_tlsconn *tc;

	/* Only the suite RFC 8446 s9.1 makes mandatory; rpc.tlsservd offers no other. */
	if (p->tp_suite != TLS13_AES_128_GCM_SHA256 ||
	    p->tp_secretlen != TLS13_SECRETLEN) {
		*errorp = EPROTONOSUPPORT;
		return NULL;
	}
	tc = kmem_zalloc(sizeof(*tc), KM_SLEEP);
	tc->tc_rbuf = kmem_alloc(TC_RECMAX, KM_SLEEP);
	tc->tc_wbuf = kmem_alloc(TC_RECMAX, KM_SLEEP);
	/* No record has been sent under either secret: s5.3, seq 0. */
	tls13_dir_init(&tc->tc_rx, p->tp_csecret, 0);
	tls13_dir_init(&tc->tc_tx, p->tp_ssecret, 0);
	memcpy(tc->tc_exporter, p->tp_exporter, sizeof(tc->tc_exporter));
	tc->tc_flags = p->tp_flags;
	*errorp = 0;
	return tc;
}

void
oncrpc_tlsconn_destroy(struct oncrpc_tlsconn *tc)
{

	if (tc == NULL)
		return;
	tls13_dir_fini(&tc->tc_rx);
	tls13_dir_fini(&tc->tc_tx);
	m_freem(tc->tc_raw);
	explicit_memset(tc->tc_rbuf, 0, TC_RECMAX);
	explicit_memset(tc->tc_wbuf, 0, TC_RECMAX);
	kmem_free(tc->tc_rbuf, TC_RECMAX);
	kmem_free(tc->tc_wbuf, TC_RECMAX);
	explicit_memset(tc, 0, sizeof(*tc));
	kmem_free(tc, sizeof(*tc));
}

void
oncrpc_tlsconn_exporter(const struct oncrpc_tlsconn *tc, uint8_t *out)
{

	memcpy(out, tc->tc_exporter, ONCRPC_TLS_EXPORTERLEN);
}

/* len bytes of buf as a fresh chain with a packet header. */
static struct mbuf *
tc_tombuf(const uint8_t *buf, u_int len)
{
	struct mbuf *top = NULL, **mp = &top, *m;
	u_int n, off = 0;

	while (off < len || top == NULL) {
		m = top == NULL ? m_gethdr(M_WAIT, MT_DATA) :
		    m_get(M_WAIT, MT_DATA);
		n = len - off;
		if (n > MLEN) {
			MCLGET(m, M_WAIT);
			n = MIN(n, MCLBYTES);
		}
		memcpy(mtod(m, void *), buf + off, n);
		m->m_len = n;
		off += n;
		*mp = m;
		mp = &m->m_next;
	}
	top->m_pkthdr.len = len;
	return top;
}

/* Seal type and len bytes at tc_wbuf + TLS13_HDRLEN into a chain. */
static int
tc_seal(struct oncrpc_tlsconn *tc, uint8_t type, u_int len, struct mbuf **mp)
{
	int error;

	error = tls13_seal(&tc->tc_tx, type, tc->tc_wbuf, len);
	if (error != 0)
		return error;
	*mp = tc_tombuf(tc->tc_wbuf, TLS13_HDRLEN + len + 1 + TLS13_TAGLEN);
	return 0;
}

static void
tc_append(struct mbuf **top, struct mbuf *m)
{

	if (*top == NULL) {
		*top = m;
		return;
	}
	(*top)->m_pkthdr.len += m->m_pkthdr.len;
	m_remove_pkthdr(m);
	m_cat(*top, m);
}

/*
 * A KeyUpdate of ours, RFC 8446 s4.6.3, sealed under the old key, after
 * which the send side changes key, s7.2.
 */
int
oncrpc_tlsconn_keyupdate(struct oncrpc_tlsconn *tc, struct mbuf **mp)
{
	uint8_t *p = tc->tc_wbuf + TLS13_HDRLEN;
	int error;

	p[0] = TLS13_HS_KEY_UPDATE;
	p[1] = 0;
	p[2] = 0;
	p[3] = 1;
	p[4] = TLS13_KU_NOT_REQUESTED;
	error = tc_seal(tc, TLS13_CT_HANDSHAKE, TLS13_HSHDRLEN + 1, mp);
	if (error == 0)
		tls13_dir_update(&tc->tc_tx);
	return error;
}

/* An alert, RFC 8446 s6. */
int
oncrpc_tlsconn_alert(struct oncrpc_tlsconn *tc, uint8_t level, uint8_t desc,
    struct mbuf **mp)
{

	tc->tc_wbuf[TLS13_HDRLEN] = level;
	tc->tc_wbuf[TLS13_HDRLEN + 1] = desc;
	return tc_seal(tc, TLS13_CT_ALERT, 2, mp);
}

/*
 * Protect the chain m, consumed, as application data records of at most
 * 2^14 bytes, RFC 8446 s5.1.  *outp gets the records, with a KeyUpdate
 * first when the key has carried enough, s5.5.
 */
int
oncrpc_tlsconn_output(struct oncrpc_tlsconn *tc, struct mbuf *m,
    struct mbuf **outp)
{
	struct mbuf *out = NULL, *r;
	u_int len, off, n;
	int error = 0;

	len = m->m_pkthdr.len;
	if (tc->tc_tx.d_seq >= TLS13_GCM_REKEY) {
		error = oncrpc_tlsconn_keyupdate(tc, &r);
		if (error != 0)
			goto out;
		tc_append(&out, r);
	}
	for (off = 0; off < len; off += n) {
		n = MIN(len - off, TLS13_MAXPLAIN);
		m_copydata(m, off, n, tc->tc_wbuf + TLS13_HDRLEN);
		error = tc_seal(tc, TLS13_CT_APPDATA, n, &r);
		if (error != 0)
			goto out;
		tc_append(&out, r);
	}
out:
	m_freem(m);
	if (error != 0) {
		m_freem(out);
		out = NULL;
	}
	*outp = out;
	return error;
}

/*
 * The handshake messages of a record after the handshake.  Only
 * KeyUpdate is expected of a client here; a message split over records
 * is not reassembled.
 */
static int
tc_handshake(struct oncrpc_tlsconn *tc, const uint8_t *p, size_t len,
    struct oncrpc_tls_in *in)
{
	size_t mlen;
	bool update = false;

	while (len > 0) {
		if (len < TLS13_HSHDRLEN) {
			in->ti_alert = ONCRPC_TLS_DECODE_ERROR;
			return EPROTO;
		}
		mlen = (size_t)p[1] << 16 | (size_t)p[2] << 8 | p[3];
		if (mlen > len - TLS13_HSHDRLEN) {
			in->ti_alert = ONCRPC_TLS_DECODE_ERROR;
			return EPROTO;
		}
		if (p[0] != TLS13_HS_KEY_UPDATE) {
			in->ti_alert = ONCRPC_TLS_UNEXPECTED_MESSAGE;
			return EPROTO;
		}
		/* s4.6.3 */
		if (mlen != 1) {
			in->ti_alert = ONCRPC_TLS_DECODE_ERROR;
			return EPROTO;
		}
		switch (p[TLS13_HSHDRLEN]) {
		case TLS13_KU_REQUESTED:
			in->ti_keyupdate = true;
			/* FALLTHROUGH */
		case TLS13_KU_NOT_REQUESTED:
			update = true;
			break;
		default:
			/* s4.6.3: any other value MUST be illegal_parameter. */
			in->ti_alert = ONCRPC_TLS_ILLEGAL_PARAMETER;
			return EPROTO;
		}
		p += TLS13_HSHDRLEN + mlen;
		len -= TLS13_HSHDRLEN + mlen;
		/*
		 * s4.6.3: the receive key changes after the record that
		 * carried the KeyUpdate; a second one in the same record
		 * would be under a key not yet in use.
		 */
		if (update && len > 0) {
			in->ti_alert = ONCRPC_TLS_UNEXPECTED_MESSAGE;
			return EPROTO;
		}
	}
	if (update)
		tls13_dir_update(&tc->tc_rx);
	return 0;
}

/*
 * Take m, consumed, more bytes of the stream, and open every whole record
 * in it.  The application data comes out in in->ti_data.  An error ends
 * the connection: in->ti_alert is then what to send the peer, or
 * ONCRPC_TLS_NOALERT when it closed with close_notify or sent a fatal alert.
 */
static int tc_input(struct oncrpc_tlsconn *, struct mbuf *,
    struct oncrpc_tls_in *);

int
oncrpc_tlsconn_input(struct oncrpc_tlsconn *tc, struct mbuf *m,
    struct oncrpc_tls_in *in)
{
	int error;

	error = tc_input(tc, m, in);
	if (error != 0) {
		/* The connection is over; nothing more is read of it. */
		tc->tc_closed = true;
		m_freem(tc->tc_raw);
		tc->tc_raw = NULL;
		tc->tc_rawlen = 0;
	}
	return error;
}

static int
tc_input(struct oncrpc_tlsconn *tc, struct mbuf *m, struct oncrpc_tls_in *in)
{
	struct mbuf *n;
	uint8_t hdr[TLS13_HDRLEN], type;
	size_t clen, reclen, len;
	int error;

	memset(in, 0, sizeof(*in));
	in->ti_alert = ONCRPC_TLS_NOALERT;
	if (tc->tc_closed) {
		/* s6.1: data after close_notify MUST be ignored. */
		m_freem(m);
		return 0;
	}
	for (n = m, len = 0; n != NULL; n = n->m_next)
		len += n->m_len;
	if (tc->tc_raw == NULL)
		tc->tc_raw = m;
	else
		m_cat(tc->tc_raw, m);
	tc->tc_rawlen += len;

	while (tc->tc_rawlen >= TLS13_HDRLEN) {
		m_copydata(tc->tc_raw, 0, TLS13_HDRLEN, hdr);
		clen = (size_t)hdr[3] << 8 | hdr[4];
		/* s5.2: record_overflow, before waiting for more of it. */
		if (clen > TLS13_MAXCIPHER) {
			in->ti_alert = ONCRPC_TLS_RECORD_OVERFLOW;
			return EMSGSIZE;
		}
		reclen = TLS13_HDRLEN + clen;
		if (tc->tc_rawlen < reclen)
			break;
		m_copydata(tc->tc_raw, 0, reclen, tc->tc_rbuf);
		m_adj(tc->tc_raw, reclen);
		tc->tc_rawlen -= reclen;
		if (tc->tc_rawlen == 0) {
			m_freem(tc->tc_raw);
			tc->tc_raw = NULL;
		}

		error = tls13_open(&tc->tc_rx, tc->tc_rbuf, reclen, &type,
		    &len);
		switch (error) {
		case 0:
			break;
		case EBADMSG:
			in->ti_alert = ONCRPC_TLS_BAD_RECORD_MAC;
			return error;
		case EMSGSIZE:
			in->ti_alert = ONCRPC_TLS_RECORD_OVERFLOW;
			return error;
		default:
			in->ti_alert = ONCRPC_TLS_UNEXPECTED_MESSAGE;
			return error;
		}
		switch (type) {
		case TLS13_CT_APPDATA:
			if (len == 0)
				break;	/* s5.1: allowed, no content */
			n = tc_tombuf(tc->tc_rbuf + TLS13_HDRLEN, len);
			tc_append(&in->ti_data, n);
			break;
		case TLS13_CT_HANDSHAKE:
			/* s5.1: handshake messages MUST NOT be empty */
			if (len == 0) {
				in->ti_alert = ONCRPC_TLS_UNEXPECTED_MESSAGE;
				return EPROTO;
			}
			error = tc_handshake(tc, tc->tc_rbuf + TLS13_HDRLEN,
			    len, in);
			if (error != 0)
				return error;
			break;
		case TLS13_CT_ALERT:
			/* s6: two bytes, level and description */
			if (len != 2) {
				in->ti_alert = ONCRPC_TLS_DECODE_ERROR;
				return EPROTO;
			}
			in->ti_rlevel = tc->tc_rbuf[TLS13_HDRLEN];
			in->ti_rdesc = tc->tc_rbuf[TLS13_HDRLEN + 1];
			in->ti_ralert = true;
			/*
			 * s6.1: after close_notify everything is ignored;
			 * s6: all other alerts but user_canceled end the
			 * connection, and none is answered.
			 */
			if (in->ti_rdesc == ONCRPC_TLS_CLOSE_NOTIFY) {
				tc->tc_closed = true;
				m_freem(tc->tc_raw);
				tc->tc_raw = NULL;
				tc->tc_rawlen = 0;
				return ECONNRESET;
			}
			if (in->ti_rdesc != ONCRPC_TLS_USER_CANCELED)
				return ECONNABORTED;
			break;
		default:
			/* s5: an unknown type is unexpected_message */
			in->ti_alert = ONCRPC_TLS_UNEXPECTED_MESSAGE;
			return EPROTO;
		}
	}
	return 0;
}
