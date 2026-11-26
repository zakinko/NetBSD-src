/*	$NetBSD$	*/

/*
 * The DTLS 1.3 records in a capture, for a look at their connection IDs,
 * RFC 9147 s4.  One line per UDP datagram to or from the server's port
 * whose first byte is that of a DTLSCiphertext record, s4.1:
 *
 *	to|from CLIENTPORT B0 CID
 *
 * CID is the IDLEN bytes after the first byte, in hexadecimal, when the C
 * bit says there is one, and "-" when not.  The header does not carry
 * the ID's length, so the caller names it.
 *
 *	cidpcap FILE SERVERPORT IDLEN
 *
 * The capture is a pcap file of IPv4 on loopback (DLT_NULL) or Ethernet.
 */

#include <arpa/inet.h>

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define	DLT_NULL_	0	/* pcap-linktype(7) */
#define	DLT_EN10MB_	1

static uint32_t
rd32(const uint8_t *p, int swap)
{

	return swap ? (uint32_t)p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3] :
	    (uint32_t)p[3] << 24 | p[2] << 16 | p[1] << 8 | p[0];
}

int
main(int argc, char **argv)
{
	uint8_t gh[24], rh[16], pkt[65536];
	const uint8_t *ip, *udp, *pl;
	uint32_t magic, link, caplen;
	unsigned sport, dport, port, idlen, i, ihl;
	size_t off, len;
	int swap;
	FILE *f;

	if (argc != 4)
		errx(1, "usage: cidpcap file serverport idlen");
	port = (unsigned)atoi(argv[2]);
	idlen = (unsigned)atoi(argv[3]);
	if ((f = fopen(argv[1], "rb")) == NULL)
		err(1, "%s", argv[1]);
	if (fread(gh, sizeof(gh), 1, f) != 1)
		errx(1, "%s: no pcap header", argv[1]);
	magic = rd32(gh, 0);
	if (magic == 0xa1b2c3d4)
		swap = 0;
	else if (magic == 0xd4c3b2a1)
		swap = 1;
	else
		errx(1, "%s: not a pcap file", argv[1]);
	link = rd32(gh + 20, swap);
	if (link == DLT_NULL_)
		off = 4;
	else if (link == DLT_EN10MB_)
		off = 14;
	else
		errx(1, "%s: link type %u", argv[1], link);

	while (fread(rh, sizeof(rh), 1, f) == 1) {
		caplen = rd32(rh + 8, swap);
		if (caplen > sizeof(pkt) || fread(pkt, caplen, 1, f) != 1)
			break;
		if (caplen < off + 20 + 8)
			continue;
		ip = pkt + off;
		if ((ip[0] >> 4) != 4 || ip[9] != 17)	/* IPv4, UDP */
			continue;
		ihl = (ip[0] & 0x0f) * 4u;
		if (caplen < off + ihl + 8)
			continue;
		udp = ip + ihl;
		sport = (unsigned)udp[0] << 8 | udp[1];
		dport = (unsigned)udp[2] << 8 | udp[3];
		if (sport != port && dport != port)
			continue;
		pl = udp + 8;
		len = caplen - off - ihl - 8;
		if (len < 1 || (pl[0] & 0xe0) != 0x20)	/* RFC 9147 s4.1 */
			continue;
		printf("%s %u %02x ", dport == port ? "to" : "from",
		    dport == port ? sport : dport, pl[0]);
		if ((pl[0] & 0x10) != 0 && len >= 1 + idlen) {
			for (i = 0; i < idlen; i++)
				printf("%02x", pl[1 + i]);
			printf("\n");
		} else
			printf("-\n");
	}
	fclose(f);
	return 0;
}
