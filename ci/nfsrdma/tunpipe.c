/*	$NetBSD$	*/

/*
 * The NetBSD end of tun.py: /dev/tun0 over stdin and stdout, a two-byte
 * length before each packet.  The device puts the family in front of each
 * packet, without which it is IPv4 only.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_tun.h>
#include <netinet/in.h>

#include <err.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

int
main(void)
{
	static uint8_t ib[256 * 1024], p[65536 + 8];
	struct pollfd pf[2];
	size_t have = 0;
	ssize_t n;
	uint16_t len;
	uint32_t af;
	int t, off = 0, on = 1;

	if ((t = open("/dev/tun0", O_RDWR)) == -1)
		err(1, "/dev/tun0");
	(void)ioctl(t, TUNSLMODE, &off);
	if (ioctl(t, TUNSIFHEAD, &on) == -1)
		err(1, "TUNSIFHEAD");
	pf[0].fd = t;
	pf[0].events = POLLIN;
	pf[1].fd = 0;
	pf[1].events = POLLIN;
	for (;;) {
		if (poll(pf, 2, -1) == -1)
			err(1, "poll");
		if (pf[0].revents != 0) {
			if ((n = read(t, p + 2, 65536)) <= 4)
				err(1, "tun");
			n -= 4;
			len = htons((uint16_t)n);
			memcpy(p + 4, &len, 2);
			if (write(1, p + 4, (size_t)n + 2) != n + 2)
				err(1, "stdout");
		}
		if (pf[1].revents != 0) {
			n = read(0, ib + have, sizeof(ib) - have);
			if (n <= 0)
				return 0;
			have += (size_t)n;
			while (have >= 2) {
				memcpy(&len, ib, 2);
				len = ntohs(len);
				if (have < (size_t)len + 2)
					break;
				af = htonl((ib[2] >> 4) == 6 ? AF_INET6 :
				    AF_INET);
				memcpy(p, &af, 4);
				memcpy(p + 4, ib + 2, len);
				(void)write(t, p, (size_t)len + 4);
				have -= (size_t)len + 2;
				memmove(ib, ib + len + 2, have);
			}
		}
	}
}
