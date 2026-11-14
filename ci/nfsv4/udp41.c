/*	$NetBSD$	*/

/*
 * Give the server a UDP socket of its own and send it an empty COMPOUND
 * of each minor version, 0 and 1, over it: RFC 8881 s2.9.1 has UDP not
 * be an NFSv4.1 transport.  Prints, for each, the overall status and the
 * count of results.  Run in the VM, as UDP does not go through the ssh
 * tunnel the other tests use.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int
main(void)
{
	struct sockaddr_in sin;
	struct timeval tv = { 5, 0 };
	socklen_t len;
	uint32_t req[13], rep[64], minor;
	ssize_t n;
	int s, c;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		err(1, "socket");
	memset(&sin, 0, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(s, (void *)&sin, sizeof(sin)) == -1)
		err(1, "bind");
	len = sizeof(sin);
	if (getsockname(s, (void *)&sin, &len) == -1)
		err(1, "getsockname");
	if (sysctlbyname("vfs.nfsv4.addsock", NULL, NULL, &s,
	    sizeof(s)) == -1)
		err(1, "addsock");

	if ((c = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		err(1, "socket");
	(void)setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	for (minor = 0; minor <= 1; minor++) {
		/* RFC 5531 s9 call body, AUTH_NONE; RFC 8881 s16.2.1 */
		req[0] = htonl(0x75647000 + minor);	/* xid */
		req[1] = htonl(0);			/* CALL */
		req[2] = htonl(2);			/* rpcvers */
		req[3] = htonl(100003);			/* NFS */
		req[4] = htonl(4);
		req[5] = htonl(1);			/* COMPOUND */
		req[6] = req[7] = htonl(0);		/* cred */
		req[8] = req[9] = htonl(0);		/* verf */
		req[10] = htonl(0);			/* tag */
		req[11] = htonl(minor);
		req[12] = htonl(0);			/* no operations */
		if (sendto(c, req, sizeof(req), 0, (void *)&sin,
		    sizeof(sin)) == -1)
			err(1, "sendto");
		n = recv(c, rep, sizeof(rep), 0);
		if (n == -1) {
			printf("minor %u: no reply\n", minor);
			continue;
		}
		/*
		 * xid, REPLY, MSG_ACCEPTED, verf (flavor, empty), SUCCESS,
		 * then status, tag (empty, as sent), count of results.
		 */
		if (n < 9 * 4 || ntohl(rep[0]) != 0x75647000 + minor ||
		    ntohl(rep[2]) != 0 || ntohl(rep[4]) != 0 ||
		    ntohl(rep[5]) != 0) {
			printf("minor %u: not a successful reply:", minor);
			for (len = 0; len < (socklen_t)(n / 4) && len < 10;
			    len++)
				printf(" %08x", ntohl(rep[len]));
			printf("\n");
			continue;
		}
		printf("minor %u: status %u, results %u\n", minor,
		    ntohl(rep[6]), ntohl(rep[8]));
	}
	return 0;
}
