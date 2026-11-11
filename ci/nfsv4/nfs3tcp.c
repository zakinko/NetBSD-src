/*	$NetBSD$	*/

/*
 * Accept TCP connections on a port and hand them to the NFS server of
 * nfsd(8), which must be running.  The storage device of the flexible
 * file layout (RFC 8435) is that server, and port 2049 over TCP is the
 * version 4 server's.  nfs3tcp port
 */

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>

#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	struct sockaddr_in sin;
	struct nfsd_args na;
	int ls, s, on = 1;

	if (argc != 2)
		errx(1, "usage: nfs3tcp port");
	if ((ls = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		err(1, "socket");
	(void)setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	memset(&sin, 0, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(atoi(argv[1]));
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(ls, (void *)&sin, sizeof(sin)) == -1)
		err(1, "bind");
	if (listen(ls, 16) == -1)
		err(1, "listen");
	for (;;) {
		struct sockaddr_in peer;
		socklen_t len = sizeof(peer);

		if ((s = accept(ls, (void *)&peer, &len)) == -1)
			err(1, "accept");
		(void)setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
		na.sock = s;
		na.name = &peer;
		na.namelen = len;
		if (nfssvc(NFSSVC_ADDSOCK, &na) == -1)
			warn("nfssvc");
		(void)close(s);
	}
}
