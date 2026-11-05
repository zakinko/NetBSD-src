/*	$NetBSD$	*/

/*
 * Accept connections on the NFS port and hand them to the kernel.  For
 * development of the version 4 server, which has no daemon yet.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <netinet/in.h>

#include <err.h>
#include <string.h>
#include <unistd.h>

int
main(void)
{
	struct sockaddr_in sin;
	int ls, s, on = 1;

	if ((ls = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		err(1, "socket");
	(void)setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	memset(&sin, 0, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(2049);
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(ls, (void *)&sin, sizeof(sin)) == -1)
		err(1, "bind");
	if (listen(ls, 16) == -1)
		err(1, "listen");
	for (;;) {
		if ((s = accept(ls, NULL, NULL)) == -1)
			err(1, "accept");
		if (sysctlbyname("vfs.nfsv4.addsock", NULL, NULL, &s,
		    sizeof(s)) == -1)
			warn("addsock");
		(void)close(s);
	}
}
