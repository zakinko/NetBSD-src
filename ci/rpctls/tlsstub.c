/*
 * A stand-in for the TLS handshake daemon, to measure the hand-off of
 * RFC 9289 alone: take each connection the kernel answered with
 * STARTTLS, report the first bytes the client sent after it, and give
 * the kernel a failed verdict.  tlsstub [count]
 */
#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/mount.h>
#include <sys/socket.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>

#include <err.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	struct nfsd_tlsarg nt;
	struct pollfd pfd;
	unsigned char b[5];
	ssize_t n;
	int i, count;

	count = argc > 1 ? atoi(argv[1]) : -1;
	setvbuf(stdout, NULL, _IOLBF, 0);
	for (i = 0; count < 0 || i < count; i++) {
		memset(&nt, 0, sizeof(nt));
		if (nfssvc(NFSSVC_TLSWAIT, &nt) == -1)
			err(1, "NFSSVC_TLSWAIT");
		if (nt.nt_fd == -1)	/* an alert, not a connection */
			continue;
		pfd.fd = nt.nt_fd;
		pfd.events = POLLIN;
		n = poll(&pfd, 1, 10000) == 1 ? recv(nt.nt_fd, b, sizeof(b),
		    MSG_WAITALL) : -1;
		/* RFC 8446 s5.1: handshake(22), legacy_record_version 0x0301 */
		printf("conn %llu: %zd bytes:", (unsigned long long)nt.nt_cookie,
		    n);
		for (ssize_t k = 0; k < n; k++)
			printf(" %02x", b[k]);
		printf("%s\n", n == 5 && b[0] == 22 && b[1] == 3 ?
		    " clienthello" : "");
		nt.nt_error = ECONNABORTED;
		if (nfssvc(NFSSVC_TLSDONE, &nt) == -1)
			warn("NFSSVC_TLSDONE");
		close(nt.nt_fd);
	}
	return 0;
}
