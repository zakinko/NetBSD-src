/*	$NetBSD$	*/

/*
 * A write lock on one byte; the exit status says.
 * try [-w] [-h SECONDS] FILE OFFSET: -w waits for it, -h keeps it.
 */

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	struct flock fl;
	int ch, fd, hold = 0, cmd = F_SETLK;

	while ((ch = getopt(argc, argv, "h:w")) != -1) {
		if (ch == 'h')
			hold = atoi(optarg);
		else if (ch == 'w')
			cmd = F_SETLKW;
		else
			errx(2, "usage");
	}
	argc -= optind;
	argv += optind;
	if (argc != 2)
		errx(2, "usage");
	if ((fd = open(argv[0], O_RDWR)) == -1)
		err(2, "%s", argv[0]);
	memset(&fl, 0, sizeof(fl));
	fl.l_whence = SEEK_SET;
	fl.l_start = strtoll(argv[1], NULL, 0);
	fl.l_len = 1;
	fl.l_type = F_WRLCK;
	if (fcntl(fd, cmd, &fl) == -1)
		return 1;
	sleep(hold);
	return 0;
}
