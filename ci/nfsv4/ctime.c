/*	$NetBSD$	*/

/*
 * Change a file over and over and see ctime move every time, as the
 * change attribute needs (RFC 7530 s5.8.1.4).  ctime FILE
 */

#include <sys/stat.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#define	ROUNDS	2000

int
main(int argc, char **argv)
{
	struct stat prev, st;
	int fd, i, same = 0;

	if (argc != 2)
		errx(2, "usage: ctime file");
	if ((fd = open(argv[1], O_RDWR | O_CREAT, 0644)) == -1)
		err(2, "open");
	if (fstat(fd, &prev) == -1)
		err(2, "fstat");
	for (i = 0; i < ROUNDS; i++) {
		if (i % 2 == 0) {
			if (fchmod(fd, i % 4 ? 0644 : 0600) == -1)
				err(2, "fchmod");
		} else if (write(fd, "x", 1) != 1)
			err(2, "write");
		if (fstat(fd, &st) == -1)
			err(2, "fstat");
		if (st.st_ctimespec.tv_sec < prev.st_ctimespec.tv_sec ||
		    (st.st_ctimespec.tv_sec == prev.st_ctimespec.tv_sec &&
		    st.st_ctimespec.tv_nsec <= prev.st_ctimespec.tv_nsec))
			same++;
		prev = st;
	}
	printf("%s: %d of %d changes did not move ctime\n", argv[1], same,
	    ROUNDS);
	return same != 0;
}
