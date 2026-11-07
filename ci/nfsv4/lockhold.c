/* Hold flock(2) on a file for some seconds, as a local process would. */
#include <sys/file.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	int fd;

	if (argc != 3 || (fd = open(argv[1], O_RDONLY)) == -1 ||
	    flock(fd, LOCK_EX) == -1) {
		perror("lockhold");
		return 1;
	}
	sleep(atoi(argv[2]));
	return 0;
}
