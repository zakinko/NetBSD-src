/*	$NetBSD$	*/

/* Print the file handle of a file in hex.  gfh FILE */

#include <sys/types.h>
#include <sys/mount.h>

#include <err.h>
#include <stdio.h>

int
main(int argc, char **argv)
{
	unsigned char fh[64];
	size_t i, len = sizeof(fh);

	if (argc != 2 || getfh(argv[1], fh, &len) == -1)
		err(1, "getfh");
	for (i = 0; i < len; i++)
		printf("%02x", fh[i]);
	putchar('\n');
	return 0;
}
