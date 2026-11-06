/*	$NetBSD$	*/

/*
 * How many pointers has the first indirect block of inode INO, as it is
 * on the disk of an FFS2 file system, with whatever is in memory left out.
 *	fib RAWDEV INO
 */

#include <sys/types.h>
#include <sys/param.h>

#include <ufs/ufs/dinode.h>
#include <ufs/ffs/fs.h>

#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	static char sbuf[SBLOCKSIZE];
	struct fs *fs = (struct fs *)sbuf;
	struct ufs2_dinode di;
	int64_t *ib;
	off_t off;
	ino_t ino;
	int fd, n = 0;
	unsigned i, cnt;

	if (argc != 3)
		errx(1, "usage");
	ino = strtoull(argv[2], NULL, 0);
	if ((fd = open(argv[1], O_RDONLY)) == -1)
		err(1, "%s", argv[1]);
	if (pread(fd, sbuf, SBLOCKSIZE, SBLOCK_UFS2) != SBLOCKSIZE)
		err(1, "sb");
	if (fs->fs_magic != FS_UFS2_MAGIC)
		errx(1, "magic %x", fs->fs_magic);
	off = (off_t)FFS_FSBTODB(fs, ino_to_fsba(fs, ino)) * DEV_BSIZE +
	    ino_to_fsbo(fs, ino) * sizeof(di);
	if (pread(fd, &di, sizeof(di), off) != sizeof(di))
		err(1, "inode");
	printf("ib %lld ", (long long)di.di_ib[0]);
	if (di.di_ib[0] != 0) {
		cnt = fs->fs_bsize / sizeof(*ib);
		if ((ib = malloc(fs->fs_bsize)) == NULL)
			err(1, "malloc");
		if (pread(fd, ib, fs->fs_bsize,
		    (off_t)FFS_FSBTODB(fs, di.di_ib[0]) * DEV_BSIZE) !=
		    fs->fs_bsize)
			err(1, "ib");
		for (i = 0; i < cnt; i++)
			n += ib[i] != 0;
	}
	printf("%d\n", n);
	return 0;
}
