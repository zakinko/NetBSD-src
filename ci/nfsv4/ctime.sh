#!/bin/sh
# ctime.c on FFS and tmpfs with the clock at its coarsest, where a stock
# kernel repeats values.  Reports; the kernel under test must say 0.
D=/var/tmp/nfsv4
cd "$D" || exit 1
cc -g -Wall -o ctime ctime.c || exit 1
old=$(sysctl -n vfs.generic.timestamp_precision)
sysctl -w vfs.generic.timestamp_precision=0 >/dev/null
mkdir -p ct.tmpfs ct.ffs
mount_tmpfs tmpfs ct.tmpfs
mount_mfs -s 32m swap ct.ffs
./ctime ct.ffs/f
./ctime ct.tmpfs/f
umount ct.tmpfs ct.ffs
sysctl -w vfs.generic.timestamp_precision="$old" >/dev/null
exit 0
