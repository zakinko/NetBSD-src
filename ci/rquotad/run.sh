#!/bin/sh
# In the VM.  Run the tests on both libraries, whatever they do.
D=/var/tmp/dest
mount -t null /dev $D/dev 2>/dev/null || (cd $D/dev && sh MAKEDEV std)
mkdir -p $D/tmp $D/var/tmp; chmod 1777 $D/tmp
cp /var/tmp/chroot.sh $D/run.sh
timeout -k 10 3000 chroot $D sh /run.sh 2>&1
