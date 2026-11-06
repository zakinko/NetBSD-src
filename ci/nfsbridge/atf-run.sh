#!/bin/sh
# Run the NFS tests in a chroot of this tree's userland, so that they
# load its rump: on the bridge, then on the stock library as the control.
# The exit status is that of the bridge.
D=/var/tmp/dest
mount -t null /dev $D/dev 2>/dev/null || (cd $D/dev && sh MAKEDEV std)
mkdir -p $D/tmp $D/var/tmp; chmod 1777 $D/tmp
cp /var/tmp/atf-chroot.sh $D/run.sh
# One bound on all of it: a hang must end with what it printed so far.
timeout -k 10 2400 chroot $D sh /run.sh 2>&1 | tee /var/tmp/atf.out
cat $D/var/tmp/raw.bridge >/var/tmp/raw.bridge
grep -q '^bridge failures: 0$' /var/tmp/atf.out
