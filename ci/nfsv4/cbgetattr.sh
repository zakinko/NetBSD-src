#!/bin/sh
# In pynfs's nfs4.0 directory: the Linux client writes under a write
# delegation and holds the data back, and another client asks.
m=/mnt/nfsv4cg
sudo mkdir -p "$m"
sudo mount -t nfs -o vers=4.0,proto=tcp,port=2049,addr=127.0.0.1,clientaddr=127.0.0.1,sec=sys,hard 127.0.0.1:/export/pynfs "$m" || exit 1
sudo sh -c ": >$m/cg; chmod 666 $m/cg"
python3 -c "
import os,time
f=os.open('$m/cg',os.O_RDWR)
time.sleep(1)
os.write(f,b'x'*5000)
time.sleep(25)" &
sleep 8
python3 ./more.py cbgetattr /export/pynfs/cg 5000
grep -E 'DELEGRETURN|OPEN:' /proc/self/mountstats | tail -6
wait
grep -E 'DELEGRETURN|OPEN:' /proc/self/mountstats | tail -6
sudo umount "$m"
ssh netbsd 'dmesg | tail -3'
