#!/bin/sh
# In pynfs's nfs4.0 directory: the Linux client writes under a write
# delegation and holds the data back, and another client asks.  VERS
# is the client's minor version, 4.0 by default.  CB_GETATTR answering
# means no DELEGRETURN while the other asks; a recall is the fallback.
v=${VERS:-4.0}
# As linux-client.sh does: a push runs this alone, and a 4.0 client
# then listened for callbacks on a port of its own choosing, which the
# tunnel does not carry, so the path was down and the server offered
# no delegation (run 43070434418, cb_trace "cbstate 2 ... refused 3").
sudo modprobe nfs 2>/dev/null || {
	sudo apt-get install -y -q "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
	sudo modprobe nfs
}
sudo modprobe nfsv4
echo 40100 | sudo tee /sys/module/nfs/parameters/callback_tcpport >/dev/null
m=/mnt/nfsv4cg
sudo mkdir -p "$m"
sudo mount -t nfs -o vers=$v,proto=tcp,port=2049,addr=127.0.0.1,clientaddr=127.0.0.1,sec=sys,hard 127.0.0.1:/export/pynfs "$m" || exit 1
sudo sh -c ": >$m/cg; chmod 666 $m/cg"
# What the server saw and asked, with the times (vfs.nfsv4.cb_trace).
ssh netbsd 'sysctl -w vfs.nfsv4.cb_trace=1 >/dev/null'
echo "client start $(date +%s)"
python3 -c "
import os,time
# An open owner gets a delegation from its second OPEN.
os.close(os.open('$m/cg',os.O_RDWR))
f=os.open('$m/cg',os.O_RDWR)
time.sleep(1)
os.write(f,b'x'*5000)
print('client wrote', int(time.time()), flush=True)
time.sleep(25)" &
sleep 8
dr() { awk '$1 == "DELEGRETURN:" { n += $2 } END { print n + 0 }' /proc/self/mountstats; }
b=$(dr)
echo "GETATTR sent $(date +%s)"
out=$(python3 ./more.py cbgetattr /export/pynfs/cg 5000)
echo "$out"
a=$(dr)
# RFC 7530 s10.4.3: the time the server constructed and reported is to
# be written to the file (df1e26e44bb).  The holder still holds its data
# back (it sleeps 25 s), so the file's mtime on the server is what the
# server wrote, and should equal the reported time_modify.
rep=$(echo "$out" | awk '$1 == "time_modify" { printf "%d.%09d", $2, $3 }')
srv=$(ssh -o LogLevel=ERROR netbsd 'stat -f %Fm /export/pynfs/cg')
echo "reported time_modify $rep, server mtime $srv"
if [ -n "$rep" ] && [ "$rep" = "$srv" ]; then
	echo "ok     CB_GETATTR $v time stored in the file"
else
	echo "FAILED CB_GETATTR $v time stored in the file: $rep vs $srv"
fi
ssh netbsd 'sysctl -w vfs.nfsv4.cb_trace=0 >/dev/null; dmesg | grep cbtrace | tail -12' 
grep -E 'DELEGRETURN|OPEN:' /proc/self/mountstats | tail -6
if [ "$a" = "$b" ]; then echo "ok     CB_GETATTR $v, no recall"
else echo "FAILED CB_GETATTR $v: DELEGRETURN $b -> $a"; fi
wait
grep -E 'DELEGRETURN|OPEN:' /proc/self/mountstats | tail -6
sudo umount "$m"
ssh netbsd 'dmesg | tail -3'
