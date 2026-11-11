#!/bin/sh
# On the runner: Linux as the Kerberos client of the VM.  The server and
# the KDC are reached through a tunnel on an address of their own, so
# that a name of the server resolves there.  client.sh OUT
OUT=$1
LOG=$OUT/gss-client.txt
S=nfsgss-server.test
CC=/var/tmp/krb5cc
sudo apt-get install -y -q nfs-common nfs-kernel-server krb5-user tcpdump python3-gssapi >/dev/null 2>&1
# Installed for rpc.svcgssd alone; it must not take the port.
sudo systemctl stop nfs-server nfs-kernel-server rpcbind 2>/dev/null
sudo rpc.nfsd 0 2>/dev/null
sudo modprobe nfs || {
	sudo apt-get install -y -q "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
	sudo modprobe nfs
}
sudo modprobe nfsv4
# The server calls back through the tunnel, to a port it can be told.
echo 40100 | sudo tee /sys/module/nfs/parameters/callback_tcpport >/dev/null
sudo modprobe rpcsec_gss_krb5
sudo ip link add gss0 type dummy
sudo ip addr add 10.99.0.1/32 dev gss0
sudo ip link set gss0 up
ssh -f -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=10 \
    -L 10.99.0.1:2049:127.0.0.1:2049 -L 10.99.0.1:8888:127.0.0.1:8888 \
    -L 10.99.0.1:4002:127.0.0.1:4002 -R 40100:127.0.0.1:40100 netbsd
sudo sh -c 'cat >>/etc/hosts' <<EOF
10.99.0.1 $S
127.0.0.1 nfsgss-client.test
EOF
sudo hostname nfsgss-client.test
sudo sh -c 'cat >/etc/krb5.conf' <<EOF
[libdefaults]
	default_realm = NFSGSS.TEST
	dns_lookup_kdc = false
	dns_canonicalize_hostname = false
	rdns = false
	udp_preference_limit = 1
	default_ccache_name = FILE:${CC}_%{uid}
[realms]
	NFSGSS.TEST = {
		kdc = 10.99.0.1:8888
	}
[domain_realm]
	.test = NFSGSS.TEST
	nfsgss-server.test = NFSGSS.TEST
EOF
scp netbsd:/var/tmp/nfsv4/client.keytab "$OUT/client.keytab"
sudo install -m 600 "$OUT/client.keytab" /etc/krb5.keytab
rm -f "$OUT/client.keytab"
sudo sh -c 'cat >/etc/idmapd.conf' <<EOF
[General]
Domain = nfsgss.test
[Mapping]
Nobody-User = nobody
Nobody-Group = nogroup
EOF
sudo useradd -m -u 2097 alice
sudo useradd -m -u 2098 bob
sudo systemctl restart nfs-idmapd 2>/dev/null || sudo rpc.idmapd
sudo sh -c 'echo N >/sys/module/nfs/parameters/nfs4_disable_idmapping' || :
cc -shared -fPIC -o /var/tmp/noenctypes.so "$(dirname "$0")/noenctypes.c"
gssd_start() {
	sudo pkill -x rpc.gssd
	sudo env LD_PRELOAD=/var/tmp/noenctypes.so rpc.gssd -v -v -f -d /var/tmp >>"$OUT/rpc.gssd.log" 2>&1 &
	sleep 2
}
gssd_start

fails=0
t() {
	echo "\$ $*"
	if timeout 120 "$@"; then echo ok; else echo "FAILED ($?)"; fails=$((fails + 1)); fi
}
n() {	# must fail
	echo "\$ ! $*"
	if timeout 60 "$@"; then echo 'FAILED: it worked'; fails=$((fails + 1)); else echo "ok, refused ($?)"; fi
}
a() { sudo -u alice "$@"; }
ticket() {
	sudo -u "$1" sh -c "kdestroy 2>/dev/null; echo $1-pw | kinit $1 >/dev/null"
}
oneflavor() {	# export sec vers options
	e=$1; sec=$2; v=$3
	m=/mnt/gss-$sec-$v
	sudo mkdir -p "$m"
	t sudo mount -v -t nfs -o "vers=$v,proto=tcp,port=2049,sec=$sec,hard,timeo=100,retrans=2$4" "$S:$e" "$m"
	grep " $m " /proc/mounts || return
	d=$m/alice-$sec-$v
	t sudo -u alice mkdir -p "$d"
	t sudo -u alice sh -c "echo PLAINTEXT-MARKER-$sec-$v >$d/m"
	t sudo -u alice dd if=/dev/urandom of=/var/tmp/gss.bin bs=1M count=4 status=none
	t sudo -u alice cp /var/tmp/gss.bin "$d/b"
	t sudo sh -c 'sync; echo 3 >/proc/sys/vm/drop_caches'
	t sudo -u alice cmp /var/tmp/gss.bin "$d/b"
	t sudo -u alice sh -c "test \"\$(cat $d/m)\" = PLAINTEXT-MARKER-$sec-$v"
	t sudo -u alice sh -c "test \"\$(stat -c %U $d/m)\" = alice"
	t sh -c "ssh netbsd 'ls -ln $e/alice-$sec-$v/m' | grep -q ' 2097 '"
	t sudo -u alice mv "$d/b" "$d/c"
	t sudo -u alice ln -s c "$d/s"
	t sudo -u alice chmod 600 "$d/c"
	t sudo -u alice sh -c "ls -la $d | grep -q ' c\$'"
	# Bob has a ticket and no right to it.
	n sudo -u bob cat "$d/c"
	echo "--- mountstats $sec v$v"; grep -E 'sec=' /proc/self/mountstats | grep "$m" | tail -1
	t sudo -u alice rm -rf "$d"
	t sudo umount "$m"
}
# RFC 7530 s3.3.3.  The server starts a context with the principal that
# made the client, and recalls a delegation for a writer on the server.
callback() {	# sec
	sec=$1
	m=/mnt/gsscb
	sudo mkdir -p "$m"
	o=$(ssh netbsd 'sysctl -n vfs.nfsv4.delegations')
	ssh netbsd 'sysctl -w vfs.nfsv4.delegations=1'
	sudo mount -t nfs -o "vers=4.0,proto=tcp,port=2049,sec=$sec,clientaddr=127.0.0.1" "$S:/export/krb5all" "$m"
	sleep 4
	sudo -u alice sh -c "echo one >$m/cb-$sec"
	sudo sh -c 'echo 3 >/proc/sys/vm/drop_caches'
	sudo tcpdump -i lo -s0 -w "$OUT/cb-$sec.pcap" tcp port 40100 >/dev/null 2>&1 &
	sudo -u alice sh -c "exec 3<$m/cb-$sec; cat <&3 >/dev/null; sleep 12" &
	sleep 4
	ssh netbsd "echo two >>/export/krb5all/cb-$sec"
	wait $!
	sleep 2
	sudo pkill -x tcpdump
	sleep 1
	# RFC 2203 s5.4: the credential of a DESTROY, gss_proc 3.
	d=$(sudo python3 -c "
import re,sys
b=open(sys.argv[1],'rb').read()
print(len(re.findall(rb'\x00\x00\x00\x06.{4}\x00\x00\x00\x01\x00\x00\x00\x03',b,re.S)))" "$OUT/cb-$sec.pcap")
	echo "callback $sec: DESTROY sent $d"
	case ${d:-0} in 0) echo 'FAILED: no DESTROY'; fails=$((fails + 1));; esac
	sudo rm -f "$OUT/cb-$sec.pcap"
	r=$(awk '/DELEGRETURN:/ {print $2}' /proc/self/mountstats | sort -n | tail -1)
	echo "callback $sec: DELEGRETURN $r"
	case ${r:-0} in 0) echo 'FAILED: no recall'; fails=$((fails + 1));; esac
	t sh -c "ssh netbsd 'tail -40 /var/tmp/nfsv4/gssd.log' | grep -q 'callback context to'"
	sudo rm -f "$m/cb-$sec"
	sudo umount "$m"
	ssh netbsd "sysctl -w vfs.nfsv4.delegations=$o"
}
wire() {	# sec: is the text on the wire?
	sec=$1
	m=/mnt/gsswire
	sudo mkdir -p "$m"
	sudo mount -t nfs -o "vers=4.0,proto=tcp,port=2049,sec=$sec" "$S:/export/krb5all" "$m"
	sudo tcpdump -i any -s0 -w "$OUT/wire-$sec.pcap" tcp port 2049 >/dev/null 2>&1 &
	sleep 2
	a sh -c "echo WIRE-MARKER-XYZZY-$sec >$m/wire-$sec; sync"
	sudo sh -c 'echo 3 >/proc/sys/vm/drop_caches'
	a cat "$m/wire-$sec" >/dev/null
	sleep 2
	sudo pkill -x tcpdump
	sleep 1
	c=$(sudo grep -a -c "WIRE-MARKER-XYZZY-$sec" "$OUT/wire-$sec.pcap")
	echo "wire $sec: $c lines carry the text"
	case $sec,$c in
	krb5p,0) ;;
	krb5p,*) echo FAILED; fails=$((fails + 1));;
	*,0) echo FAILED: no text at all; fails=$((fails + 1));;
	esac
	sudo rm -f "$m/wire-$sec"
	sudo umount "$m"
	sudo rm -f "$OUT/wire-$sec.pcap"
}
# The Linux client asks for the enctypes of its kernel and takes what
# the KDC gives, so these all come out as the strongest.
linux() {
	sudo rm -f /tmp/krb5cc* /var/tmp/krb5ccmachine* ${CC}_*
	gssd_start
	ticket alice; ticket bob
	for s in krb5 krb5i krb5p; do
		oneflavor /export/krb5all "$s" 4.0 ""
	done
	echo "--- gssd saw"; ssh netbsd "tail -12 /var/tmp/nfsv4/gssd.log"
}
# Each enctype by name, with libgssapi as the client and the probe.
oneenctype() {	# name number
	c=/var/tmp/krb5-$2.conf
	sed "s/^\[libdefaults\]/[libdefaults]\n\tpermitted_enctypes = $1\n\tdefault_tgs_enctypes = $1\n\tdefault_tkt_enctypes = $1/" /etc/krb5.conf >"$c"
	chmod 644 "$c"
	echo "=== enctype $1"
	sudo -u alice env KRB5_CONFIG="$c" KRB5CCNAME=FILE:${CC}-$2 sh -c 'echo alice-pw | kinit alice >/dev/null'
	sudo -u alice env KRB5_CONFIG="$c" KRB5CCNAME=FILE:${CC}-$2 \
	    python3 "$(dirname "$0")/probe.py" "$S" /export/krb5all /export/krb5ponly /export/sysonly ||
	    fails=$((fails + 1))
	ssh netbsd "tail -5 /var/tmp/nfsv4/gssd.log" | grep "alice.*enctype" | tail -1
	ssh netbsd "tail -5 /var/tmp/nfsv4/gssd.log" | grep -q "alice.*enctype $2," ||
	    { echo "FAILED: enctype $2 not used"; fails=$((fails + 1)); }
}
{
	uname -r
	ss -ltn | grep -E '8888|2049'
	ssh netbsd 'netstat -an -f inet | grep -E "8888|2049"; tail -5 /var/tmp/nfsv4/kdc.log'
	KRB5_TRACE=/dev/stdout sh -c 'echo alice-pw | kinit alice' | tail -8
	for pair in 'aes256-cts-hmac-sha384-192 20' 'aes128-cts-hmac-sha256-128 19' \
	    'aes256-cts-hmac-sha1-96 18' 'aes128-cts-hmac-sha1-96 17'; do
		set -- $pair
		echo "=== Linux, enctype $1"
		sudo sed -i -E "/^\t(permitted|default_tgs|default_tkt)_enctypes/d; s/^\[libdefaults\]/[libdefaults]\n\tpermitted_enctypes = $1\n\tdefault_tgs_enctypes = $1\n\tdefault_tkt_enctypes = $1/" /etc/krb5.conf
		linux
		ssh netbsd "tail -12 /var/tmp/nfsv4/gssd.log" | grep -q "alice.*enctype $2," ||
		    { echo "FAILED: enctype $2 not used"; fails=$((fails + 1)); }
	done
	sudo sed -i -E "/^\t(permitted|default_tgs|default_tkt)_enctypes/d" /etc/krb5.conf
	sudo rm -f /tmp/krb5cc* /var/tmp/krb5ccmachine* ${CC}_*; gssd_start; ticket alice; ticket bob
	echo '=== version 3'
	for s in krb5 krb5i krb5p; do
		oneflavor /export/krb5all "$s" 3 ",mountport=4002,mountproto=tcp,nolock"
	done
	sudo mkdir -p /mnt/gsssec3
	n sudo mount -t nfs -o vers=3,proto=tcp,port=2049,mountport=4002,mountproto=tcp,nolock,sec=krb5 "$S:/export/krb5ponly" /mnt/gsssec3
	n sudo mount -t nfs -o vers=3,proto=tcp,port=2049,mountport=4002,mountproto=tcp,nolock,sec=sys "$S:/export/krb5all" /mnt/gsssec3
	wire krb5; wire krb5i; wire krb5p
	echo '=== the flavors of an export'
	sudo mkdir -p /mnt/gsssec
	n sudo mount -t nfs -o vers=4.0,proto=tcp,port=2049,sec=krb5 "$S:/export/krb5ponly" /mnt/gsssec
	n sudo mount -t nfs -o vers=4.0,proto=tcp,port=2049,sec=sys "$S:/export/krb5all" /mnt/gsssec
	t sudo mount -t nfs -o vers=4.0,proto=tcp,port=2049,sec=krb5p "$S:/export/krb5ponly" /mnt/gsssec
	t sudo umount /mnt/gsssec
	n sudo mount -t nfs -o vers=4.0,proto=tcp,port=2049,sec=krb5 "$S:/export/sysonly" /mnt/gsssec
	t sudo mount -t nfs -o vers=4.0,proto=tcp,port=2049,sec=sys "$S:/export/sysonly" /mnt/gsssec
	t sudo umount /mnt/gsssec
	echo '=== the RPC layer, by hand'
	oneenctype aes256-cts-hmac-sha384-192 20
	oneenctype aes128-cts-hmac-sha256-128 19
	oneenctype aes256-cts-hmac-sha1-96 18
	oneenctype aes128-cts-hmac-sha1-96 17
	echo '=== callbacks'
	sudo rpc.svcgssd -f -v >"$OUT/svcgssd.log" 2>&1 &
	sleep 2
	for s in krb5 krb5i krb5p; do callback $s; done
	sudo pkill -x rpc.svcgssd
	echo '=== refused principals'
	c=/var/tmp/krb5cc-ghost
	sudo -u alice sh -c "echo ghost-pw | KRB5CCNAME=FILE:$c kinit ghost >/dev/null"
	sudo -u alice env KRB5CCNAME=FILE:$c PROBE=refused python3 "$(dirname "$0")/probe.py" "$S" /export/krb5all /export/krb5ponly /export/sysonly ||
	    fails=$((fails + 1))
	echo '=== expiry of a context'
	c=/var/tmp/krb5cc-short
	sudo -u alice sh -c "echo alice-pw | KRB5CCNAME=FILE:$c kinit -l 2m alice >/dev/null"
	sudo -u alice env KRB5CCNAME=FILE:$c PROBE=expiry python3 "$(dirname "$0")/probe.py" "$S" /export/krb5all /export/krb5ponly /export/sysonly ||
	    fails=$((fails + 1))
	echo '=== RFC 1964'
	ssh netbsd 'sh /var/tmp/nfsv4/vm-des.sh'
	echo "failures: $fails"
	ssh netbsd "tail -20 /var/tmp/nfsv4/gssd.log"
	sudo dmesg | grep -iE 'rpc|nfs|gss' | grep -iE 'fail|err|bad|gss_' | sort -k3 | uniq -c -f2 | tail -30
} >"$LOG" 2>&1
sudo pkill -x rpc.gssd
cat "$LOG"
test "$fails" = 0
