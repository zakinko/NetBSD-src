#!/bin/sh
# On the runner: Linux as the Kerberos client of the VM.  The server and
# the KDC are reached through a tunnel on an address of their own, so
# that a name of the server resolves there.  client.sh OUT
OUT=$1
LOG=$OUT/gss-client.txt
S=nfsgss-server.test
CC=/var/tmp/krb5cc
sudo apt-get install -y -q nfs-common krb5-user tcpdump python3-gssapi >/dev/null 2>&1
sudo modprobe nfs || {
	sudo apt-get install -y -q "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
	sudo modprobe nfs
}
sudo modprobe nfsv4
sudo modprobe rpcsec_gss_krb5
sudo ip link add gss0 type dummy
sudo ip addr add 10.99.0.1/32 dev gss0
sudo ip link set gss0 up
ssh -f -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=10 \
    -L 10.99.0.1:2049:127.0.0.1:2049 -L 10.99.0.1:8888:127.0.0.1:8888 \
    -L 10.99.0.1:4002:127.0.0.1:4002 netbsd
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
	default_ccache_name = FILE:${CC}_%{uid}
	permitted_enctypes = aes256-cts-hmac-sha1-96
[realms]
	NFSGSS.TEST = {
		kdc = tcp/10.99.0.1:8888
	}
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
for u in alice bob; do
	sudo useradd -m -u $(( $(printf %d "'$u") + 2000 )) "$u"
done
sudo systemctl restart nfs-idmapd 2>/dev/null || sudo rpc.idmapd
sudo sh -c 'echo N >/sys/module/nfs/parameters/nfs4_disable_idmapping' || :
gssd_start() {
	sudo pkill -x rpc.gssd
	sudo rpc.gssd -v -v -f -d /var/tmp >>"$OUT/rpc.gssd.log" 2>&1 &
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
	t a mkdir -p "$d"
	t a sh -c "echo PLAINTEXT-MARKER-$sec-$v >$d/m"
	t a dd if=/dev/urandom of=/var/tmp/gss.bin bs=1M count=4 status=none
	t a cp /var/tmp/gss.bin "$d/b"
	t sudo sh -c 'sync; echo 3 >/proc/sys/vm/drop_caches'
	t a cmp /var/tmp/gss.bin "$d/b"
	t a sh -c "test \"\$(cat $d/m)\" = PLAINTEXT-MARKER-$sec-$v"
	t a sh -c "test \"\$(stat -c %U $d/m)\" = alice"
	t sh -c "ssh netbsd 'ls -ln $e/alice-$sec-$v/m' | grep -q ' 2097 '"
	t a mv "$d/b" "$d/c"
	t a ln -s c "$d/s"
	t a chmod 600 "$d/c"
	t a sh -c "ls -la $d | grep -q ' c\$'"
	# Bob has a ticket and no right to it.
	n sudo -u bob cat "$d/c"
	echo "--- mountstats $sec v$v"; grep -E 'sec=' /proc/self/mountstats | grep "$m" | tail -1
	t a rm -rf "$d"
	t sudo umount "$m"
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
enctype() {	# name number
	sudo sed -i "s/permitted_enctypes = .*/permitted_enctypes = $1/" /etc/krb5.conf
	sudo rm -f ${CC}_*
	gssd_start
	ticket alice; ticket bob
	echo "=== enctype $1"
	for s in krb5 krb5i krb5p; do
		oneflavor /export/krb5all "$s" 4.0 ""
	done
	echo "--- gssd saw"; ssh netbsd "tail -6 /var/tmp/nfsv4/gssd.log"
	ssh netbsd "tail -6 /var/tmp/nfsv4/gssd.log" | grep -q "enctype $2," ||
	    { echo "FAILED: enctype $2 not used"; fails=$((fails + 1)); }
}
{
	uname -r
	enctype aes256-cts-hmac-sha1-96 18
	enctype aes128-cts-hmac-sha1-96 17
	enctype aes128-cts-hmac-sha256-128 19
	enctype aes256-cts-hmac-sha384-192 20
	sudo sed -i 's/permitted_enctypes = .*/permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96/' /etc/krb5.conf
	sudo rm -f ${CC}_*; gssd_start; ticket alice; ticket bob
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
	sudo -u alice env KRB5CCNAME=FILE:${CC}_$(id -u alice) \
	    python3 "$(dirname "$0")/probe.py" "$S" /export/krb5all /export/krb5ponly /export/sysonly ||
	    fails=$((fails + 1))
	echo "failures: $fails"
	ssh netbsd "tail -20 /var/tmp/nfsv4/gssd.log"
	sudo dmesg | grep -iE 'rpc|nfs|gss' | tail -20
} >"$LOG" 2>&1
sudo pkill -x rpc.gssd
cat "$LOG"
test "$fails" = 0
