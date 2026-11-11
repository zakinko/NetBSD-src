#!/bin/sh
# On the runner: the Linux client of version 3 sets and reads ACLs over
# NFSACL, and each one is compared with what the server's own getfacl
# says.  AUTH_SYS first, then Kerberos, set up as ci/nfsgss/client.sh
# does.  The traffic is captured for tshark.  linux.sh OUT
OUT=$1
H=$(cd "$(dirname "$0")" && pwd)
LOG=$OUT/nfsacl-linux.txt
S=nfsgss-server.test
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q nfs-common \
    nfs-kernel-server krb5-user acl tshark >/dev/null 2>&1
sudo systemctl stop nfs-server nfs-kernel-server rpcbind 2>/dev/null
sudo rpc.nfsd 0 2>/dev/null
sudo modprobe nfs || {
	sudo apt-get install -y -q "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
	sudo modprobe nfs
}
sudo modprobe nfsv3
sudo modprobe rpcsec_gss_krb5
sudo ip link add gss0 type dummy
sudo ip addr add 10.99.0.1/32 dev gss0
sudo ip link set gss0 up
ssh -f -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=10 \
    -L 10.99.0.1:2049:127.0.0.1:2049 -L 10.99.0.1:8888:127.0.0.1:8888 \
    -L 10.99.0.1:4002:127.0.0.1:4002 netbsd
sudo sh -c "echo '10.99.0.1 $S' >>/etc/hosts; echo '127.0.0.1 nfsgss-client.test' >>/etc/hosts"
sudo hostname nfsgss-client.test
sudo cp "$H/krb5.conf" /etc/krb5.conf
scp netbsd:/var/tmp/nfsv4/client.keytab "$OUT/client.keytab"
sudo install -m 600 "$OUT/client.keytab" /etc/krb5.keytab
rm -f "$OUT/client.keytab"
sudo useradd -m -u 2097 alice
sudo useradd -m -u 2098 bob
sudo groupadd -g 3001 acla
sudo groupadd -g 3002 aclb
cc -shared -fPIC -o /var/tmp/noenctypes.so "$H/../nfsgss/noenctypes.c"
sudo pkill -x rpc.gssd
sudo env LD_PRELOAD=/var/tmp/noenctypes.so rpc.gssd -v -f -d /var/tmp \
    >>"$OUT/nfsacl-gssd.log" 2>&1 &
sleep 2
# Where alice and bob can read the helpers.
sudo mkdir -p /var/tmp/nfsacl
sudo cp "$H"/*.sh "$H"/*.py /var/tmp/nfsacl/
sudo chmod -R a+rX /var/tmp/nfsacl
H=/var/tmp/nfsacl
sudo tcpdump -i any -s 0 -w "$OUT/nfsacl.pcap" 'tcp port 2049' >/dev/null 2>&1 &
sleep 1

fails=0
t() {
	echo "\$ $*"
	if timeout 120 "$@"; then echo ok; else
		echo "FAILED ($?)"; fails=$((fails + 1)); return 1; fi
}
n() {	# must fail, and say why on stderr
	echo "\$ ! $*"
	if timeout 60 "$@"; then echo 'FAILED: it worked'; fails=$((fails + 1)); else echo "ok, refused ($?)"; fi
}
cacl() { ${AS:-} sh "$H/cacl.sh" "$@"; }
same() { sh "$H/same.sh" "$@"; }
fresh() { sudo sh -c 'echo 3 >/proc/sys/vm/drop_caches'; }

# On a file system with POSIX.1e ACLs.  as is "" or "sudo -u alice".
posix() {	# mount-point server-dir as
	m=$1; e=$2; as=$3
	AS=$as; export AS
	f=$m/f; d=$m/d
	t $as touch "$f"
	t $as chmod 640 "$f"
	echo '# a file with no ACL has the ACL of its mode'
	t sh "$H/same.sh" "$f" "$e/f"
	t test "$(cacl "$f" | tr '\n' ' ')" = "group::r-- other::--- user::rw- "
	echo '# named user and group, and the mask'
	t $as setfacl -m u:2097:rw,u:2098:r,g:3001:r,g:3002:rx,m::rwx "$f"
	fresh
	t sh "$H/same.sh" "$f" "$e/f"
	t sh -c "${AS:-} sh '$H/cacl.sh' '$f' | grep -qx 'user:2098:r--'"
	t sh -c "${AS:-} sh '$H/cacl.sh' '$f' | grep -qx 'mask::rwx'"
	echo '# the mode follows the mask, and the mask the mode'
	t sh -c "ssh netbsd 'ls -ln $e/f' | grep -q '^-rw-rwx---'"
	t $as chmod 600 "$f"
	fresh
	t sh "$H/same.sh" "$f" "$e/f"
	t sh -c "${AS:-} sh '$H/cacl.sh' '$f' | grep -qx 'mask::---'"
	echo '# a mask on its own, as Solaris sends one'
	t $as setfacl -m m::r "$f"
	fresh
	t sh "$H/same.sh" "$f" "$e/f"
	echo '# taken away again'
	t $as setfacl -b "$f"
	fresh
	t sh "$H/same.sh" "$f" "$e/f"
	t test "$(cacl "$f" | wc -l)" = 3
	echo '# default ACL of a directory, and what it gives what is made in it'
	t $as mkdir "$d"
	t sh "$H/same.sh" -d "$d" "$e/d"
	t test "$(cacl -d "$d" | wc -l)" = 0
	t $as setfacl -d -m u::rwx,g::rx,o::-,u:2097:rwx,g:3001:rx,m::rwx "$d"
	t $as setfacl -m u:2098:rx "$d"
	fresh
	t sh "$H/same.sh" -d "$d" "$e/d"
	t sh "$H/same.sh" "$d" "$e/d"
	t $as sh -c "umask 022; echo x >'$d/new'; mkdir '$d/sub'"
	fresh
	t sh "$H/same.sh" "$d/new" "$e/d/new"
	t sh "$H/same.sh" "$d/sub" "$e/d/sub"
	t sh "$H/same.sh" -d "$d/sub" "$e/d/sub"
	t sh -c "${AS:-} sh '$H/cacl.sh' '$d/new' | grep -qx 'user:2097:rwx'"
	t sh -c "${AS:-} sh '$H/cacl.sh' -d '$d/sub' | grep -qx 'user:2097:rwx'"
	echo '# the default ACL taken away'
	t $as setfacl -k "$d"
	fresh
	t sh "$H/same.sh" -d "$d" "$e/d"
	t test "$(cacl -d "$d" | wc -l)" = 0
	echo '# a default ACL is not for a file'
	n $as setfacl -d -m u:2097:r "$f"
	echo '# only the owner sets an ACL'
	n sudo -u bob setfacl -m u:2098:rwx "$f"
	echo '# setfacl makes the mask a named entry needs'
	t $as touch "$m/g"
	t $as setfacl -m u:2097:r "$m/g"
	t sh "$H/same.sh" "$m/g" "$e/g"
	t $as rm -rf "$f" "$m/g" "$d"
	AS=
}

# Where there is no POSIX.1e ACL: read from the mode, refused to set,
# and nothing else on the mount fails for it.
noposix() {	# mount-point server-dir
	m=$1; e=$2
	t touch "$m/f"
	t chmod 754 "$m/f"
	fresh
	t test "$(cacl "$m/f" | tr '\n' ' ')" = "group::r-x other::r-- user::rwx "
	n setfacl -m u:2097:rw "$m/f"
	setfacl -m u:2097:rw "$m/f" 2>&1 | tee /var/tmp/why
	t grep -q 'Operation not supported' /var/tmp/why
	t mkdir "$m/d"
	t test "$(cacl -d "$m/d" | wc -l)" = 0
	t sh -c "echo y >'$m/d/new'"
	t test "$(cat "$m/d/new")" = y
	echo '# the client keeps asking: the cap stays for the mount'
	t test "$(cacl "$m/d/new" | wc -l)" = 3
	t rm -rf "$m/f" "$m/d"
}

{
	uname -a
	grep -E 'CONFIG_NFS_V3_ACL|CONFIG_NFSD_V3_ACL' "/boot/config-$(uname -r)"
	o=vers=3,proto=tcp,port=2049,mountport=4002,mountproto=tcp,nolock
	echo '=== AUTH_SYS'
	for x in pacl:posix acl:noposix tmpfs:noposix; do
		e=/export/${x%%:*}; mp=/mnt/s${x%%:*}
		sudo mkdir -p "$mp"
		t sudo mount -v -t nfs -o "$o,sec=sys" "$S:$e" "$mp" || continue
		echo "== $e"
		if [ "${x##*:}" = posix ]; then
			posix "$mp" "$e" ""
		else
			noposix "$mp" "$e"
		fi
		t sudo umount "$mp"
	done
	if ssh netbsd 'test -d /tank/x'; then
		echo '== /tank/x'
		sudo mkdir -p /mnt/zfs
		t sudo mount -v -t nfs -o "$o,sec=sys" "$S:/tank/x" /mnt/zfs &&
		    { noposix /mnt/zfs /tank/x; t sudo umount /mnt/zfs; }
	else
		echo '== /tank/x: no ZFS in the VM (the module did not build)'
	fi
	echo '# a mount with noacl sends no NFSACL at all'
	sudo mkdir -p /mnt/noacl
	t sudo mount -t nfs -o "$o,sec=sys,noacl" "$S:/export/pacl" /mnt/noacl
	t touch /mnt/noacl/z
	t sudo umount /mnt/noacl
	ssh netbsd 'rm -f /export/pacl/z'

	echo '=== Kerberos'
	sudo -u alice sh -c "kdestroy 2>/dev/null; echo alice-pw | kinit alice >/dev/null"
	sudo -u bob sh -c "kdestroy 2>/dev/null; echo bob-pw | kinit bob >/dev/null"
	for sec in krb5 krb5i krb5p; do
		mp=/mnt/k$sec
		sudo mkdir -p "$mp"
		t sudo mount -v -t nfs -o "$o,sec=$sec" "$S:/export/pacl5" "$mp" || continue
		echo "== /export/pacl5 sec=$sec"
		t sudo -u alice mkdir "$mp/a-$sec"
		posix "$mp/a-$sec" "/export/pacl5/a-$sec" "sudo -u alice"
		t sudo -u alice rmdir "$mp/a-$sec"
		grep -E 'sec=' /proc/self/mountstats | grep "$mp" | tail -1
		t sudo umount "$mp"
	done
	echo '# the sec=sys flavor is refused on the Kerberos export'
	sudo mkdir -p /mnt/kno
	n sudo mount -t nfs -o "$o,sec=sys" "$S:/export/pacl5" /mnt/kno

	echo '=== NFSACL by hand'
	if timeout 900 python3 "$H/probe.py" "$S" 4002; then echo ok; else
		echo "FAILED probe ($?)"; fails=$((fails + 1)); fi

	echo "failures: $fails"
} 2>&1 | tee "$LOG"
sleep 1
sudo pkill -x tcpdump
sleep 1
sudo chmod 644 "$OUT/nfsacl.pcap" 2>/dev/null
# The last line is the client's; the probe prints its own before it.
test "$(grep '^failures:' "$LOG" | tail -1)" = 'failures: 0'
