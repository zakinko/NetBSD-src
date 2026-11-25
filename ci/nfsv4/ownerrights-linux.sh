#!/bin/sh
# OWNER_RIGHTS@ (draft-ietf-nfsv4-acls-update-06 8.4.3) in a group area on
# ZFS, from the Linux client of the runner.  The ACL is set from here with
# nfs4_setfacl, so the who string goes through the server both ways.  For
# each action as a member: rc, the ACL, the content, and whether the other
# member can still read and write.  ownerrights-linux.sh OUT
OUT=$1
VERS=${VERS:-4.1}
LOG=$OUT/ownerrights-linux-$VERS.txt
sudo apt-get install -y -q nfs-common nfs4-acl-tools attr rsync vim-tiny >/dev/null 2>&1
sudo modprobe nfs || {
	sudo apt-get install -y -q "linux-modules-extra-$(uname -r)" >/dev/null 2>&1
	sudo modprobe nfs
}
sudo modprobe nfsv4
echo 40100 | sudo tee /sys/module/nfs/parameters/callback_tcpport >/dev/null
echo Y | sudo tee /sys/module/nfs/parameters/nfs4_disable_idmapping >/dev/null
# The same numbers on both sides, as AUTH_SYS carries numbers.
sudo groupadd -g 3000 proj; sudo groupadd -g 3001 solo
sudo useradd -u 2001 -g 100 -G proj,solo -m m1
sudo useradd -u 2002 -g 100 -G proj -m m2
sudo useradd -u 2003 -g 100 -m out
ssh netbsd 'groupadd -g 3000 proj; groupadd -g 3001 solo
    useradd -u 2001 -g 100 -G proj,solo m1; useradd -u 2002 -g 100 -G proj m2
    useradd -u 2003 -g 100 out; id m1'
m=/mnt/or
sudo mkdir -p $m
GRP='rwaDdxtTnNcy'	# members: everything but write_acl (C) and write_owner (o)
nproj() { sudo nfs4_getfacl "$1" 2>/dev/null | grep -c ':3000:'; }
nori() { sudo nfs4_getfacl "$1" 2>/dev/null | grep -c 'OWNER_RIGHTS@'; }
as() { o=$(sudo -u "$1" sh -c "$2" 2>&1 </dev/null); r=$?
	echo "  rc=$r $1: $2" | cut -c1-120
	[ -z "$o" ] || echo "$o" | head -4 | sed 's/^/    out: /' | cut -c1-150; }
state() {
	sudo stat -c '  mode %A owner %U:%G' "$1"
	for v in m1 m2 out; do
		sudo -u $v cat "$1" >/dev/null 2>&1 && r=r || r=-
		sudo -u $v sh -c ": >> '$1'" >/dev/null 2>&1 && w=w || w=-
		printf '  %s:%s%s' $v $r $w
	done
	echo "   named-proj=$(nproj "$1") owner_rights=$(nori "$1")"
	echo "  content: $(sudo cat "$1" | tr '\n' '|' | cut -c1-40)"
}
fresh() { sudo rm -f "$1"; sudo -u m1 sh -c "umask 022; echo a > '$1'"; }
try() { d=$1; u=$2; shift 2; f=$d/f; fresh $f; as $u "$*"; state $f; }
area() { # dir label extra-aces
	d=$1; echo; echo "##### $2 ($d)"
	sudo mkdir -p $d; sudo chown 0:3000 $d; sudo chmod 770 $d
	sudo nfs4_setfacl -s "A::OWNER@:rwaDdxtTnNcCoy,A:fdg:3000:$GRP$3" $d
	echo "  nfs4_setfacl rc=$?"; sudo nfs4_getfacl $d | sed 's/^/    /'
	ssh netbsd "ls -ld /tank/x/$(basename $d)"
	printf 'xx\n' > /tmp/src; chmod 644 /tmp/src; touch -d 2026-01-01 /tmp/src
	(cd /tmp; rm -rf tt; mkdir tt; cp -p src tt/f; tar cf t.tar -C tt f)
	echo "--- f as created by m1"; fresh $d/f; sudo nfs4_getfacl $d/f | sed 's/^/    /'; state $d/f
	f=$d/f
	try $d m1 "chmod 600 $f"
	try $d m1 "chmod 666 $f"
	try $d m1 "chmod 777 $f"
	try $d m2 "chmod 666 $f"
	try $d m1 "nfs4_setfacl -a A::2003:rw $f"
	try $d m1 "chgrp solo $f"
	try $d m1 "sh -c 'echo 1 >> $f'"
	try $d m1 "cp /tmp/src $f"
	try $d m1 "cp -p /tmp/src $f"
	try $d m1 "install -m 640 /tmp/src $f"
	try $d m1 "tar -xpf /tmp/t.tar -C $d"
	try $d m1 "rsync -a /tmp/src $f"
	try $d m1 "vi -u NONE -es -c 'normal Ax' -c wq $f"
	try $d m1 "sed -i s/a/b/ $f"
	try $d m1 "sh -c 'echo new > $d/t && mv $d/t $f'"
	echo "--- inheritance"
	sudo rm -rf $d/n $d/sub
	as m1 "umask 022; echo n > $d/n; mkdir $d/sub"
	as m2 "umask 022; echo s > $d/sub/s"
	for x in $d/n $d/sub $d/sub/s; do echo "  $x"; sudo nfs4_getfacl $x | sed 's/^/    /'; state $x; done
	echo "--- a client that copies the ACL back as text (root, nfs4_getfacl | nfs4_setfacl -S)"
	fresh $f; sudo nfs4_getfacl $f > /tmp/acl.txt; sudo nfs4_setfacl -S /tmp/acl.txt $f; echo "  rc=$?"
	sudo nfs4_getfacl $f | sed 's/^/    /'; state $f
	echo "--- the raw xattr written back (root, getfattr/setfattr system.nfs4_acl)"
	fresh $f; v=$(sudo getfattr --only-values -e hex -n system.nfs4_acl $f 2>/dev/null | tail -1)
	sudo setfattr -n system.nfs4_acl -v "$v" $f; echo "  rc=$?"; state $f
	echo "--- root repairs"
	fresh $f; as m1 "chmod 600 $f"; sudo chmod 660 $f; echo "  root chmod 660 rc=$?"
	sudo nfs4_getfacl $f | sed 's/^/    /'; state $f
}
{
	uname -a
	sudo mount -v -t nfs -o vers=$VERS,proto=tcp,port=2049,addr=127.0.0.1,clientaddr=127.0.0.1,sec=sys,hard,timeo=100,retrans=2 \
	    127.0.0.1:/tank/x $m || exit 1
	ssh netbsd 'LD_LIBRARY_PATH=/lib zpool get -H feature@acl_owner_rights tank'
	area $m/or 'OWNER_RIGHTS@ read_acl only' ',A:fd:OWNER_RIGHTS@:c'
	area $m/stock 'no OWNER_RIGHTS@' ''
	ssh netbsd 'LD_LIBRARY_PATH=/lib zpool get -H feature@acl_owner_rights tank'
	sudo umount $m
} 2>&1 | tee "$LOG"
