#!/bin/sh
# OWNER_RIGHTS@ from the FreeBSD NFSv4 client, run as root in the FreeBSD
# VM with 127.0.0.1:2049 forwarded to the server.  The area /tank/x/or was
# made by ownerrights-linux.sh.  What does a client that does not know the
# who show, does a member's chmod fail, and does writing the ACL back keep
# OWNER_RIGHTS@?
uname -a
pw groupadd proj -g 3000; pw groupadd solo -g 3001
pw groupshow users >/dev/null 2>&1 || pw groupadd users -g 100
pw useradd m1 -u 2001 -g 100 -G proj,solo -m; pw useradd m2 -u 2002 -g 100 -G proj -m
pw useradd out -u 2003 -g 100 -m
sysctl vfs.nfs.enable_uidtostring=1 >/dev/null 2>&1
m=/mnt/or
mkdir -p /mnt
mount -t nfs -o nfsv4,minorversion=1,port=2049,tcp 127.0.0.1:/tank/x /mnt; echo "mount rc=$?"
mount | grep /mnt
as() { o=$(su -m "$1" -c "$2" 2>&1 </dev/null); r=$?; echo "  rc=$r $1: $2" | cut -c1-120
	[ -z "$o" ] || echo "$o" | head -4 | sed 's/^/    out: /' | cut -c1-150; }
state() {
	stat -f '  mode %Sp owner %Su:%Sg' "$1"
	for v in m1 m2 out; do
		su -m $v -c "cat $1" >/dev/null 2>&1 && r=r || r=-
		su -m $v -c "sh -c ': >> $1'" >/dev/null 2>&1 && w=w || w=-
		printf '  %s:%s%s' $v $r $w
	done; echo
	echo "  content: $(tr '\n' '|' <"$1" | cut -c1-40)"
}
fresh() { rm -f "$1"; su -m m1 -c "umask 022; echo a > $1"; }
echo "--- the area and a file in it, as FreeBSD shows them"
getfacl $m; echo "  getfacl rc=$?"
fresh $m/f; getfacl $m/f; echo "  getfacl rc=$?"; state $m/f
echo "--- for comparison, a file in the area without OWNER_RIGHTS@"
fresh /mnt/stock/f; getfacl /mnt/stock/f; echo "  getfacl rc=$?"
for c in "chmod 600 $m/f" "chmod 666 $m/f" "setfacl -m u:out:r::allow $m/f" \
    "cp -p /etc/hosts $m/f" "install -m 640 /etc/hosts $m/f" \
    "sh -c 'echo new > $m/t && mv $m/t $m/f'"; do
	fresh $m/f; as m1 "$c"; getfacl -q $m/f 2>&1 | sed 's/^/    /'; state $m/f
done
echo "--- root writes the ACL back as FreeBSD read it (getfacl | setfacl -M), then adds an entry"
fresh $m/f; getfacl -q $m/f > /tmp/acl.txt; echo "  getfacl rc=$? lines=$(wc -l < /tmp/acl.txt)"; cat /tmp/acl.txt | sed 's/^/    /'
setfacl -b -M /tmp/acl.txt $m/f; echo "  setfacl -M rc=$?"; getfacl -q $m/f 2>&1 | sed 's/^/    /'
fresh $m/g; setfacl -m u:out:r::allow $m/g; echo "  setfacl -m rc=$?"; getfacl -q $m/g 2>&1 | sed 's/^/    /'
umount /mnt
