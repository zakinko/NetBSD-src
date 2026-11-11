#!/bin/sh
# In the VM, before vm-kdc.sh, which starts the mountd that reads the
# exports: FFS with POSIX.1e ACLs, once for AUTH_SYS and once for
# Kerberos, and the exports of both.  vm-acl.sh
set -eu
D=/var/tmp/nfsv4
command -v getfacl setfacl
n=3
for e in pacl pacl5; do
	mkdir -p "/export/$e"
	dd if=/dev/zero of="/var/tmp/$e.img" bs=1m count=128 2>/dev/null
	newfs -O 2ea -F -s 128m "/var/tmp/$e.img" | tail -1
	[ -e "/dev/vnd${n}d" ] || (cd /dev && sh MAKEDEV "vnd$n")
	vnconfig "vnd$n" "/var/tmp/$e.img"
	mount -o posix1eacls "/dev/vnd${n}d" "/export/$e"
	chmod 1777 "/export/$e"
	n=$((n + 1))
done
mount | grep -E '/export/pacl'
cat >>/etc/exports <<EOT
/export/pacl -maproot=root -noresvport -noresvmnt
/export/pacl5 -sec=krb5:krb5i:krb5p -maproot=nobody -noresvport -noresvmnt
EOT
# The client mounts through the tunnel, from a port that is not reserved.
sed -e '/-noresvmnt/!s/$/ -noresvmnt/' /etc/exports >/etc/exports.new
mv /etc/exports.new /etc/exports
cat /etc/exports
# The server's own view, for the client to be compared with.
touch /export/pacl/selftest
setfacl -m u:2097:rw,m::rw /export/pacl/selftest
getfacl -n /export/pacl/selftest
rm /export/pacl/selftest
