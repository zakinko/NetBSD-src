#!/bin/sh
# In the OmniOS VM: the illumos client on versions 3 and 2 of NFS, which
# carry NFSACL versions 3 and 2.  The server is the NetBSD VM behind
# the runner, 10.0.2.2 to a QEMU guest.  Each ACL is printed in the form
# of sacl.sh, after a line "=== LABEL SERVER-PATH [-d]", for
# omnios-check.sh to compare.  omnios.sh
S=10.0.2.2
fails=0
t() {
	echo "\$ $*"
	if "$@"; then echo ok; else echo "FAILED ($?)"; fails=$((fails + 1)); return 1; fi
}
n() {
	echo "\$ ! $*"
	if "$@"; then echo 'FAILED: it worked'; fails=$((fails + 1)); else echo "ok, refused ($?)"; fi
}
# illumos' getfacl: "mask:rw-", "other:r--", "#effective" comments and
# "default:" before each entry of -d.
norm() {
	sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e 's/^default://' \
	    -e 's/^mask:\([^:]*\)$/mask::\1/' -e 's/^other:\([^:]*\)$/other::\1/' |
	    grep -v '^$' | sort
}
show() {	# label server-path [-d] client-path
	l=$1; sp=$2; d=$3; cp=$4
	echo "=== $l $sp $d"
	if [ "$d" = -d ]; then getfacl -d "$cp"; else getfacl -a "$cp"; fi | norm
}
uname -a
for v in 3 2; do
	m=/mnt/p$v
	mkdir -p $m
	t mount -F nfs -o vers=$v,proto=tcp $S:/export/pacl $m || continue
	f=$m/o$v; d=$m/od$v
	rm -rf $f $d
	t touch $f
	t chmod 640 $f
	show v$v-mode /export/pacl/o$v "" $f
	t setfacl -m user:2097:rw-,user:2098:r--,group:3001:r--,mask:rwx $f
	show v$v-named /export/pacl/o$v "" $f
	t chmod 600 $f
	show v$v-chmod /export/pacl/o$v "" $f
	t mkdir $d
	t setfacl -m default:user::rwx,default:group::r-x,default:other:---,default:user:2097:rwx,default:mask:rwx $d
	show v$v-dfl /export/pacl/od$v -d $d
	t sh -c "echo x >$d/new"
	show v$v-inherit /export/pacl/od$v/new "" $d/new
	echo '# no extended attributes: GETXATTRDIR is PROC_UNAVAIL'
	n runat $f ls
	echo '# and the ACLs are still there after it'
	show v$v-after /export/pacl/o$v "" $f
	t umount $m
done
for e in tmpfs acl; do
	m=/mnt/$e
	mkdir -p $m
	t mount -F nfs -o vers=3,proto=tcp $S:/export/$e $m || continue
	rm -f $m/o
	t touch $m/o
	t chmod 754 $m/o
	show $e-mode /export/$e/o "" $m/o
	n setfacl -m user:2097:rw-,mask:rw- $m/o
	t sh -c "echo y >$m/o2"
	rm -f $m/o $m/o2
	t umount $m
done
echo "failures: $fails"
