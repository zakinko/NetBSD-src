#!/bin/sh
# In the OmniOS VM: the illumos client on versions 3 and 2 of NFS, which
# carry NFSACL versions 3 and 2.  The server is the NetBSD VM behind
# the runner, 192.168.122.2 to an anyvm guest.  Each ACL is printed in the form
# of sacl.sh, after a line "=== LABEL SERVER-PATH [-d]", for
# omnios-check.sh to compare.  omnios.sh
S=192.168.122.2
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
# What the client sees of the server's rpcbind, before any mount.
rpcinfo -p $S 2>&1 | head -30
rpcinfo -T tcp $S 100003 3 2>&1
rpcinfo -T tcp $S 100005 3 2>&1
for v in 3 2; do
	m=/mnt/p$v
	mkdir -p $m
	t mount -F nfs -o vers=$v,proto=tcp,retry=2 $S:/export/pacl $m || continue
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
	echo '# named attributes: GETXATTRDIR, then NFS on its handles'
	x=$m/x$v
	rm -f $x
	t touch $x
	t runat $x cp /etc/hosts a
	t runat $x cp a b
	t runat $x rm b
	t runat $x cp a c
	echo "xattr-ls v$v $(runat $x ls | sort | tr '\n' ' ')"
	echo "xattr-cat v$v $(runat $x cat a | cksum)"
	echo "xattr-want v$v $(cksum </etc/hosts)"
	echo "xattr-wantnl v$v $( (cat /etc/hosts; echo) | cksum)"
	n runat $x mkdir d
	# Does ls -l ask NFSACL for the ACL of an attribute?  See the capture.
	echo "xattr-lsl v$v"; runat $x ls -l
	echo "xattr-lsl-end v$v $(date -u +%H:%M:%S)"
	echo '# and the ACLs are still there after it'
	show v$v-after /export/pacl/o$v "" $f
	t umount $m
done
for e in tmpfs acl; do
	m=/mnt/$e
	mkdir -p $m
	t mount -F nfs -o vers=3,proto=tcp,retry=2 $S:/export/$e $m || continue
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
