#!/bin/sh
# Run the NFS tests in a chroot of this tree's userland, so that they
# load its rump: on the bridge, then t_rquotad and all of tests/fs/nfs
# on the stock library as the control.
D=/var/tmp/dest
mount -t null /dev $D/dev 2>/dev/null || (cd $D/dev && sh MAKEDEV std)
mkdir -p $D/tmp $D/var/tmp; chmod 1777 $D/tmp
cat >$D/run.sh <<EOT
#!/bin/sh
cd /usr/tests/fs/nfs
atf-run | tee /var/tmp/raw.bridge | atf-report
echo '=== t_rquotad raw, bridge'
grep -vE '^tc-so:|^tc-se:Executing' /var/tmp/raw.bridge | grep -A14 'tc-start.*get_nfs_be_1_both' | head -40
grep -E 'tc-s[oe]:' /var/tmp/raw.bridge | sed -n 1,30p
cd /usr/tests/fs/vfs
for t in t_vfsops t_vnops t_rmdirrace t_renamerace t_ro; do
	[ -x \$t ] || continue
	for c in \$(./\$t -l | sed -n 's/^ident: //p' | grep '^nfs'); do
		r=\$(./\$t -r /var/tmp/res.\$\$ \$c >/dev/null 2>&1; head -1 /var/tmp/res.\$\$)
		echo "\$t:\$c: \$r"
	done
done
so=\$(ls /usr/lib/librumpfs_nfsserver.so.*.* | head -1)
cp \$so /usr/lib/bridge-nfsserver.so
cp /usr/lib/stock-nfsserver.so \$so
echo '=== control: stock library'
cd /usr/tests/fs/nfs
atf-run | tee /var/tmp/raw.stock | atf-report
grep -E 'tc-s[oe]:' /var/tmp/raw.stock | sed -n 1,30p
EOT
chroot $D sh /run.sh >/var/tmp/atf.out 2>&1
cat /var/tmp/atf.out
