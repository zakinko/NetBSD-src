#!/bin/sh
# Inside the chroot.  Nothing here is cut: the raw logs are the record.
cd /usr/tests/fs/nfs
atf-run | tee /var/tmp/raw.bridge | atf-report
echo '=== raw, bridge'
cat /var/tmp/raw.bridge
f=$(grep -cE '^tc-end:.*, (failed|broken),' /var/tmp/raw.bridge)
cd /usr/tests/fs/vfs
for t in t_vfsops t_vnops t_rmdirrace t_renamerace t_ro; do
	[ -x $t ] || continue
	for c in $(./$t -l | sed -n 's/^ident: //p' | grep '^nfs'); do
		r=$(./$t -r /var/tmp/res.$$ $c >/dev/null 2>&1; head -1 /var/tmp/res.$$)
		echo "$t:$c: $r"
		case $r in failed*|broken*) f=$((f + 1)) ;; esac
	done
done
echo "bridge failures: $f"
so=$(ls /usr/lib/librumpfs_nfsserver.so.*.* | head -1)
cp $so /usr/lib/bridge-nfsserver.so
cp /usr/lib/stock-nfsserver.so $so
echo '=== control: stock library'
cd /usr/tests/fs/nfs
atf-run | tee /var/tmp/raw.stock | atf-report
echo '=== raw, stock'
cat /var/tmp/raw.stock
cp /usr/lib/bridge-nfsserver.so $so
