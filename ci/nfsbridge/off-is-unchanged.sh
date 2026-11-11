#!/bin/sh
# With the option off, the files of sys/nfs must come out as they were,
# but for the include of the option's header.  off-is-unchanged.sh BASE
set -eu
B=$1
X=$(mktemp -d)
fail=0
for f in $(git diff --name-only "$B" HEAD -- sys/nfs | grep -E '\.[ch]$'); do
	case $f in sys/nfs/nfs_oncrpc.c|sys/nfs/nfs_acl.c) continue ;; esac
	# A file the base does not have is built only with the option, or
	# by a module: nfs_xattr.c, nfs_srvxattr.c.
	git cat-file -e "$B:$f" 2>/dev/null || { echo "new: $f"; continue; }
	git show "$B:$f" >"$X/old"
	unifdef -UNFSSERVER_ONCRPC -U_KERNEL_OPT "$f" >"$X/new" || [ $? -eq 1 ]
	# The base may have the option already, as the base of nfsacl does.
	unifdef -UNFSSERVER_ONCRPC -U_KERNEL_OPT "$X/old" >"$X/oldu" || [ $? -eq 1 ]
	cat -s "$X/oldu" >"$X/o"; cat -s "$X/new" >"$X/n"
	if diff -u "$X/o" "$X/n" >"$X/d"; then
		echo "same: $f"
	else
		cat "$X/d"; echo "CHANGED: $f"; fail=1
	fi
done
rm -rf "$X"
exit $fail
