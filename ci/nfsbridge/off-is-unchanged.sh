#!/bin/sh
# With the option off, the files of sys/nfs must come out as they were,
# but for the include of the option's header.  off-is-unchanged.sh BASE
set -eu
B=$1
X=$(mktemp -d)
fail=0
for f in $(git diff --name-only "$B" HEAD -- sys/nfs | grep -E '\.[ch]$'); do
	case $f in sys/nfs/nfs_oncrpc.c) continue ;; esac
	git show "$B:$f" >"$X/old"
	unifdef -UNFSSERVER_ONCRPC -U_KERNEL_OPT "$f" >"$X/new" || [ $? -eq 1 ]
	unifdef -U_KERNEL_OPT "$X/old" >"$X/oldu" || [ $? -eq 1 ]
	cat -s "$X/oldu" >"$X/o"; cat -s "$X/new" >"$X/n"
	if diff -u "$X/o" "$X/n" >"$X/d"; then
		echo "same: $f"
	else
		cat "$X/d"; echo "CHANGED: $f"; fail=1
	fi
done
rm -rf "$X"
exit $fail
