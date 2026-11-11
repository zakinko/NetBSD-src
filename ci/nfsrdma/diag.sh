#!/bin/sh
# What the server's threads are waiting on, and its connections: for a
# call that gets no answer.  Run on the VM.
echo "== $(date +%T) diag"
# The LWP's own name: run 43021120172 printed the wchans with no
# names, as the header swallowed the column.
ps -axs -o pid,lid,stat,wchan,lname,comm 2>/dev/null | \
    awk 'NR == 1 || $5 !~ /idle/' | head -160
netstat -an -f inet | grep -E '\.(2049|20049) '
sysctl vfs.nfsv4 2>/dev/null | grep -vE 'idmap|domain|referral|moved|impl'
dmesg | tail -20
# The stacks of the RPC workers and the callback threads, by crash(8) on
# the running kernel: where a worker waits, not only on what.
P=/var/tmp/nfsv4/ddbps.txt
if command -v crash >/dev/null; then
	echo 'ps/l' | crash -M /dev/mem -N /netbsd 2>/dev/null >"$P"
	for a in $(awk '/ (nfs|nfsv4cb)\// { for (i = 1; i <= NF; i++) if ($i ~ /^(0x)?ffff/) { print $i; break } }' "$P"); do
		echo "== bt/a $a"
		echo "bt/a $a" | crash -M /dev/mem -N /netbsd 2>&1 | grep -v '^crash>' | head -30
	done
	grep -E ' (nfs|nfsv4cb)/' "$P" | head -20
fi
