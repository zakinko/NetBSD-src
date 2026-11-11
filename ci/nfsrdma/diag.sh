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
