#!/bin/sh
# What the server's threads are waiting on, and its connections: for a
# call that gets no answer.  Run on the VM.
echo "== $(date +%T) diag"
ps -axs -o pid,lid,stat,wchan=WCHAN........,command 2>/dev/null | \
    awk 'NR == 1 || $5 !~ /idle/' | head -120
netstat -an -f inet | grep -E '\.(2049|20049) '
sysctl vfs.nfsv4 2>/dev/null | grep -vE 'idmap|domain|referral|moved|impl'
dmesg | tail -20
