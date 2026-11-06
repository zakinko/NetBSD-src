#!/bin/sh
# Stop every nfsd and prove it.  What is left after the wait is a failure.
list() { ps -ax -o pid=,comm= | awk '$2 == "nfsd" { print $1 }'; }
p=$(list)
echo "nfsd before: $(echo $p)"
[ -n "$p" ] && kill -TERM $p
i=0
while [ $i -lt 30 ] && [ -n "$(list)" ]; do sleep 1; i=$((i + 1)); done
echo "after ${i}s: [$(echo $(list))]"
[ -z "$(list)" ]
