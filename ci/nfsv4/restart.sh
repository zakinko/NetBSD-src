#!/bin/sh
# In the VM: end this instance of the server and start another, as a
# restart looks to clients.  The modules hold all the state there is.
set -eu
D=/var/tmp/nfsv4
kill "$(cat "$D/nfsv4d.pid")"
sleep 1
modunload nfsv4
modload nfsv4
cd "$D"
./nfsv4d "$D/stable" </dev/null >>nfsv4d.log 2>&1 &
echo $! >nfsv4d.pid
sleep 1
