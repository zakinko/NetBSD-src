#!/bin/sh
# Run pynfs's 4.0 suite against the server in the VM, through an ssh
# tunnel.  pynfs's failures are the measurement, so they do not fail the
# job; the rig failing does.  pynfs.sh OUT
set -eu
OUT=$1
REV=cd4701827a8261fedbfb4c6e39029fb9671321a6
EXPORT=/export/pynfs
LIMIT=${LIMIT:-3000}
sudo apt-get update -q
sudo apt-get install -y -q libkrb5-dev python3-dev swig python3-gssapi \
    python3-ply python3-setuptools >/dev/null
git clone -q git://git.linux-nfs.org/projects/cdmackay/pynfs.git "$HOME/pynfs"
git -C "$HOME/pynfs" checkout -q "$REV"
(cd "$HOME/pynfs" && python3 setup.py build) >"$OUT/pynfs-build.log" 2>&1
ssh -f -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=10 \
    -L 2049:127.0.0.1:2049 netbsd
sleep 2
cd "$HOME/pynfs/nfs4.0"
rc=0
timeout "$LIMIT" python3 ./testserver.py 127.0.0.1:"$EXPORT" --maketree \
    --rundeps --json="$OUT/pynfs.json" ${PYNFS_ARGS:-all} \
    >"$OUT/pynfs.log" 2>&1 || rc=$?
echo "testserver.py exit status $rc"
tail -5 "$OUT/pynfs.log"
