#!/bin/sh
# Run a pynfs suite, by default 4.0's (SUITE=nfs4.1 for the other), against the server in the VM, through an ssh
# tunnel.  pynfs's failures are the measurement, so they do not fail the
# job; the rig failing does.  pynfs.sh OUT [EXPORT [NAME]]
set -eu
OUT=$1
REV=cd4701827a8261fedbfb4c6e39029fb9671321a6
EXPORT=${2:-/export/pynfs}
NAME=${3:-pynfs}
LIMIT=${LIMIT:-3000}
if [ ! -d "$HOME/pynfs" ]; then
	sudo apt-get update -q
	sudo apt-get install -y -q libkrb5-dev python3-dev swig python3-gssapi \
	    python3-ply python3-setuptools >/dev/null
	git clone -q git://git.linux-nfs.org/projects/cdmackay/pynfs.git "$HOME/pynfs"
	git -C "$HOME/pynfs" checkout -q "$REV"
	# The server calls back through the tunnel, so the ports must be
	# known beforehand, and pynfs picks any.
	sed -i -e 's/^        self.port = 0$/        self.port = next(_cb_ports)/' \
	    -e '0,/^class CBServer/s//_cb_ports = iter(range(40001, 40005))\n&/' \
	    "$HOME/pynfs/nfs4.0/nfs4lib.py"
	# In Python 3 this compares an int with bytes, and always fails.
	sed -i "s/if path\[0\] != b'\/':/if path[:1] != b'\/':/" \
	    "$HOME/pynfs/nfs4.0/testserver.py"
	(cd "$HOME/pynfs" && python3 setup.py build) >"$OUT/pynfs-build.log" 2>&1
fi
# The tests of the conformance table of version 4.2 go in with pynfs's.
if [ -f ci/nfsv4/pynfs42/st_v42.py ]; then
	cp ci/nfsv4/pynfs42/st_v42.py "$HOME/pynfs/nfs4.1/server41tests/"
	grep -q st_v42 "$HOME/pynfs/nfs4.1/server41tests/__init__.py" ||
	    sed -i 's/"st_sparse.py",/"st_sparse.py", "st_v42.py",/' \
	    "$HOME/pynfs/nfs4.1/server41tests/__init__.py"
fi
cd "$HOME/pynfs/${SUITE:-nfs4.0}"
rc=0
# As root, as the base line was: MKNOD and chown need it.
timeout "$LIMIT" sudo -E python3 ./testserver.py 127.0.0.1:"$EXPORT" --maketree \
    --rundeps --json="$OUT/$NAME.json" ${PYNFS_ARGS:-all} </dev/null \
    >"$OUT/$NAME.log" 2>&1 || rc=$?
echo "testserver.py exit status $rc"
tail -5 "$OUT/$NAME.log"
