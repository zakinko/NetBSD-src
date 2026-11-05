#!/bin/sh
# Cross build zfs.kmod against this tree.  Its XDR is its own, renamed
# openzfs_xdr_*, so it does not meet the xdr module.
#   zfs-module.sh SHA WORK OUT
set -eu
SHA=$1; W=$2; OUT=$3
S=$PWD/sys
P=$PWD/ci/nfsv4/zfs-patches
git init -q "$W/zfs"; cd "$W/zfs"
git fetch -q --depth 1 https://github.com/zakinko/zfs "$SHA"
git checkout -q FETCH_HEAD
# What the port needs that is not at SHA yet.
for p in "$P"/*.patch; do git apply "$p"; done
python3 - <<'P'
import re
# Current has no struct uvm to look into; 11.0, which the port follows, has.
import subprocess
for f in subprocess.check_output('grep -rl pagedaemon_lwp module/os/bsd',shell=True,text=True).split():
    t=open(f).read()
    t2=re.sub(r'curlwp\s*==\s*uvm\.pagedaemon_lwp','uvm_lwp_is_pagedaemon(curlwp)',t)
    t2=re.sub(r'curlwp\s*!=\s*uvm\.pagedaemon_lwp','!uvm_lwp_is_pagedaemon(curlwp)',t2)
    assert t2!=t,f
    open(f,'w').write(t2)
P
mkdir -p "$W/zobj"; cd module
"$W/tools/bin/nbmake-amd64" -f Makefile.netbsd S="$S" MAKEOBJDIR="$W/zobj" \
    MKDEBUG=no MKCTF=no -j"$(nproc)" >"$OUT/zfs-module.log" 2>&1 ||
    { grep -nE ' error|\*\*\*' "$OUT/zfs-module.log" | head -30; exit 1; }
cp "$W/zobj/zfs.kmod" "$OUT/modules/"
ls -l "$OUT/modules/zfs.kmod"
