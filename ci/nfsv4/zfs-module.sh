#!/bin/sh
# Cross build zfs.kmod against this tree.  The kernel's XDR is a module of
# its own here and nfsv4 needs it too, so the module must use that rather
# than carry a copy of the same symbols.
#   zfs-module.sh SHA WORK OUT
set -eu
SHA=$1; W=$2; OUT=$3
S=$PWD/sys
git init -q "$W/zfs"; cd "$W/zfs"
git fetch -q --depth 1 https://github.com/zakinko/zfs "$SHA"
git checkout -q FETCH_HEAD
python3 - <<'P'
import re
p='module/Makefile.netbsd';s=open(p).read()
s2=re.sub(r'SRCS\+=\s*xdr\.c \\\n\s*xdr_array\.c \\\n\s*xdr_mem\.c\n','',s)
assert s2!=s
open(p,'w').write(s2)
p='module/os/bsd/zfs/kmod_core.c';s=open(p).read()
a='MODULE(MODULE_CLASS_DRIVER, zfs, "zlib");'
assert s.count(a)==1
open(p,'w').write(s.replace(a,'MODULE(MODULE_CLASS_DRIVER, zfs, "zlib,xdr");'))
P
mkdir -p "$W/zobj"; cd module
"$W/tools/bin/nbmake-amd64" -f Makefile.netbsd S="$S" MAKEOBJDIR="$W/zobj" \
    MKDEBUG=no MKCTF=no -j"$(nproc)" >"$OUT/zfs-module.log" 2>&1 ||
    { grep -nE ' error|\*\*\*' "$OUT/zfs-module.log" | head -30; exit 1; }
cp "$W/zobj/zfs.kmod" "$OUT/modules/"
ls -l "$OUT/modules/zfs.kmod"
