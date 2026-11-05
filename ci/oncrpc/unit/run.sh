#!/bin/sh
# Unit tests of sys/oncrpc and the kernel's XDR on the host: the sources
# as they are, against shim/.  run.sh OBJDIR, from the top of the tree.
set -eu
O=$1; D=ci/oncrpc/unit
mkdir -p "$O/gen/rpc" "$O/gen/sys"
cp common/include/rpc/xdr.h "$O/gen/rpc/"
cp sys/sys/queue.h "$O/gen/sys/"
{ echo 'typedef long long longlong_t; typedef unsigned long long u_longlong_t;'
  cat common/include/rpc/types.h; } >"$O/gen/rpc/types.h"
ln -sfn "$PWD/sys/oncrpc" "$O/gen/oncrpc"
${CC:-clang} -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=undefined \
    -w -D_KERNEL -D_DEFAULT_SOURCE -I"$D/shim" -I"$O/gen" -o "$O/t_rpcxdr" \
    "$D/t_rpcxdr.c" "$D/t_svc.c" "$D/shimlib.c" \
    common/lib/libc/rpc/xdr.c common/lib/libc/rpc/xdr_array.c \
    common/lib/libc/rpc/xdr_mem.c sys/oncrpc/xdr_mbuf.c \
    sys/oncrpc/oncrpc_msg.c sys/oncrpc/oncrpc_auth.c sys/oncrpc/oncrpc_rm.c
ASAN_OPTIONS=detect_leaks=0 "$O/t_rpcxdr" | grep -v '^ok'
