#!/bin/sh
# In the VM: which poly1305 code the new library runs on this CPU, whether
# the first version of the fix (obj-old) loads at all, then the comparison.
w=/root/nb
O=$w/new/src/crypto/external/apache2/openssl
# 9.4's libc has no pthread_create; libcrypto is linked without libpthread
I="-I$O/include -I$O/dist/include -lpthread"
cd $w
sh genhdr.sh $w/new/src || exit 1
cc -O2 $I -o evp evpcheck.c -L$w/obj-new -lcrypto || exit 1
for s in poly1305_init_int poly1305_init_fpu poly1305_blocks poly1305_blocks_fpu poly1305_blocks_vsx; do
	LD_LIBRARY_PATH=$w/obj-new gdb -nx -batch -ex "handle SIGILL nostop noprint pass" \
	    -ex "break main" -ex run -ex "break $s" -ex continue -ex "info symbol \$pc" \
	    --args ./evp one POLY1305 < /dev/null > gdb.out 2>&1
	if grep -q -E "^$s( \+ [0-9]+)? in section" gdb.out; then echo "path: $s called"; else echo "path: $s not called"; fi
done
if [ -d obj-old ]; then
	LD_LIBRARY_PATH=$w/obj-old ./evp kat > old.out 2>&1; echo "old rc $?"; tail -2 old.out | sed 's/^/old: /'
fi
PROBE=OPENSSL_ppccap_P NBCFLAGS="$I" sh invm.sh test poly1305_init:POLY1305 poly1305_init:ChaCha20-Poly1305
