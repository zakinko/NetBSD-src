#!/bin/sh
# Build NetBSD's libcrypto before and after the fix inside a NetBSD VM and
# compare them:  run.sh <arch>
# Expects nbsrc-base.tgz and nbsrc-new.tgz in the current directory.
set -u
arch=$1
# one CPU under TCG takes ~4.5 h per build, so build only the fix
[ $arch = sparc64 ] && BUILDS=new
ci=$(cd "$(dirname "$0")" && pwd)
vm() { sh "$ci/vm.sh" "$@"; }
fail=0

boot() { # cpu
	vm start $arch "$1" || exit 1
	vm put $arch nbsrc-base.tgz nbsrc-new.tgz "$ci/nbbuild.sh" \
	    "$ci/nbtest.sh" "$ci/evpcheck.c" "$ci/invm.sh" || exit 1
}
# The command goes into a file run with sh, so root's login shell, whatever
# it is, never parses the environment settings.
t() { # label, env settings, nbtest args...
	echo "::group::$1"
	label=$1 envs=$2; shift 2
	printf 'cd /root/nb && %s sh invm.sh test %s\n' "$envs" "$*" > "cmd-$label.sh"
	vm put $arch "cmd-$label.sh"
	vm ssh $arch sh /root/nb/cmd-$label.sh 2>&1 | tee "test-$arch-$label.log"
	tail -1 "test-$arch-$label.log" | grep -qx PASS || fail=1
	echo "::endgroup::"
}

boot ""
echo "::group::build"
start=$(date +%s)
printf 'BUILDS="%s" sh /root/nb/invm.sh build\n' "${BUILDS:-base new}" > cmd-build.sh
vm put $arch cmd-build.sh
vm ssh $arch sh /root/nb/cmd-build.sh 2>&1 | tee "build-$arch.log"
echo "build took $(( $(date +%s) - start )) s"
echo "::endgroup::"
for b in ${BUILDS:-base new}; do grep -q "^$b rc 0" "build-$arch.log" || bad=1; done
[ -z "${bad:-}" ] || {
	printf 'grep -m5 -B5 -E "error:|Error code" /root/nb/build-*.log\n' > cmd-err.sh
	vm put $arch cmd-err.sh; vm ssh $arch sh /root/nb/cmd-err.sh; exit 1; }

S="SPEED='ChaCha20-Poly1305 POLY1305 SHA512 MD5 SM3 AES-128-CBC'"
case $arch in
aarch64)
	t max-default "PROBE='OPENSSL_arm_midr OPENSSL_armcap_P' $S" poly1305_init:POLY1305 poly1305_init:ChaCha20-Poly1305 \
	    sha512_block_data_order:SHA512 ossl_md5_block_asm_data_order:MD5 \
	    ossl_hwsm3_block_data_order:SM3 ecp_sm2p256_mul:SM2
	# Hide the crypto extensions (NEON only): AES then takes the
	# bit-sliced code for CBC decryption, SHA-512 the integer code.
	t max-neon "ARMCAP=1 $S" ossl_bsaes_cbc_encrypt:AES-128-CBC \
	    sha512_block_data_order:SHA512
	;;
riscv64)
	t default "$S" ossl_hwsm3_block_data_order:SM3
	;;
sparc64)
	# BUILDS=new: compared with the release's /usr/lib/libcrypto (3.5.7)
	t default "BASELIB=/usr/lib $S" poly1305_init:POLY1305 poly1305_init:ChaCha20-Poly1305
	;;
esac
vm stop $arch
[ $fail = 0 ] && echo "all PASS" || echo "some FAIL"
exit $fail
