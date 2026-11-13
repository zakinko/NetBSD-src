#!/bin/sh
# Build NetBSD's libcrypto before and after the fix inside a NetBSD VM and
# compare them:  run.sh <arch>
# Expects nbsrc-base.tgz and nbsrc-new.tgz in the current directory.
set -u
arch=$1
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
vm ssh $arch sh /root/nb/invm.sh build 2>&1 | tee "build-$arch.log"
echo "build took $(( $(date +%s) - start )) s"
echo "::endgroup::"
grep -q "^new rc 0" "build-$arch.log" && grep -q "^base rc 0" "build-$arch.log" || {
	printf 'grep -m5 -B5 -E "error:|Error code" /root/nb/build-*.log\n' > cmd-err.sh
	vm put $arch cmd-err.sh; vm ssh $arch sh /root/nb/cmd-err.sh; exit 1; }

S="SPEED='ChaCha20-Poly1305 POLY1305 SHA512 MD5 SM3 AES-128-CBC'"
case $arch in
aarch64)
	t max-default "$S" poly1305_init:POLY1305 poly1305_init:ChaCha20-Poly1305 \
	    sha512_block_data_order:SHA512 ossl_md5_block_asm_data_order:MD5 \
	    ossl_hwsm3_block_data_order:SM3 ecp_sm2p256_mul:SM2
	# Hide the crypto extensions (NEON only): AES then takes the
	# bit-sliced code for CBC decryption, SHA-512 the integer code.
	t max-neon "ARMCAP=1 $S" ossl_bsaes_cbc_encrypt:AES-128-CBC \
	    sha512_block_data_order:SHA512
	vm stop $arch
	# VPSM4 is picked by MIDR, for Neoverse N1 and V1 without SM4.
	vm start $arch neoverse-n1 || exit 1
	t n1 "SPEED='SM4-CBC SM4-CTR'" vpsm4_cbc_encrypt:SM4-CBC
	;;
riscv64)
	t default "$S" ossl_hwsm3_block_data_order:SM3
	;;
sparc64)
	t default "$S" poly1305_init:POLY1305 poly1305_init:ChaCha20-Poly1305
	;;
esac
vm stop $arch
[ $fail = 0 ] && echo "all PASS" || echo "some FAIL"
exit $fail
