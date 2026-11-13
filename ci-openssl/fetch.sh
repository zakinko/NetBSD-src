#!/bin/sh
# Fetch the vmactions NetBSD 11.1 image for <arch> into ./vm:  fetch.sh <arch>
set -e
arch=$1
u=https://github.com/anyvm-org/netbsd-builder/releases/download/v2.2.9
mkdir -p vm
curl -fsSL -o vm/netbsd-11.1-$arch.host.id_rsa $u/netbsd-11.1-$arch-host.id_rsa
chmod 600 vm/netbsd-11.1-$arch.host.id_rsa
curl -fsSL $u/netbsd-11.1-$arch.qcow2.zst | zstd -dq -o vm/netbsd-11.1-$arch.qcow2
if [ $arch = sparc64 ]; then
	# Ubuntu's qemu-system-sparc64 is older than the image needs
	mkdir -p vm/qemu-sparc64
	curl -fsSL $u/qemu-10.2.3-sparc64-noble.tar.zst | zstd -dq | tar -xf - -C vm/qemu-sparc64
	ls vm/qemu-sparc64 vm/qemu-sparc64/* | head
fi
ls -l vm
