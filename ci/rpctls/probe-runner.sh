#!/bin/sh
# What the runner's kernel offers a Linux NFS client for RPC-over-TLS
# (RFC 9289): kTLS, the net/handshake upcall that tlshd answers, and
# the xprtsec= mount option in the NFS and SUNRPC modules.
set -x
uname -a
K=$(uname -r)
grep -E 'CONFIG_(TLS|TLS_DEVICE|NET_HANDSHAKE|SUNRPC|SUNRPC_GSS|NFS_FS|NFS_V4|NFSD)=' /boot/config-$K
sudo modprobe tls && lsmod | grep -E '^tls'
for m in fs/nfs/nfs net/sunrpc/sunrpc; do
	f=$(ls /lib/modules/$K/kernel/$m.ko* 2>/dev/null | head -1)
	echo "== $m: $f"
	case $f in
	*.zst) zstdcat $f ;; *.xz) xzcat $f ;; *) cat $f ;;
	esac | strings | grep -E -i 'xprtsec|tls_handshake|handshake_req' | sort -u | head
done
grep -E 'handshake' /proc/kallsyms | head -5
apt-cache policy ktls-utils
sudo apt-get install -y ktls-utils >/dev/null 2>&1; ls -l /usr/sbin/tlshd; tlshd --help 2>&1 | head -5
python3 -c 'import OpenSSL; print("pyOpenSSL", OpenSSL.__version__)' || apt-cache policy python3-openssl python3-gssapi
exit 0
