#!/bin/sh
# On the runner: Kerberos over RPC-with-TLS.  cbprobe.py for the channel
# bindings of RFC 5403, which no Linux client sends, then the Linux
# client with sec=krb5* and xprtsec=tls, RPCSEC_GSS version 1 inside
# TLS.  The KDC and gssd are the VM's, from ci/nfsgss/vm-kdc.sh.
# cb-client.sh OUT CERTDIR
OUT=$1 CERTS=$2
LOG=$OUT/cb-client.txt
S=nfsgss-server.test
HERE=$(cd "$(dirname "$0")" && pwd)
exec >"$LOG" 2>&1
set -x
sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l timeout 300 \
    apt-get install -y -q krb5-user python3-gssapi python3-openssl nfs-common
sudo ip link add gss0 type dummy
sudo ip addr add 10.99.0.1/32 dev gss0
sudo ip link set gss0 up
ssh -f -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=10 \
    -L 10.99.0.1:2049:127.0.0.1:2049 -L 10.99.0.1:8888:127.0.0.1:8888 netbsd
echo "10.99.0.1 $S" | sudo tee -a /etc/hosts
echo "127.0.0.1 nfsgss-client.test" | sudo tee -a /etc/hosts
sudo hostname nfsgss-client.test
printf '%s\n' '[libdefaults]' \
    '	default_realm = NFSGSS.TEST' \
    '	dns_lookup_kdc = false' \
    '	dns_canonicalize_hostname = false' \
    '	rdns = false' \
    '	udp_preference_limit = 1' \
    '[realms]' \
    '	NFSGSS.TEST = {' \
    '		kdc = 10.99.0.1:8888' \
    '	}' \
    '[domain_realm]' \
    '	.test = NFSGSS.TEST' | sudo tee /etc/krb5.conf
scp netbsd:/var/tmp/nfsv4/client.keytab "$OUT/client.keytab"
sudo install -m 600 "$OUT/client.keytab" /etc/krb5.keytab
rm -f "$OUT/client.keytab"
sudo useradd -m -u 2097 alice
sudo -u alice sh -c 'echo alice-pw | kinit alice' && sudo -u alice klist
fails=0
sudo -u alice python3 "$HERE/cbprobe.py" $S "$CERTS/ca.pem" || fails=$((fails + 1))

# The Linux client: RPCSEC_GSS version 1 inside TLS.
sudo modprobe rpcsec_gss_krb5
sudo mkdir -p /run/rpc_pipefs
mountpoint -q /run/rpc_pipefs || sudo mount -t rpc_pipefs sunrpc /run/rpc_pipefs
sudo sh -c "/usr/sbin/tlshd -s >$OUT/tlshd-krb5.log 2>&1 & echo \$! >$OUT/tlshd.pid"
sudo sh -c "rpc.gssd -v -f >$OUT/rpc.gssd-tls.log 2>&1 & echo \$! >$OUT/gssd.pid"
sleep 2
sudo mkdir -p /mnt/k
for sec in krb5 krb5i krb5p; do
	sudo -u alice sh -c 'echo alice-pw | kinit alice'
	if sudo timeout 90 mount -t nfs -o vers=4.0,sec=$sec,xprtsec=tls,soft,timeo=50,retrans=1 \
	    $S:/export/krb5all /mnt/k; then
		if sudo -u alice sh -c "head -c 1048576 /dev/urandom >/tmp/k.bin && cp /tmp/k.bin /mnt/k/tls-$sec && cmp /tmp/k.bin /mnt/k/tls-$sec && rm /mnt/k/tls-$sec"; then
			echo "krb5 over tls: $sec ok"
		else
			echo "krb5 over tls: $sec io FAILED"; fails=$((fails + 1))
		fi
		sudo umount /mnt/k
	else
		echo "krb5 over tls: $sec mount FAILED"; fails=$((fails + 1))
	fi
done
sudo kill "$(cat "$OUT/tlshd.pid")" "$(cat "$OUT/gssd.pid")"
echo "cb-client failures $fails"
exit 0
