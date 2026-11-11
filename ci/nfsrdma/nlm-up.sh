#!/bin/sh
# NLM and NSM for the version 3 mount, which RFC 8267 s5.1 keeps on TCP:
# an IP link to the VM that the server can call back over (tun.py and
# tunpipe, from ci/nlm of the nfsnlm branch), and everything but the
# forwarded ports of 192.0.2.1 sent down it.  nlm-up.sh OUT
OUT=$1
F=$OUT/tun.in
rm -f "$F"
mkfifo "$F"
sudo sh -c "exec python3 ci/nfsrdma/tun.py nb0 <$F" | \
    ssh -o ServerAliveInterval=15 netbsd /var/tmp/tunpipe >"$F" &
sleep 3
ssh netbsd 'ifconfig tun0 10.77.0.2 10.77.0.1 netmask 255.255.255.255 up'
sudo ip addr add 10.77.0.1 peer 10.77.0.2 dev nb0
sudo ip link set nb0 up mtu 1400
ping -c 2 10.77.0.2
# The mount names 192.0.2.1; rpcbind, NLM and NSM of the server are on
# the far side of nb0, and the server calls back to 10.77.0.1.
sudo iptables -t nat -A OUTPUT -d 192.0.2.1 -p tcp -m multiport \
    ! --dports 2049,1234,20049 -j DNAT --to-destination 10.77.0.2
sudo iptables -t nat -A OUTPUT -d 192.0.2.1 -p udp -j DNAT --to-destination 10.77.0.2
sudo iptables -t nat -A POSTROUTING -o nb0 -j MASQUERADE
sudo apt-get install -y -q rpcbind nfs-common >/dev/null 2>&1
sudo systemctl start rpcbind rpc-statd
rpcinfo -p 192.0.2.1 | grep -E 'nlockmgr|status' || echo 'no NLM seen'
