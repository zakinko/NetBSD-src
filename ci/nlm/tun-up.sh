#!/bin/sh
# The link between the runner and the VM: tun.py and tunpipe over ssh,
# IPv4 and IPv6.  tun-up.sh OUT
OUT=$1
F=$OUT/tun.in
rm -f "$F"
mkfifo "$F"
sudo sh -c "exec python3 ci/nlm/tun.py nb0 <$F" | \
    ssh -o ServerAliveInterval=15 netbsd /var/tmp/tunpipe >"$F" &
sleep 3
ssh netbsd 'ifconfig tun0 10.77.0.2 10.77.0.1 netmask 255.255.255.255 up
ifconfig tun0 inet6 fd77::2 fd77::1 prefixlen 128 alias
ifconfig tun0'
sudo ip addr add 10.77.0.1 peer 10.77.0.2 dev nb0
sudo ip link set nb0 up mtu 1400
sudo sysctl -q -w net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.nb0.disable_ipv6=0
sudo ip -6 addr add fd77::1 peer fd77::2 dev nb0 nodad
ip addr show nb0
