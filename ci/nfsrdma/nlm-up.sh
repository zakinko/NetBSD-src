#!/bin/sh
# NLM and NSM for the version 3 mount, which RFC 8267 s5.1 keeps on TCP:
# an IP link to the VM that the server can call back over (tun.py and
# tunpipe, from ci/nlm of the nfsnlm branch), and everything but the
# forwarded ports of 192.0.2.1 sent down it.  nlm-up.sh OUT
OUT=$1
# Each command with the time, to find where it waits.
PS4='+ $(date +%T) '
set -x
F=$OUT/tun.in
rm -f "$F"
mkfifo "$F"
# Off the step's output, or the step waits on the pipe for ever.
sudo sh -c "exec python3 ci/nfsrdma/tun.py nb0 <$F" 2>>"$OUT/tun.err" | \
    ssh -o ServerAliveInterval=15 netbsd /var/tmp/tunpipe >"$F" 2>>"$OUT/tun.err" &
sleep 3
ssh netbsd 'ifconfig tun0 10.77.0.2 10.77.0.1 netmask 255.255.255.255 up'
sudo ip addr add 10.77.0.1 peer 10.77.0.2 dev nb0
sudo ip link set nb0 up mtu 1400
ping -c 2 10.77.0.2
ssh netbsd 'rpcinfo -p | grep -E "nlockmgr|status"; netstat -an -f inet | grep -E "\\.111 "'
# Run 43047611152 lost name resolution after the rules below; ask
# before and after them.
resolvectl query archive.ubuntu.com 2>&1 | head -2
# The mount names 192.0.2.1; rpcbind, NLM and NSM of the server are on
# the far side of nb0, and the server calls back to 10.77.0.1.
sudo iptables -t nat -A OUTPUT -d 192.0.2.1 -p tcp -m multiport \
    ! --dports 2049,1234,20049 -j DNAT --to-destination 10.77.0.2
sudo iptables -t nat -A OUTPUT -d 192.0.2.1 -p udp -j DNAT --to-destination 10.77.0.2
sudo iptables -t nat -A POSTROUTING -o nb0 -j MASQUERADE
resolvectl query archive.ubuntu.com 2>&1 | head -2
sudo systemctl start rpcbind rpc-statd
# TCP across the link, seen at both ends, as ping alone went through in
# run 43007424174 and rpcinfo did not.
ssh netbsd 'timeout 15 tcpdump -n -i tun0 -c 20 -v 2>&1' >"$OUT/tun0.txt" &
sudo timeout 15 tcpdump -n -i nb0 -c 20 -v >"$OUT/nb0.txt" 2>&1 &
sleep 2
timeout 8 bash -c 'exec 3<>/dev/tcp/10.77.0.2/111' && echo 'tcp 111 connects' || echo 'tcp 111 does not connect'
sleep 14
cat "$OUT/nb0.txt" "$OUT/tun0.txt"
# Both ways, to tell the link from the redirection when one fails.
# A TCP connection to 111 completes (run 43016625749) and rpcinfo still
# gets nothing: watch what it sends, by TCP and by UDP.
sudo timeout 25 tcpdump -n -i nb0 -c 40 -v >"$OUT/nb0-rpc.txt" 2>&1 &
sleep 2
timeout -s KILL 10 rpcinfo -T tcp 10.77.0.2 100000 2 || echo 'rpcinfo -T tcp: no answer'
timeout -s KILL 10 rpcinfo -T udp 10.77.0.2 100000 2 || echo 'rpcinfo -T udp: no answer'
timeout -s KILL 20 rpcinfo -p 10.77.0.2 | grep -E 'nlockmgr|status' || echo 'no NLM seen on 10.77.0.2'
sleep 3
cat "$OUT/nb0-rpc.txt"
timeout -s KILL 20 rpcinfo -p 192.0.2.1 | grep -E 'nlockmgr|status' || echo 'no NLM seen on 192.0.2.1'
sudo iptables -t nat -L -n -v
ssh netbsd 'rpcinfo -p | grep -E "nlockmgr|status"; netstat -an -f inet | grep -E "\.111 "'
