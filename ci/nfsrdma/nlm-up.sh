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
# What the server starts, NLM_GRANTED above all, has to come from the
# address the client knows the server by: the client's lockd takes a
# grant only from the host of the blocked lock (rpc_cmp_addr() in
# nlmclnt_grant(), fs/lockd/clntlock.c), and in run 43075641108 denied
# one from 10.77.0.2, so the lock waited for the 30 s retry.
sudo iptables -t nat -A INPUT -i nb0 -s 10.77.0.2 -j SNAT --to-source 192.0.2.1
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
# rpcinfo asked by program goes to the address the server's rpcbind
# gives for itself, and in run 43075641108 that was 192.168.122.10, the
# VM's address behind qemu, which the runner cannot reach: rpcinfo hung
# in connect().  Ask NLM at its address and port directly instead.
sudo timeout 25 tcpdump -n -i nb0 -c 40 -v >"$OUT/nb0-rpc.txt" 2>&1 &
sleep 2
p=$(ssh netbsd rpcinfo -p | awk '$1 == 100021 && $2 == 4 && $3 == "tcp" { print $4 }')
echo "NLM 4 by TCP on the server's port $p"
timeout -s KILL 10 rpcinfo -n "$p" -t 10.77.0.2 100021 4 || echo 'NLM 4: no answer'
timeout -s KILL 10 rpcinfo -n "$p" -t 192.0.2.1 100021 4 || echo 'NLM 4 by 192.0.2.1: no answer'
sleep 3
cat "$OUT/nb0-rpc.txt"
sudo iptables -t nat -L -n -v
ssh netbsd 'rpcinfo -p | grep -E "nlockmgr|status"; netstat -an -f inet | grep -E "\.111 "'
