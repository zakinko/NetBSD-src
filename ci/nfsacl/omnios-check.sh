#!/bin/sh
# On the runner: run omnios.sh in the OmniOS VM, and compare each ACL it
# printed with the server's own.  omnios-check.sh OUT
OUT=$1
H=$(cd "$(dirname "$0")" && pwd)
L=$OUT/nfsacl-omnios.txt
scp "$H/omnios.sh" omnios:/var/tmp/omnios.sh
# Both VMs are 192.168.122.10 to themselves and see the runner as
# 192.168.122.2; the universal addresses the NetBSD rpcbind gives out
# have to name the latter.  The runner's rpcbind is back on 0.0.0.0:111
# by now although it was stopped before the NetBSD VM came up (seen in
# run 43226914643), so it is stopped and masked here, where the port is
# taken.
sudo systemctl mask --now rpcbind.socket rpcbind.service >/dev/null 2>&1 || :
sudo python3 "$H/rpcb-nat.py" 111 10111 192.168.122.10 192.168.122.2 \
    >"$OUT/nfsacl-rpcb-nat.txt" 2>&1 &
NAT=$!
sleep 1
kill -0 $NAT 2>/dev/null || { cat "$OUT/nfsacl-rpcb-nat.txt"; exit 1; }
# And what the runner's port 111 leads to.
ss -lntup | grep -E ':(111|2049|4002) ' || :
rpcinfo -p 127.0.0.1 2>&1 | head -30 || :
for p in 111 2049 4002; do
	if timeout 5 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null; then
		echo "runner to 127.0.0.1:$p: open"; else echo "runner to 127.0.0.1:$p: no"; fi
done
# Where a call to port 111 through the forward goes: captured in the
# VM and on the runner.
ssh -o LogLevel=ERROR netbsd 'i=$(ifconfig -l | tr " " "\n" | grep -v "^lo" | head -1); tcpdump -n -i $i -c 40 -w /var/tmp/p111.pcap port 111 >/dev/null 2>&1 & echo $! >/var/tmp/p111.pid' || :
sudo timeout 30 tcpdump -n -i lo -c 40 port 111 >"$OUT/nfsacl-p111-runner.txt" 2>&1 &
sleep 2
timeout 20 rpcinfo -T tcp 127.0.0.1 100000 4 2>&1 || :
timeout 20 rpcinfo -T udp 127.0.0.1 100000 4 2>&1 || :
sleep 2
ssh -o LogLevel=ERROR netbsd 'kill $(cat /var/tmp/p111.pid) 2>/dev/null; sleep 1; tcpdump -n -r /var/tmp/p111.pcap 2>&1 | head -40' || :
sleep 1; cat "$OUT/nfsacl-p111-runner.txt" | head -40
ssh -o LogLevel=ERROR netbsd "netstat -an | grep -E '[.](111|2049|4002) '; ps -axo pid,args | grep '[r]pcbind'; cat /etc/hosts.allow /etc/hosts.deny 2>/dev/null; npfctl show 2>/dev/null | head -5; ifconfig -a | grep inet" || :
# The calls of the illumos client, to see what runat and ls -l ask.
sudo tcpdump -i any -s 0 -w "$OUT/nfsacl-omnios.pcap" 'tcp port 2049' >/dev/null 2>&1 &
sleep 2
# Bounded and shown as it goes: a call the server never answers holds
# the client, and the line it stopped at is the one to see.
timeout 1200 ssh omnios 'sh /var/tmp/omnios.sh' 2>&1 | tee "$L" |
    sed 's/^/omnios: /'
sudo pkill -x tcpdump
sudo kill $NAT 2>/dev/null
sleep 1
sudo chmod 644 "$OUT/nfsacl-omnios.pcap" 2>/dev/null
if command -v tshark >/dev/null; then
	tshark -r "$OUT/nfsacl-omnios.pcap" -Y 'nfsacl || nfs' -T fields \
	    -e frame.time_relative -e rpc.program -e rpc.programversion \
	    -e rpc.procedure -e rpc.msgtyp -e nfs.status3 \
	    >"$OUT/nfsacl-omnios-calls.txt" 2>&1 || :
	echo "calls captured: $(wc -l <"$OUT/nfsacl-omnios-calls.txt")"
fi
awk '/^=== /{f=sprintf("%s/acl.%s", T, $2); print $3 " " $4 > (f ".where"); next}
    f != "" && /^[a-z]+:/{print > f}
    /^\$ |^ok|^FAILED|^failures/{f=""}' T="$OUT" "$L"
for w in "$OUT"/acl.*.where; do
	[ -e "$w" ] || continue
	c=${w%.where}
	read sp d <"$w"
	ssh -o LogLevel=ERROR netbsd "sh /var/tmp/nfsv4/sacl.sh $d '$sp'" >"$c.server"
	# A file system of NFSv4 ACLs has no POSIX.1e ACL to show, and the
	# server makes one of the mode (nfsacl_acl_from_mode()); that is
	# what the client must print.
	if grep -q '@:' "$c.server"; then
		ssh -o LogLevel=ERROR netbsd "stat -f %Lp '$sp'" | awk '{
		    split("user::,group::,other::", w, ",")
		    for (i = 1; i <= 3; i++) {
			b = substr($1, i, 1) + 0
			print w[i] (b >= 4 ? "r" : "-") (b % 4 >= 2 ? "w" : "-") (b % 2 ? "x" : "-")
		    }}' | sort >"$c.server"
	fi
	# The server sends an ACL of three entries as four, with a mask of
	# the group's (design: the encode of 3 to 4), and illumos prints
	# it; the server's own has none.  Such a mask is dropped here.
	if ! grep -q '^user:[^:]' "$c" && ! grep -q '^group:[^:]' "$c" &&
	    ! grep -q '^mask::' "$c.server" &&
	    [ "$(sed -n 's/^mask:://p' "$c")" = "$(sed -n 's/^group:://p' "$c")" ]; then
		grep -v '^mask::' "$c" >"$c.n" && mv "$c.n" "$c"
	fi
	if cmp -s "$c" "$c.server"; then echo "same: ${c##*/acl.}"; else
		echo "DIFFERENT: ${c##*/acl.}"; diff "$c" "$c.server"; fi
done | tee -a "$L"
# Named attributes: the list runat gives against the server's, and the
# bytes of a: as the client wrote them, and as the server keeps them
# (getextattr ends its print with a newline).
for v in 3 2; do
	c=$(sed -n "s/^xattr-ls v$v //p" "$L")
	s=$(ssh -o LogLevel=ERROR netbsd "lsextattr -q user /export/pacl/x$v" |
	    tr ' \t' '\n\n' | grep -v '^$' | sort | tr '\n' ' ')
	if [ -n "$c" ] && [ "$c" = "$s" ]; then echo "same: xattr-ls v$v: $c"; else
		echo "DIFFERENT: xattr-ls v$v: client '$c' server '$s'"; fi
	c=$(sed -n "s/^xattr-cat v$v //p" "$L")
	w=$(sed -n "s/^xattr-want v$v //p" "$L")
	if [ -n "$c" ] && [ "$c" = "$w" ]; then echo "same: xattr-cat v$v"; else
		echo "DIFFERENT: xattr-cat v$v: '$c' want '$w'"; fi
	s=$(ssh -o LogLevel=ERROR netbsd "getextattr -q user a /export/pacl/x$v | cksum")
	w=$(sed -n "s/^xattr-wantnl v$v //p" "$L")
	if [ -n "$s" ] && [ "$s" = "$w" ]; then echo "same: xattr-server v$v"; else
		echo "DIFFERENT: xattr-server v$v: '$s' want '$w'"; fi
done | tee -a "$L"
cat "$L"
grep -q '^failures: 0$' "$L" && ! grep -q '^DIFFERENT' "$L"
