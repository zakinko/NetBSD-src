#!/bin/sh
# Replace /netbsd over ssh, reboot, prove which kernel came up.
#   swap.sh KERNEL MARK ssh-command...
set -eu
K=$1; MARK=$2; shift 2
old=$("$@" 'sysctl -n kern.boottime')
"$@" 'cat >/netbsd.new' <"$K"
"$@" 'cp -p /netbsd /netbsd.old && mv /netbsd.new /netbsd && sync'
"$@" '(sleep 2; shutdown -r now) >/dev/null 2>&1 &' || :
i=0; new=
while [ $i -lt 60 ]; do
	sleep 5; i=$((i + 1))
	new=$("$@" 'sysctl -n kern.boottime' 2>/dev/null) || new=
	[ -n "$new" ] && [ "$new" != "$old" ] && break
	new=
done
[ -n "$new" ]
v=$("$@" 'uname -v'); echo "$v"
case $v in *"($MARK)"*) ;; *) echo "not $MARK"; exit 1 ;; esac
"$@" 'cksum -a sha256 /netbsd' | grep -q "$(sha256sum "$K" | cut -d' ' -f1)"
echo SWAP OK
