#!/bin/sh
# What pynfs's --serverhelper asks of the server.  pynfs runs as root
# here and the way into the VM is the user's.
u=${SUDO_USER:-root}
s() { sudo -u "$u" ssh netbsd "$@"; }
case $1 in
reboot)	s 'sh /var/tmp/nfsv4/restart.sh' ;;
unlink)	s "rm '$2'" ;;
rename)	s "mv '$2' '$3'" ;;
link)	s "ln '$2' '$3'" ;;
chmod)	s "chmod $2 '$3'" ;;
*)	echo "pynfs-helper: $*" >&2; exit 1 ;;
esac
