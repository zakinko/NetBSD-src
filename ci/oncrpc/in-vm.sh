#!/bin/sh
# Install the modules for the running kernel and exercise them.
set -eu
D=/var/tmp/oncrpc
R=$(uname -r)
for k in "$D"/modules/*.kmod; do
	m=$(basename "$k" .kmod)
	mkdir -p "/stand/amd64/$R/modules/$m"
	cp "$k" "/stand/amd64/$R/modules/$m/"
done
sysctl kern.module.verbose
sysctl -w kern.module.verbose=1
# solaris must pull in xdr by itself.
modload solaris
modstat | grep -E '^(solaris|xdr)[[:space:]]'
modstat -n xdr | grep -q xdr
modunload solaris
modunload xdr
echo "SOLARIS+XDR OK"
if [ -f "$D/t_oncrpc.c" ]; then
	cd "$D"
	cc -g -Wall -o t_oncrpc t_oncrpc.c -latf-c
	mkdir -p k_oncrpc
	cp modules/k_oncrpc.kmod k_oncrpc/
	printf '%s\n\n%s\n\n%s\n' \
	    'Content-Type: application/X-atf-atffile; version="1"' \
	    'prop: test-suite = "oncrpc"' 'tp: t_oncrpc' >Atffile
	rc=0
	atf-run t_oncrpc >t.tps || rc=$?
	atf-report <t.tps
	# Nothing may be left holding them.
	modunload k_oncrpc || rc=1
	modunload oncrpc || rc=1
	modunload xdr || rc=1
	dmesg | grep -E 'panic|LOCKDEBUG|Mutex error' && rc=1
	exit $rc
fi
