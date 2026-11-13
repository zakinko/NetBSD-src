#!/bin/sh
# Compare NetBSD's libcrypto before and after the build-glue fix.
# /usr/bin/openssl links libcrypto statically, so a program of our own
# (evpcheck.c, linked dynamically) is pointed at each library in turn.
#   nbtest.sh <before-libdir> <after-libdir> [sym:alg ...]
# sym:alg runs "evpcheck one alg" under gdb against the after library and
# passes when the breakpoint on sym is hit.
# Environment: SPEED="alg ..."; ARMCAP=<value> sets OPENSSL_armcap.
B=$1 A=$2; shift 2
here=$(cd "$(dirname "$0")" && pwd)
w=$(mktemp -d "$HOME/nbtest.XXXXXX") || exit 1
trap 'rm -rf "$w"' EXIT
fail=0

cc -O2 -o "$w/evpcheck" "$here/evpcheck.c" -L"$A" -lcrypto || exit 1
run() { l=$1; shift; env LD_LIBRARY_PATH="$l" ${ARMCAP:+OPENSSL_armcap=$ARMCAP} "$w/evpcheck" "$@"; }

echo "machine: $(uname -m) $(sysctl -n machdep.cpu_brand 2>/dev/null)${ARMCAP:+ OPENSSL_armcap=$ARMCAP}"
for l in "$B" "$A"; do
	got=$(LD_LIBRARY_PATH="$l" ldd "$w/evpcheck" | awk '/libcrypto/ {print $3}')
	case $got in
	"$l"/*) echo "ok   loads $got" ;;
	*) echo "FAIL loads $got, not from $l"; fail=1 ;;
	esac
done

for l in "$B" "$A"; do
	run "$l" kat | sed "s|^\([a-zA-Z]*\) |\1 $(basename "$l") |"
	run "$l" kat >/dev/null || fail=1
	run "$l" out 1 > "$w/$(basename "$l").out" || fail=1
done
if grep FAIL "$w"/*.out; then fail=1; fi
n=$(wc -l < "$w/$(basename "$A").out")
if cmp -s "$w/$(basename "$B").out" "$w/$(basename "$A").out"; then
	echo "ok   $n results identical"
else
	echo "FAIL results differ:"; diff "$w/$(basename "$B").out" "$w/$(basename "$A").out" | head; fail=1
fi

/usr/bin/openssl genpkey -algorithm SM2 -out "$w/sm2.key" 2>/dev/null
/usr/bin/openssl pkey -in "$w/sm2.key" -pubout -out "$w/sm2.pub"
for s in "$B" "$A"; do for v in "$B" "$A"; do
	if run "$s" sm2sign "$w/sm2.key" "$w/sig" && run "$v" sm2verify "$w/sm2.pub" "$w/sig"; then
		echo "ok   sm2 sign $(basename "$s") verify $(basename "$v")"
	else
		echo "FAIL sm2 sign $(basename "$s") verify $(basename "$v")"; fail=1
	fi
done; done

# The assembler is linked into both libraries; only the fixed one calls it.
# gdb here does not resolve pending breakpoints when a library loads, so
# stop at main first and set the breakpoint once libcrypto is mapped.
reached() { # lib sym alg
	env LD_LIBRARY_PATH="$1" ${ARMCAP:+OPENSSL_armcap=$ARMCAP} gdb -nx -batch \
	    -ex "break main" -ex run -ex "break $2" -ex continue -ex "info symbol \$pc" \
	    --args "$w/evpcheck" one "$3" < /dev/null 2>&1 | grep -q "^$2 in section"
}
for spec in "$@"; do
	sym=${spec%%:*} alg=${spec#*:}
	if reached "$A" "$sym" "$alg"; then a=reached; else a="not reached"; fi
	if reached "$B" "$sym" "$alg"; then b=reached; else b="not reached"; fi
	if [ "$a" = reached ] && [ "$b" != reached ]; then
		echo "ok   $sym ($alg): $(basename "$A") $a, $(basename "$B") $b"
	else
		echo "FAIL $sym ($alg): $(basename "$A") $a, $(basename "$B") $b"; fail=1
	fi
done

# Three alternating rounds, so a busy host shows up as scatter rather than
# as a difference between the libraries.
for alg in $SPEED; do
	for r in 1 2 3; do
		for l in "$B" "$A"; do
			printf '%-12s ' "$(basename "$l")"; run "$l" speed "$alg"
		done
	done
done

[ $fail = 0 ] && echo PASS || echo FAIL
exit $fail
