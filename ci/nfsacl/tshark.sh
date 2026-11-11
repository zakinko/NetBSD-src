#!/bin/sh
# Wireshark's packet-nfsacl.c reads the capture of linux.sh and probe.py:
# every NFSACL frame decodes, to its end, with no expert warning.
# tshark.sh PCAP OUT
P=$1; OUT=$2
tshark -v | head -1
tshark -r "$P" -Y nfsacl -T fields -e frame.number -e rpc.msgtyp \
    -e nfsacl.procedure_v3 -e nfs.status -e nfsacl.mask -e nfsacl.aclcnt \
    -e nfsacl.dfaclcnt >"$OUT/nfsacl-fields.txt"
echo "NFSACL frames: $(wc -l <"$OUT/nfsacl-fields.txt")"
awk -F'\t' '{ k = ($2 == 0 ? "call" : "reply") " proc " $3; n[k]++ }
    END { for (k in n) print k ": " n[k] }' "$OUT/nfsacl-fields.txt" | sort
tshark -r "$P" -Y nfsacl -V >"$OUT/nfsacl-decode.txt"
bad=$(tshark -r "$P" -Y 'nfsacl && (_ws.malformed || _ws.expert.severity >= "warning")' | wc -l)
echo "malformed or warned: $bad"
grep -n -i -E 'malformed|garbage|exception' "$OUT/nfsacl-decode.txt" | head -20
calls=$(awk -F'\t' '$2 == 1 && ($3 == 1 || $3 == 2)' "$OUT/nfsacl-fields.txt" | wc -l)
echo "GETACL and SETACL replies: $calls"
[ "$bad" -eq 0 ] && [ "$calls" -gt 0 ] &&
    ! grep -q -i -E 'malformed|garbage' "$OUT/nfsacl-decode.txt"
