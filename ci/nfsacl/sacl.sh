#!/bin/sh
# In the VM: an ACL as getfacl prints it, numeric, one entry a line,
# sorted, with nothing but the entries.  sacl.sh [-d] FILE
d=
[ "$1" = -d ] && { d=-d; shift; }
getfacl -n $d "$1" | sed -e 's/#.*//' -e 's/[[:space:]]*$//' | grep -v '^$' | sort
