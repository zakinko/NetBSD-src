#!/bin/sh
# On the runner: an ACL as the client's getfacl prints it, in the form
# of sacl.sh.  cacl.sh [-d] FILE
# Without -d, -a: getfacl of Linux prints the default entries too.
d=-a
[ "$1" = -d ] && { d=-d; shift; }
getfacl -n -c $d "$1" 2>/dev/null | sed -e 's/#.*//' -e 's/[[:space:]]*$//' | grep -v '^$' | sort
