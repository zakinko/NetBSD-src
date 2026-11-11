#!/bin/sh
# Which of the tests in the VM a push needs, from the files it changed:
# select.sh BASE [HEAD].  Prints the names, space separated, with a space
# at each end so that a workflow can ask contains(..., ' name ').  The run
# of everything is the workflow_dispatch one; this is for the push.
#
# A source file brings in the tests that go through it; a test changed
# brings in itself.  A base that is not there (a new branch, a rewritten
# one) means the last commit only.
set -eu
base=$1 head=${2:-HEAD}
if ! git cat-file -e "$base^{commit}" 2>/dev/null; then
	base=$(git rev-parse "$head~1")
fi
t=
add() { for n; do case " $t " in *" $n "*) ;; *) t="$t $n";; esac; done; }
for f in $(git diff --name-only "$base" "$head"); do
	case $f in
	sys/fs/nfsv4/nfsv4_acl.c)	add aclcreate t41b;;
	sys/fs/nfsv4/nfsv4_open.c|sys/fs/nfsv4/nfsv4_change.c)
					add aclcreate retention t41b t40rm;;
	sys/fs/nfsv4/nfsv4_attr.c)	add owner retention named t41b;;
	sys/fs/nfsv4/nfsv4_idmap.c)	add owner;;
	sys/fs/nfsv4/nfsv4_xattr.c)	add named retention;;
	sys/fs/nfsv4/nfsv4_cb.c|sys/fs/nfsv4/nfsv4_deleg.c)
					add cbgetattr t41b t40rm;;
	sys/fs/nfsv4/nfsv4_ops.c)	add edge t41b;;
	sys/fs/nfsv4/nfsv4_referral.c)	add fsloc t41b;;
	sys/fs/nfsv4/*|sys/modules/nfsv4/*|sys/oncrpc/*)
					add t41b;;
	sys/nfs/*|sys/kern/vfs_vnops.c|sys/kern/vfs_syscalls.c)
					add t41b cbgetattr;;
	ci/nfsv4/aclcreate.py)		add aclcreate;;
	ci/nfsv4/owner.py)		add owner;;
	ci/nfsv4/retention.py)		add retention;;
	ci/nfsv4/named-attr.py)		add named;;
	ci/nfsv4/cbgetattr.sh|ci/nfsv4/more.py)	add cbgetattr;;
	ci/nfsv4/edge.py)		add edge;;
	ci/nfsv4/t41b.py)		add t41b;;
	ci/nfsv4/t40rm.py)		add t40rm;;
	ci/nfsv4/each-commit.sh)	add each;;
	ci/nfsv4/in-vm.sh|ci/nfsv4/nfsv4d.c|ci/nfsv4/pynfs.sh)
					add t41b;;
	esac
done
echo "$t "
