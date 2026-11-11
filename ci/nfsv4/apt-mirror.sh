#!/bin/sh
# Point apt away from *.ubuntu.com when the runner cannot resolve it, as
# from 2026-11-11 14:57Z, when every apt-get in the jobs failed with
# "Temporary failure resolving".  Runs first in each job, so that what
# comes after, the steps of the actions included, finds a mirror that
# answers.  Nothing is changed when ubuntu.com resolves.
set -u
M=${APT_MIRROR:-http://mirrors.edge.kernel.org/ubuntu/}
if getent hosts azure.archive.ubuntu.com >/dev/null &&
    getent hosts security.ubuntu.com >/dev/null; then
	echo "apt-mirror: ubuntu.com resolves, left alone"
	exit 0
fi
echo "apt-mirror: ubuntu.com does not resolve, using $M"
for f in /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list; do
	[ -f "$f" ] || continue
	sudo sed -i -E "s#https?://[a-z.]*ubuntu\.com/ubuntu/?#$M#g" "$f"
done
sudo apt-get update -q >/dev/null 2>&1 || echo "apt-mirror: update failed"
