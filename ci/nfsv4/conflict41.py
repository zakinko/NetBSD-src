#!/usr/bin/env python3
"""Open a file for writing as a second client, to take a read delegation
from the Linux client that holds it, RFC 8881 s10.4.  From pynfs's nfs4.1
directory: conflict41.py EXPORT NAME.  Waits through NFS4ERR_DELAY for
the holder to give it back."""
import sys, time
import nfs_ops, nfs4client
from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *
from server41tests.environment import use_obj
op = nfs_ops.NFS4ops()
exp = sys.argv[1].strip('/').encode().split(b'/')
name = sys.argv[2].encode()
c = nfs4client.NFS4Client(b'127.0.0.1', 2049, 1)
s = c.new_client_session(b"conflict%d" % int(time.time()))
ops = use_obj(exp + name.split(b'/')[:-1]) + [op.open(0, OPEN4_SHARE_ACCESS_WRITE,
      OPEN4_SHARE_DENY_NONE, open_owner4(0, b"conflict"),
      openflag4(OPEN4_NOCREATE), open_claim4(CLAIM_NULL, name.split(b'/')[-1]))]
delays = 0
for i in range(30):
    res = s.compound(ops)
    if res.status != NFS4ERR_DELAY:
        break
    delays += 1
    time.sleep(1)
print("open", res.status, "after", delays, "delays")
sys.exit(0 if res.status == NFS4_OK and delays > 0 else 1)
