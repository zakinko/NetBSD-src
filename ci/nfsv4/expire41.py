#!/usr/bin/env python3
"""A client of 4.1 whose lease runs out keeps its client ID and session,
RFC 8881 s8.4.3: SEQUENCE renews it (s8.3) and says that state was
revoked, the stateids it held answer NFS4ERR_EXPIRED until FREE_STATEID
(s15.1.5.4, s18.38.3), and a new OPEN or LOCK, which names none of them,
is not refused.  Run from pynfs's nfs4.1 directory: expire41.py EXPORT.
Failures are the measurement."""
import sys, time, traceback
import nfs_ops, nfs4client, nfs4lib
from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *
from server41tests.environment import create_file, check
op = nfs_ops.NFS4ops()
fails = 0
def t(name, got, want):
    global fails
    want = want if isinstance(want, (list, tuple)) else [want]
    ok = got in want
    print("%s %s: got %s, want %s" % ("ok  " if ok else "FAIL", name, got, want))
    sys.stdout.flush()
    if not ok:
        fails += 1

export = sys.argv[1].strip('/').encode().split(b'/')
stamp = b"%d" % int(time.time())
c = nfs4client.NFS4Client(b'127.0.0.1', 2049, 1)
c.homedir = export
# SessionRecord.compound() takes SEQUENCE's result out; keep it.
remove_seq_op = nfs4client.SessionRecord.remove_seq_op
def keep_seq(self, res):
    self.last_seq = res.resarray[0]
    return remove_seq_op(self, res)
nfs4client.SessionRecord.remove_seq_op = keep_seq
def flags(res):
    return s.last_seq.sr_resok4.sr_status_flags
try:
    s = c.new_client_session(stamp + b"x")
    res = create_file(s, stamp + b"old", path=export + [stamp + b"old"])
    check(res)
    ofh, osid = res.resarray[-1].object, res.resarray[-2].stateid
    # The lease is NFSV4_LEASE, 90 s, and the lease thread looks every 10.
    print("waiting for the lease to run out")
    sys.stdout.flush()
    time.sleep(115)
    res = s.compound([])
    t("s8.3 SEQUENCE after the lease ran out", res.status, NFS4_OK)
    t("s8.4.3 EXPIRED_ALL_STATE_REVOKED",
      bool(flags(res) & SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED), True)
    res = create_file(s, stamp + b"new", path=export + [stamp + b"new"])
    t("s15.1.5.4 a new OPEN is not EXPIRED", res.status, NFS4_OK)
    if res.status == NFS4_OK:
        nfh, nsid = res.resarray[-1].object, res.resarray[-2].stateid
        res = s.compound([op.putfh(nfh), op.lock(WRITE_LT, False, 0, 10,
            locker4(True, open_to_lock_owner4(0, nsid, 0,
            lock_owner4(0, stamp + b"lo"))))])
        t("s15.1.5.4 a new LOCK is not EXPIRED", res.status, NFS4_OK)
        res = s.compound([op.putfh(nfh), op.read(stateid4(0, nsid.other),
            0, 10)])
        t("the new open reads", res.status, NFS4_OK)
    res = s.compound([op.test_stateid([osid])])
    t("s8.4.3 TEST_STATEID of the old open",
      res.resarray[-1].tsr_status_codes[0] if res.status == NFS4_OK
      else res.status, NFS4ERR_EXPIRED)
    res = s.compound([op.putfh(ofh), op.read(stateid4(0, osid.other), 0, 10)])
    t("s8.4.3 READ with the old open", res.status, NFS4ERR_EXPIRED)
    res = s.compound([op.free_stateid(osid)])
    t("s18.38.3 FREE_STATEID of the old open", res.status, NFS4_OK)
    res = s.compound([op.test_stateid([osid])])
    t("s18.38.3 freed: BAD_STATEID",
      res.resarray[-1].tsr_status_codes[0] if res.status == NFS4_OK
      else res.status, NFS4ERR_BAD_STATEID)
    res = s.compound([])
    t("s8.4.3 nothing lost left: the flag is gone",
      bool(flags(res) & SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED), False)
except Exception:
    traceback.print_exc()
    t("exception", "exception", "none")
print("failures:", fails)
sys.exit(0)
