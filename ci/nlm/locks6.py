#!/usr/bin/python3
"""A blocked lock over IPv6: NLM_GRANTED has to find the client through
rpcbind's GETADDR.  locks6.py FILE"""
import fcntl, os, select, signal, sys, time
P = sys.argv[1]
def holder(wait):
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        f = open(P, 'r+')
        try:
            fcntl.lockf(f, fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB), 10, 7000)
            os.write(w, b'1')
        except OSError:
            os.write(w, b'0')
        signal.pause()
        os._exit(0)
    return pid, r
a, ra = holder(False)
assert os.read(ra, 1) == b'1'
b, rb = holder(False)
x = os.read(rb, 1)
print('second, not waiting:', x)
os.kill(b, 9); os.waitpid(b, 0)
c, rc = holder(True)
assert not select.select([rc], [], [], 2)[0]
t = time.time()
os.kill(a, 9); os.waitpid(a, 0)
ok = select.select([rc], [], [], 25)[0]
dt = time.time() - t
print('waiter', 'got it' if ok else 'timed out', f'in {dt:.1f} s')
os.kill(c, 9); os.waitpid(c, 0)
sys.exit(0 if x == b'0' and ok and dt < 10 else 1)
