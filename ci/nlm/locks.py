#!/usr/bin/python3
"""fcntl and flock on a file of a version 3 mount, as a Linux program does
them.  locks.py V3FILE V4FILE: V4FILE is the same file by version 4.0.
Each lock is held by a process of its own, killed to let it go."""
import fcntl, os, select, signal, struct, subprocess, sys, time

V3, V4 = sys.argv[1], sys.argv[2]
fails = 0

def check(what, got, want):
    global fails
    print(('ok   ' if got == want else 'FAIL ') + f'{what} = {got}' +
          ('' if got == want else f', wanted {want}'), flush=True)
    if got != want:
        fails += 1

class Holder:
    def __init__(self, path, typ, off, ln, wait=False, flock=False):
        self.r, w = os.pipe()
        self.pid = os.fork()
        if self.pid == 0:
            os.close(self.r)
            f = open(path, 'r+')
            nb = 0 if wait else fcntl.LOCK_NB
            try:
                if flock:
                    fcntl.flock(f, typ | nb)
                else:
                    fcntl.lockf(f, typ | nb, ln, off)
                os.write(w, b'1')
            except OSError:
                os.write(w, b'0')
                os._exit(1)
            signal.pause()
            os._exit(0)
        os.close(w)
    def result(self, timeout=8):
        r, _, _ = select.select([self.r], [], [], timeout)
        return os.read(self.r, 1).decode() if r else 'blocked'
    def drop(self):
        os.kill(self.pid, signal.SIGKILL)
        os.waitpid(self.pid, 0)
        os.close(self.r)

def tryit(path, typ, off, ln, **k):
    h = Holder(path, typ, off, ln, **k)
    v = h.result()
    h.drop()
    return v == '1'

EX, SH = fcntl.LOCK_EX, fcntl.LOCK_SH

print('# ranges, two processes')
h = Holder(V3, EX, 0, 10)
check('first holds', h.result(), '1')
check('inside is refused', tryit(V3, EX, 5, 1), False)
check('outside passes', tryit(V3, EX, 20, 1), True)
f = open(V3, 'r+')
fl = struct.pack('hhqqi', fcntl.F_WRLCK, 0, 5, 1, 0)
r = struct.unpack('hhqqi', fcntl.fcntl(f, fcntl.F_GETLK, fl))
check('F_GETLK type', r[0], fcntl.F_WRLCK)
check('F_GETLK start', r[2], 0)
check('F_GETLK len', r[3], 10)
f.close()
h.drop()
check('free after', tryit(V3, EX, 5, 1), True)

print('# shared with shared')
h = Holder(V3, SH, 100, 10)
check('first', h.result(), '1')
check('second shared overlaps', tryit(V3, SH, 105, 10), True)
check('exclusive is refused', tryit(V3, EX, 105, 1), False)
h.drop()

print('# one process splits a lock')
f = open(V3, 'r+')
fcntl.lockf(f, EX, 100, 200)
fcntl.lockf(f, fcntl.LOCK_UN, 20, 240)
check('the hole is free', tryit(V3, EX, 245, 1), True)
check('left still held', tryit(V3, EX, 230, 1), False)
check('right still held', tryit(V3, EX, 270, 1), False)
f.close()

print('# blocking: NLM_GRANTED, or it would be 30 seconds of polling')
h = Holder(V3, EX, 300, 10)
check('holder', h.result(), '1')
w = Holder(V3, EX, 300, 10, wait=True)
check('waiter waits', w.result(2), 'blocked')
t0 = time.time()
h.drop()
check('waiter gets it', w.result(25), '1')
dt = time.time() - t0
print(f'     in {dt:.1f} s')
check('under 10 s', dt < 10, True)
w.drop()

print('# a waiter killed: NLM_CANCEL')
h = Holder(V3, EX, 320, 10)
check('holder', h.result(), '1')
w = Holder(V3, EX, 320, 10, wait=True)
check('waiter waits', w.result(2), 'blocked')
w.drop()
time.sleep(2)
print(subprocess.run(['ssh', 'netbsd', 'sysctl vfs.nlm.nwaiters'],
                     capture_output=True, text=True).stdout.strip(), flush=True)
h.drop()
check('free', tryit(V3, EX, 320, 10), True)

print('# flock(2), which Linux turns into a whole-file lock over NLM')
h = Holder(V3, EX, 0, 0, flock=True)
check('flock', h.result(), '1')
check('second flock refused', tryit(V3, EX, 0, 0, flock=True), False)
h.drop()
check('free', tryit(V3, EX, 0, 0, flock=True), True)

print('# version 3 against version 4.0: VOP_ADVLOCK is the place they meet')
h = Holder(V3, EX, 400, 10)
check('v3 holds', h.result(), '1')
check('v4 refused', tryit(V4, EX, 405, 1), False)
check('v4 beside passes', tryit(V4, EX, 420, 1), True)
h.drop()
check('v4 free', tryit(V4, EX, 405, 1), True)
h = Holder(V4, EX, 500, 10)
check('v4 holds', h.result(), '1')
check('v3 refused', tryit(V3, EX, 505, 1), False)
check('v3 beside passes', tryit(V3, EX, 520, 1), True)
h.drop()
check('v3 free', tryit(V3, EX, 505, 1), True)
h = Holder(V4, EX, 600, 10)
check('v4 holds', h.result(), '1')
w = Holder(V3, EX, 600, 10, wait=True)
check('v3 waits on v4', w.result(2), 'blocked')
t0 = time.time()
h.drop()
check('v3 gets it when v4 lets go', w.result(25), '1')
print(f'     in {time.time() - t0:.1f} s')
w.drop()

print(f'failures: {fails}')
sys.exit(1 if fails else 0)
