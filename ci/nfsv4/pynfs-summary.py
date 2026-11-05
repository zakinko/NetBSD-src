#!/usr/bin/env python3
"""Count a pynfs --json result and list every test by outcome.

The JSON distinguishes only failure, skipped and the rest, and pynfs's
"warning" lands in the rest, so the text log is read for the count of warnings
and compared.
"""
import json, re, sys

js, log = sys.argv[1:3]
d = json.load(open(js))
rows = []
for t in d['testcase']:
    if 'failure' in t:
        s = 'FAIL'
    elif 'skipped' in t:
        s = 'OMIT'
    else:
        s = 'PASS'
    rows.append((t['code'], t['name'], s,
                 t.get('failure', {}).get('message', '').replace('\n', ' ')))
n = {k: sum(r[2] == k for r in rows) for k in ('PASS', 'FAIL', 'OMIT')}
print('tests %d pass-or-warn %d fail %d omit %d time %.0fs' % (
    len(rows), n['PASS'], n['FAIL'], n['OMIT'], d['time']))
print('json header: tests=%s failures=%s skipped=%s' % (d['tests'], d['failures'], d['skipped']))
for l in open(log, errors='replace'):
    if re.search(r'\bOf those:|tests? run|Skipped,', l, re.I):
        print('log: ' + l.strip())
with open(js.replace('.json', '.tsv'), 'w') as f:
    f.write('code\tname\tresult\tmessage\n')
    for r in sorted(rows):
        f.write('\t'.join(r) + '\n')
print('failed: ' + ' '.join(r[0] for r in sorted(rows) if r[2] == 'FAIL'))
