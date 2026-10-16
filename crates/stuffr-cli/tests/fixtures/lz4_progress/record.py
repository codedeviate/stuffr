#!/usr/bin/env python3
"""Record what a command writes to standard error, as a terminal sees it.

usage: record.py OUT [--slow MB_PER_S] -- CMD...

Standard error is a pty (so the reference behaves as on a terminal); every
read from it is stored as `<milliseconds since start>\\t<repr of the bytes>`.
`--slow` makes standard output a pipe that a consumer drains at that rate,
which paces a decode (a decode of cached data is too fast to show the
refresh gate). Standard input is /dev/null.
"""
import os, pty, select, subprocess, sys, threading, time

args = sys.argv[1:]
out = args.pop(0)
rate = None
if args[0] == "--slow":
    rate = float(args[1]); args = args[2:]
assert args[0] == "--"
cmd = args[1:]
m, s = pty.openpty()
t0 = time.monotonic()
p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                     stdout=subprocess.PIPE if rate else subprocess.DEVNULL,
                     stderr=s, close_fds=True)
os.close(s)
if rate:
    def eat():
        while True:
            d = p.stdout.read(65536)
            if not d:
                break
            time.sleep(len(d) / (rate * 1e6))
    threading.Thread(target=eat, daemon=True).start()
rec = []
def grab():
    d = os.read(m, 65536)
    if d:
        rec.append((int((time.monotonic() - t0) * 1000), d))
    return d
while True:
    r, _, _ = select.select([m], [], [], 0.05)
    try:
        if r and not grab():
            break
        if not r and p.poll() is not None:
            while select.select([m], [], [], 0.05)[0] and grab():
                pass
            break
    except OSError:
        break
p.wait()
with open(out, "w") as f:
    for t, d in rec:
        f.write(f"{t}\t{d!r}\n")
