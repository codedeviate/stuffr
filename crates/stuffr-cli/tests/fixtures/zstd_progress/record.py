#!/usr/bin/env python3
"""record.py OUT DIR ARGV...: run ARGV in DIR with standard error on a
pseudo-terminal (stdin and stdout stay ordinary), write what it wrote to
standard error, raw (CR bytes kept, the tty's own LF -> CRLF translation
undone), to OUT."""
import os, pty, subprocess, sys, termios, tty
out, cwd, *argv = sys.argv[1:]
master, slave = pty.openpty()
attrs = termios.tcgetattr(slave)
attrs[1] &= ~termios.OPOST      # no \n -> \r\n translation
termios.tcsetattr(slave, termios.TCSANOW, attrs)
env = dict(os.environ, LC_ALL="C")
p = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=slave, env=env)
os.close(slave)
data = b""
while True:
    try:
        b = os.read(master, 65536)
    except OSError:
        break
    if not b:
        break
    data += b
p.wait()
open(out, "wb").write(data)
