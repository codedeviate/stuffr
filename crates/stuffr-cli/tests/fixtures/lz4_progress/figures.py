#!/usr/bin/env python3
"""Record lz4's compression progress figures over generated text.

usage: figures.py LZ4

For each shape below: generate the input, record `LZ4 -f -T1 -vvvv [OPTS] in
in.lz4` with `record.py` (standard error a pty) into `figures_<shape>.rec`,
and write `figures_<shape>.jobs`: one line per refresh the reference should
draw, `<input before the job> <bytes counted> <one-shot 0|1>`, computed from
the reference's own output file:
- a one-shot frame (input under 4 MiB): the whole input, the whole frame;
- a streamed frame: per 4 MiB job (one 4 MiB block each), the input before
  it and the block bytes written so far, without the header, end mark or
  checksum;
- a legacy frame: per 8 MiB job, the input before it and everything written
  so far, magic included.

The input is `text(n, 51)`, a port of `compat_harness::text` (XorShift over
its word list), byte-identical to the Rust one; the shapes are prefixes of
one stream.
"""
import os, struct, subprocess, sys, tempfile

LZ4 = sys.argv[1]
HERE = os.path.dirname(os.path.abspath(__file__))
WORDS = [b"the", b"quick", b"brown", b"fox", b"jumps", b"over", b"lazy", b"dog",
         b"stuffr", b"gzip", b"member", b"deflate", b"header", b"and", b"of",
         b"a", b"to", b"in", b"file"]
MASK = (1 << 64) - 1
MIB = 1 << 20


def text(n, seed):
    x, v = seed, bytearray()
    def nxt():
        nonlocal x
        x ^= (x << 13) & MASK
        x ^= x >> 7
        x ^= (x << 17) & MASK
        return x
    while len(v) < n:
        v += WORDS[nxt() % len(WORDS)]
        v += b"\n" if nxt() % 9 == 0 else b" "
    return bytes(v[:n])


SHAPES = [  # name, input size, options
    ("2m", 2 * MIB, []),
    ("4m", 4 * MIB, []),
    ("4m1", 4 * MIB + 1, []),
    ("14m", 14 * MIB, []),
    ("14m_l", 14 * MIB, ["-l"]),
    ("14m_bd", 14 * MIB, ["-BD"]),
    ("empty", 0, []),
]


def jobs(data, frame, legacy):
    n = len(data)
    if legacy:
        assert frame[:4] == b"\x02\x21\x4c\x18"
        out, at, before = [], 4, 0
        while at < len(frame):
            (size,) = struct.unpack_from("<I", frame, at)
            at += 4 + size
            out.append((before, at, 0))
            before += 8 * MIB
        return out
    if n < 4 * MIB:
        return [(n, len(frame), 1)]
    flg = frame[4]
    at = 7 + (8 if flg & 0x08 else 0) + (4 if flg & 0x01 else 0)
    blocks, out, before = 0, [], 0
    while True:
        (word,) = struct.unpack_from("<I", frame, at)
        if word == 0:
            break
        size = word & 0x7FFFFFFF
        step = 4 + size + (4 if flg & 0x10 else 0)
        blocks += step
        at += step
        out.append((before, blocks, 0))
        before += 4 * MIB
    assert len(out) == (n + 4 * MIB - 1) // (4 * MIB), "one block per job"
    return out


with tempfile.TemporaryDirectory() as d:
    for name, size, opts in SHAPES:
        src, dst = os.path.join(d, "in"), os.path.join(d, "in.lz4")
        data = text(size, 51)
        with open(src, "wb") as f:
            f.write(data)
        rec = os.path.join(HERE, f"figures_{name}.rec")
        subprocess.run([sys.executable, os.path.join(HERE, "record.py"), rec, "--",
                        LZ4, "-f", "-T1", "-vvvv", *opts, src, dst],
                       check=True, env={**os.environ, "LC_ALL": "C"})
        with open(dst, "rb") as f:
            frame = f.read()
        with open(os.path.join(HERE, f"figures_{name}.jobs"), "w") as f:
            for row in jobs(data, frame, "-l" in opts):
                f.write("%d %d %d\n" % row)
