#!/usr/bin/env python3
"""Build LHA level-2 and level-3 archives, from the format layout alone.

Salvage Stage 2 Task 5, fix round 2 (review finding N3). This is the THIRD
independent derivation of the level-2/3 header layout that `legacy/lha_salvage.rs`
stands on, and it is checked in for one reason: the task report cited it as
evidence, and evidence a future reader cannot re-run is not evidence. The other
two derivations are `delharc 0.6.2`'s `src/header/parser.rs` (cited by line in
the module doc) and the module's own parser.

Nothing in the test suite runs this. What IS run, on every build, is
`lha_salvage.rs`'s `the_header_geometry_agrees_with_delharcs_own_parser`, which
parses the same shapes both ways and requires byte-exact agreement on the
payload start. This script exists so the CLI-level evidence in the task report
(`stuffr list` versus `stuffr salvage`, on healthy files) can be reproduced.

The repo has NO committed level-2 or level-3 fixture: every archive this writes
is a throwaway, and none of it is borrowed or externally witnessed — so its
provenance is exactly "hand-built from the published layout", the same standing
`MANIFEST.md` gives `sample.arj`. It is not a witness for the layout; it is a
second author's reading of it, which is worth having and worth not overstating.

    python3 build_level_2_and_3_lha.py OUTDIR

writes, into OUTDIR:

    level2.lzh              healthy, one stored entry, common CRC-16 correct
    level2-badcrc.lzh       the same, one bit flipped in the common CRC-16
    level2-nocommon.lzh     no common (0x00) header at all: nothing to gate on
    level2-msdos-size.lzh   a 0x42 header declaring 5000 over a base header's 100
    level2-damaged.lzh      two entries, the first header's total size wiped
    level3.lzh              healthy level 3: u32 lengths, 4-byte chain counters
"""

import os
import struct
import sys

EXT_COMMON = 0x00
EXT_FILENAME = 0x01
EXT_MSDOS_SIZE = 0x42


def crc16_arc(data: bytes) -> int:
    """CRC-16/ARC: reflected polynomial 0xA001, init 0, no final xor.

    Written out rather than imported so this file shares no code with the
    crate's `legacy::crc` or with delharc's table.
    """
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xA001 if crc & 1 else 0)
    return crc


def level2(name: bytes, content: bytes, *, common=True, good_crc=True,
           msdos_size=None, base_lie=None) -> bytes:
    """A level-2 archive holding one `-lh0-` (stored) entry.

    Base header, 26 fixed bytes: a u16 TOTAL header size at 0 (level 2 spends
    the length and checksum bytes on one figure), the 5-byte method at 2, two
    u32 sizes at 7 and 11, a u32 Unix timestamp at 15, a reserved byte, the
    level byte at 20, the file CRC-16 at 21, OS-TYPE at 23 and the u16 first
    extension-header length at 24. No filename: level 2 keeps it in a 0x01
    extension header.
    """
    declared = base_lie if base_lie is not None else len(content)

    chain = []
    if common:
        chain.append(bytes([EXT_COMMON]) + b"\x00\x00")
    if msdos_size is not None:
        chain.append(bytes([EXT_MSDOS_SIZE])
                     + struct.pack("<QQ", msdos_size, msdos_size))
    chain.append(bytes([EXT_FILENAME]) + name)

    # Each extension header is <its own bytes> + <u16 length of the NEXT one>,
    # and the chain ends with a zero.
    lengths = [len(part) + 2 for part in chain]
    total = 26 + sum(lengths)

    header = bytearray()
    header += struct.pack("<H", total)
    header += b"-lh0-"
    header += struct.pack("<II", declared, declared)
    header += struct.pack("<I", 1_000_000_000)
    header += bytes([0x20, 2])
    header += struct.pack("<H", crc16_arc(content))
    header += b"U"
    header += struct.pack("<H", lengths[0])
    assert len(header) == 26, len(header)

    common_crc_at = None
    for index, part in enumerate(chain):
        if part[0] == EXT_COMMON:
            common_crc_at = len(header) + 1
        header += part
        following = lengths[index + 1] if index + 1 < len(lengths) else 0
        header += struct.pack("<H", following)
    assert len(header) == total, (len(header), total)

    if common_crc_at is not None:
        # The checksum covers the WHOLE header with its own two bytes zeroed,
        # which is the state they are in right now.
        crc = crc16_arc(bytes(header))
        if not good_crc:
            crc = (crc + 1) & 0xFFFF
        header[common_crc_at:common_crc_at + 2] = struct.pack("<H", crc)

    return bytes(header) + content + b"\x00"


def level3(name: bytes, content: bytes) -> bytes:
    """A level-3 archive holding one `-lh0-` entry.

    Materially a different shape: the first two bytes are a mandated `4, 0`
    (the word size and a zero), the whole-header length and the first
    extension-header length are u32s at 24 and 28 rather than one u16 at 24,
    and every extension header's trailing counter is four bytes wide.
    """
    name_header = 1 + len(name) + 4
    total = 32 + name_header

    out = bytearray()
    out += bytes([4, 0])
    out += b"-lh0-"
    out += struct.pack("<II", len(content), len(content))
    out += struct.pack("<I", 1_000_000_000)
    out += bytes([0x20, 3])
    out += struct.pack("<H", crc16_arc(content))
    out += b"U"
    out += struct.pack("<II", total, name_header)
    assert len(out) == 32, len(out)

    out += bytes([EXT_FILENAME]) + name + struct.pack("<I", 0)
    assert len(out) == total, (len(out), total)

    return bytes(out) + content + b"\x00\x00"


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)

    healthy = level2(b"level2.txt", b"level two payload, thirty bytes")
    damaged = bytearray(
        level2(b"gone.txt", b"first payload")[:-1]
        + level2(b"survivor.txt", b"second payload")
    )
    damaged[0:2] = b"\xff\xff"

    files = {
        "level2.lzh": healthy,
        "level2-badcrc.lzh": level2(b"level2.txt", b"level two payload",
                                    good_crc=False),
        "level2-nocommon.lzh": level2(b"nocrc.txt", b"payload", common=False),
        "level2-msdos-size.lzh": level2(b"big.txt", b"\xee" * 5000,
                                        msdos_size=5000, base_lie=100),
        "level2-damaged.lzh": bytes(damaged),
        "level3.lzh": level3(b"level3.txt", b"level three payload"),
    }
    for filename, data in files.items():
        path = os.path.join(out, filename)
        with open(path, "wb") as handle:
            handle.write(data)
        print(f"{len(data):5}  {path}")


if __name__ == "__main__":
    main()
