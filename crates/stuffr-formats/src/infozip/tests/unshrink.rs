//! `unshrink.c`: the fixtures, hand-built code streams, and the damage
//! table.

use super::explode::{Bits, DAMAGED, Damaged, damage, fill, table, write_inputs};
use crate::infozip::unshrink::unshrink_counted;
use crate::infozip::{Stop, WSIZE, unshrink};

/// What one [`unshrink`] call did: the C's return code (0 for success),
/// every chunk it flushed, and the partial clears it performed.
struct Run {
    code: i32,
    chunks: Vec<usize>,
    out: Vec<u8>,
    clears: u32,
}

fn run_in(input: &[u8], window: &mut [u8]) -> Run {
    let mut chunks = Vec::new();
    let mut out = Vec::new();
    let (r, clears) = unshrink_counted(
        &mut input.iter(),
        window,
        &mut |c: &[u8]| -> Result<(), ()> {
            chunks.push(c.len());
            out.extend_from_slice(c);
            Ok(())
        },
    );
    let code = match r {
        Ok(()) => 0,
        Err(Stop::Code(c)) => c,
        Err(Stop::Flush(())) => unreachable!("this flush never fails"),
        Err(Stop::Length { .. }) => unreachable!("explode's alone"),
    };
    Run {
        code,
        chunks,
        out,
        clears,
    }
}

/// [`run_in`] over a zeroed window.
fn run(input: &[u8]) -> Run {
    run_in(input, &mut vec![0; WSIZE])
}

/// The data of every entry of `zip`, walking its local headers (none of
/// these fixtures uses a data descriptor).
fn entries(zip: &[u8]) -> Vec<&[u8]> {
    let mut at = 0;
    let mut v = Vec::new();
    while zip.len() >= at + 30 && zip[at..at + 4] == *b"PK\x03\x04" {
        assert_eq!(zip[at + 6] & 8, 0, "entry at {at} has a data descriptor");
        let entry = super::first_entry_data(&zip[at..]);
        let data_at = entry.as_ptr() as usize - zip.as_ptr() as usize;
        v.push(entry);
        at = data_at + entry.len();
    }
    v
}

/// Task 1's shrink fixtures: each entry's output is what `unzip -p <zip>
/// <name>` gives (the SHA-256s below, from `/usr/bin/unzip -p` and the same
/// in ubuntu:24.04), in one final chunk; `shrink-full-table.zip` fills the
/// code table and so performs partial clears.
#[test]
fn unshrink_fixtures() {
    for (file, n, len, sha) in [
        (
            "shrink-commons.zip",
            0,
            76,
            "1f155fbeed0dc3b21ee30e7a648c98ba1123083b814a58ad852d37447a608f0e",
        ),
        (
            "shrink-commons.zip",
            1,
            81,
            "2402e6ef55b5f8886f6632078f50a23cbc73ece37aac7951e77c2a4098acdf5f",
        ),
        (
            "shrink-full-table.zip",
            0,
            26001,
            "95f38a7766a808afb9dcb8a14fd59afcb8cbfed30627b3d86f262af44a9752ce",
        ),
    ] {
        let Some(zip) = super::fixture(file) else {
            return;
        };
        let data = entries(&zip)[n];
        let r = run(data);
        assert_eq!((r.code, &r.chunks), (0, &vec![len]), "{file} entry {n}");
        assert_eq!(super::sha256(&r.out), sha, "{file} entry {n}");
    }
}

/// Code 256 then 2 is a partial clear: `shrink-full-table.zip` fills the
/// table and clears it (counted), and decodes to `unzip -p`'s bytes after;
/// the hand-built `partial-clear` stream reuses a cleared code for a new
/// string, and `orphan-reads-the-window` (in [`hand_built_streams`]) shows
/// the clear leaving an undefined parent marked defined, as the C does.
#[test]
fn unshrink_partial_clear_is_handled() {
    if let Some(zip) = super::fixture("shrink-full-table.zip") {
        let r = run(entries(&zip)[0]);
        assert_eq!(r.code, 0);
        assert!(r.clears > 0, "shrink-full-table.zip made no partial clear");
        eprintln!("shrink-full-table.zip: {} partial clears", r.clears);
    }
    let (_, stream) = hand_streams()
        .into_iter()
        .find(|(name, _)| *name == "partial-clear")
        .unwrap();
    let r = run(&stream);
    assert_eq!((r.code, r.clears), (0, 1));
    assert_eq!(r.out, b"ababXaYb");
}

// ---- hand-built code streams ----

/// A shrink code stream: codes of the current code size, LSB first.
struct Codes {
    w: Bits,
    size: u32,
}

impl Codes {
    fn new() -> Codes {
        Codes {
            w: Bits::default(),
            size: 9,
        }
    }

    fn code(&mut self, c: u32) -> &mut Codes {
        self.w.put(c, self.size);
        self
    }

    fn codes(&mut self, cs: &[u32]) -> &mut Codes {
        for &c in cs {
            self.code(c);
        }
        self
    }

    /// 256, 1: one bit more per code.
    fn wider(&mut self) -> &mut Codes {
        self.code(256).code(1);
        self.size += 1;
        self
    }

    fn finish(self) -> Vec<u8> {
        self.w.finish()
    }
}

/// The hand-built unshrink streams: (name, stream).
fn hand_streams() -> Vec<(&'static str, Vec<u8>)> {
    let mut v = Vec::new();
    let codes = |f: &dyn Fn(&mut Codes)| {
        let mut c = Codes::new();
        f(&mut c);
        c.finish()
    };
    // nothing: READBITS finds no byte, PK_OK, no flush at all
    v.push(("empty", vec![]));
    // one literal
    v.push((
        "one-code",
        codes(&|c| {
            c.code(65);
        }),
    ));
    // 'A', then 257 before it is defined (KwKwK): "AA"
    v.push((
        "kwkwk",
        codes(&|c| {
            c.codes(&[65, 257]);
        }),
    ));
    // 'a', 'b' (257 = "ab"), 257 (258 = "ba"); 256,2 clears both, leaves
    // both; 'X' then takes the first free code, 257 again, as the child of
    // the previous code, 257 itself (an orphan, as unshrink.c's notes say);
    // 'a', 'Y', 'b' take 258 to 260
    v.push((
        "partial-clear",
        codes(&|c| {
            c.codes(&[97, 98, 257, 256, 2, 88, 97, 89, 98]);
        }),
    ));
    // the code size grows to 10, then 13, and the codes follow it:
    // 'A', 'B' (257 = "AB"), 'C', 257
    v.push((
        "wider",
        codes(&|c| {
            c.code(65)
                .wider()
                .code(66)
                .wider()
                .wider()
                .wider()
                .codes(&[67, 257]);
        }),
    ));
    // 256,1 a fifth time: 14 bits, PK_ERR, after 'A' was buffered (not
    // flushed: the error returns before the final flush)
    v.push((
        "wider-than-13",
        codes(&|c| {
            c.code(65).wider().wider().wider().wider().code(256).code(1);
        }),
    ));
    // 256 then anything but 1 or 2 is ignored
    v.push((
        "escape-other",
        codes(&|c| {
            c.codes(&[65, 256, 7, 66]);
        }),
    ));
    // the first code may be anything: 300 is output as (uch)300 = ','
    v.push((
        "first-code-300",
        codes(&|c| {
            c.codes(&[300, 65]);
        }),
    ));
    // 300 (free) as the parent of 257; a partial clear marks 300 as having
    // a child and frees 257, and 300 then decodes as defined: value[300],
    // never written, is the window's byte, then parent 0 & CODE_MASK = 0
    v.push((
        "orphan-reads-the-window",
        codes(&|c| {
            c.codes(&[300, 65, 256, 2, 300]);
        }),
    ));
    // a code whose parent chain is a free code naming itself: KwKwK
    // forever, until the 8 KiB stack underflows (PK_ERR)
    v.push((
        "stack-underflow",
        codes(&|c| {
            c.codes(&[300, 301]);
        }),
    ));
    // 7936 literals: the 7935 free codes are all taken, the next new
    // code overflows (PK_ERR), and the buffered output is never flushed
    v.push((
        "table-full",
        codes(&|c| {
            for i in 0..7937 {
                c.code(97 + i % 26);
            }
        }),
    ));
    // 'a'..'d', 256,1, then 'e' in 10 bits: 64 bits, eight bytes, which
    // the first refill took whole; then one byte, 'z'. The next READBITS
    // refills only those 8 of its 10 bits, yet a byte came, so G.zipeof
    // stays 0 and the code decodes, its missing bits zero
    let mut s = codes(&|c| {
        c.codes(&[97, 98, 99, 100]).wider().code(101);
    });
    assert_eq!(s.len(), 8);
    s.push(b'z');
    v.push(("partial-final-code", s));
    v
}

/// The hand-built streams give what `unshrink.c` gives: each expected row is
/// the C driver's (README) over the streams `write_hand_inputs` writes
/// (return code, chunks, and output, whose SHA-256 the driver printed), the
/// window zeroed or, where the second column says, 0xAA.
#[test]
fn hand_built_streams() {
    #[rustfmt::skip]
    let want: [(&str, u8, i32, &[usize], &str); 13] = [
        ("empty", 0, 0, &[], ""),
        ("one-code", 0, 0, &[1], "A"),
        ("kwkwk", 0, 0, &[3], "AAA"),
        ("partial-clear", 0, 0, &[8], "ababXaYb"),
        ("wider", 0, 0, &[5], "ABCAB"),
        ("wider-than-13", 0, 2, &[], ""),
        ("escape-other", 0, 0, &[2], "AB"),
        ("first-code-300", 0, 0, &[2], ",A"),
        ("orphan-reads-the-window", 0, 0, &[4], ",A\0\0"),
        ("orphan-reads-the-window", 0xaa, 0, &[4], ",A\0\u{aa}"),
        ("stack-underflow", 0, 2, &[], ""),
        ("table-full", 0, 2, &[], ""),
        ("partial-final-code", 0, 0, &[6], "abcdez"),
    ];
    let streams = hand_streams();
    for (name, fill, code, chunks, out) in want {
        let (_, s) = streams.iter().find(|(n, _)| *n == name).unwrap();
        let r = run_in(s, &mut vec![fill; WSIZE]);
        let out: Vec<u8> = out.chars().map(|c| c as u32 as u8).collect();
        assert_eq!(
            (r.code, &r.chunks[..], &r.out),
            (code, chunks, &out),
            "{name} (window {fill:#04x})"
        );
    }
}

/// Over 64 KiB of output: flushes of a full `G.outbuf` (65536) and the
/// rest, and nothing more.
#[test]
fn flush_chunks_are_outbuf_sized() {
    let s = {
        let mut c = Codes::new();
        // 'a' then KwKwK chains: 257 "aa", 258 "aaa", ..., widening the
        // codes at 512; 70000 bytes in all is past one outbuf
        c.code(97);
        let mut n = 1usize;
        let mut next = 257u32;
        while n < 70_000 {
            if next == 1 << c.size {
                c.wider();
            }
            c.code(next);
            n += (next - 255) as usize;
            next += 1;
        }
        c.finish()
    };
    let r = run(&s);
    assert_eq!(r.code, 0);
    let total = r.out.len();
    assert!(total > WSIZE, "{total}");
    assert_eq!(r.chunks, vec![WSIZE, total - WSIZE]);
    assert!(r.out.iter().all(|&b| b == b'a'));
}

/// Writes the hand-built streams to `$STUFFR_INFOZIP_DAMAGE_OUT/unshrink-hand/`
/// with the driver's manifest, each once over a zeroed area and once over
/// one of 0xAA.
#[test]
#[ignore = "writes the hand-built streams for the C driver; see tests/data/infozip/README"]
fn write_hand_inputs() {
    let out = std::path::PathBuf::from(
        std::env::var_os("STUFFR_INFOZIP_DAMAGE_OUT").expect("STUFFR_INFOZIP_DAMAGE_OUT"),
    )
    .join("unshrink-hand");
    std::fs::create_dir_all(&out).unwrap();
    let mut manifest = String::new();
    for (i, (name, stream)) in hand_streams().into_iter().enumerate() {
        let path = out.join(format!("{name}.in"));
        std::fs::write(&path, &stream).unwrap();
        for fill in ["00", "aa"] {
            manifest += &format!(
                "{i:03}|{name}|0|0|0|{fill}|hand|{}|{}\n",
                super::sha256(&stream),
                path.display()
            );
        }
    }
    std::fs::write(out.join("manifest.txt"), manifest).unwrap();
}

// ---- the damage table: tests/data/infozip/unshrink_damage.txt ----

/// The unshrink table's undamaged streams: (name, file, entry).
const BASES: [(&str, &str, usize); 3] = [
    ("test1", "shrink-commons.zip", 0),
    ("test2", "shrink-commons.zip", 1),
    ("full", "shrink-full-table.zip", 0),
];

/// The unshrink bases: (name, stream).
fn bases() -> Option<Vec<(&'static str, Vec<u8>)>> {
    let mut v = Vec::new();
    for (name, file, n) in BASES {
        let zip = super::fixture(file)?;
        v.push((name, entries(&zip)[n].to_vec()));
    }
    Some(v)
}

/// Damaged inputs `0..DAMAGED`, cycling through [`BASES`] (no `ucsize`
/// kind: unshrink never reads it).
fn damaged_inputs() -> Option<Vec<Damaged>> {
    let bases = bases()?;
    Some(
        (0..DAMAGED)
            .map(|i| {
                let (base, b) = &bases[(i % BASES.len() as u64) as usize];
                let (input, missing, _, kind) = damage(b, i, None);
                Damaged {
                    i,
                    base,
                    flags: 0,
                    ucsize: 0,
                    missing,
                    input,
                    kind,
                }
            })
            .collect(),
    )
}

/// One row of `unshrink_damage.txt`, the C driver's output:
/// `NNN|base|kind|input-sha256|rc|total|chunks|output-sha256`.
fn row(r: &Run, d: &Damaged) -> String {
    let chunks: Vec<String> = r.chunks.iter().map(usize::to_string).collect();
    format!(
        "{:03}|{}|{}|{}|{}|{}|{}|{}",
        d.i,
        d.base,
        d.kind,
        super::sha256(&d.input),
        r.code,
        r.out.len(),
        if chunks.is_empty() {
            "-".to_owned()
        } else {
            chunks.join(",")
        },
        super::sha256(&r.out),
    )
}

/// Every damaged input gives exactly the C's return code and flushed chunks
/// (lengths and bytes): Info-ZIP's own `unshrink.c`, compiled against a
/// stub `G` (the driver and recipe are in the fixtures' README), recorded
/// in `unshrink_damage.txt`, with `G.area` starting as [`fill`] says. A
/// truncation where the archive ends (`short`) is the same to unshrink as
/// one where the entry's data ends: it never looks at `G.csize`.
#[test]
fn damage_codes_match_the_c() {
    let Some(rows) = table("unshrink_damage.txt") else {
        return;
    };
    assert_eq!(rows.len() as u64, DAMAGED, "rows in unshrink_damage.txt");
    for (name, b) in bases().unwrap() {
        assert_eq!(run(&b).code, 0, "{name} undamaged");
    }
    let mut wrong = Vec::new();
    let mut codes = std::collections::BTreeMap::new();
    for (d, want) in damaged_inputs().unwrap().iter().zip(&rows) {
        let r = run_in(&d.input, &mut vec![fill(d.i); WSIZE]);
        *codes.entry(r.code).or_insert(0) += 1;
        let got = row(&r, d);
        if got != *want {
            wrong.push(format!("  want {want}\n  got  {got}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {DAMAGED} rows differ from unshrink.c:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    for code in [0, 2] {
        assert!(
            codes.contains_key(&code),
            "no row with code {code}: {codes:?}"
        );
    }
    eprintln!("unshrink damage codes: {codes:?}");
}

/// Recipe (README): writes the damaged inputs and the driver's manifest
/// under `$STUFFR_INFOZIP_DAMAGE_OUT/unshrink/`.
#[test]
#[ignore = "generator for unshrink_damage.txt; see tests/data/infozip/README"]
fn write_damage_inputs() {
    write_inputs("unshrink", &damaged_inputs().expect("fixtures"));
}

/// A window under `WSIZE` is refused.
#[test]
#[should_panic(expected = "under WSIZE")]
fn short_window_panics() {
    let _ = unshrink(&mut [].iter(), &mut [0; 100], &mut |_| Ok::<(), ()>(()));
}

/// The tables live in the window at `G.area.shrink`'s offsets (`Parent` as
/// native `int`s at 0, `value` at 32768, `Stack` at 40960), and the rest of
/// the window is left as it was: what the next entry's inflate or explode
/// finds there in unzip.
#[test]
fn tables_are_kept_where_the_c_keeps_them() {
    let (_, s) = hand_streams()
        .into_iter()
        .find(|(n, _)| *n == "kwkwk")
        .unwrap();
    let mut w = vec![0xaa; WSIZE];
    assert_eq!(run_in(&s, &mut w).code, 0);
    let parent = |c: usize| i32::from_ne_bytes(w[c * 4..c * 4 + 4].try_into().unwrap());
    assert_eq!(parent(0), 256);
    assert_eq!(parent(65), 256);
    assert_eq!(&w[1024..1028], [0xaa; 4], "Parent[256] is never written");
    assert_eq!(parent(257), 65, "257 = 'A' + 'A'");
    assert_eq!(parent(258), 0x2000, "FREE_CODE");
    assert_eq!(w[32768 + 66], 66, "value[66]");
    assert_eq!(w[32768 + 257], b'A', "value[257]");
    assert_eq!(w[32768 + 258], 0xaa, "value[258] is never written");
    assert_eq!(
        &w[40960 + 8190..40960 + 8192],
        b"AA",
        "the last string on the stack"
    );
    assert!(w[49152..].iter().all(|&b| b == 0xaa), "past the tables");
}

/// unshrink never reads the declared size: `shrink-full-table.zip` with its
/// ucsize patched to 10 (local and central) still gives all 26001 bytes and
/// `unzip -t` "OK" on both references (probe in compat.md, "Task 5
/// probes"), which is why [`unshrink`] takes no `ucsize`.
#[test]
fn ucsize_is_not_read() {
    let Some(zip) = super::fixture("shrink-full-table.zip") else {
        return;
    };
    let r = run(entries(&zip)[0]);
    assert_eq!((r.code, r.out.len()), (0, 26001));
}
