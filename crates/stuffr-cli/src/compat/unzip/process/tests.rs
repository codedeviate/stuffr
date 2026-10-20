//! process.c pieces, unit by unit, and a sandboxed run end to end.

use std::ffi::OsString;

use super::*;
use crate::compat::unzip::{EXIT_CODES_APPLE, Flavour, run_in_counted};

/// One stored entry per name (no extra field, MS-DOS time 0) and the end
/// record, as a minimal writer makes them.
fn tiny_zip(names: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for name in names {
        let off = out.len() as u32;
        out.extend_from_slice(&LOCAL_HDR_SIG);
        out.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&[0; 12]); // crc, sizes
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(name);
        central.extend_from_slice(&CENTRAL_HDR_SIG);
        central.extend_from_slice(&[30, 3, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        central.extend_from_slice(&[0; 12]);
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0; 8]); // extra, comment, disk, internal
        central.extend_from_slice(&(0o100644u32 << 16).to_le_bytes());
        central.extend_from_slice(&off.to_le_bytes());
        central.extend_from_slice(name);
    }
    let (at, len, n) = (out.len() as u32, central.len() as u32, names.len() as u16);
    out.extend(central);
    out.extend_from_slice(&END_CENTRAL_SIG);
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&at.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

/// A scratch directory holding `files`, removed when dropped.
struct Dir(std::path::PathBuf);
impl Dir {
    fn with(tag: &str, files: &[(&str, &[u8])]) -> Dir {
        let d = std::env::temp_dir().join(format!("stuffr-unzip-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        for (name, bytes) in files {
            std::fs::write(d.join(name), bytes).unwrap();
        }
        Dir(d)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(d: &Dir, args: &[&str]) -> (i32, String, String, crate::compat::host::InputReads) {
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let (code, out, err, reads) =
        run_in_counted(Flavour::Apple, &d.0, "unzip", &args, b"", &|_| None);
    let total = reads
        .values()
        .fold(crate::compat::host::InputReads::default(), |a, r| {
            crate::compat::host::InputReads {
                opens: a.opens + r.opens,
                bytes: a.bytes + r.bytes,
                len: a.len.max(r.len),
            }
        });
    (
        code,
        String::from_utf8_lossy(&out).into_owned(),
        String::from_utf8_lossy(&err).into_owned(),
        total,
    )
}

/// A listing in the sandbox (R7): the archive is opened through
/// `Host::track`, every byte read is counted, and the walk reads the
/// archive about once.
#[test]
fn a_sandboxed_listing_reads_through_track() {
    let z = tiny_zip(&[b"a.txt", b"dir/b.txt"]);
    let d = Dir::with("sandbox-list", &[("t.zip", &z)]);
    let (code, out, err, reads) = run(&d, &["-l", "t.zip"]);
    assert_eq!((code, err.as_str()), (0, ""), "{out}");
    assert!(out.starts_with("Archive:  t.zip\n"), "{out}");
    assert!(
        out.contains(" a.txt\n") && out.contains(" dir/b.txt\n"),
        "{out}"
    );
    assert!(out.ends_with(" 2 files\n"), "{out}");
    assert_eq!(reads.opens, 1);
    assert!(
        reads.bytes >= z.len() as u64 && reads.bytes <= 3 * z.len() as u64,
        "{reads:?}"
    );
}

/// Every listing mode over a few hostile shapes: no panic, an exit code
/// unzip has.
#[test]
fn hostile_archives_never_panic() {
    let good = tiny_zip(&[b"a", b"b"]);
    let mut shapes: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"PK\x05\x06".to_vec(),
        good[good.len() - 22..].to_vec(),
        good[..good.len() - 1].to_vec(),
    ];
    // Every count, size and offset of the end record all ones.
    let mut ones = good.clone();
    let e = ones.len() - 22;
    ones[e + 4..e + 20].fill(0xff);
    shapes.push(ones);
    // A Zip64 locator pointing past itself, and one pointing at 0.
    for target in [u64::MAX, 0] {
        let mut z = good[..good.len() - 22].to_vec();
        z.extend_from_slice(&END_CENTLOC64_SIG);
        z.extend_from_slice(&0u32.to_le_bytes());
        z.extend_from_slice(&target.to_le_bytes());
        z.extend_from_slice(&1u32.to_le_bytes());
        z.extend_from_slice(&good[good.len() - 22..]);
        shapes.push(z);
    }
    // A name length of 65535 running off the end.
    let mut long = good.clone();
    let c = long.windows(4).position(|w| w == CENTRAL_HDR_SIG).unwrap();
    long[c + 28..c + 30].copy_from_slice(&[0xff, 0xff]);
    shapes.push(long);
    for (i, z) in shapes.iter().enumerate() {
        let d = Dir::with(&format!("hostile-{i}"), &[("h.zip", z)]);
        for args in [
            &["-l", "h.zip"][..],
            &["-v", "h.zip"],
            &["-z", "h.zip"],
            &["-qT", "h.zip"],
        ] {
            let (code, out, err, _) = run(&d, args);
            assert!(
                EXIT_CODES_APPLE.contains(&code),
                "shape {i} {args:?}: exit {code}\n{out}\n{err}"
            );
        }
    }
}

fn entry() -> CentralEntry {
    CentralEntry::default()
}

#[test]
fn zip64_values_replace_the_all_ones_fields_in_order() {
    let env = |_: &str| None;
    let mut err: Vec<u8> = Vec::new();
    let host = crate::compat::host::Host::Real;
    let mut uz = Uz::new(host, Flavour::Apple, &env, &mut err);
    let mut ef = vec![0x01, 0x00, 24, 0];
    for v in [5_000_000_000u64, 3_000_000_000, 77] {
        ef.extend_from_slice(&v.to_le_bytes());
    }
    // Only ucsize and the offset are all ones: they take the first two.
    let mut e = CentralEntry {
        ucsize: 0xffff_ffff,
        csize: 10,
        relative_offset_local_header: 0xffff_ffff,
        ..entry()
    };
    assert_eq!(get_zip64_data(&mut uz, &mut e, &ef), PK_COOL);
    assert_eq!(
        (e.ucsize, e.csize, e.relative_offset_local_header),
        (5_000_000_000, 10, 3_000_000_000)
    );
    assert_eq!(uz.lrec.ucsize, 5_000_000_000);

    // A value past what is left of the field: PK_ERR.
    let mut e = CentralEntry {
        ucsize: 0xffff_ffff,
        csize: 0xffff_ffff,
        ..entry()
    };
    let short = [0x01, 0x00, 8, 0, 1, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(get_zip64_data(&mut uz, &mut e, &short), PK_ERR);
    assert_eq!(e.ucsize, 1); // the first value was taken before the second failed

    // A block that runs past the field ends the scan.
    let mut e = CentralEntry {
        ucsize: 0xffff_ffff,
        ..entry()
    };
    uz.lrec = Lrec::default();
    assert_eq!(
        get_zip64_data(&mut uz, &mut e, &[0x01, 0x00, 40, 0, 1, 2]),
        PK_COOL
    );
    assert_eq!(e.ucsize, 0xffff_ffff);

    // The C checks against the rest of the whole field, not the block:
    // a 4-byte block followed by another block still yields 8 bytes.
    let mut e = CentralEntry {
        ucsize: 0xffff_ffff,
        ..entry()
    };
    let spill = [0x01, 0x00, 4, 0, 9, 0, 0, 0, 0x99, 0x99, 0, 0];
    assert_eq!(get_zip64_data(&mut uz, &mut e, &spill), PK_COOL);
    // (byte 5, the second 0x99, is left out: `makeint64()`.)
    assert_eq!(e.ucsize, 0x0099_0000_0009);
}

#[test]
fn unix_times_from_the_extra_field() {
    let ut = |flags: u8, times: &[u32]| {
        let mut v = b"UT".to_vec();
        v.extend_from_slice(&((1 + 4 * times.len()) as u16).to_le_bytes());
        v.push(flags);
        for t in times {
            v.extend_from_slice(&t.to_le_bytes());
        }
        v
    };
    let mut z = IzTimes::default();
    // Central: the modification time only.
    let f = ef_scan_for_izux(&ut(7, &[1_600_000_000, 2, 3]), true, 0, Some(&mut z));
    assert_eq!((f, z.mtime, z.atime), (7, 1_600_000_000, 0));
    // Local: all three.
    let mut z = IzTimes::default();
    let f = ef_scan_for_izux(&ut(7, &[1_600_000_000, 2, 3]), false, 0, Some(&mut z));
    assert_eq!((f, z.mtime, z.atime, z.ctime), (7, 1_600_000_000, 2, 3));
    // The top bit set: kept only when the DOS time says 2038 or later.
    let mut z = IzTimes::default();
    assert_eq!(
        ef_scan_for_izux(&ut(1, &[0x9000_0000]), true, 0, Some(&mut z)),
        0
    );
    let f = ef_scan_for_izux(&ut(1, &[0x9000_0000]), true, 0x7500_0000, Some(&mut z));
    assert_eq!((f, z.mtime), (1, 0x9000_0000));
    // A time that is not there.
    assert_eq!(ef_scan_for_izux(&ut(1, &[]), true, 0, Some(&mut z)), 0);
    // An old IZUNIX block after an EF_TIME one is ignored; before it, the
    // EF_TIME block's flags replace its own.
    let ux = |m: u32, a: u32| [&b"UX\x08\x00"[..], &a.to_le_bytes(), &m.to_le_bytes()].concat();
    let mut z = IzTimes::default();
    let both = [ut(1, &[100]), ux(200, 300)].concat();
    assert_eq!(ef_scan_for_izux(&both, true, 0, Some(&mut z)), 1);
    assert_eq!(z.mtime, 100);
    let mut z = IzTimes::default();
    assert_eq!(ef_scan_for_izux(&ux(200, 300), true, 0, Some(&mut z)), 3);
    assert_eq!((z.mtime, z.atime), (200, 300));
    // No storage asked for: nothing.
    assert_eq!(ef_scan_for_izux(&ut(1, &[5]), true, 0, None), 0);
}

#[test]
fn includes_and_excludes() {
    let env = |_: &str| None;
    let mut err: Vec<u8> = Vec::new();
    let mut uz = Uz::new(
        crate::compat::host::Host::Real,
        Flavour::Apple,
        &env,
        &mut err,
    );
    uz.process_all_files = false;
    uz.pfnames = vec![b"*.txt".to_vec(), b"x".to_vec()];
    uz.pxnames = vec![b"b*".to_vec()];
    let mut fm = vec![false; 2];
    let mut xm = vec![false; 1];
    assert!(selected(&uz, b"a.txt", Some(&mut fm), Some(&mut xm)));
    assert!(!selected(&uz, b"b.txt", Some(&mut fm), Some(&mut xm)));
    assert!(!selected(&uz, b"y", None, None));
    assert_eq!((fm, xm), (vec![true, false], vec![true]));
    uz.o.c_flag = true;
    assert!(selected(&uz, b"A.TXT", None, None));
    // No include pattern: everything not excluded.
    uz.pfnames.clear();
    assert!(selected(&uz, b"y", None, None));
    assert!(!selected(&uz, b"B", None, None));
}

/// `-DIZ_HAVE_UXUIDGID`'s owner (Task 10 fix round: the scan is wired, the
/// hook decides): `Ux` of exactly 4 bytes, `ux` version 1 (sizes 2, 4, 8;
/// one that runs past the block is not taken: T10-12), a full `UX`; none
/// without an owner to fill.
#[test]
fn the_owner_comes_from_ux_blocks() {
    use super::super::Flavour;
    let block = |id: u16, data: &[u8]| {
        let mut v = id.to_le_bytes().to_vec();
        v.extend_from_slice(&(data.len() as u16).to_le_bytes());
        v.extend_from_slice(data);
        v
    };
    let scan = |ef: &[u8]| {
        let mut z = IzTimes::default();
        let mut ug = [7u64, 7];
        let f = ef_scan_for_izux_owner(ef, false, 0, Some(&mut z), Some((&mut ug, Flavour::Apple)));
        (f & EB_UX2_VALID != 0, ug)
    };
    assert_eq!(
        scan(&block(0x7855, &[0xe8, 3, 0xf4, 1])),
        (true, [1000, 500])
    );
    assert!(!scan(&block(0x7855, &[0xe8, 3, 0xf4])).0);
    assert_eq!(
        scan(&block(0x7875, &[1, 4, 0xe8, 3, 0, 0, 4, 0xf4, 1, 0, 0])),
        (true, [1000, 500])
    );
    assert_eq!(
        scan(&block(
            0x7875,
            &[1, 2, 0xe8, 3, 8, 0xf4, 1, 0, 0, 0, 0, 0, 0]
        )),
        (true, [1000, 500])
    );
    assert!(!scan(&block(0x7875, &[1, 4, 0xe8, 3, 0, 0, 9, 1])).0);
    assert!(!scan(&block(0x7875, &[2, 2, 0xe8, 3, 2, 0xf4, 1])).0);
    let mut ux = vec![0u8; 8];
    ux.extend_from_slice(&[0xe8, 3, 0xf4, 1]);
    assert_eq!(scan(&block(0x5855, &ux)), (true, [1000, 500]));
    let mut z = IzTimes::default();
    let f = ef_scan_for_izux(&block(0x7855, &[0xe8, 3, 0xf4, 1]), false, 0, Some(&mut z));
    assert_eq!(f & EB_UX2_VALID, 0);
}
