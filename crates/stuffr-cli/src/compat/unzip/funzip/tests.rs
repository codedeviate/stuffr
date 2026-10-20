//! funzip's rulings, which no reference can show (the differential rows are
//! in `tests/compat_unzip_common.rs`), and its sandbox answers (R7).

use std::ffi::OsString;
use std::io::Write;

use super::*;
use crate::compat::unzip::{Flavour, run_in_counted};

/// A run of funzip in a sandbox: exit code, standard output, standard error.
fn run(args: &[&str], stdin: &[u8]) -> (i32, Vec<u8>, String) {
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    let dir = std::env::temp_dir();
    let (code, out, err, _) =
        run_in_counted(Flavour::Apple, &dir, "funzip", &args, stdin, &|_| None);
    (code, out, String::from_utf8(err).unwrap())
}

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn crc(data: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(data);
    c.sum()
}

/// A gzip member around `body` with flag byte `flags` and MTIME `mtime`,
/// its trailer for `data`.
fn gzip(flags: u8, mtime: u32, body: &[u8], data: &[u8]) -> Vec<u8> {
    let mut v = vec![0x1f, 0x8b, 8, flags];
    v.extend_from_slice(&mtime.to_le_bytes());
    v.extend_from_slice(&[0, 3]);
    v.extend_from_slice(body);
    v.extend_from_slice(&crc(data).to_le_bytes());
    v.extend_from_slice(&(data.len() as u32).to_le_bytes());
    v
}

/// Traditional PKWARE encryption of an 11-byte header, `check`, `body`.
fn encrypt(password: &[u8], check: u8, body: &[u8]) -> Vec<u8> {
    let mut plain = b"stuffr-hdr!".to_vec();
    plain.push(check);
    plain.extend_from_slice(body);
    // Encrypting with the decryption keys: c = p ^ s for the stream byte
    // s (what decrypting a 0 gives), and decrypting c moves the keys on
    // with p.
    let mut k = Keys::new(password);
    plain
        .iter()
        .map(|&p| {
            let c = p ^ k.clone().decrypt_byte(0);
            assert_eq!(k.decrypt_byte(c), p);
            c
        })
        .collect()
}

/// A local header (and nothing after the data but an end record) for a
/// zip whose first entry is `body` under `method` and `flags`.
fn zip(method: u16, flags: u16, body: &[u8], data: &[u8]) -> Vec<u8> {
    let mut v = b"PK\x03\x04".to_vec();
    for x in [20u16, flags, method, 0x1883, 0x5022] {
        v.extend_from_slice(&x.to_le_bytes());
    }
    for x in [crc(data), body.len() as u32, data.len() as u32] {
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.push(b'a');
    v.extend_from_slice(body);
    v.extend_from_slice(b"PK\x05\x06");
    v.extend_from_slice(&[0; 18]);
    v
}

/// ruling: T12-1. `getc() << 8` of `EOF` is two's complement's -256: a
/// two-byte field cut after one byte reads `0xff00 | b`, and an empty one
/// `0xffff`.
#[test]
fn a_two_byte_field_cut_short_reads_high_ones() {
    let mut inp = In::new(Box::new(&b"\x50"[..]));
    assert_eq!(getc2(&mut inp), 0xff50);
    let mut inp = In::new(Box::new(&b""[..]));
    assert_eq!(getc2(&mut inp), 0xffff);
    // ... so neither is a magic number
    for input in [&b""[..], b"P", b"\x1f"] {
        let (code, out, err) = run(&[], input);
        assert_eq!(
            (code, out.len(), err.as_str()),
            (3, 0, "funzip error: input not a zip or gzip file\n")
        );
    }
}

/// ruling: T12-3. An encrypted gzip member's check byte is a header byte
/// a gzip header never fills (`h[9]` with bit 3 of MTIME's third byte,
/// else `h[15]`): it is 0, as Ubuntu's binary gives every time (Apple's
/// gives 0 for `h[9]` and stack garbage for `h[15]`).
#[test]
fn an_encrypted_gzip_member_checks_against_zero() {
    let data = b"gzip data\n";
    for mtime in [0, 0x0008_0000] {
        let ok = gzip(0x20, mtime, &encrypt(b"pw", 0, &deflate(data)), data);
        assert_eq!(run(&["-pw"], &ok), (0, data.to_vec(), String::new()));
        let bad = gzip(0x20, mtime, &encrypt(b"pw", 1, &deflate(data)), data);
        assert_eq!(
            run(&["-pw"], &bad),
            (
                3,
                vec![],
                "funzip error: incorrect password for first entry\n".to_owned()
            )
        );
    }
}

/// ruling: T12-4 and R7. Standard output is charged to the sandbox's
/// 8 MiB budget; past it funzip says "out of space on stdout", exit 9,
/// after what fitted (whole windows).
#[test]
fn a_full_standard_output_is_out_of_space() {
    let data = vec![0u8; 9 << 20];
    let (code, out, err) = run(&[], &gzip(0, 0, &deflate(&data), &data));
    assert_eq!(
        (code, out.len(), err.as_str()),
        (9, 8 << 20, "funzip error: out of space on stdout\n")
    );
    // A stored entry cut short goes on with 0xff bytes up to its length
    // (the C's `getc()` EOF): bounded by the same budget.
    let data = vec![b'x'; 100];
    let mut z = zip(0, 0, &data, &data);
    z.truncate(40);
    let len = (64u32 << 20).to_le_bytes();
    z[18..22].copy_from_slice(&len);
    z[22..26].copy_from_slice(&len);
    let (code, out, err) = run(&[], &z);
    assert_eq!(
        (code, out.len(), err.as_str()),
        (9, 8 << 20, "funzip error: out of space on stdout\n")
    );
    assert_eq!(&out[..9], b"xxxxxxxxx");
    assert!(out[9..].iter().all(|&b| b == 0xff));
}

/// R7: a sandbox has no terminal, so an encrypted entry without `-password`
/// is "no tty to prompt for password", exit 1; nor is the usage shown.
#[test]
fn no_terminal_no_password_and_no_usage() {
    let data = b"secret\n";
    let z = zip(0, 1, &encrypt(b"pw", (crc(data) >> 24) as u8, data), data);
    assert_eq!(
        run(&[], &z),
        (
            1,
            vec![],
            "funzip error: no tty to prompt for password\n".to_owned()
        )
    );
    assert_eq!(run(&["-pw"], &z), (0, data.to_vec(), String::new()));
    let (code, _, err) = run(&["-h"], b"");
    assert_eq!(
        (code, err.as_str()),
        (3, "funzip error: input not a zip or gzip file\n")
    );
}

/// funzip reads its input as a stream: a stdin far larger than its buffer
/// is decoded front to back, and the warning about more entries reads the
/// four bytes after the first entry only.
#[test]
fn a_stream_is_read_front_to_back() {
    let data: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let mut z = zip(8, 0, &deflate(&data), &data);
    z.truncate(z.len() - 22);
    z.extend_from_slice(&zip(0, 0, b"b", b"b"));
    let (code, out, err) = run(&[], &z);
    assert_eq!(code, 0);
    assert!(out == data);
    assert_eq!(
        err,
        "funzip warning: zipfile has more than one entry--rest ignored\n"
    );
}
