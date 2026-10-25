//! fileio.c pieces: the buffered reader's ruling, the time conversion,
//! `fnfilter()`, `makeint64()`.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use super::*;
use crate::compat::host::{Host, SANDBOX_OUTPUT_CAP, Sandbox};
use crate::compat::unzip::Flavour;

fn sandbox() -> Host {
    Host::Sandbox(Sandbox {
        dir: std::env::temp_dir(),
        stdin: None,
        stdout: Arc::new(Mutex::new(Vec::new())),
        budget: Arc::new(AtomicU64::new(SANDBOX_OUTPUT_CAP)),
        reads: Arc::new(Mutex::new(BTreeMap::new())),
    })
}

/// A run's `G` in a sandbox (UTC, no terminal), as Apple.
fn with_uz(f: impl FnOnce(&mut Uz)) {
    let env = |_: &str| None;
    let mut err: Vec<u8> = Vec::new();
    let mut uz = Uz::new(sandbox(), Flavour::Apple, &env, &mut err);
    f(&mut uz);
}

/// ruling: past `G.inbuf`'s end (which `find_ecrec64()`'s count can take
/// `G.inptr + G.incnt` to) bytes read as zeros, never from beyond it.
#[test]
fn readbuf_past_the_buffer_reads_zeros() {
    with_uz(|uz| {
        let n = uz.zin.inbuf.len();
        uz.zin.inbuf[n - 6..].copy_from_slice(b"abcdef");
        uz.zin.inptr = n - 6;
        uz.zin.incnt = 10;
        // Something to read once the count is spent: none (no archive is
        // open), so the read stops there.
        let mut buf = [0xffu8; 10];
        assert_eq!(readbuf(uz, &mut buf), 10);
        assert_eq!(&buf, b"abcdef\0\0\0\0");
        assert_eq!(uz.zin.incnt, 0);
    });
}

/// ruling: T13-7. A name shorter on disk than declared reads what is there,
/// is NUL-terminated at the declared length, and the bytes past the short
/// read are zeros (the C's are uninitialised): the code is `PK_OK`, and a
/// read that gives nothing at all is `PK_EOF`.
#[test]
fn read_filename_full_short_read_t13_7() {
    // An open archive with nothing more in it: reads end at its end.
    struct Rm(std::path::PathBuf);
    impl Drop for Rm {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let path = std::env::temp_dir().join(format!("stuffr-unzip-{}-t137", std::process::id()));
    std::fs::write(&path, b"").unwrap();
    let _rm = Rm(path.clone());
    let open = || Some(std::fs::File::open(&path).unwrap().into());
    with_uz(|uz| {
        uz.zin.fd = open();
        uz.zin.inbuf[..3].copy_from_slice(b"abc");
        uz.zin.inptr = 0;
        uz.zin.incnt = 3;
        let rc = read_filename_full(uz, 8, &PInfo::default(), false);
        assert_eq!(rc, PK_OK);
        let full = uz.filename_full.as_ref().expect("buffer kept");
        assert_eq!(&full[..9], b"abc\0\0\0\0\0\0");
        assert_eq!(c_str(&uz.filename), b"abc");
        assert_eq!(uz.zin.incnt, 0);
    });
    with_uz(|uz| {
        uz.zin.fd = open();
        uz.zin.incnt = 0; // nothing buffered, nothing in the archive
        assert_eq!(read_filename_full(uz, 8, &PInfo::default(), false), PK_EOF);
    });
}

#[test]
fn readbuf_refills_a_block_at_a_time() {
    let dir = std::env::temp_dir().join(format!("stuffr-unzip-readbuf-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("f");
    let data: Vec<u8> = (0..(INBUFSIZ * 2 + 5)).map(|i| i as u8).collect();
    std::fs::File::create(&path)
        .unwrap()
        .write_all(&data)
        .unwrap();
    with_uz(|uz| {
        uz.zin.fd = Some(std::fs::File::open(&path).unwrap().into());
        let mut got = vec![0u8; INBUFSIZ + 100];
        assert_eq!(readbuf(uz, &mut got), INBUFSIZ + 100);
        assert_eq!(got, data[..INBUFSIZ + 100]);
        assert_eq!(uz.zin.cur_zipfile_bufstart, 2 * INBUFSIZ as i64);
        // A short read at the end returns what there was.
        let mut rest = vec![0u8; INBUFSIZ * 2];
        assert_eq!(readbuf(uz, &mut rest), INBUFSIZ - 95);
        // Seeking back into the last block read keeps the buffer.
        assert_eq!(seek_zipf(uz, (2 * INBUFSIZ + 1) as i64), PK_OK);
        let mut four = [0u8; 4];
        assert_eq!(readbuf(uz, &mut four), 4);
        assert_eq!(four, data[2 * INBUFSIZ + 1..2 * INBUFSIZ + 5]);
        // Before the start: PK_BADERR; past the end: PK_EOF.
        assert_eq!(seek_zipf(uz, -1), super::super::PK_BADERR);
        assert_eq!(seek_zipf(uz, 10 * INBUFSIZ as i64), PK_EOF);
    });
    let _ = std::fs::remove_dir_all(&dir);
}

/// ruling: months 0, 14 and 15 read `ydays[]` outside its 13 entries in the
/// C; here month 0 is January and 14 and 15 a whole year on (as month 13,
/// which reads `ydays[12]`).
#[test]
fn dos_times_in_utc() {
    with_uz(|uz| {
        let dos = |y: u32, mo: u32, d: u32, h: u32, mi: u32, s: u32| {
            (((y - 1980) << 9 | mo << 5 | d) << 16) | (h << 11) | (mi << 5) | (s / 2)
        };
        assert_eq!(
            dos_to_unix_time(uz, dos(2020, 1, 2, 3, 4, 6)),
            1_577_934_246
        );
        assert_eq!(
            dos_to_unix_time(uz, dos(2024, 3, 1, 0, 0, 0)),
            1_709_251_200
        );
        assert_eq!(
            dos_to_unix_time(uz, dos(2020, 0, 1, 0, 0, 0)),
            1_577_836_800
        );
        assert_eq!(
            dos_to_unix_time(uz, dos(2020, 13, 1, 0, 0, 0)),
            1_609_459_200
        );
        assert_eq!(
            dos_to_unix_time(uz, dos(2020, 15, 1, 0, 0, 0)),
            1_609_459_200
        );
        // Past 2106 the 64-bit `time_t` keeps the value (the saturation
        // only catches a wrapped 32-bit sum).
        assert_eq!(
            dos_to_unix_time(uz, dos(2107, 12, 31, 23, 59, 58)),
            4_354_905_598
        );
    });
}

#[test]
fn utc_fields() {
    let t = utc(1_577_934_246);
    assert_eq!((t.year, t.mon, t.mday, t.hour, t.min), (2020, 1, 2, 3, 4));
    let t = utc(951_782_400); // 2000-02-29
    assert_eq!((t.year, t.mon, t.mday), (2000, 2, 29));
    let t = utc(0xffff_ffff);
    assert_eq!((t.year, t.mon, t.mday, t.hour, t.min), (2106, 2, 7, 6, 28));
}

#[test]
fn fnfilter_escapes_and_truncates() {
    with_uz(|uz| {
        assert_eq!(fnfilter1(uz, b"plain.txt"), b"plain.txt");
        assert_eq!(fnfilter1(uz, b"nl\nx\x01\x1f"), b"nl^Jx^A^_");
        // Not printable in the C locale: `?`.
        // Only the C locale is pinned here: a sandbox is fixed to it, and a real
        // locale is process-global and absent on some machines, so it cannot be
        // set deterministically in a unit test (the Apple suite covers it).
        assert_eq!(fnfilter1(uz, b"\x7f\x80\xe9"), b"???");
        // A C string: the name ends at its NUL.
        assert_eq!(fnfilter1(uz, b"ab\0cd"), b"ab");
        // A sandbox is the C locale whatever `native_is_utf8` says (the
        // real locale's answers are the Apple suite's: `init_locale`).
        uz.native_is_utf8 = true;
        assert_eq!(fnfilter1(uz, b"\x80\x9f\xa0\xad\xe9\xff"), b"??????");
        uz.native_is_utf8 = false;
        // Past `size - 4` bytes of output the name ends in `...`.
        let long = vec![b'n'; WSIZE];
        let out = fnfilter_at(uz, &long, 0, 16);
        assert_eq!(out, b"nnnnnnnnnnnn...");
        assert_eq!(&uz.slide[..16], b"nnnnnnnnnnnn...\0");
        let ctl = [b'n'; 11]
            .iter()
            .chain(b"\x01\x01")
            .copied()
            .collect::<Vec<u8>>();
        // An escape that starts before `size - 4` is kept whole.
        assert_eq!(fnfilter_at(uz, &ctl, 0, 16), b"nnnnnnnnnnn^A...");
        // What fnfilter wrote is in the window, as the C's `space` is.
        assert_eq!(&uz.slide[..17], b"nnnnnnnnnnn^A...\0");
    });
}

#[test]
fn makeint64_leaves_out_byte_5_as_upstream_does() {
    let b = [7, 0, 0, 0, 1, 0xff, 2, 3];
    assert_eq!(makeint64(Flavour::Apple, &b), 0x0302_0001_0000_0007);
    assert_eq!(makeword(&[0x34, 0x12]), 0x1234);
    assert_eq!(makelong(&[0x78, 0x56, 0x34, 0x12]), 0x1234_5678);
}

#[test]
fn oem_names_are_code_page_850() {
    with_uz(|uz| {
        let dos = PInfo {
            hostnum: FS_FAT_,
            hostver: 20,
            ..PInfo::default()
        };
        let mut s = *b"caf\x82\0\x82";
        ext_ascii_to_native(uz, &mut s, &dos, false);
        // Converted up to the NUL only.
        assert_eq!(&s, b"caf\xe9\0\x82");
        // PKZIP 2.5 with Unix attributes: already ISO 8859-1.
        let pk25 = PInfo {
            hostver: 25,
            has_ux_att: true,
            ..dos
        };
        let mut s = *b"\x82";
        ext_ascii_to_native(uz, &mut s, &pk25, false);
        assert_eq!(&s, b"\x82");
        let unix = PInfo {
            hostnum: 3,
            ..PInfo::default()
        };
        let mut s = *b"\x82";
        ext_ascii_to_native(uz, &mut s, &unix, false);
        assert_eq!(&s, b"\x82");
    });
}

/// ruling: T14-4. The Ubuntu flavour has no OEM table (20-unzip60-alt-
/// iconv-utf8.patch): a sandbox converts nothing, a Windows NT name of any
/// version included.
#[test]
fn ubuntu_names_stay_as_stored_in_a_sandbox() {
    let env = |_: &str| None;
    let mut err: Vec<u8> = Vec::new();
    let mut uz = Uz::new(sandbox(), Flavour::Ubuntu, &env, &mut err);
    crate::compat::unzip::unix::charset::init_conversion_charsets(&mut uz);
    assert!(uz.o.oem_cp.is_empty());
    uz.o.oem_cp = b"CP866".to_vec();
    for (hostnum, hostver) in [(FS_FAT_, 20), (FS_NTFS_, 20), (FS_NTFS_, 50)] {
        let p = PInfo {
            hostnum,
            hostver,
            ..PInfo::default()
        };
        let mut s = *b"caf\x82\0\x82";
        ext_ascii_to_native(&uz, &mut s, &p, false);
        assert_eq!(&s, b"caf\x82\0\x82");
    }
}

/// ruling: T11-5. The first password prompt names the archive and the
/// entry while both, filtered, fit `2*FILNAMSIZ` bytes (Apple 2048, Ubuntu
/// 8192), else it is "Enter password: " (ubuntu:
/// 20-cve-2018-1000035-unzip-buffer-overflow.patch; Apple's build dies one
/// byte past its buffer).
#[test]
fn the_password_prompt_fits_its_buffer() {
    let env = |_: &str| None;
    for (f, room) in [(Flavour::Apple, 2048), (Flavour::Ubuntu, 8192)] {
        let mut err: Vec<u8> = Vec::new();
        let mut uz = Uz::new(sandbox(), f, &env, &mut err);
        let zfn = b"lon3.zip";
        // each ^A shows as two bytes
        let fits = vec![1u8; (room - zfn.len()) / 2];
        let p = passw_prompt(&mut uz, zfn, &fits);
        assert_eq!(
            p.len(),
            zfn.len() + 2 * fits.len() + b"[] password: ".len() + 1
        );
        assert!(p.starts_with(b"[lon3.zip] ^A^A"), "{f:?}");
        assert!(p.ends_with(b"^A password: "));
        let over = [fits.clone(), b"A".to_vec()].concat();
        assert_eq!(passw_prompt(&mut uz, zfn, &over), b"Enter password: ");
        assert_eq!(
            passw_prompt(&mut uz, b"a.zip", b"s.txt"),
            b"[a.zip] s.txt password: "
        );
    }
}
