//! A single-stream output takes its input file's permission bits, as gzip,
//! bzip2, xz and zstd do (security audit HOST-1): a 0600 file compressed or
//! decompressed stays 0600 instead of landing at the umask default.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use stuffr::ops::{
    CompressOpts, ConvertSource, DecompressOpts, Input, Output, RecompressOpts, compress,
    decompress, recompress_source,
};

fn tmp(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("stuffr-outmode-{}-{}", std::process::id(), name));
    let _ = std::fs::remove_file(&p);
    p
}

fn mode(p: &std::path::Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
}

fn chmod(p: &std::path::Path, m: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
}

#[test]
fn pack_and_unpack_keep_a_0600_inputs_mode() {
    let src = tmp("secret.txt");
    let packed = tmp("secret.txt.gz");
    let unpacked = tmp("secret.out");
    std::fs::write(&src, b"top secret").unwrap();
    chmod(&src, 0o600);

    compress(
        Input::Path(src.clone()),
        Output::Path(packed.clone()),
        &CompressOpts::default(),
    )
    .unwrap();
    assert_eq!(mode(&packed), 0o600, "pack");

    decompress(
        Input::Path(packed.clone()),
        Output::Path(unpacked.clone()),
        &DecompressOpts::default(),
    )
    .unwrap();
    assert_eq!(mode(&unpacked), 0o600, "unpack");
    assert_eq!(std::fs::read(&unpacked).unwrap(), b"top secret");

    let converted = tmp("secret.txt.bz2");
    let source = ConvertSource::open(Input::Path(packed.clone()), None).unwrap();
    recompress_source(
        source,
        Output::Path(converted.clone()),
        &RecompressOpts {
            codec: Some(stuffr::FormatId::new("bzip2")),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(mode(&converted), 0o600, "convert");

    for p in [src, packed, unpacked, converted] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn the_inputs_mode_is_copied_without_setid_bits() {
    let src = tmp("exec.sh");
    let packed = tmp("exec.sh.gz");
    std::fs::write(&src, b"#!/bin/sh\n").unwrap();
    chmod(&src, 0o4750);
    compress(
        Input::Path(src.clone()),
        Output::Path(packed.clone()),
        &CompressOpts::default(),
    )
    .unwrap();
    assert_eq!(mode(&packed), 0o750);
    let _ = std::fs::remove_file(src);
    let _ = std::fs::remove_file(packed);
}

/// `--force` over an existing destination: its mode intersected with the
/// input's, so neither a locked-down destination nor a private input is
/// widened.
#[test]
fn a_replaced_destination_is_never_wider_than_the_input_or_itself() {
    let src = tmp("both.txt");
    let dst = tmp("both.txt.gz");
    std::fs::write(&src, b"payload").unwrap();
    std::fs::write(&dst, b"old").unwrap();
    chmod(&src, 0o600);
    chmod(&dst, 0o644);
    let force = CompressOpts {
        force: true,
        ..Default::default()
    };
    compress(Input::Path(src.clone()), Output::Path(dst.clone()), &force).unwrap();
    assert_eq!(mode(&dst), 0o600, "a private input stays private");

    chmod(&src, 0o644);
    chmod(&dst, 0o640);
    compress(Input::Path(src.clone()), Output::Path(dst.clone()), &force).unwrap();
    assert_eq!(
        mode(&dst),
        0o640,
        "a locked-down destination stays locked down"
    );

    let _ = std::fs::remove_file(src);
    let _ = std::fs::remove_file(dst);
}
