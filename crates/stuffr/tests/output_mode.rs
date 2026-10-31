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

/// Review I1: the mode is read without opening a non-regular input. A FIFO
/// opened, `fstat`ed and closed before the real open would block, then cut
/// its writer off (EPIPE) and leave the real open waiting for a writer that
/// is gone. A decode from a FIFO completes; an extraction returns.
#[test]
fn a_fifo_input_with_a_writer_still_decodes() {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::mpsc;
    use std::time::Duration;

    fn fifo_with_writer(name: &str, bytes: Vec<u8>) -> (PathBuf, std::thread::JoinHandle<()>) {
        let fifo = tmp(name);
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let path = fifo.clone();
        let writer = std::thread::spawn(move || {
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&path) {
                let _ = f.write_all(&bytes);
            }
        });
        (fifo, writer)
    }

    fn within<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(Duration::from_secs(20))
            .expect("hung on a FIFO input")
    }

    let gz = {
        let src = tmp("fifo-src.txt");
        let dst = tmp("fifo-src.txt.gz");
        std::fs::write(&src, vec![b'z'; 300_000]).unwrap();
        compress(
            Input::Path(src.clone()),
            Output::Path(dst.clone()),
            &CompressOpts::default(),
        )
        .unwrap();
        let bytes = std::fs::read(&dst).unwrap();
        let _ = std::fs::remove_file(src);
        let _ = std::fs::remove_file(dst);
        bytes
    };
    let (fifo, writer) = fifo_with_writer("in.fifo", gz);
    let out = tmp("fifo.out");
    let (f2, o2) = (fifo.clone(), out.clone());
    within(move || {
        decompress(
            Input::Path(f2),
            Output::Path(o2),
            &DecompressOpts {
                format: Some(stuffr::FormatId::new("gzip")),
                ..Default::default()
            },
        )
        .unwrap()
    });
    writer.join().unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), vec![b'z'; 300_000]);
    let _ = std::fs::remove_file(&fifo);
    let _ = std::fs::remove_file(&out);

    // `unpack -C` from a FIFO: a tar written by stuffr itself.
    let tar = {
        let container = stuffr::registry()
            .require_container(stuffr::FormatId::new("tar"))
            .unwrap();
        let t = tmp("fifo-tree.tar");
        {
            let sink = stuffr::PlainSink::new(Box::new(std::fs::File::create(&t).unwrap()));
            let mut w = container.create(sink, &Default::default()).unwrap();
            w.add(
                &stuffr::EntryMeta {
                    name: "fifo-tree/a.txt".to_string(),
                    size: Some(5),
                    kind: stuffr::EntryKind::File,
                    ..Default::default()
                },
                &mut &b"alpha"[..],
            )
            .unwrap();
            w.finish().unwrap().finish().unwrap();
        }
        let bytes = std::fs::read(&t).unwrap();
        let _ = std::fs::remove_file(t);
        bytes
    };
    let (fifo, writer) = fifo_with_writer("tree.fifo", tar);
    let dest = tmp("fifo-dest");
    let _ = std::fs::remove_dir_all(&dest);
    let (f2, d2) = (fifo.clone(), dest.clone());
    // Since `FileSource` says a FIFO does not seek, the tar is read forward,
    // as from standard input; it used to fail its first seek ("Illegal
    // seek", exit 1).
    let extracted = within(move || {
        stuffr::entries::extract(
            Input::Path(f2),
            &d2,
            &stuffr::entries::Selection::All,
            &Default::default(),
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    });
    assert_eq!(extracted, Ok(()));
    assert_eq!(
        std::fs::read(dest.join("fifo-tree/a.txt")).unwrap(),
        b"alpha"
    );
    // The writer is unblocked by our open; whatever it then meets, it ends.
    let _ = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&fifo);
    writer.join().unwrap();
    let _ = std::fs::remove_file(&fifo);
    let _ = std::fs::remove_dir_all(&dest);
}
