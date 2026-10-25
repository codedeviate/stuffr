use crate::common::*;

/// Shrink (method 1) and implode (method 6) entries unpack through the Info-ZIP
/// decoders; the header CRC-32 is checked on the way, so equal sizes here also
/// mean the bytes hash to what each archive's own header declares.
#[test]
fn unpack_reads_shrink_and_implode() {
    let cases: [(&str, &[(&str, usize)]); 4] = [
        ("shrink-full-table.zip", &[("x.txt", 26001)]),
        ("implode-hand-4k-3trees.zip", &[("hand.txt", 9400)]),
        ("implode-hand-8k-2trees.zip", &[("hand.txt", 9400)]),
        (
            "shrink-commons.zip",
            &[("TEST1.XML", 76), ("TEST2.XML", 81)],
        ),
    ];
    let dir = tmp_dir();
    for (fixture, sizes) in cases {
        let Some(bytes) = infozip_fixture(fixture) else {
            return;
        };
        let archive = dir.join(fixture);
        std::fs::write(&archive, &bytes).unwrap();
        let dest = dir.join(format!("out-{fixture}"));
        let out = run_output(&[
            "unpack",
            archive.to_str().unwrap(),
            "-C",
            dest.to_str().unwrap(),
        ]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{fixture}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        for (name, len) in sizes {
            assert_eq!(std::fs::read(dest.join(name)).unwrap().len(), *len);
        }
        assert!(
            std::fs::read_dir(&dest).unwrap().count() > 0,
            "{fixture}: nothing extracted"
        );
        let test = run_output(&["test", archive.to_str().unwrap()]);
        assert_eq!(test.status.code(), Some(0), "{fixture}");
    }
    // The four hand-built variants hold the same 9400 bytes.
    let mut first: Option<Vec<u8>> = None;
    for v in ["4k-2trees", "4k-3trees", "8k-2trees", "8k-3trees"] {
        let dest = dir.join(format!("out-implode-hand-{v}.zip"));
        if !dest.exists() {
            let archive = dir.join(format!("implode-hand-{v}.zip"));
            std::fs::write(
                &archive,
                infozip_fixture(&format!("implode-hand-{v}.zip")).unwrap(),
            )
            .unwrap();
            let out = run_output(&[
                "unpack",
                archive.to_str().unwrap(),
                "-C",
                dest.to_str().unwrap(),
            ]);
            assert_eq!(out.status.code(), Some(0), "{v}");
        }
        let got = std::fs::read(dest.join("hand.txt")).unwrap();
        assert_eq!(got.len(), 9400);
        assert_eq!(*first.get_or_insert_with(|| got.clone()), got, "{v}");
    }
}

#[test]
fn unpack_damaged_implode_is_exit_5() {
    let Some(mut bytes) = infozip_fixture("implode-hand-4k-2trees.zip") else {
        return;
    };
    let dir = tmp_dir();
    // Inside the payload (the local header is 30 + name bytes).
    bytes[200] ^= 0x5A;
    let archive = dir.join("damaged.zip");
    std::fs::write(&archive, &bytes).unwrap();
    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dir.join("out").to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `list` enumerates shrink and implode archives without decoding them (the
/// payload decodes on its first read, so listing a damaged one still works).
/// The CLI's listing has no codec column;
/// `zip::tests::shrink_and_implode_entries_decode` pins the per-entry codec.
#[test]
fn list_shows_shrink_and_implode_entries() {
    let dir = tmp_dir();
    for (fixture, name, size) in [
        ("shrink-commons.zip", "TEST1.XML", 76),
        ("implode-hand-8k-3trees.zip", "hand.txt", 9400),
    ] {
        let Some(bytes) = infozip_fixture(fixture) else {
            return;
        };
        let archive = dir.join(fixture);
        std::fs::write(&archive, &bytes).unwrap();
        let out = run_output(&["list", "--json", archive.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(0), "{fixture}");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains(name), "{fixture}: {text}");
        assert!(
            text.contains(&format!("\"size\":{size}")),
            "{fixture}: {text}"
        );
    }
}

/// Listing never decodes a payload, so a damaged implode entry still lists
/// (exit 0); unpacking it is where the damage is found (exit 5).
#[test]
fn list_of_a_damaged_implode_is_exit_0_and_unpack_is_exit_5() {
    let Some(mut bytes) = infozip_fixture("implode-hand-4k-2trees.zip") else {
        return;
    };
    bytes[200] ^= 0x5A;
    let dir = tmp_dir();
    let archive = dir.join("damaged-list.zip");
    std::fs::write(&archive, &bytes).unwrap();
    let list = run_output(&["list", archive.to_str().unwrap()]);
    assert_eq!(
        list.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&list.stderr)
    );
    let out = run_output(&[
        "unpack",
        archive.to_str().unwrap(),
        "-C",
        dir.join("out").to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(5));
}

/// On a pipe the zip is read forward-only, where shrink and implode are not
/// decodable: exit 3, and the message says why and what to do instead.
#[test]
fn unpack_of_a_piped_implode_zip_is_exit_3_and_names_the_way_out() {
    let Some(bytes) = infozip_fixture("implode-hand-4k-2trees.zip") else {
        return;
    };
    let dir = tmp_dir();
    let out = run_with_stdin_output(
        &["unpack", "-", "-C", dir.join("out").to_str().unwrap()],
        &bytes,
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "{err}");
    assert!(
        err.contains("seekable source") && err.contains("stuffr convert"),
        "{err}"
    );
    assert!(!err.contains("cannot decompress"), "{err}");
}

// `stuffr bench`. The binary under test is a debug build, where bench
// refuses to time anything, so these cover the usage errors (which are
// checked first) and the refusal itself.
