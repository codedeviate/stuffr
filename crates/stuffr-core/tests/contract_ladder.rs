//! The Phase 0 contract test.
//!
//! If this test is honest, the whole streaming premise of `stuffr` holds: a
//! container with a trailing index, read from a pipe, still yields real data —
//! and says exactly what it approximated to do so.

use stuffr_core::testing::{MOCK_CONTAINER, MockContainer, mock_archive_bytes};
use stuffr_core::{
    Container, Fidelity, FileSource, OpenOpts, ReaderSource, Rung, Source, StreamPolicy, resolve,
};

const ENTRIES: &[(&str, &[u8])] = &[
    ("a.txt", b"alpha"),
    ("nested/b.bin", b"bravo bravo"),
    ("c.log", b""),
];

fn archive() -> Vec<u8> {
    mock_archive_bytes(ENTRIES)
}

fn as_file(bytes: &[u8]) -> Box<dyn Source> {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut f, bytes).unwrap();
    let (_, path) = f.keep().unwrap();
    Box::new(FileSource::open(&path).unwrap())
}

fn as_pipe(bytes: &[u8]) -> Box<dyn Source> {
    Box::new(ReaderSource::new(std::io::Cursor::new(bytes.to_vec())))
}

/// Reads every entry, returning the data and the fidelity report.
fn read_all(src: Box<dyn Source>) -> (Vec<(String, Vec<u8>)>, stuffr_core::FidelityReport) {
    let caps = MockContainer.caps();
    let resolved = resolve(src, MOCK_CONTAINER, caps, &StreamPolicy::default()).unwrap();
    let mut ar = MockContainer.open(resolved, &OpenOpts::default()).unwrap();

    let mut out = Vec::new();
    while let Some(mut e) = ar.next_entry().unwrap() {
        let name = e.meta().name.clone();
        let mut data = Vec::new();
        e.reader().read_to_end(&mut data).unwrap();
        out.push((name, data));
    }

    // No merge: fidelity() is now authoritative on its own. That is the point
    // of passing Resolved into open().
    let report = ar.fidelity().clone();
    (out, report)
}

#[test]
fn data_is_identical_from_a_file_and_from_a_pipe() {
    let bytes = archive();
    let (from_file, _) = read_all(as_file(&bytes));
    let (from_pipe, _) = read_all(as_pipe(&bytes));

    assert_eq!(
        from_file, from_pipe,
        "entry data must not depend on the input's seekability"
    );
    assert_eq!(from_file.len(), ENTRIES.len());
    assert_eq!(from_file[1].0, "nested/b.bin");
    assert_eq!(from_file[1].1, b"bravo bravo");
    assert_eq!(
        from_file[2].1, b"",
        "a zero-length entry must survive both paths"
    );
}

#[test]
fn the_file_read_is_lossless_and_authoritative() {
    let (_, report) = read_all(as_file(&archive()));
    assert_eq!(report.rung, Rung::Exact);
    assert!(report.rung.is_authoritative());
    assert!(
        report.is_lossless(),
        "unexpected warnings: {:?}",
        report.warnings
    );
}

#[test]
fn the_pipe_read_is_lossy_in_exactly_the_documented_ways() {
    let (_, report) = read_all(as_pipe(&archive()));

    assert_eq!(report.rung, Rung::ForwardOnly);
    assert!(!report.rung.is_authoritative());
    assert!(!report.is_lossless());

    // Precisely these two losses, and nothing else.
    assert!(report.warnings.contains(&Fidelity::TrailingIndexUnread {
        format: MOCK_CONTAINER
    }));
    assert!(report.warnings.contains(&Fidelity::EntryCountUnknown));

    let unexpected: Vec<_> = report
        .warnings
        .iter()
        .filter(|w| {
            !matches!(
                w,
                Fidelity::TrailingIndexUnread { .. } | Fidelity::EntryCountUnknown
            )
        })
        .collect();
    assert!(
        unexpected.is_empty(),
        "undocumented fidelity loss: {unexpected:?}"
    );
}

#[test]
fn random_access_works_from_a_file_and_is_refused_on_a_pipe() {
    let bytes = archive();

    let caps = MockContainer.caps();
    let r = resolve(
        as_file(&bytes),
        MOCK_CONTAINER,
        caps,
        &StreamPolicy::default(),
    )
    .unwrap();
    let mut ar = MockContainer.open(r, &OpenOpts::default()).unwrap();
    let mut e = ar.by_index(1).unwrap();
    let mut data = Vec::new();
    e.reader().read_to_end(&mut data).unwrap();
    assert_eq!(data, b"bravo bravo");

    let r = resolve(
        as_pipe(&bytes),
        MOCK_CONTAINER,
        caps,
        &StreamPolicy::default(),
    )
    .unwrap();
    let mut ar = MockContainer.open(r, &OpenOpts::default()).unwrap();
    let err = ar.by_index(1).unwrap_err();
    assert!(matches!(err, stuffr_core::Error::NotSeekable { .. }));
}

#[test]
fn opting_out_of_approximation_recovers_full_fidelity_from_a_pipe() {
    // --stream-policy with forward-only disabled must spill and become exact.
    let policy = StreamPolicy::Adaptive {
        allow_forward_only: false,
        spill: stuffr_core::SpillPolicy::default(),
        allow_degraded: true,
    };
    let bytes = archive();
    let r = resolve(
        as_pipe(&bytes),
        MOCK_CONTAINER,
        MockContainer.caps(),
        &policy,
    )
    .unwrap();
    assert_eq!(r.rung, Rung::Spilled);

    let mut ar = MockContainer.open(r, &OpenOpts::default()).unwrap();
    let mut e = ar.by_index(2).unwrap();
    let mut data = Vec::new();
    e.reader().read_to_end(&mut data).unwrap();
    assert_eq!(data, b"");
    // `Entry` holds a `Box<dyn Read + Send>`, so dropck conservatively extends
    // the mutable borrow of `ar` through `e`'s whole scope (the boxed trait
    // object's destructor could, in principle, touch it). Drop `e` explicitly
    // so the immutable `ar.fidelity()` borrow below is allowed; this changes
    // nothing about what is asserted.
    drop(e);
    assert!(
        ar.fidelity().is_lossless(),
        "spilling must restore full fidelity"
    );
}

#[test]
fn fidelity_warnings_serialize_for_the_json_output_mode() {
    let (_, report) = read_all(as_pipe(&archive()));
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("forward-only"));
    assert!(json.contains("trailing-index-unread"));
}
