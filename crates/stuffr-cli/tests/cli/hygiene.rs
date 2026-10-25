use crate::common::*;
use std::path::Path;

// ---------------------------------------------------------------------
// The test suite's own temp directories.
// ---------------------------------------------------------------------

/// `tmp_dir()` named its directories `stuffr-cli-archive-{pid}-{counter}`,
/// never removed them on a failing path, and so accumulated thousands of
/// them. PIDs are reused, so a later run landing on a recycled PID inherited
/// its predecessor's directories WITH CONTENTS, and five unrelated tests
/// failed with "already exists" — a red gate that went green again when the
/// leftovers were deleted, with no code change at all.
///
/// The fix is a random component no other run can reproduce. What this test
/// pins is precisely that: the part of the name that is not derivable from
/// the pid and the counter must exist. Under the old scheme the whole name
/// was derivable, and the tail below was the counter's digits alone.
#[test]
fn a_temp_directory_name_is_not_reproducible_from_the_pid_and_a_counter() {
    let dir = tmp_dir();
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "a fresh temp directory must be empty — inheriting one with contents \
         in it is the whole failure this guards against"
    );

    let name = dir.file_name().unwrap().to_string_lossy().into_owned();
    let derivable = format!("stuffr-cli-archive-{}-", std::process::id());
    let tail = name
        .strip_prefix(&derivable)
        .unwrap_or_else(|| panic!("unexpected temp directory name: {name}"));
    assert!(
        tail.contains('-') && !tail.chars().all(|c| c.is_ascii_digit()),
        "everything after the pid was the counter alone, so a second run on a \
         recycled pid reproduced this name exactly: {name}"
    );

    // `tmp()` shares the same token, and had the same weakness: its old name
    // was `stuffr-cli-{pid}-{name}` exactly, every character of it derivable
    // by any other run that landed on the same pid.
    let other = tmp("token-check");
    let other_name = other.file_name().unwrap().to_string_lossy().into_owned();
    assert_ne!(
        other_name,
        format!("stuffr-cli-{}-token-check", std::process::id()),
        "tmp() must carry the run token too"
    );
    assert!(
        other_name.ends_with("-token-check"),
        "…and must still end in the caller's own name: {other_name}"
    );
}

/// Every `cargo install stuffr-cli --features <x>` a shipped document prints
/// must name a feature `stuffr-cli` actually declares.
///
/// This exists because the opposite shipped. `crates/stuffr-cli/Cargo.toml`
/// carried no `[features]` section at all, while `README.md` printed
/// `cargo install stuffr-cli --features c-backed` as a copyable line — and
/// Cargo resolves a `--features` name against the package being installed,
/// not against its dependencies, so the command answered "the package
/// 'stuffr-cli' does not contain this feature" and the only working spelling
/// (`--features stuffr/c-backed`) appeared in no document. Phase 3b made it
/// acute by adding `legacy`, whose whole point is that a user turns it on.
///
/// Parsed out of the documents rather than listed here: a command added to a
/// README by a future phase is exactly the case a hardcoded list cannot
/// cover. The `[features]` table is read as text for the same reason the
/// version grep in `CLAUDE.md` is — no TOML parser is a dependency of this
/// crate, and a feature line is `name = [...]` at the start of a line, which
/// is unambiguous inside the one section this looks at.
#[test]
fn documented_install_commands_name_features_this_crate_declares() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = std::fs::read_to_string(manifest_dir.join("Cargo.toml")).unwrap();

    let features: Vec<String> = manifest
        .split("\n[")
        .find(|section| section.starts_with("features]"))
        .expect(
            "stuffr-cli must declare a [features] section: without one, every \
                 documented `cargo install stuffr-cli --features …` fails",
        )
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(_, rhs)| rhs.trim_start().starts_with('['))
        .map(|(name, _)| name.trim().to_string())
        .collect();
    assert!(
        features.contains(&"legacy".to_string()),
        "the parse found {features:?}; if `legacy` is missing the scan itself is broken, \
         not the manifest"
    );

    // The same list the count guards scan — widened past this crate's own
    // three documents for the same reason they were: a stale `--features`
    // spelling in `CONTRIBUTING.md` or on another crate's published page
    // fails exactly as loudly for the reader who copies it.
    let docs = user_facing_documents();
    let mut commands_checked = 0usize;
    for doc in docs {
        let text = std::fs::read_to_string(&doc).unwrap();
        for line in text.lines() {
            // `cargo install [--locked] stuffr-cli ...`: flags may precede
            // the package name.
            let Some(rest) = line
                .split("cargo install")
                .nth(1)
                .and_then(|r| r.split("stuffr-cli").nth(1))
            else {
                continue;
            };
            let Some(after) = rest.split("--features").nth(1) else {
                continue;
            };
            let name = after.split_whitespace().next().unwrap_or("");
            commands_checked += 1;
            assert!(
                features.contains(&name.to_string()),
                "{} prints `cargo install stuffr-cli --features {name}`, but stuffr-cli \
                 declares only {features:?} — that command fails with \"the package \
                 'stuffr-cli' does not contain this feature\"",
                doc.display()
            );
        }
    }
    assert!(
        commands_checked >= 2,
        "expected the READMEs to print at least the c-backed and legacy install \
         commands; found {commands_checked} — the scan has stopped finding them"
    );
}

/// **An UNQUALIFIED "<number> codecs/containers" claim, checked too.**
///
/// The sibling below only checks a count carrying one of three qualifiers,
/// which is why `crates/stuffr-cli/README.md` could name all five legacy
/// formats and then, twenty lines lower in the same published page, say
/// "Eleven codecs (…) and four containers (…)" with nothing failing. A bare
/// codec count is the same class that test already owns; only the phrasing
/// escaped it.
///
/// The rule has to allow a legitimately NARROWED claim — a feature table's
/// `pure` row really does describe eleven codecs and four containers — so it
/// is: an unqualified count must be the FULL registry figure, unless the
/// clause it sits in carries a narrowing cue (`pure`, `writable`,
/// `round-trip`, `read-only`, `legacy`, `no-default-features`), in which
/// case one of the narrowed figures will do. A claim that is neither is what
/// "Eleven codecs and four containers" was.
///
/// Clauses, not sentences: the flattened text is split on `. ` AND on `|`,
/// so a markdown table cell is its own clause and a cue in the neighbouring
/// row cannot vouch for it.
///
/// **What it does not reach**, so nobody overtrusts it: spelled-out numbers
/// only (a digit evades, as it does in the sibling — no document uses one
/// today); the nouns `codecs` and `containers` only, never `formats`, which
/// is deliberately left to narrate; and a cue anywhere in the clause is
/// taken at face value rather than parsed, so a long clause can excuse a
/// narrowed count it did not really mean.
#[test]
fn no_document_carries_a_stale_unqualified_codec_or_container_count() {
    const LEGACY_ONLY_CODECS: &[&str] = &["compress"];
    const LEGACY_ONLY_CONTAINERS: &[&str] = &["lha", "arj", "arc", "zoo"];
    const CUES: &[&str] = &[
        "pure",
        "pure-tier",
        "writable",
        "round-trip",
        "read-only",
        "legacy",
        "no-default-features",
    ];
    const QUALIFIERS: &[&str] = &["round-trip", "read-only", "pure-tier"];
    /// How many words before the count a narrowing cue may sit.
    const CUE_WINDOW: usize = 8;

    let registry = stuffr::registry();
    let rows = registry.matrix();
    let is_container = |id| registry.container(id).is_some();
    let count = |container: bool, pred: &dyn Fn(&stuffr::FormatRow) -> bool| {
        rows.iter()
            .filter(|r| is_container(r.id) == container && pred(r))
            .count()
    };
    let legacy = |container: bool, id: &str| {
        if container {
            LEGACY_ONLY_CONTAINERS.contains(&id)
        } else {
            LEGACY_ONLY_CODECS.contains(&id)
        }
    };
    // The full count is the only one an unqualified, uncued claim may use.
    let full = |container: bool| count(container, &|_| true);
    // With a cue, any of these is a true statement about some build.
    let narrowed = |container: bool| {
        [
            count(container, &|r| r.write),
            count(container, &|r| !r.write),
            count(container, &|r| !legacy(container, r.id.as_str())),
        ]
    };

    const NUMBERS: &[(&str, usize)] = &[
        ("one", 1),
        ("two", 2),
        ("three", 3),
        ("four", 4),
        ("five", 5),
        ("six", 6),
        ("seven", 7),
        ("eight", 8),
        ("nine", 9),
        ("ten", 10),
        ("eleven", 11),
        ("twelve", 12),
        ("thirteen", 13),
        ("fourteen", 14),
        ("fifteen", 15),
        ("sixteen", 16),
        ("seventeen", 17),
        ("eighteen", 18),
        ("nineteen", 19),
        ("twenty", 20),
    ];

    let mut claims_checked = 0usize;
    for doc in user_facing_documents() {
        let text = std::fs::read_to_string(&doc).unwrap();
        let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
        for clause in flat.split(". ").flat_map(|s| s.split('|')) {
            let words: Vec<String> = clause
                .split(' ')
                .map(|w| {
                    w.trim_matches(|c: char| !c.is_alphanumeric() && c != '-')
                        .to_lowercase()
                })
                .collect();
            for i in 0..words.len() {
                let Some((_, value)) = NUMBERS.iter().find(|(w, _)| *w == words[i]) else {
                    continue;
                };
                let Some(noun) = words.get(i + 1) else {
                    continue;
                };
                // A qualified claim belongs to the sibling test, which can
                // say exactly which figure it must be.
                if QUALIFIERS.contains(&noun.as_str()) {
                    continue;
                }
                let container = match noun.as_str() {
                    "containers" => true,
                    "codecs" => false,
                    _ => continue,
                };
                claims_checked += 1;
                // The cue must be NEAR the count, not merely somewhere in
                // the clause. Measured why: `default = ["pure", "legacy"]`
                // appears in the same sentence as a general headline count
                // on `crates/stuffr/README.md`, and a clause-wide cue let a
                // deliberately-stalened "eleven codecs and four containers"
                // pass on the strength of a `pure` inside a code span twelve
                // words away. Eight words back through the noun is enough
                // for every real narrowed claim in the tree and not enough
                // for that.
                let from = i.saturating_sub(CUE_WINDOW);
                let cued = words[from..=i + 1]
                    .iter()
                    .any(|w| CUES.contains(&w.as_str()));
                let want_full = full(container);
                let ok = if cued {
                    *value == want_full || narrowed(container).contains(value)
                } else {
                    *value == want_full
                };
                assert!(
                    ok,
                    "{} says `{} {noun}`, but this build registers {want_full} {noun} \
                     (narrowed counts, allowed only in a clause naming a narrowing — \
                     {CUES:?}, within {CUE_WINDOW} words — are {:?}). The clause is \
                     {clause:?}",
                    doc.display(),
                    words[i],
                    narrowed(container),
                );
            }
        }
    }

    assert!(
        claims_checked >= 5,
        "the scan found only {claims_checked} unqualified counts — it is matching nothing \
         and proving nothing"
    );
}

/// **Every "<number> round-trip/read-only/pure-tier <noun>" claim in the
/// documents a user reads, checked against the live registry.**
///
/// This closes a class rather than an instance. Three stale
/// write-capability claims were found BY HAND across Phase 3c Tasks 5, 6 and
/// 7 — `README.md`'s own headline said "four round-trip containers, plus
/// four read-only legacy containers" when the binary had six and two — and
/// the reason no test caught any of them is structural:
/// `the_examples_page_cannot_carry_a_stale_count_or_a_shipped_still_to_come`
/// derives ROW counts from the registry and has no notion of the WRITE
/// column, and it reads only the `--examples` page, not the two READMEs
/// where two of the three lived.
///
/// Three qualifiers, each with a count the registry can answer:
///
/// - `round-trip` — the format can be written as well as read
///   (`FormatRow::write`, which is `ContainerCaps::write` for a container
///   and `CodecCaps::encode` for a codec; zstd's `weak` still counts as
///   writable, which is what `stuffr formats` shows).
/// - `read-only` — it cannot.
/// - `pure-tier` — what remains once the legacy formats are excluded, which
///   is what `--no-default-features --features pure` builds. Included rather
///   than exempted on purpose: a tier-narrowed sentence is a real thing to
///   want to write, and leaving it unchecked would be a loophole any stale
///   claim could take.
///
/// The noun is `codecs` or `containers` and never `formats`, deliberately:
/// `README.md` carries a historical "Phase 3b adds three READ-ONLY legacy
/// formats" sentence that was true when written and is narrating, not
/// claiming. Narrowing the noun is how that stays sayable without carving a
/// per-sentence exception a future stale claim could hide in. An optional
/// `legacy` may sit between the qualifier and the noun ("two read-only
/// legacy containers").
#[test]
fn no_document_carries_a_stale_round_trip_or_read_only_count() {
    // `compress` is to codecs what `LEGACY_ONLY_CONTAINERS` is to
    // containers: registered only when the `legacy` feature is compiled in,
    // which every real build of this binary does (see
    // `the_examples_page_cannot_carry_a_stale_count_or_a_shipped_still_to_come`'s
    // own comment for the measured proof), so it is what a `pure-tier`
    // count excludes.
    const LEGACY_ONLY_CODECS: &[&str] = &["compress"];
    const LEGACY_ONLY_CONTAINERS: &[&str] = &["lha", "arj", "arc", "zoo"];

    let registry = stuffr::registry();
    let rows = registry.matrix();
    let is_container = |id| registry.container(id).is_some();

    let count = |container: bool, pred: &dyn Fn(&stuffr::FormatRow) -> bool| {
        rows.iter()
            .filter(|r| is_container(r.id) == container && pred(r))
            .count()
    };
    let legacy = |container: bool, id: &str| {
        if container {
            LEGACY_ONLY_CONTAINERS.contains(&id)
        } else {
            LEGACY_ONLY_CODECS.contains(&id)
        }
    };

    // (qualifier, is_container) -> the count the registry says
    let expected = |qualifier: &str, container: bool| -> usize {
        match qualifier {
            "round-trip" => count(container, &|r| r.write),
            "read-only" => count(container, &|r| !r.write),
            "pure-tier" => count(container, &|r| !legacy(container, r.id.as_str())),
            other => unreachable!("unhandled qualifier {other}"),
        }
    };

    const NUMBERS: &[(&str, usize)] = &[
        ("one", 1),
        ("two", 2),
        ("three", 3),
        ("four", 4),
        ("five", 5),
        ("six", 6),
        ("seven", 7),
        ("eight", 8),
        ("nine", 9),
        ("ten", 10),
        ("eleven", 11),
        ("twelve", 12),
        ("thirteen", 13),
        ("fourteen", 14),
        ("fifteen", 15),
        ("sixteen", 16),
        ("seventeen", 17),
        ("eighteen", 18),
        ("nineteen", 19),
        ("twenty", 20),
    ];

    let docs = user_facing_documents();

    let mut claims_checked = 0usize;
    for doc in &docs {
        let text = std::fs::read_to_string(doc).unwrap();
        // Whitespace-normalised: every one of these documents wraps, and a
        // count split across a line break must still read as one phrase.
        let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
        let words: Vec<String> = flat
            .split(' ')
            .map(|w| {
                w.trim_matches(|c: char| !c.is_alphanumeric() && c != '-')
                    .to_lowercase()
            })
            .collect();
        for i in 0..words.len() {
            let Some((_, value)) = NUMBERS.iter().find(|(w, _)| *w == words[i]) else {
                continue;
            };
            let Some(qualifier) = words.get(i + 1) else {
                continue;
            };
            if !["round-trip", "read-only", "pure-tier"].contains(&qualifier.as_str()) {
                continue;
            }
            // An optional `legacy` between the qualifier and the noun.
            let noun = match words.get(i + 2).map(String::as_str) {
                Some("legacy") => words.get(i + 3),
                other => other.and_then(|_| words.get(i + 2)),
            };
            let container = match noun.map(String::as_str) {
                Some("containers") => true,
                Some("codecs") => false,
                // `formats` deliberately excluded — see this test's doc.
                _ => continue,
            };
            claims_checked += 1;
            let want = expected(qualifier, container);
            assert_eq!(
                *value,
                want,
                "{} says `{} {qualifier}{} {}`, but this build has {want}. This is the \
                 check that closes the class three stale write-capability claims were found \
                 by hand in: the row-count guard cannot see the WRITE column, so nothing \
                 else would say so",
                doc.display(),
                words[i],
                if words.get(i + 2).map(String::as_str) == Some("legacy") {
                    " legacy"
                } else {
                    ""
                },
                if container { "containers" } else { "codecs" },
            );
        }
    }

    // A scan that matched nothing would pass forever. These documents carry
    // such claims today and the point of the test is that they stay true.
    assert!(
        claims_checked >= 8,
        "the scan found only {claims_checked} qualified counts across the {} documents — \
         it is matching nothing and proving nothing",
        docs.len()
    );
}
