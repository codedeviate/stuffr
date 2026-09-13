use stuffr_core::FormatKind;
use stuffr_core::testing::{CODEC_SLOTS, CONTAINER_SLOTS};

#[test]
fn facade_reexports_core_version() {
    assert_eq!(stuffr::VERSION, stuffr_core::VERSION);
    assert!(!stuffr::VERSION.is_empty());
}

/// Slot names the fuzzer's selector tables carry that this build legitimately
/// does not register — a format present on only ONE of the two tiers.
///
/// **Empty today, and that is measured rather than assumed.** Every format
/// with two backends registers under a single shared `FormatId` —
/// `xz_shared.rs`'s `XZ`, `lzma_shared.rs`'s `LZMA`, `zstd_shared.rs`'s
/// `ZSTD` — so which backend wins changes the *implementation* behind a name,
/// never the name itself. All fifteen slots therefore resolve on both legs
/// the gate runs (`make test` and `make test-pure`).
///
/// **It will not stay empty.** `stuffr/Cargo.toml`'s `legacy = []` is in
/// `full` but not in `default = ["pure"]`, so the first Phase 3-4 legacy
/// format registers under `--all-features` and not on the default leg. The
/// day its slot is appended, this test fails `make test-pure` — and the fix
/// is a name here, not a weakened assertion.
///
/// A name added here must be a real one-tier format, not a typo being waved
/// through: a typo resolves on neither tier, which is exactly what the
/// assertion below exists to catch.
const TIER_SPECIFIC: &[&str] = &[];

/// A `TIER_SPECIFIC` entry that names no slot at all is an exemption with
/// nothing to exempt — most likely a slot that was renamed out from under it,
/// leaving the real name unguarded while the stale one silently keeps the
/// escape hatch alive. The tables are append-only, so this can only happen by
/// mistake, and nothing else in the tree would notice.
#[test]
fn every_tier_specific_exemption_names_a_real_slot() {
    for name in TIER_SPECIFIC {
        assert!(
            CODEC_SLOTS.contains(name) || CONTAINER_SLOTS.contains(name),
            "TIER_SPECIFIC exempts {name:?}, which is in neither slot table — a stale \
             exemption leaves the slot it was meant to cover unguarded"
        );
    }
}

/// Every selector slot must name a format this build actually registers.
///
/// The tables are the wire format of every corpus seed on disk, so a typo in
/// one is not a compile error anywhere — it is a slot that silently decodes to
/// "no such format" and a fuzz target that quietly tests nothing. Nothing else
/// in the tree would notice.
#[test]
fn every_selector_slot_names_a_registered_format() {
    let matrix = stuffr::registry().matrix();
    let ids = |kind: FormatKind| -> Vec<&'static str> {
        matrix
            .iter()
            .filter(|row| row.kind == kind)
            .map(|row| row.id.as_str())
            .collect()
    };

    for (table, kind, label) in [
        (CODEC_SLOTS, FormatKind::Codec, "CODEC_SLOTS"),
        (CONTAINER_SLOTS, FormatKind::Container, "CONTAINER_SLOTS"),
    ] {
        let registered = ids(kind);
        for name in table {
            assert!(
                registered.contains(name) || TIER_SPECIFIC.contains(name),
                "{label} slot {name:?} is registered by neither tier — a typo there is a \
                 corpus seed that decodes to no format at all. Registered {kind:?}s here: \
                 {registered:?}"
            );
        }
    }
}

/// A duplicated slot is not an error anywhere else, but it wastes a selector
/// value and makes two distinct bytes mean the same format forever — the table
/// is append-only, so it cannot be tidied up later.
#[test]
fn no_selector_slot_is_listed_twice() {
    for (table, label) in [
        (CODEC_SLOTS, "CODEC_SLOTS"),
        (CONTAINER_SLOTS, "CONTAINER_SLOTS"),
    ] {
        for (i, name) in table.iter().enumerate() {
            assert!(
                !table[..i].contains(name),
                "{label} lists {name:?} twice (slots {} and {i}); the table is append-only, so \
                 the duplicate cannot be removed later without changing every seed's meaning",
                table[..i].iter().position(|n| n == name).unwrap()
            );
        }
    }
}
