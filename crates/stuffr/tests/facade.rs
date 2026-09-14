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
/// **No longer empty, exactly as predicted below, and the day has come:**
/// Phase 3b appended `compress`, `lha` and `arj` to `CODEC_SLOTS` /
/// `CONTAINER_SLOTS`. Measured, not assumed — `cargo test -p stuffr --test
/// facade every_selector_slot_names_a_registered_format`:
/// - `--all-features` (`legacy` on): passes.
/// - no features beyond the default (`legacy` off): failed with `CODEC_SLOTS
///   slot "compress" is registered by neither tier` before these three names
///   were added here.
///
/// So this is feature-gating, not the pure/c-backed backend split the
/// paragraph below was originally written about — but the shape is the same
/// the comment predicted: a name registered on `make test` and not on `make
/// test-pure` needs to be named here, and the fix is a name, not a weakened
/// assertion.
///
/// Every format with two backends still registers under a single shared
/// `FormatId` — `xz_shared.rs`'s `XZ`, `lzma_shared.rs`'s `LZMA`,
/// `zstd_shared.rs`'s `ZSTD` — so backend selection alone never puts a name
/// here; only a feature that is off by default does.
///
/// A name added here must be a real one-tier (or, as here, one-feature-set)
/// format, not a typo being waved through: a typo resolves on neither tier,
/// which is exactly what the assertion below exists to catch.
const TIER_SPECIFIC: &[&str] = &["compress", "lha", "arj"];

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
