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
/// format, not a typo being waved through.
///
/// **The exemption is CONDITIONAL on the feature being absent**, and that is
/// the whole of it. A flat `&[&str]` consulted unconditionally would exempt
/// these three on `--all-features` too, where all three ARE registered — so
/// a name misspelled in a slot table and mirrored into this list would be
/// rescued by the very exemption meant to expose it, and pass on both legs
/// forever. (What still works today without the condition: `lha` genuinely
/// registers under `--all-features`, so it passes on the FIRST clause,
/// verified rather than exempted. It is the mirrored typo that escapes,
/// because a typo registers nowhere and the exemption then covers it
/// everywhere.)
///
/// `cfg!(feature = ...)` rather than a live-registry witness, which is what
/// `stuffr-cli`'s `legacy_bundle_compiled` has to use: THIS crate is the one
/// that declares the features, so it can ask the question directly, and a
/// misspelled FEATURE name is a `cargo` check-cfg warning — which `-D
/// warnings` turns into a build failure — rather than a silently false
/// constant.
struct TierSpecific {
    /// The slot name, as it appears in `CODEC_SLOTS`/`CONTAINER_SLOTS`.
    name: &'static str,
    /// Whether the Cargo feature that registers it is compiled into THIS
    /// build. When it is, the name is not exempt from anything: it must be
    /// genuinely registered.
    compiled: bool,
}

const TIER_SPECIFIC: &[TierSpecific] = &[
    TierSpecific {
        name: "compress",
        compiled: cfg!(feature = "compress"),
    },
    TierSpecific {
        name: "lha",
        compiled: cfg!(feature = "lha"),
    },
    TierSpecific {
        name: "arj",
        compiled: cfg!(feature = "arj"),
    },
];

/// True only if `name` is listed AND its feature is absent from this build.
fn exempt_from_registration(name: &str) -> bool {
    TIER_SPECIFIC.iter().any(|t| t.name == name && !t.compiled)
}

/// A `TIER_SPECIFIC` entry that names no slot at all is an exemption with
/// nothing to exempt — most likely a slot that was renamed out from under it,
/// leaving the real name unguarded while the stale one silently keeps the
/// escape hatch alive. The tables are append-only, so this can only happen by
/// mistake, and nothing else in the tree would notice.
#[test]
fn every_tier_specific_exemption_names_a_real_slot() {
    for entry in TIER_SPECIFIC {
        let name = &entry.name;
        assert!(
            CODEC_SLOTS.contains(name) || CONTAINER_SLOTS.contains(name),
            "TIER_SPECIFIC exempts {name:?}, which is in neither slot table — a stale \
             exemption leaves the slot it was meant to cover unguarded"
        );
    }
}

/// The other half, and the one the flat list could not make: when a
/// `TIER_SPECIFIC` name's feature IS compiled, the format must genuinely be
/// registered. Checking the slot table alone (which is what
/// `every_tier_specific_exemption_names_a_real_slot` does) looks in the same
/// wrong place a mirrored typo lives in.
#[test]
fn every_tier_specific_name_is_registered_when_its_feature_is_compiled() {
    let matrix = stuffr::registry().matrix();
    for entry in TIER_SPECIFIC {
        if !entry.compiled {
            continue;
        }
        assert!(
            matrix.iter().any(|row| row.id.as_str() == entry.name),
            "TIER_SPECIFIC names {:?} and its Cargo feature IS compiled into this build, \
             but no such format is registered — either the registration broke or the name \
             is a typo the exemption would otherwise wave through on both legs",
            entry.name
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
                registered.contains(name) || exempt_from_registration(name),
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
