#![no_main]
use libfuzzer_sys::fuzz_target;
use std::path::Path;
use stuffr::entries;
use stuffr::ops::{self, Input};
use stuffr::probe::{self, Chain, MAX_CHAIN_DEPTH, PROBE_LEN, TAIL_LEN};
use stuffr_core::testing::check_error_is_classified;
use stuffr_core::{DEFAULT_MAX_RATIO, DecodeOpts};

/// The formats a chain names, outermost first.
fn layers(chain: &Chain) -> Vec<stuffr_core::FormatId> {
    let mut out = Vec::new();
    let mut c = chain;
    loop {
        match c {
            Chain::Codec { codec, inner } => {
                out.push(*codec);
                c = inner;
            }
            Chain::Container { container } => {
                out.push(*container);
                return out;
            }
            _ => return out,
        }
    }
}

/// Truthful identification on arbitrary bytes, below the file layer: every
/// registered confirm function as a window and as the whole stream, the
/// strict identification `ls` uses with and without a tail and a name, and
/// the inner-layer verdict `info` prints. None may panic; a strict chain
/// stays under `MAX_CHAIN_DEPTH` codec layers; the layer `info` names is
/// one of the chain's own.
fn identification(data: &[u8]) {
    let reg = stuffr::registry();
    let prefix = &data[..data.len().min(PROBE_LEN)];
    for row in reg.matrix() {
        for whole in [false, true] {
            let _ = reg.confirm(row.id, prefix, whole);
        }
    }
    let opts = DecodeOpts {
        memory_limit: Some(64 * 1024 * 1024),
        ..Default::default()
    };
    let tail = data
        .get(data.len().saturating_sub(TAIL_LEN)..)
        .filter(|t| t.len() == TAIL_LEN);
    for name in [None, Some(Path::new("x.tar.gz")), Some(Path::new("x.tar"))] {
        for t in [None, tail] {
            if let Some(chain) = probe::identify_strict(reg, name, prefix, t, &opts) {
                let codecs = layers(&chain)
                    .len()
                    .saturating_sub(usize::from(chain.container().is_some()));
                assert!(codecs < MAX_CHAIN_DEPTH, "{codecs} codec layers: {chain:?}");
            }
        }
        if let Ok((chain, _)) = probe::resolve_chain_checked(reg, name, prefix)
            && let Some(id) = probe::first_unconfirmed_layer(reg, &chain, prefix, &opts)
        {
            assert!(
                layers(&chain).contains(&id),
                "{id} is not a layer of {chain:?}"
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    identification(data);

    // No selector: arbitrary bytes go straight at format detection itself, so
    // `resolve_chain_deep` and the container dispatch inside `entries::list`
    // are exercised on every input — not just ones already shaped as one
    // registered format's payload. This is the layer Phase 2c's silent
    // wrong-format bug lived in.
    //
    // `ops::inspect` and `entries::list` both take `ops::Input`, which is
    // `Path(PathBuf) | Stdin` — there is no bytes variant — so the payload is
    // written to a temp file per iteration. Same throughput cost
    // `container.rs`'s seekable branch accepts, for the same reason: the
    // invariant must be reachable, and only a real (seekable) file lets
    // detection and the container open take the same path a real caller's
    // file input does.
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("input");
    std::fs::write(&path, data).expect("write temp input");

    if let Err(e) = ops::inspect(Input::Path(path.clone())) {
        check_error_is_classified(&e).expect("inspect error classification");
    }

    // Bounded for the same reason `codec.rs` bounds `DecodeOpts`: an
    // unbounded pre-flight allocation in a pure codec must not turn every
    // subsequent run into an OOM instead of a finding.
    let memory_limit = Some(64 * 1024 * 1024);
    if let Err(e) = entries::list(Input::Path(path), DEFAULT_MAX_RATIO, memory_limit) {
        check_error_is_classified(&e).expect("list error classification");
    }
});
