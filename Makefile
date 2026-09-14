# stuffr — development gates.
#
# `make check` is the project's Definition of Done, made executable. It runs
# the same commands in the same order a CI job would, so a green local run and
# a green pipeline mean the same thing.

CARGO ?= cargo

.PHONY: help check fmt fmt-check lint test test-pure release miri hooks clean fuzz-corpus fuzz

help:
	@echo 'stuffr development targets:'
	@echo '  make check    fmt, lint, test, release build — the full gate'
	@echo '  make fmt      format the workspace'
	@echo '  make lint     clippy, all targets and features, warnings denied'
	@echo '  make test     full test suite with all features'
	@echo '  make test-pure  the default (pure) tier, where no C backend wins'
	@echo '  make release  optimised build, plus the no-default-features check'
	@echo '  make miri     Miri over the two unsafe regions (tar.rs, ar.rs)'
	@echo '  make hooks    install the commit-msg hook (once per clone)'
	@echo '  make clean    remove build artefacts'
	@echo '  make fuzz-corpus  (re)generate fuzz/corpus/{codec,container,chain}'
	@echo '  make fuzz     short, seeded smoke pass over codec/container/chain (mirrors CI)'

# Ordered so the cheapest gate fails first.
check: fmt-check lint test test-pure release
	@echo '✓ all gates passed'

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all --check

lint:
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

test:
	$(CARGO) test --workspace --all-features

# Not redundant with `test`. Where a format has both a C and a pure backend,
# registration is mutually exclusive and the C one wins, so `--all-features`
# resolves every such format to its C backend and never exercises the pure one
# end to end. Tests written `#[cfg(all(feature = "x-pure", not(feature =
# "x-c")))]` — the ones that prove what a default `cargo install` actually does
# — compile to nothing under `--all-features` and would never run at all.
#
# The default feature set IS the pure tier, so this runs them. It is a
# different test set, not a subset: `test` covers the C backends, this covers
# the pure selection, and neither contains the other.
test-pure:
	$(CARGO) test --workspace

# The second build is not redundant: it proves stuffr-core still compiles with
# no optional features, which is the guarantee behind "cargo install needs no
# C toolchain".
#
# The third and fourth are a compile-only floor, not a third test leg:
# `check` runs exactly two (`test`, `test-pure`).
#
# This used to guard the pure+legacy combination, back when `default =
# ["pure"]` and `legacy` lived only in the `--all-features` leg (which also
# enables `c-backed`) — so pure+legacy (what a `--features legacy` user on a
# pure build actually has) was never TESTED by either leg. That gap is
# CLOSED now, not by this target: `legacy` joined `default` (see
# `crates/stuffr/Cargo.toml`), so `test-pure`'s plain `cargo test --workspace`
# already builds and runs the real pure+legacy combination end to end, with
# behavioural tests, not just a compile check.
#
# Closing that gap opened the inverse one: with `legacy` in `default` too,
# NOTHING in `test`/`test-pure`/the two builds above ever compiles `pure`
# WITHOUT `legacy` — which is exactly `--no-default-features --features
# pure`, the configuration the `purity` CI job's `cargo tree` assumes
# compiles (it only walks the dependency graph; it proves no C library
# leaks in, not that the crate builds). A legacy format that accidentally
# leaned on something `pure` doesn't otherwise pull in would pass the whole
# gate and only break for a `--no-default-features --features pure`
# consumer. `cargo check`, not `cargo test`, is what this guards — a full
# third `cargo test` run would cost another 35-60s for a combination whose
# realistic failure mode is a compile error, not a behavioural one.
#
# Two commands, checking two different things — stated explicitly because a
# fix-round review once caught an earlier draft's comment and command
# disagreeing, and the same shape of mistake (a comment describing the
# combination the OTHER command tests) is easy to reintroduce here:
# - `--features pure --no-default-features` (no `legacy`, no `c-backed`) is
#   the newly-untested combination above: pure alone, isolated from legacy.
#   Verified clean: 0 warnings.
# - `--features legacy --no-default-features` (no `pure`, no `c-backed`) is
#   narrower still: legacy alone, isolated from every optional codec/
#   container. It compiles too, but with 7 dead-code warnings in
#   `stuffr-formats` (`normalize.rs`'s error-normalisation helpers, used only
#   by the pure/c-backed codecs this configuration excludes) — expected, and
#   not what a `--features legacy` user's build actually looks like (every
#   real build of `stuffr-cli` now carries `pure` too — see the dependency-
#   edge note in `crates/stuffr-cli/Cargo.toml`). Kept anyway as the same
#   zero-optional-features floor the two builds above check for
#   `stuffr-core`/`stuffr-formats`, applied to `stuffr` under `legacy`
#   specifically: it proves `legacy` does not silently lean on `pure` being
#   compiled in, independent of whether a real build has `pure` on.
release:
	$(CARGO) build --release --workspace
	$(CARGO) build -p stuffr-core --no-default-features
	$(CARGO) build -p stuffr-formats --no-default-features
	$(CARGO) check -p stuffr --features pure --no-default-features
	$(CARGO) check -p stuffr --features legacy --no-default-features

# NOT part of `check`, deliberately: Miri is 10-50x slower than a native run
# and the gate is already 35-60s. Run it when you touch the self-referential
# pointer handling in `tar.rs` or `ar.rs` — the workspace's only two `unsafe`
# regions — and let the CI `miri` job run it the rest of the time.
#
# Scoped to those two modules' own tests rather than the whole crate. That is
# not a coverage compromise: nothing outside them contains `unsafe`, and the
# pure codecs' decode loops under Miri cost minutes each for no aliasing
# information at all.
#
# Exactly the two format features, NOT --all-features: `xz-c`, `lzma-c` and
# `zstd-c` link liblzma and libzstd, and Miri cannot execute foreign
# functions. `stuffr-formats`' default feature set is EMPTY, so naming the
# two is also what makes these modules compile at all.
#
# Both aliasing models, because they disagree: Stacked Borrows is the stricter
# and older one, Tree Borrows the newer model that accepts some patterns SB
# rejects. Passing one is not passing the other, and both regions are clean
# under both today.
#
# The `--skip`s are a Miri limitation, not a coverage choice: Miri cannot
# spawn a process, so every cross-implementation test that shells out to
# `tar`, `ar` or `bsdtar` aborts under it. Those tests exercise interop
# rather than aliasing and are covered by `make test`. Do not widen this list
# to silence a Miri failure in a test that really does exercise the pointer
# regions — that failure is the bug.
# Every test in tar.rs/ar.rs that spawns a reference tool, by name. Keep
# this list exact rather than broad: a wildcard that happened to cover a
# pointer-exercising test would hide exactly the failure this target exists
# to find. `cargo miri test` fails hard on the first unsupported operation,
# so a newly added subprocess test shows up as a loud Miri failure and is
# added here deliberately.
MIRI_SKIP = --skip system_tar_ --skip we_accept_what_system_tar_ \
            --skip every_reference_writer_ --skip system_ar_ \
            --skip we_accept_what_system_ar_ --skip require_bin
# `-Zmiri-disable-isolation` because several of these tests write a real temp
# file (tar's `by_index` test needs a genuinely seekable source, which a
# Cursor is not, as far as `FileSource` is concerned). Isolation is Miri's
# default and it makes any `std::fs` call an unsupported-operation error, not
# a UB finding — turning it off changes nothing about the aliasing checks
# this target exists for.
MIRIFLAGS_BASE = -Zmiri-disable-isolation
# One filter, not two. libtest matches a filter as a SUBSTRING, and
# `tar::tests` contains `ar::tests` — so this single filter selects both
# modules and nothing else, and running them separately would just run tar's
# twice. Written as `ar::tests` with this comment rather than as a clever
# one-liner, because the coincidence is the sort of thing that gets
# "corrected" into a filter that silently stops covering tar.
MIRI_FILTER = ar::tests
# A floor on the test count, because everything above can fail OPEN. libtest
# exits 0 when a filter matches nothing, so the substring coincidence the
# filter depends on — or one too many entries in the skip list — would leave
# this target green while covering neither `unsafe` region, which is the one
# failure mode it exists to prevent. A floor rather than an exact count, so
# adding a test does not churn the Makefile; raise it when the real number
# moves well past it.
MIRI_MIN_TESTS = 28
miri:
	@set -e; \
	tmp=$$(mktemp); \
	trap 'rm -f "$$tmp"' EXIT INT TERM; \
	for flags in '$(MIRIFLAGS_BASE) -Zmiri-tree-borrows' '$(MIRIFLAGS_BASE)'; do \
	  echo "==> MIRIFLAGS=$$flags"; \
	  if MIRIFLAGS="$$flags" $(CARGO) +nightly miri test -p stuffr-formats --lib \
	      --features tar,ar -- $(MIRI_FILTER) $(MIRI_SKIP) > "$$tmp" 2>&1; then \
	    cat "$$tmp"; \
	  else \
	    cat "$$tmp"; exit 1; \
	  fi; \
	  n=$$(sed -n 's/^test result: ok\. \([0-9][0-9]*\) passed.*/\1/p' "$$tmp" | head -1); \
	  if [ -z "$$n" ] || [ "$$n" -lt $(MIRI_MIN_TESTS) ]; then \
	    echo "make miri: $${n:-0} tests ran, expected at least $(MIRI_MIN_TESTS)." >&2; \
	    echo "  The filter '$(MIRI_FILTER)' relies on 'tar::tests' containing" >&2; \
	    echo "  'ar::tests'. A module rename breaks that silently, and libtest" >&2; \
	    echo "  exits 0 on a filter that matches nothing." >&2; \
	    exit 1; \
	  fi; \
	  echo "==> $$n tests passed under MIRIFLAGS=$$flags"; \
	done

# Local rehearsal of ci.yml's `fuzz-smoke` job: same fixed -runs/-seed
# budget per target, same non-zero-execution-count check (Ruling H — see
# that job's comments for why the check exists and how it was verified to
# actually fail). NOT part of `check`, for the same reason `miri` isn't:
# cargo-fuzz needs the nightly toolchain, and `make check` is meant to run
# after every edit on whatever toolchain is active.
#
# Unlike CI, this does NOT `rm rust-toolchain.toml` — that file is a
# tracked part of a local checkout, not an ephemeral one, and deleting it
# out from under your working tree to run one target would be a surprise
# every other command in this Makefile has to live with afterwards. Every
# invocation below uses an explicit `+nightly` override instead, which wins
# over the 1.95 pin without touching the file (verified locally: `cargo
# fuzz run` with the pin in place and no override fails with "the option
# `Z` is only accepted on the nightly compiler"; `cargo +nightly fuzz run`
# does not).
#
# cargo-fuzz itself is a precondition, not something this target installs:
# `cargo install cargo-fuzz --locked` once per machine, matching the
# version ci.yml pins (0.13.2 at time of writing). A Makefile reaching past
# the workspace to modify your toolchain on every invocation would be worse
# than asking once.
FUZZ_RUNS = 2000
FUZZ_SEED = 1
fuzz: fuzz-corpus
	@status=0; \
	for target in codec container chain; do \
	  cmd="cargo +nightly fuzz run $$target -- -runs=$(FUZZ_RUNS) -seed=$(FUZZ_SEED)"; \
	  echo "==> $$cmd"; \
	  tmp=$$(mktemp); \
	  if ! $$cmd >"$$tmp" 2>&1; then \
	    echo "make fuzz: target '$$target' crashed (or otherwise exited non-zero) — see output below" >&2; \
	    cat "$$tmp"; rm -f "$$tmp"; status=1; continue; \
	  fi; \
	  : "No '|| true' on the next line, unlike ci.yml's otherwise-identical" ; \
	  : "copy. A make recipe runs under a plain /bin/sh with no -e, so a" ; \
	  : "no-match grep pipeline sets \$$? and carries on, reaching the" ; \
	  : "explicit empty/zero check below. GitHub Actions runs its run: block" ; \
	  : "under bash -e -o pipefail, where the same line would abort the whole" ; \
	  : "script before that check ever ran — hence the '|| true' there and" ; \
	  : "not here. Do not tidy either half into matching the other." ; \
	  n=$$(grep -oE 'Done [0-9]+ runs' "$$tmp" | tail -1 | grep -oE '[0-9]+'); \
	  if [ -z "$$n" ] || [ "$$n" -eq 0 ]; then \
	    echo "make fuzz: target '$$target' reported zero (or no) executions — treating as a failure, not a clean run" >&2; \
	    cat "$$tmp"; rm -f "$$tmp"; status=1; continue; \
	  fi; \
	  echo "target '$$target': $$n executions — OK"; \
	  rm -f "$$tmp"; \
	done; \
	exit $$status

hooks:
	git config core.hooksPath .githooks
	@echo '✓ commit-msg hook active (core.hooksPath = .githooks)'

# Regenerates fuzz/fuzz-run seed corpus under fuzz/corpus/{codec,container,chain}.
#
# NOT part of `check`: this WRITES real files under `fuzz/corpus/`, which is
# generated and gitignored (`fuzz/.gitignore`'s `/corpus`) rather than
# refreshed on every commit. `fuzz` depends on it because fuzzing from an
# empty corpus is much WORSE coverage — not because the execution-count check
# in that recipe would catch it. It would not: libFuzzer still performs its
# `-runs=N` mutation passes from nothing and prints a full `Done N runs`
# (measured: `codec` against an emptied corpus reported `Done 2000 runs`, exit
# 0). That check catches a target returning early on every input, or a run
# that never started. The generator itself lives in the FACADE crate
# (`crates/stuffr/tests/fuzz_corpus.rs`), not `stuffr-core` — `stuffr-core`
# has zero format dependencies and cannot build a real gzip stream or tar
# archive, only mocks — so it IS compiled and type-checked by `make
# test`/`make test-pure` on every run; only this target's actual write is
# skipped there, via `#[ignore]`.
#
# The recipe below does NOT just run that test: it checks the filter matched
# something and that seeds reached the disk. Neither is paranoia. A cargo test
# filter that matches nothing exits 0 and prints `0 passed`, so renaming the
# generator turns this target into a silent no-op — and `fuzz`'s downstream
# execution-count check will not notice, as this comment's own paragraph above
# already establishes (libFuzzer reports a full `Done N runs` from an empty
# corpus). With no guard at either end, the corpus — the harness's entire
# coverage story — could quietly become nothing with every gate still green.
# `--exact` would not close it: a renamed test matches nothing under `--exact`
# too, and still exits 0. Counting what ran, and then looking at the disk, is
# what closes it.
#
# `--features testing,legacy`, not just `testing`: Phase 3b's three read-only
# legacy slots (`compress`, `lha`, `arj`) are feature-gated behind `legacy`
# (in `full`, not in `default`), and `generate_corpus` only seeds a slot this
# build's registry actually has — see `registered_codec_slots`/
# `registered_container_slots` in `fuzz_corpus.rs`. Without `legacy` here,
# this target would keep regenerating a corpus silently missing all three,
# with every count-based guard below still green (they derive their expected
# counts from the same registry, so they'd agree with the smaller corpus).
fuzz-corpus:
	@out=$$($(CARGO) test -p stuffr --features testing,legacy generate_corpus -- --ignored 2>&1); \
	status=$$?; \
	printf '%s\n' "$$out"; \
	[ $$status -eq 0 ] || exit $$status; \
	ran=$$(printf '%s\n' "$$out" | sed -n 's/^test result: ok\. \([0-9][0-9]*\) passed.*/\1/p' \
	       | awk '{ total += $$1 } END { print total + 0 }'); \
	if [ "$$ran" -eq 0 ]; then \
	  echo "make fuzz-corpus: the 'generate_corpus' filter matched no test — the corpus was NOT regenerated" >&2; \
	  echo "  (a cargo test filter that matches nothing exits 0; this is the guard that turns that into a failure)" >&2; \
	  exit 1; \
	fi; \
	for target in codec container chain; do \
	  dir=fuzz/corpus/$$target; \
	  if [ -z "$$(find $$dir -type f -size +0c 2>/dev/null | head -1)" ]; then \
	    echo "make fuzz-corpus: $$dir holds no non-empty seed after a run the generator reported as passing" >&2; \
	    exit 1; \
	  fi; \
	done; \
	echo "✓ corpus regenerated ($$ran generator test(s) ran; codec/container/chain all non-empty)"

clean:
	$(CARGO) clean
