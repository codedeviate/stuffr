# stuffr — development gates.
#
# `make check` is the project's Definition of Done, made executable. It runs
# the same commands in the same order a CI job would, so a green local run and
# a green pipeline mean the same thing.

CARGO ?= cargo

# Two modes. DAYTIME (the default) holds back: fewer test threads, a lower
# libFuzzer RSS ceiling, and the same thread limit inside the Docker run, so
# there is a margin left on a machine that is also running Docker and IDEs.
# OVERNIGHT is `FULL=1` (any value but empty or 0): every core, libFuzzer's
# default ceiling, as before. `FULL=0` is daytime.
# Both modes run exactly the same tests; only concurrency (and the fuzz memory
# cap, which also sets libFuzzer's malloc limit) differs. CI passes
# FULL=1. TEST_THREADS is the daytime count (chosen by measurement, see
# CONTRIBUTING.md "What the gate costs"); it is ignored under FULL=1.
FULL ?=
TEST_THREADS ?= 4
ifeq ($(filter-out 0,$(strip $(FULL))),)
TEST_THREAD_ARGS = -- --test-threads=$(TEST_THREADS)
FUZZ_RSS_ARGS = -rss_limit_mb=1024
else
TEST_THREAD_ARGS =
FUZZ_RSS_ARGS =
endif

.PHONY: help check check-legs lint-latest deps-guard fmt fmt-check lint doc test test-pure release miri hooks clean fuzz-corpus fuzz compat-ubuntu sweep-tmp leak-snapshot leak-check tmp-leaks-selftest

help:
	@echo 'stuffr development targets:'
	@echo '  make check    fmt, lint, test, release build — the full gate'
	@echo '                (always ends by sweeping stale stuffr-* temp folders)'
	@echo '                Modes: daytime by default ($(TEST_THREADS) test threads, fuzz -rss_limit_mb=1024,'
	@echo '                the same thread limit in compat-ubuntu); FULL=1 (any value but'
	@echo '                empty or 0) lifts the limits: every core, libFuzzer default ceiling'
	@echo '  make check FULL=1  overnight mode (also works with test, test-pure, fuzz, compat-ubuntu)'
	@echo '  make sweep-tmp  remove stuffr-* temp folders older than a day (live pids kept)'
	@echo '  make leak-check  fail on stuffr-* temp folders made since the last leak-snapshot'
	@echo '  make tmp-leaks-selftest  self-test of scripts/tmp-leaks.sh'
	@echo '  make fmt      format the workspace, and fuzz/ (excluded from it)'
	@echo '  make lint     clippy, all targets and features, warnings denied'
	@echo '                (the workspace, and fuzz/ --locked)'
	@echo '  make lint-latest  clippy on the newest installed stable (own target dir)'
	@echo '  make test     full test suite with all features'
	@echo '  make test-pure  the default (pure) tier, where no C backend wins'
	@echo '  make release  optimised build, plus the no-default-features check'
	@echo '  make miri     Miri over the two unsafe regions (tar.rs, ar.rs)'
	@echo '  make hooks    install the commit-msg hook (once per clone)'
	@echo '  make clean    remove build artefacts'
	@echo '  make fuzz-corpus  (re)generate fuzz/corpus/{codec,container,chain,roundtrip,salvage,compat,infozip}'
	@echo '  make fuzz     short, seeded smoke pass over the seven targets (mirrors CI)'
	@echo '  make compat-ubuntu  the unzip, compress and zip suites against Ubuntu 24.04, in Docker'
	@echo '                (not in check; COMPAT_UBUNTU_ARGS=... is passed to the tests)'

# Ordered so the cheapest gate fails first.
#
# The legs run in a sub-make so `sweep-tmp` runs whether they passed or failed;
# `check` then exits with the legs' status. The leak snapshot is taken just
# before `test` and checked after `test-pure`.
#
# The leak snapshot is a fresh file per `check` run (mktemp, removed at the
# end), so two gates in one checkout cannot overwrite each other's.
check:
	@mkdir -p target; \
	snap=$$(mktemp target/tmp-leaks.snapshot.XXXXXX) || exit 1; \
	$(MAKE) --no-print-directory check-legs LEAK_SNAPSHOT="$$snap"; s=$$?; \
	rm -f "$$snap"; \
	$(MAKE) --no-print-directory sweep-tmp; \
	exit $$s

# One recipe, run in order, so `make -j` cannot reorder the snapshot, the tests
# and the leak check.
check-legs:
	@for t in deps-guard fmt-check lint doc leak-snapshot test test-pure leak-check release; do \
	  $(MAKE) --no-print-directory $$t || exit $$?; \
	done
	@echo '✓ all gates passed'

# Temp-folder hygiene. Only direct `stuffr-*` children of the user's temp dir
# are ever considered; see scripts/tmp-leaks.sh. The snapshot lives in target/,
# not the temp dir; `check` passes its own unique path (see above), and this
# default serves a hand-run `make leak-snapshot leak-check`.
LEAK_SNAPSHOT ?= target/tmp-leaks.snapshot

sweep-tmp:
	@sh scripts/tmp-leaks.sh sweep

leak-snapshot:
	@sh scripts/tmp-leaks.sh snapshot $(LEAK_SNAPSHOT)

leak-check:
	@sh scripts/tmp-leaks.sh check $(LEAK_SNAPSHOT)

tmp-leaks-selftest:
	@sh scripts/tmp-leaks.sh selftest

# Warns, never fails, when `target/debug/deps` has grown large enough to slow
# the gate. On macOS the dev profile's default `split-debuginfo=unpacked`
# keeps every build's `*.rcgu.o` beside the binaries, and cargo never prunes
# stale ones. At 1,123,729 entries (34 GB of target/) a freshly linked test
# binary took 20-22 s to START from that directory and 0 s from any other
# (amfid busy; not Gatekeeper, not ESET), which turned a 166 s gate into
# 6660 s. A fresh build holds ~6,000 entries. The threshold is a round number,
# about half the measured 1.1M slow point; one release cycle added about 15k
# entries per gate, so 100,000 tripped on a healthy tree. CI starts clean and
# never trips it.
DEPS_GUARD_MAX ?= 500000

deps-guard:
	@n=$$(ls -f target/debug/deps 2>/dev/null | wc -l | tr -d ' '); \
	if [ "$${n:-0}" -gt $(DEPS_GUARD_MAX) ]; then \
	  echo "⚠ target/debug/deps holds $$n entries (> $(DEPS_GUARD_MAX)): new test binaries"; \
	  echo "  start slowly from a crowded deps dir. Run 'cargo clean' once (see CONTRIBUTING.md)."; \
	fi

# `fuzz/` is `exclude`d from the workspace (see the root `Cargo.toml`), so a
# `--workspace` command does not reach it — which left FOUR fuzz targets
# unlinted, unformatted, and `fuzz/Cargo.lock` a version-bump site nothing in
# the gate could see. All three symptoms have one cause and one fix: name the
# manifest explicitly here, in both the format and the lint gates.
#
# **`--locked` is the part that closes the lockfile hole, and it is not
# decoration.** `fuzz/Cargo.lock` pins `stuffr`/`stuffr-core`/`stuffr-formats`
# by version, and nothing else in the gate builds the fuzz crate — so a bump
# that edited the four `Cargo.toml` sites and forgot the lockfile used to stay
# invisible until somebody ran `make fuzz`. Measured, by setting the lockfile
# back to `0.4.1` and re-running this target: `error: the lock file
# .../fuzz/Cargo.lock needs to be updated but --locked was passed to prevent
# this`, exit 101. So the gate now fails the bump directly.
#
# Cheap, and it was already clean when it landed: clippy found zero warnings
# across the four targets, rustfmt two wrapping violations (both fixed in the
# same commit). This adds coverage, not a backlog.
#
# NOT folded into `[workspace] members` instead, which would close the same
# three: that puts four libFuzzer-linked binaries into `cargo build --release
# --workspace`, i.e. into `release` below, for no gain.
#
# CI needs no separate edit — its `gate` job runs `make check`, so both new
# steps ride along.
fmt:
	$(CARGO) fmt --all
	$(CARGO) fmt --manifest-path fuzz/Cargo.toml --all

fmt-check:
	$(CARGO) fmt --all --check
	$(CARGO) fmt --manifest-path fuzz/Cargo.toml --all --check

lint:
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings
	$(CARGO) clippy --manifest-path fuzz/Cargo.toml --all-targets --locked -- -D warnings

# Rustdoc under `-D warnings`: a public item's doc comment that links a private
# item, or a link that no longer resolves, renders as dead text on docs.rs and
# nothing else in the gate notices. 0.10.2 had 288 of them. Write a private
# item as a plain code span, not an intra-doc link.
doc:
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --workspace --no-deps --all-features

test:
	$(CARGO) test --workspace --all-features $(TEST_THREAD_ARGS)

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
	$(CARGO) test --workspace $(TEST_THREAD_ARGS)

# Clippy on the newest installed `stable`, with the gate's exact arguments, in
# its own target dir so the pinned toolchain's cache is untouched. CI's
# `gate (stable)` job runs whatever stable is current; 0.10.0's first tag failed
# there on a lint the pinned 1.95 did not have. Not part of `check`: update
# stable first (`rustup update stable`) — the release skill says when.
lint-latest:
	CARGO_TARGET_DIR=target/lint-latest rustup run stable $(CARGO) clippy --workspace --all-targets --all-features -- -D warnings
	CARGO_TARGET_DIR=target/lint-latest rustup run stable $(CARGO) clippy --manifest-path fuzz/Cargo.toml --all-targets --locked -- -D warnings

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
#   container. `normalize.rs`'s helpers are gated on their consumers, so it
#   carries no dead-code warnings; it is still not what a `--features legacy`
#   user's build actually looks like (every real build of `stuffr-cli` now
#   carries `pure` too — see the dependency-edge note in
#   `crates/stuffr-cli/Cargo.toml`). Kept anyway as the same
#   zero-optional-features floor the two builds above check for
#   `stuffr-core`/`stuffr-formats`, applied to `stuffr` under `legacy`
#   specifically: it proves `legacy` does not silently lean on `pure` being
#   compiled in, independent of whether a real build has `pure` on.
# - `stuffr-formats --no-default-features` runs under `RUSTFLAGS="-D warnings"`:
#   the shape `cargo publish --dry-run` verify-builds; 0.10.0's dry run printed
#   six warnings nothing in the gate could see. `-D warnings` changes RUSTFLAGS,
#   which would invalidate every dependency's cache in `target/`, so this one
#   line gets its own target dir (`target/no-default-strict`).
release:
	$(CARGO) build --release --workspace
	$(CARGO) build -p stuffr-core --no-default-features
	RUSTFLAGS="-D warnings" CARGO_TARGET_DIR=target/no-default-strict $(CARGO) build -p stuffr-formats --no-default-features
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
# added here deliberately. Tests that only exercise multi-megabyte limits
# (the 16 MiB pax ceiling) and the GNU long-name ceiling tests (16 MiB and a
# 1 MiB long name, 0.10.3) are skipped under Miri too: they don't touch the
# unsafe regions and Miri runs them for hours.
MIRI_SKIP = --skip system_tar_ --skip we_accept_what_system_tar_ \
            --skip every_reference_writer_ --skip system_ar_ \
            --skip we_accept_what_system_ar_ --skip require_bin \
            --skip a_gnu_tar_sparse_archive_ --skip gnu_ar_on_mach_o_ \
            --skip a_pax_header_past_the_ceiling_ \
            --skip a_pax_header_inside_the_ceiling_ \
            --skip a_long_name_ --skip a_normal_long_name_ \
            --skip bsd_ar_with_odd_names_
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

# Local counterpart of ci.yml's `fuzz-smoke` job: same fixed -runs/-seed
# flags per target, same non-zero-execution-count check (Ruling H — see
# that job's comments for why the check exists and how it was verified to
# actually fail). NOT part of `check`, for the same reason `miri` isn't:
# cargo-fuzz needs the nightly toolchain, and `make check` is meant to run
# after every edit on whatever toolchain is active.
#
# NOT the same budget as CI, though: CI starts from the seeds alone, while
# this run loads the whole local `fuzz/corpus/<target>`, and libFuzzer
# executes every loaded input once before mutating — so once a local corpus
# outgrows -runs=$(FUZZ_RUNS), this is a regression replay of that corpus
# with no mutation at all.
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
# All seven targets are seeded. `salvage` was the exception until the Salvage
# Stage 1 final fix wave, and the measurement is worth keeping: unseeded, it
# plateaued at `cov: 217` after 100,000 runs, and the binary's own
# `salvage --list` over all 64 accumulated corpus inputs produced not one
# salvaged record — so its only oracle call (`check_salvage_claim`, which
# then fired on `SalvageStatus::Intact` alone, and `Intact` needs a CRC-32
# that matches its payload) was unreachable by construction. `target
# 'salvage': 2000 executions — OK` was true and proved nothing. Since
# Salvage Stage 3 the oracle is asked about all three claim-bearing tiers
# (`Intact`, `Complete`, `Unattested`). See `SALVAGE_SHAPES` in
# `crates/stuffr/tests/fuzz_corpus.rs` for what each of its twenty-nine
# seed shapes is for — at least one per `SALVAGE_SLOTS` entry, which
# `every_salvage_slot_carries_at_least_one_seed` fails the build over.
#
# `-runs` is sized per target to the corpus it loads: libFuzzer counts the
# initial corpus load against `-runs`, and `fuzz/corpus/<target>` only ever
# grows, so a fixed budget used to be swallowed whole by a large local corpus
# (salvage held 12,019 inputs: zero mutations, "OK"). The recipe counts the
# files (a missing dir counts 0), passes `-runs=<files> + FUZZ_RUNS`, and
# fails a target whose `Done N runs` is below the `-runs` it was given.
#
# An execution count still is not evidence, and this recipe's check is only
# that a target mutated. To measure whether the salvage oracle actually FIRES,
# see CONTRIBUTING.md's `STUFFR_FUZZ_SALVAGE_TRACE` recipe.
fuzz: fuzz-corpus
	@status=0; \
	for target in codec container chain roundtrip salvage compat infozip; do \
	  corpus=$$(find fuzz/corpus/$$target -type f 2>/dev/null | wc -l | tr -d ' '); \
	  runs=$$((corpus + $(FUZZ_RUNS))); \
	  cmd="cargo +nightly fuzz run $$target -- $(FUZZ_RSS_ARGS) -runs=$$runs -seed=$(FUZZ_SEED)"; \
	  echo "==> $$cmd"; \
	  tmp=$$(mktemp); \
	  if ! $$cmd >"$$tmp" 2>&1; then \
	    echo "make fuzz: target '$$target' crashed (or otherwise exited non-zero) — see output below" >&2; \
	    cat "$$tmp"; rm -f "$$tmp"; status=1; continue; \
	  fi; \
	  : "No '|| true' on the next line, unlike ci.yml's otherwise-identical" ; \
	  : "copy. A make recipe runs under a plain /bin/sh with no -e, so a" ; \
	  : "no-match grep pipeline sets \$$? and carries on, reaching the" ; \
	  : "explicit empty/short-run check below. GitHub Actions runs its run: block" ; \
	  : "under bash -e -o pipefail, where the same line would abort the whole" ; \
	  : "script before that check ever ran — hence the '|| true' there and" ; \
	  : "not here. Do not tidy either half into matching the other." ; \
	  n=$$(grep -oE 'Done [0-9]+ runs' "$$tmp" | tail -1 | grep -oE '[0-9]+'); \
	  if [ -z "$$n" ] || [ "$$n" -lt "$$runs" ]; then \
	    echo "make fuzz: target '$$target' ran $$n executions, expected $$runs ($$corpus corpus + $(FUZZ_RUNS) mutated) — a short run means no full mutation budget; treating as a failure" >&2; \
	    cat "$$tmp"; rm -f "$$tmp"; status=1; continue; \
	  fi; \
	  echo "target '$$target': $$n executions ($$corpus corpus + $$((n - corpus)) mutated) — OK"; \
	  rm -f "$$tmp"; \
	done; \
	exit $$status

hooks:
	git config core.hooksPath .githooks
	@echo '✓ commit-msg hook active (core.hooksPath = .githooks)'

# Regenerates fuzz/fuzz-run seed corpus under
# fuzz/corpus/{codec,container,chain,roundtrip,salvage,compat,infozip}.
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
	for target in codec container chain roundtrip salvage compat infozip; do \
	  dir=fuzz/corpus/$$target; \
	  if [ -z "$$(find $$dir -type f -size +0c 2>/dev/null | head -1)" ]; then \
	    echo "make fuzz-corpus: $$dir holds no non-empty seed after a run the generator reported as passing" >&2; \
	    exit 1; \
	  fi; \
	done; \
	echo "✓ corpus regenerated ($$ran generator test(s) ran; all seven target corpora non-empty)"

# The unzip family's Ubuntu oracle (0.16.0, ruling R10): apt's unzip
# 6.0-28ubuntu4.1 on ubuntu:24.04, which only CI's ubuntu-latest otherwise has.
# Builds tests/docker/ubuntu-24.04 (the toolchain rust-toolchain.toml names)
# and runs the Ubuntu and shared unzip suites in it with `CI=1`, so a missing
# or wrong reference fails instead of skipping. The repository is mounted
# read-only; cargo's registry and the target directory are named Docker
# volumes, so runs are incremental and the host's `target/` is never written.
# Runs as the image's unprivileged user (root ignores modes). Not part of
# `check`: Docker is not a gate dependency. `COMPAT_UBUNTU_ARGS` goes after
# `--` (a test name filter, `--nocapture`). The lib unit tests of
# `compat::unzip` run first (P42): the Linux-only ones run nowhere else.
# The compress family's ncompress personality (0.18.0) has its oracle here
# too, apt's ncompress 5.0-1 (`uncompress.real`): the `compat::compress` lib
# tests, then `compat_compress_ncompress`, one container for both.
# `docker volume rm
# stuffr-ubuntu-target stuffr-ubuntu-cargo-registry` starts clean.
COMPAT_UBUNTU_IMAGE ?= stuffr-ubuntu-24.04
COMPAT_UBUNTU_ARGS ?=
# Daytime mode also limits the container's test threads (it ignores the
# host's environment); FULL=1 lifts it. If COMPAT_UBUNTU_ARGS already carries
# its own --test-threads, the daytime one is omitted (libtest rejects or
# ignores a repeated option), so the user's value is the only one.
ifeq ($(filter-out 0,$(strip $(FULL))),)
COMPAT_UBUNTU_THREADS = --test-threads=$(TEST_THREADS)
else
COMPAT_UBUNTU_THREADS =
endif
COMPAT_UBUNTU_ALL_ARGS = $(if $(findstring --test-threads,$(COMPAT_UBUNTU_ARGS)),,$(COMPAT_UBUNTU_THREADS)) $(COMPAT_UBUNTU_ARGS)
COMPAT_UBUNTU_RUN = docker run --rm -e CI=1 \
	  -v "$(CURDIR)":/src:ro \
	  -v stuffr-ubuntu-cargo-registry:/home/oracle/.cargo/registry \
	  -v stuffr-ubuntu-target:/target \
	  $(COMPAT_UBUNTU_IMAGE)

compat-ubuntu:
	docker build --quiet \
	  --build-arg RUST_TOOLCHAIN=$$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml) \
	  -t $(COMPAT_UBUNTU_IMAGE) tests/docker/ubuntu-24.04
	$(COMPAT_UBUNTU_RUN) \
	  cargo test --locked -p stuffr-cli --lib compat::unzip -- $(COMPAT_UBUNTU_ALL_ARGS)
	$(COMPAT_UBUNTU_RUN) \
	  cargo test --locked -p stuffr-cli --test compat_unzip_ubuntu --test compat_unzip_common --test compat_unzip_safety \
	    --test compat_unzip_tty --test compat_unzip_umask --test compat_unzip_harness_selftest -- $(COMPAT_UBUNTU_ALL_ARGS)
	$(COMPAT_UBUNTU_RUN) sh -c \
	  'cargo test --locked -p stuffr-cli --lib compat::compress -- $(COMPAT_UBUNTU_ALL_ARGS) \
	   && cargo test --locked -p stuffr-cli --test compat_compress_ncompress -- $(COMPAT_UBUNTU_ALL_ARGS)'
	$(COMPAT_UBUNTU_RUN) sh -c \
	  'cargo test --locked -p stuffr-cli --lib compat::zip -- $(COMPAT_UBUNTU_ALL_ARGS) \
	   && cargo test --locked -p stuffr-cli --test compat_zip_common --test compat_zip_ubuntu --test compat_zip_bytes --test compat_zip_tty --test compat_zip_harness_selftest -- $(COMPAT_UBUNTU_ALL_ARGS)'

clean:
	$(CARGO) clean
