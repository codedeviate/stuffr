# stuffr — development gates.
#
# `make check` is the project's Definition of Done, made executable. It runs
# the same commands in the same order a CI job would, so a green local run and
# a green pipeline mean the same thing.

CARGO ?= cargo

.PHONY: help check fmt fmt-check lint test test-pure release miri hooks clean

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
release:
	$(CARGO) build --release --workspace
	$(CARGO) build -p stuffr-core --no-default-features
	$(CARGO) build -p stuffr-formats --no-default-features

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

hooks:
	git config core.hooksPath .githooks
	@echo '✓ commit-msg hook active (core.hooksPath = .githooks)'

clean:
	$(CARGO) clean
