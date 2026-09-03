# stuffr — development gates.
#
# `make check` is the project's Definition of Done, made executable. It runs
# the same commands in the same order a CI job would, so a green local run and
# a green pipeline mean the same thing.

CARGO ?= cargo

.PHONY: help check fmt fmt-check lint test test-pure release hooks clean

help:
	@echo 'stuffr development targets:'
	@echo '  make check    fmt, lint, test, release build — the full gate'
	@echo '  make fmt      format the workspace'
	@echo '  make lint     clippy, all targets and features, warnings denied'
	@echo '  make test     full test suite with all features'
	@echo '  make test-pure  the default (pure) tier, where no C backend wins'
	@echo '  make release  optimised build, plus the no-default-features check'
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

hooks:
	git config core.hooksPath .githooks
	@echo '✓ commit-msg hook active (core.hooksPath = .githooks)'

clean:
	$(CARGO) clean
