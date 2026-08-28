# stf — development gates.
#
# `make check` is the project's Definition of Done, made executable. It runs
# the same commands in the same order a CI job would, so a green local run and
# a green pipeline mean the same thing.

CARGO ?= cargo

.PHONY: help check fmt fmt-check lint test release hooks clean

help:
	@echo 'stf development targets:'
	@echo '  make check    fmt, lint, test, release build — the full gate'
	@echo '  make fmt      format the workspace'
	@echo '  make lint     clippy, all targets and features, warnings denied'
	@echo '  make test     full test suite with all features'
	@echo '  make release  optimised build, plus the no-default-features check'
	@echo '  make hooks    install the commit-msg hook (once per clone)'
	@echo '  make clean    remove build artefacts'

# Ordered so the cheapest gate fails first.
check: fmt-check lint test release
	@echo '✓ all gates passed'

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all --check

lint:
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

test:
	$(CARGO) test --workspace --all-features

# The second build is not redundant: it proves stuffr-core still compiles with
# no optional features, which is the guarantee behind "cargo install needs no
# C toolchain".
release:
	$(CARGO) build --release --workspace
	$(CARGO) build -p stuffr-core --no-default-features

hooks:
	git config core.hooksPath .githooks
	@echo '✓ commit-msg hook active (core.hooksPath = .githooks)'

clean:
	$(CARGO) clean
