# The Debian 13 oracle of the Linux compatibility families (0.27.0): apt's
# unzip 6.0-29+deb13u1, zip 3.0-15+deb13u1, ncompress 5.0-3, bzip2 and GNU
# gzip 1.13 on debian:trixie, with a Rust toolchain to build and run the
# suites beside them. (Replaces the Ubuntu 24.04 image of 0.16.0-0.26.0.)
# The harness checks the unzip, zip and ncompress versions itself
# (`unzip_dir()`, `zip_dir()`, `ncompress_dir()` require them under `CI`), so a
# newer apt package fails the run loudly instead of being used as the oracle.
#
# Used by `make compat-debian`, which builds this image and runs the unzip,
# compress, zip, bzip2 and gzip suites in it with `CI=1`. The repository is
# mounted read-only at /src; cargo's registry and the target directory are
# named volumes, so runs are incremental and nothing is written into the
# host's `target/`.
# Pinned by digest (the multi-arch index of debian:trixie on 2026-11-13) so a
# re-pushed tag cannot change the base under us; refresh it deliberately.
FROM debian:trixie@sha256:9c6e381421d0f48d1b8133e573f33c185ee16cbf505eda9c4a8a4791b25ea8a6

# The channel `rust-toolchain.toml` names; the Makefile passes it.
ARG RUST_TOOLCHAIN=1.95

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      unzip zip ncompress bzip2 gzip build-essential curl ca-certificates locales \
 && sed -i 's/^# *\(en_US.UTF-8 UTF-8\)/\1/' /etc/locale.gen \
 && locale-gen \
 && rm -rf /var/lib/apt/lists/*

# Not root: root ignores permission bits, so every mode-dependent row would
# answer differently (the lz4 lesson, 0.15.0). The uid is arbitrary and
# assumes nothing about the host's; /src is read-only and world-readable.
RUN useradd --create-home --uid 4242 --shell /bin/bash oracle \
 && mkdir /target \
 && chown oracle:oracle /target
USER oracle
ENV CARGO_HOME=/home/oracle/.cargo \
    RUSTUP_HOME=/home/oracle/.rustup \
    CARGO_TARGET_DIR=/target \
    PATH=/home/oracle/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain "${RUST_TOOLCHAIN}" \
          --component rustfmt --component clippy \
 && mkdir -p /home/oracle/.cargo/registry /home/oracle/.cargo/git

WORKDIR /src
