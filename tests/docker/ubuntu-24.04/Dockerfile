# The Ubuntu oracle of the unzip compatibility family (0.16.0, ruling R10):
# apt's `unzip` 6.0-28ubuntu4.1 on ubuntu:24.04, as CI's ubuntu-latest has it,
# with a Rust toolchain to build and run the suites beside it. Since 0.18.0
# it also carries apt's ncompress 5.0-1, the compress family's ncompress
# oracle (`compress` and `uncompress.real`; `ncompress_dir()` requires that
# version under `CI`). Since 0.19.0 its apt `zip` 3.0-13ubuntu0.2 is the zip
# family's Ubuntu oracle (`zip`, `zipcloak`, `zipnote`, `zipsplit`;
# `zip_dir()` requires that version under `CI`).
#
# Used by `make compat-ubuntu`, which builds this image and runs
# `compat_unzip_ubuntu` and `compat_unzip_common` in it with `CI=1`. The
# repository is mounted read-only at /src; cargo's registry and the target
# directory are named volumes, so runs are incremental and nothing is written
# into the host's `target/`.
#
# The harness checks the unzip version itself (`unzip_dir()` requires
# `dpkg-query -W -f '${Version}' unzip` = 6.0-28ubuntu4.1), so a newer apt
# package fails the run loudly instead of being used as the oracle.
FROM ubuntu:24.04

# The channel `rust-toolchain.toml` names; the Makefile passes it.
ARG RUST_TOOLCHAIN=1.95

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      unzip zip ncompress build-essential curl ca-certificates locales \
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
