//! Exposes the compile target triple to the crate as `env!("TARGET")`, which
//! `stuffr version --json` reports. Cargo sets `TARGET` for build scripts
//! only, not for the crate itself, hence this forwarding.

fn main() {
    let target = std::env::var("TARGET").expect("cargo sets TARGET for build scripts");
    println!("cargo:rustc-env=TARGET={target}");
    println!("cargo:rerun-if-changed=build.rs");
}
