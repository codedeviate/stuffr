use crate::common::*;

/// `version` prints what `--version` prints; `version --json` is one object.
#[test]
fn version_subcommand_matches_flag_and_json_parses() {
    let flag = run_output(&["--version"]);
    let sub = run_output(&["version"]);
    assert!(sub.status.success());
    assert_eq!(sub.stdout, flag.stdout);

    let out = run_output(&["version", "--json"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schema"], 1);
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    assert!(v["host_fs_abi"].is_null());
    assert!(
        v["personalities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n == "zstdcat")
    );
}
