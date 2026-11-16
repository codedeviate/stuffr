use crate::common::*;

/// `formats --json` reports the same rows as the table, as one object.
#[test]
fn formats_json_matches_table() {
    let table = run_output(&["formats"]);
    assert!(table.status.success());
    let table = String::from_utf8(table.stdout).unwrap();
    // Data rows are the lines under the header up to the blank line.
    let rows = table
        .lines()
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .count();

    let out = run_output(&["formats", "--json"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["schema"], 1);
    let formats = v["formats"].as_array().unwrap();
    assert_eq!(formats.len(), rows);

    let gzip = formats.iter().find(|f| f["format"] == "gzip").unwrap();
    assert_eq!(gzip["kind"], "codec");
    assert_eq!(gzip["read"], true);
    assert_eq!(gzip["write"], true);
    assert!(
        gzip["extensions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e == "gz")
    );
    assert!(matches!(gzip["tier"].as_str(), Some("pure" | "c")));

    for f in formats {
        assert!(matches!(f["kind"].as_str(), Some("codec" | "container")));
        assert!(matches!(f["salvage"].as_str(), Some("yes" | "weak" | "no")));
        assert!(f["parallel"].is_boolean());
    }
    // Single-implementation formats are always pure.
    let tar = formats.iter().find(|f| f["format"] == "tar").unwrap();
    assert_eq!(tar["tier"], "pure");
}
