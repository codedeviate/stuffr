//! Rendering a [`Listing`] as `stuffr ls` prints it: the `FORMAT  SIZE  DATE
//! NAME` rows, or one JSON object.

use std::io::{self, Write};
use std::path::Path;
use std::time::SystemTime;

use super::format::{compact_format, human_size, ls_date, rfc3339_utc};
use super::walk::{Listing, Row, RowKind};

/// A name as stuffr shows one: escaped by `fmt_name`, after the same lossy
/// UTF-8 step the walk's warnings take.
fn shown_name(name: &std::ffi::OsStr) -> String {
    stuffr::fmt_name(&name.to_string_lossy()).to_string()
}

fn format_cell(row: &Row) -> String {
    match &row.kind {
        RowKind::File { chain, .. } => compact_format(chain),
        RowKind::Folder => "[FOLDER]".to_string(),
    }
}

fn size_cell(row: &Row) -> String {
    match row.kind {
        RowKind::File { size, .. } => human_size(size),
        RowKind::Folder => String::new(),
    }
}

/// The rows, block by block, then the footer when anything was not openable.
///
/// Column widths are the widest values across the whole listing, so `-r`'s
/// blocks line up with each other. A block after the first output line gets
/// a blank line and a `relative/path/:` header, as `ls -lR` prints them; the
/// top folder's rows have no header.
pub fn render_text(listing: &Listing, now: SystemTime, out: &mut dyn Write) -> io::Result<()> {
    let rows = listing.blocks.iter().flat_map(|b| &b.rows);
    let fw = rows
        .clone()
        .map(|r| format_cell(r).len())
        .max()
        .unwrap_or(0);
    let sw = rows.map(|r| size_cell(r).len()).max().unwrap_or(0);
    let mut wrote = false;
    for block in &listing.blocks {
        if !block.rel_path.as_os_str().is_empty() {
            if wrote {
                writeln!(out)?;
            }
            writeln!(out, "{}/:", shown_name(block.rel_path.as_os_str()))?;
            wrote = true;
        }
        for row in &block.rows {
            let slash = if matches!(row.kind, RowKind::Folder) {
                "/"
            } else {
                ""
            };
            writeln!(
                out,
                "{:<fw$}  {:>sw$}  {}  {}{slash}",
                format_cell(row),
                size_cell(row),
                ls_date(row.modified, now),
                shown_name(&row.name),
            )?;
            wrote = true;
        }
    }
    if listing.not_openable > 0 {
        writeln!(
            out,
            "{} of {} files shown, {} not openable",
            listing.shown,
            listing.shown + listing.not_openable,
            listing.not_openable
        )?;
    }
    Ok(())
}

/// `{entries, shown, skipped, warnings}`; each entry's `path` is relative to
/// the listed folder and is the real name (lossy only for non-UTF-8), not
/// the escaped display form: JSON's own escaping keeps it unambiguous, as
/// `list --json` treats entry names.
pub fn render_json(listing: &Listing) -> serde_json::Value {
    let mut entries = Vec::new();
    for block in &listing.blocks {
        for row in &block.rows {
            let path = Path::new(&block.rel_path).join(&row.name);
            let (kind, format, size) = match &row.kind {
                RowKind::File { chain, size } => (
                    "file",
                    serde_json::Value::from(chain.describe()),
                    serde_json::Value::from(*size),
                ),
                RowKind::Folder => ("folder", serde_json::Value::Null, serde_json::Value::Null),
            };
            entries.push(serde_json::json!({
                "path": path.to_string_lossy(),
                "kind": kind,
                "format": format,
                "size": size,
                "modified": rfc3339_utc(row.modified),
            }));
        }
    }
    serde_json::json!({
        "entries": entries,
        "shown": listing.shown,
        "skipped": listing.not_openable,
        "warnings": listing.warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ls::walk::Block;
    use std::path::PathBuf;
    use std::time::{Duration, UNIX_EPOCH};
    use stuffr::probe::Chain;

    fn file(name: &str, chain: Chain, size: u64, t: SystemTime) -> Row {
        Row {
            name: name.into(),
            kind: RowKind::File { chain, size },
            modified: t,
        }
    }

    fn gzip() -> Chain {
        Chain::Codec {
            codec: stuffr::format::FormatId::new("gzip"),
            inner: Box::new(Chain::Raw),
        }
    }

    /// 2019-01-05 12:00 UTC: old enough to print its year in every zone.
    fn old() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_546_689_600)
    }

    fn text(l: &Listing) -> String {
        let mut v = Vec::new();
        render_text(l, old() + Duration::from_secs(400 * 86_400), &mut v).unwrap();
        String::from_utf8(v).unwrap()
    }

    #[test]
    fn rows_align_across_blocks_and_the_footer_counts() {
        let l = Listing {
            blocks: vec![
                Block {
                    rel_path: PathBuf::new(),
                    rows: vec![
                        file("a.gz", gzip(), 10, old()),
                        Row {
                            name: "sub".into(),
                            kind: RowKind::Folder,
                            modified: old(),
                        },
                    ],
                },
                Block {
                    rel_path: PathBuf::from("x/y"),
                    rows: vec![file("b.gz", gzip(), 4_404_019, old())],
                },
            ],
            shown: 2,
            not_openable: 3,
            warnings: vec![],
        };
        let t = text(&l);
        let d = ls_date(old(), old() + Duration::from_secs(400 * 86_400));
        assert_eq!(
            t,
            format!(
                "gzip       10B  {d}  a.gz\n\
                 [FOLDER]        {d}  sub/\n\
                 \n\
                 x/y/:\n\
                 gzip      4.2M  {d}  b.gz\n\
                 2 of 5 files shown, 3 not openable\n"
            )
        );
    }

    #[test]
    fn an_empty_top_block_starts_with_the_first_header() {
        let l = Listing {
            blocks: vec![
                Block {
                    rel_path: PathBuf::new(),
                    rows: vec![],
                },
                Block {
                    rel_path: PathBuf::from("a\nb"),
                    rows: vec![file("c\td.gz", gzip(), 0, old())],
                },
            ],
            shown: 1,
            not_openable: 0,
            warnings: vec![],
        };
        let d = ls_date(old(), old() + Duration::from_secs(400 * 86_400));
        assert_eq!(text(&l), format!("a\\nb/:\ngzip  0B  {d}  c\\td.gz\n"));
    }

    #[test]
    fn empty_listing_is_empty_text() {
        let l = Listing {
            blocks: vec![Block {
                rel_path: PathBuf::new(),
                rows: vec![],
            }],
            shown: 0,
            not_openable: 0,
            warnings: vec![],
        };
        assert_eq!(text(&l), "");
    }

    #[test]
    fn json_has_the_spec_shape() {
        let l = Listing {
            blocks: vec![
                Block {
                    rel_path: PathBuf::new(),
                    rows: vec![Row {
                        name: "sub".into(),
                        kind: RowKind::Folder,
                        modified: old(),
                    }],
                },
                Block {
                    rel_path: PathBuf::from("sub"),
                    rows: vec![file("a.gz", gzip(), 7, old())],
                },
            ],
            shown: 1,
            not_openable: 2,
            warnings: vec!["stuffr: cannot read x: nope".into()],
        };
        let v = render_json(&l);
        assert_eq!(
            v,
            serde_json::json!({
                "entries": [
                    {"path": "sub", "kind": "folder", "format": null, "size": null,
                     "modified": "2019-01-05T12:00:00Z"},
                    {"path": "sub/a.gz", "kind": "file", "format": "gzip", "size": 7,
                     "modified": "2019-01-05T12:00:00Z"},
                ],
                "shown": 1,
                "skipped": 2,
                "warnings": ["stuffr: cannot read x: nope"],
            })
        );
    }
}
