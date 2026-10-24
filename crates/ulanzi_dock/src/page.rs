//! Page (button set) ZIP builder.
//!
//! Ported from Bitfocus `src/zip-builder.ts` (MIT; see `NOTICE`). Layout:
//! `manifest.json` at the root plus `Images/<id>.png` icons, DEFLATE level 1
//! (as in the source). Differences from the source: icon ids are deterministic
//! (`k00`.. / `wide`) instead of random UUIDs, and the bad-byte retry uses a
//! deterministic dummy file instead of random hex. Neither affects the layout.

use crate::protocol::{is_payload_safe, SmallWindowMode};
use serde_json::{json, Map, Value};
use std::io::{Cursor, Write};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

pub const KEY_COUNT: usize = 13;
/// Index of the wide (small window) area.
pub const WIDE_INDEX: usize = 13;
pub const KEY_WIDTH: u32 = 196;
pub const KEY_HEIGHT: u32 = 196;
pub const WIDE_WIDTH: u32 = 458;
pub const WIDE_HEIGHT: u32 = 196;
/// Grid cell (col,row) of the wide area; it spans cells 3_2 and 4_2.
pub const WIDE_CELL: (u8, u8) = (3, 2);
const MAX_RETRIES: usize = 64;

#[derive(Clone, Debug, Default)]
pub struct KeySpec {
    pub name: Option<String>,
    /// PNG-encoded 196x196 icon.
    pub png: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct PageSpec {
    pub keys: Vec<KeySpec>,
    /// PNG for the 458x196 wide area. Used as its icon in modes -1 and Background.
    pub wide_png: Option<Vec<u8>>,
    /// -1 = disabled (SmallViewMode 2 with the wide icon, as the source does);
    /// otherwise a `SmallWindowMode` value (clock/stats modes carry no icon).
    pub small_window_mode: i32,
}

impl Default for PageSpec {
    fn default() -> Self {
        Self { keys: vec![KeySpec::default(); KEY_COUNT], wide_png: None, small_window_mode: -1 }
    }
}

impl PageSpec {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set_key(&mut self, idx: usize, name: Option<&str>, png: Vec<u8>) {
        self.keys[idx] = KeySpec { name: name.map(String::from), png: Some(png) };
    }
}

/// Key index (0..13) to grid cell `(col,row)`: row-major over the 5x3 grid with
/// the two wide-area cells skipped, so 0..=4 row 0, 5..=9 row 1, 10..=12 row 2.
/// `WIDE_INDEX` maps to the wide cell.
pub fn key_cell(idx: usize) -> Option<(u8, u8)> {
    match idx {
        0..=9 => Some(((idx % 5) as u8, (idx / 5) as u8)),
        10..=12 => Some(((idx - 10) as u8, 2)),
        WIDE_INDEX => Some(WIDE_CELL),
        _ => None,
    }
}

/// Inverse of [`key_cell`].
pub fn cell_key(col: u8, row: u8) -> Option<usize> {
    (0..=WIDE_INDEX).find(|&i| key_cell(i) == Some((col, row)))
}

#[derive(Debug)]
pub enum PageError {
    Zip(String),
    /// No bad-byte-free ZIP found within the retry budget.
    Unsafe,
}
impl std::fmt::Display for PageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PageError::Zip(s) => write!(f, "zip error: {s}"),
            PageError::Unsafe => write!(f, "could not build a D200-safe ZIP after {MAX_RETRIES} retries"),
        }
    }
}
impl std::error::Error for PageError {}
impl From<zip::result::ZipError> for PageError {
    fn from(e: zip::result::ZipError) -> Self {
        PageError::Zip(e.to_string())
    }
}
impl From<std::io::Error> for PageError {
    fn from(e: std::io::Error) -> Self {
        PageError::Zip(e.to_string())
    }
}

fn font() -> Value {
    json!({"Align": "bottom", "Color": 0xffffff, "FontName": "Source Han Sans SC", "ShowTitle": true, "Size": 10, "Weight": 80})
}

fn build_manifest(spec: &PageSpec) -> (Value, Vec<(String, Vec<u8>)>) {
    let mut manifest = Map::new();
    let mut icons: Vec<(String, Vec<u8>)> = Vec::new();

    for (idx, key) in spec.keys.iter().enumerate().take(KEY_COUNT) {
        if key.name.is_none() && key.png.is_none() {
            continue;
        }
        let (col, row) = key_cell(idx).expect("valid key");
        let mut vp = Map::new();
        vp.insert("Font".into(), font());
        if let Some(n) = &key.name {
            vp.insert("Text".into(), json!(n));
        }
        if let Some(png) = &key.png {
            let id = format!("k{idx:02}");
            vp.insert("Icon".into(), json!(format!("Images/{id}.png")));
            icons.push((id, png.clone()));
        }
        manifest.insert(format!("{col}_{row}"), json!({"State": 0, "ViewParam": [Value::Object(vp)]}));
    }

    // The wide slot always carries SmallViewMode so the firmware allocates 458px.
    let mut vp = Map::new();
    vp.insert("Font".into(), font());
    vp.insert("Text".into(), json!(""));
    let mode = spec.small_window_mode;
    let bg = mode == -1 || mode == SmallWindowMode::Background as i32;
    if bg {
        if let Some(png) = &spec.wide_png {
            vp.insert("Icon".into(), json!("Images/wide.png"));
            icons.push(("wide".into(), png.clone()));
        }
    }
    let view_mode = if mode == -1 { SmallWindowMode::Background as i32 } else { mode };
    manifest.insert(
        format!("{}_{}", WIDE_CELL.0, WIDE_CELL.1),
        json!({"State": 0, "SmallViewMode": view_mode, "ViewParam": [Value::Object(vp)]}),
    );
    (Value::Object(manifest), icons)
}

fn compress(manifest: &Value, icons: &[(String, Vec<u8>)], dummy: Option<&[u8]>) -> Result<Vec<u8>, PageError> {
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated).compression_level(Some(1));
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("manifest.json", opts)?;
    zip.write_all(manifest.to_string().as_bytes())?;
    if let Some(d) = dummy {
        zip.start_file("dummy.txt", opts)?;
        zip.write_all(d)?;
    }
    zip.add_directory("Images/", opts)?;
    for (id, data) in icons {
        zip.start_file(format!("Images/{id}.png"), opts)?;
        zip.write_all(data)?;
    }
    Ok(zip.finish()?.into_inner())
}

/// Deterministic dummy content that grows with each retry (hex-like text from an LCG).
fn dummy_bytes(retry: usize) -> Vec<u8> {
    let mut s = 0x9e3779b97f4a7c15u64 ^ (retry as u64).wrapping_mul(0xff51afd7ed558ccd);
    (0..8 * retry * 2)
        .map(|_| {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            b"0123456789abcdef"[(s >> 60) as usize]
        })
        .collect()
}

/// Build the ZIP **without** the bad-byte fix. Exposed so tests can prove the fix matters.
pub fn build_page_zip_unchecked(spec: &PageSpec) -> Result<Vec<u8>, PageError> {
    let (m, icons) = build_manifest(spec);
    compress(&m, &icons, None)
}

/// Build the ZIP payload, retrying with a growing dummy file until no byte at
/// offset 1016 + 1024*n is 0x00 or 0x7c (same method as the source).
pub fn build_page_zip(spec: &PageSpec) -> Result<Vec<u8>, PageError> {
    let (m, icons) = build_manifest(spec);
    let mut payload = compress(&m, &icons, None)?;
    let mut retries = 0;
    while !is_payload_safe(&payload) {
        retries += 1;
        if retries > MAX_RETRIES {
            return Err(PageError::Unsafe);
        }
        payload = compress(&m, &icons, Some(&dummy_bytes(retries)))?;
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::find_unsafe_offsets;
    use std::io::Read;

    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut s = seed | 1;
        (0..len)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn key_cells_roundtrip() {
        let mut seen = std::collections::HashSet::new();
        for i in 0..=WIDE_INDEX {
            let (c, r) = key_cell(i).unwrap();
            assert!(c < 5 && r < 3);
            assert_eq!(cell_key(c, r), Some(i));
            assert!(seen.insert((c, r)));
        }
        assert_eq!(key_cell(14), None);
        assert_eq!(key_cell(12), Some((2, 2)));
        assert_eq!(key_cell(WIDE_INDEX), Some((3, 2)));
    }

    #[test]
    fn manifest_and_entries() {
        let mut spec = PageSpec::new();
        spec.set_key(0, Some("A"), vec![1, 2, 3]);
        spec.set_key(12, None, vec![4]);
        spec.wide_png = Some(vec![9; 5]);
        let zip_bytes = build_page_zip(&spec).unwrap();
        let mut ar = zip::ZipArchive::new(Cursor::new(zip_bytes)).unwrap();
        let mut s = String::new();
        ar.by_name("manifest.json").unwrap().read_to_string(&mut s).unwrap();
        let m: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(m["0_0"]["ViewParam"][0]["Text"], "A");
        assert_eq!(m["0_0"]["ViewParam"][0]["Icon"], "Images/k00.png");
        assert_eq!(m["2_2"]["ViewParam"][0]["Icon"], "Images/k12.png");
        assert_eq!(m["3_2"]["SmallViewMode"], 2);
        assert_eq!(m["3_2"]["ViewParam"][0]["Icon"], "Images/wide.png");
        let mut b = Vec::new();
        ar.by_name("Images/wide.png").unwrap().read_to_end(&mut b).unwrap();
        assert_eq!(b, vec![9; 5]);
    }

    #[test]
    fn clock_mode_has_no_wide_icon() {
        let mut spec = PageSpec::new();
        spec.wide_png = Some(vec![1]);
        spec.small_window_mode = SmallWindowMode::DigitalTime as i32;
        let z = build_page_zip(&spec).unwrap();
        let mut ar = zip::ZipArchive::new(Cursor::new(z)).unwrap();
        assert!(ar.by_name("Images/wide.png").is_err());
    }

    #[test]
    fn bad_byte_rule_is_avoided_across_many_sizes() {
        let mut unsafe_without_fix = 0;
        for n in 0..400usize {
            let mut spec = PageSpec::new();
            spec.set_key(0, None, noise(1500 + n * 7, n as u64 + 1));
            spec.set_key(1, Some("x"), noise(300 + n, 1000 + n as u64));
            spec.wide_png = Some(noise(2000 + n * 3, 77 + n as u64));
            if !is_payload_safe(&build_page_zip_unchecked(&spec).unwrap()) {
                unsafe_without_fix += 1;
            }
            let fixed = build_page_zip(&spec).unwrap();
            assert!(find_unsafe_offsets(&fixed).is_empty(), "size step {n}");
            assert!(is_payload_safe(&fixed));
            // still a valid zip
            zip::ZipArchive::new(Cursor::new(fixed)).unwrap();
        }
        assert!(unsafe_without_fix > 0, "test inputs never hit the bad-byte case");
    }
}
