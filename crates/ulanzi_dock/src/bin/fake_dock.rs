//! Software-only demo: build a page, push it through the fake dock, print events.
//! Usage: fake-dock <output-folder>. Opens no device, no window, plays no sound.

use std::time::Duration;
use ulanzi_dock::dock::Dock;
use ulanzi_dock::fake::FakeDock;
use ulanzi_dock::page::PageSpec;

/// 3x5 digit glyphs, one row per 3 bits.
const DIGITS: [[u8; 5]; 10] = [
    [7, 5, 5, 5, 7],
    [2, 6, 2, 2, 7],
    [7, 1, 7, 4, 7],
    [7, 1, 7, 1, 7],
    [5, 5, 7, 1, 1],
    [7, 4, 7, 1, 7],
    [7, 4, 7, 5, 7],
    [7, 1, 1, 1, 1],
    [7, 5, 7, 5, 7],
    [7, 5, 7, 1, 7],
];

fn numbered_png(w: u32, h: u32, bg: [u8; 3], number: usize) -> Vec<u8> {
    let mut px = vec![0u8; (w * h * 3) as usize];
    for p in px.chunks_mut(3) {
        p.copy_from_slice(&bg);
    }
    let digits: Vec<usize> = number.to_string().bytes().map(|b| (b - b'0') as usize).collect();
    let scale = 16u32;
    let total_w = digits.len() as u32 * 4 * scale - scale;
    let (x0, y0) = ((w - total_w) / 2, (h - 5 * scale) / 2);
    for (di, d) in digits.iter().enumerate() {
        for (row, bits) in DIGITS[*d].iter().enumerate() {
            for col in 0..3u32 {
                if bits >> (2 - col) & 1 == 1 {
                    for dy in 0..scale {
                        for dx in 0..scale {
                            let x = x0 + di as u32 * 4 * scale + col * scale + dx;
                            let y = y0 + row as u32 * scale + dy;
                            let i = ((y * w + x) * 3) as usize;
                            px[i..i + 3].copy_from_slice(&[255, 255, 255]);
                        }
                    }
                }
            }
        }
    }
    let mut out = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut out, w, h);
        enc.set_color(png::ColorType::Rgb);
        enc.set_depth(png::BitDepth::Eight);
        enc.write_header().and_then(|mut wr| wr.write_image_data(&px)).expect("png encode");
    }
    out
}

fn main() {
    let Some(dir) = std::env::args_os().nth(1) else {
        eprintln!("usage: fake-dock <output-folder>");
        std::process::exit(2);
    };
    let mut dock = Dock::new(FakeDock::with_out_dir(&dir));

    let mut spec = PageSpec::new();
    for i in 0..13usize {
        let bg = [(i * 19 % 200) as u8 + 20, (255 - i * 13 % 200) as u8 / 2, (i * 37 % 200) as u8 + 30];
        spec.set_key(i, Some(&format!("Key {i}")), numbered_png(196, 196, bg, i));
    }
    spec.wide_png = Some(numbered_png(458, 196, [20, 40, 90], 13));

    dock.set_page(&spec).expect("set page");
    dock.set_brightness(60).expect("brightness");
    let fake = dock.transport();
    println!("pages received: {}, brightness: {:?}, errors: {:?}", fake.pages_received, fake.brightness, fake.errors);
    println!("saved page to {}", std::path::Path::new(&dir).display());

    dock.transport_mut().device_info("fake D200H");
    dock.transport_mut().press(4);
    dock.transport_mut().release(4);
    dock.transport_mut().heartbeat();
    while let Some(ev) = dock.poll_event(Duration::from_millis(1)).expect("poll") {
        println!("event: {ev:?}");
    }
}
