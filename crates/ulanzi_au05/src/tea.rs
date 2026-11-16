//! Plain TEA (64-bit blocks, 32 rounds, ECB) with the AU05's fixed vendor key.
//!
//! The key is the same for every unit (static analysis of Ulanzi Studio 3.4.4, then an independent decrypt
//! of all captured reports, 2026-11-16). It is a vendor constant: keep it in private repositories only.
const KEY: [u32; 4] = [0xcaa5_baca, 0xbc2a_8a6d, 0xca5a_9eba, 0x9bb8_8bca];
const DELTA: u32 = 0x9e37_79b9;

pub fn encrypt_block(block: &mut [u8]) {
    let (mut v0, mut v1) = load(block);
    let mut sum = 0u32;
    for _ in 0..32 {
        sum = sum.wrapping_add(DELTA);
        v0 = v0.wrapping_add(
            (v1 << 4).wrapping_add(KEY[0]) ^ v1.wrapping_add(sum) ^ (v1 >> 5).wrapping_add(KEY[1]),
        );
        v1 = v1.wrapping_add(
            (v0 << 4).wrapping_add(KEY[2]) ^ v0.wrapping_add(sum) ^ (v0 >> 5).wrapping_add(KEY[3]),
        );
    }
    store(block, v0, v1);
}

pub fn decrypt_block(block: &mut [u8]) {
    let (mut v0, mut v1) = load(block);
    let mut sum = DELTA.wrapping_mul(32);
    for _ in 0..32 {
        v1 = v1.wrapping_sub(
            (v0 << 4).wrapping_add(KEY[2]) ^ v0.wrapping_add(sum) ^ (v0 >> 5).wrapping_add(KEY[3]),
        );
        v0 = v0.wrapping_sub(
            (v1 << 4).wrapping_add(KEY[0]) ^ v1.wrapping_add(sum) ^ (v1 >> 5).wrapping_add(KEY[1]),
        );
        sum = sum.wrapping_sub(DELTA);
    }
    store(block, v0, v1);
}

fn load(b: &[u8]) -> (u32, u32) {
    assert_eq!(b.len(), 8, "TEA works on 8-byte blocks");
    (
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
    )
}
fn store(b: &mut [u8], v0: u32, v1: u32) {
    b[..4].copy_from_slice(&v0.to_le_bytes());
    b[4..8].copy_from_slice(&v1.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
    #[test]
    fn known_vectors_from_the_real_key() {
        // A zero block, as seen in every unused block of a real report.
        let mut b = [0u8; 8];
        encrypt_block(&mut b);
        assert_eq!(b.to_vec(), hex("3890c499a360aaad"));
        // Real captured blocks (au05_capture.txt) and what they decrypt to.
        for (cipher, plain) in [
            ("2f12546e779bb7de", "8b10720104000000"), // knob right down
            ("3c81720972017506", "8b106f0100000000"), // K1 down
            ("23af678d687ee3b1", "0b7bb00d0814f601"), // status: 3504 mV, 20 %
        ] {
            let mut b = hex(cipher);
            decrypt_block(&mut b);
            assert_eq!(b, hex(plain));
            encrypt_block(&mut b);
            assert_eq!(b, hex(cipher));
        }
    }
}
