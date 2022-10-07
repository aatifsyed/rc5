use anyhow::ensure;
use num::Zero;

pub struct SecretKey<'a> {
    buffer: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for SecretKey<'a> {
    type Error = anyhow::Error;

    fn try_from(buffer: &'a [u8]) -> Result<Self, Self::Error> {
        let num_bytes = buffer.len();
        ensure!(
            num_bytes <= 255,
            "secret key length of {num_bytes} is not in allowed range 0..=255"
        );
        Ok(Self { buffer })
    }
}

/*
 * This function should return a cipher text for a given key and plaintext
 *
 */
pub fn encode_block_rc5_32_12_16(key: SecretKey, plaintext: impl AsRef<[u8]>) -> Vec<u8> {
    type Word = u32;
    let w = 32; // The length of a word in bits, typically 16, 32 or 64. Encryption is done in 2-word blocks.
    let u = w / 8; // The length of a word in bytes.
    let b = 16; // The length of the key in bytes.
    let K = key.buffer; // The key, considered as an array of bytes (using 0-based indexing).
    const c: usize = 4; // The length of the key in words (or 1, if b = 0).
    let mut L = [Word::zero(); c]; // A temporary working array used during key scheduling. initialized to the key in words.
    const r: usize = 12; // The number of rounds to use when encrypting data.
    const t: usize = 2 * (r + 1); // the number of round subkeys required.
    let mut S = [Word::zero(); t]; // The round subkey words.
    let Pw: Word = 0xB7E15163;
    let Qw: Word = 0x9E3779B9;

    for (src, dst) in K.iter().zip(bytemuck::cast_slice_mut::<_, u8>(&mut L)) {
        *dst = *src;
    }

    S[0] = Pw;
    for i in 1..t {
        S[i] = S[i - 1].wrapping_add(Qw)
    }

    let (mut i, mut j) = (0, 0);
    let (mut A, mut B) = (Word::zero(), Word::zero());

    for _ in 0..(std::cmp::max(t, c) * 3) {
        S[i] = (S[i].wrapping_add(A).wrapping_add(B)).rotate_left(3);
        A = S[i];
        L[j] = (L[j].wrapping_add(A).wrapping_add(B)).rotate_left(A.wrapping_add(B));
        B = L[j];
        i = (i + 1) % t;
        j = (j + 1) % c;
    }

    let plaintext = bytemuck::cast_slice::<_, Word>(plaintext.as_ref());

    let mut A = plaintext[0].wrapping_add(S[0]);
    let mut B = plaintext[1].wrapping_add(S[1]);

    for i in 1..=r {
        A = (A ^ B).rotate_left(B).wrapping_add(S[2 * i]);
        B = (B ^ A).rotate_left(A).wrapping_add(S[2 * i + 1]);
    }

    bytemuck::cast_slice(&[A, B]).to_owned()
}

/*
 * This function should return a plaintext for a given key and ciphertext
 *
 */
pub fn decode(key: SecretKey, ciphertext: impl AsRef<[u8]>) -> Vec<u8> {
    let mut plaintext = Vec::new();
    plaintext
}
