use std::mem::size_of;

use anyhow::ensure;
use num::Zero;

#[derive(Debug, Clone, Copy)]
/// Buffer guaranteed to be of a valid length for RC5
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

// Seal the trait because I am *not* doing arbitrary bit width arithmetic.
// Could be persuaded once `awint` and `num` are better friends.
pub trait Word: sealed::Sealed {
    /// A magic constant
    /// This can't be const fn<T: Word>() because float arith in const fn is not supported
    /// Can't be runtime calculated because my implementation has floating point errors :(
    /// ```
    /// # use std::mem::size_of;
    /// # use num::ToPrimitive;
    ///
    /// pub fn P<T: num::NumCast>() -> T {
    ///     let num_bits = size_of::<T>() * 8;
    ///     let not_rounded = (std::f64::consts::E - 2.0)
    ///         * 2f64.powf(num_bits.to_f64().expect("too many bits to fit in an f64"));
    ///     let rounded = math::round::half_to_odd(
    ///         not_rounded,
    ///         0, // no decimal places
    ///     );
    ///     num::NumCast::from(rounded).expect("couldn't cast from f64")
    /// }
    /// assert_eq!(P::<u16>(), 0xB7E1);
    /// assert_eq!(P::<u32>(), 0xB7E15163);
    /// // assert_eq!(P::<u64>(), 0xB7E151628AED2A6B); // fails
    /// ```
    const P: Self;
    /// A magic constant
    const Q: Self;
}
impl Word for u16 {
    const P: Self = 0xB7E1;
    const Q: Self = 0x9E37;
}
impl Word for u32 {
    const P: Self = 0xB7E15163;
    const Q: Self = 0x9E3779B9;
}
impl Word for u64 {
    const P: Self = 0xB7E151628AED2A6B;
    const Q: Self = 0x9E3779B97F4A7C15;
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for u16 {}
    impl Sealed for u32 {}
    impl Sealed for u64 {}
}

// could we just have a static table for num_rounds = 255 for each type? probably
fn make_round_subkey_words<WordT: Word + num::Zero + Clone + num::traits::WrappingAdd>(
    num_rounds: u8,
) -> Vec<WordT> {
    let t = 2 * (usize::from(num_rounds) + 1);
    let mut S = vec![WordT::zero(); t];
    S[0] = WordT::P;
    for i in 1..t {
        S[i] = S[i - 1].wrapping_add(&WordT::Q)
    }
    S
}

fn make_secret_key_working_array<WordT: num::Zero + Clone + bytemuck::Pod>(
    key: SecretKey,
) -> Vec<WordT> {
    let mut b = key.buffer.len();
    if b == 0 {
        b = 1
    }
    // make L at least as many bytes long as secret_key
    let mut L = vec![WordT::zero(); num::integer::div_ceil(b, size_of::<WordT>())];
    for (src, dst) in key
        .buffer
        .iter()
        .zip(bytemuck::cast_slice_mut::<_, u8>(&mut L))
    {
        *dst = *src
    }
    L
}

/*
 * This function should return a cipher text for a given key and plaintext
 *
 */
pub fn encode_block_rc5_32_12_16(key: SecretKey, plaintext: impl AsRef<[u8]>) -> Vec<u8> {
    type Word = u32;
    const c: usize = 4; // The length of the key in words (or 1, if b = 0).
    const r: usize = 12; // The number of rounds to use when encrypting data.
    const t: usize = 2 * (r + 1); // the number of round subkeys required.

    let mut L = make_secret_key_working_array::<Word>(key);
    let mut S = make_round_subkey_words::<Word>(r.try_into().unwrap());

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
pub fn decode_block_rc5_32_12_16(key: SecretKey, ciphertext: impl AsRef<[u8]>) -> Vec<u8> {
    type Word = u32;
    const c: usize = 4; // The length of the key in words (or 1, if b = 0).
    const r: usize = 12; // The number of rounds to use when encrypting data.
    const t: usize = 2 * (r + 1); // the number of round subkeys required.

    let mut L = make_secret_key_working_array::<Word>(key);
    let mut S = make_round_subkey_words::<Word>(r.try_into().unwrap());

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

    let ciphertext = bytemuck::cast_slice::<_, Word>(ciphertext.as_ref());

    let mut B = ciphertext[1];
    let mut A = ciphertext[0];

    for i in (1..=r).rev() {
        B = (B.wrapping_sub(S[2 * i + 1])).rotate_right(A) ^ A;
        A = (A.wrapping_sub(S[2 * i])).rotate_right(B) ^ B;
    }
    B = B.wrapping_sub(S[1]);
    A = A.wrapping_sub(S[0]);
    bytemuck::cast_slice(&[A, B]).to_owned()
}
