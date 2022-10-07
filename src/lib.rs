#![allow(non_snake_case)]
use std::{borrow::Cow, mem::size_of, num::NonZeroUsize};

use anyhow::ensure;

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

pub struct SecretKeyWords<'a, WordT>
where
    [WordT]: ToOwned,
{
    buffer: Cow<'a, [WordT]>,
}

impl<'a, WordT: bytemuck::Pod> TryFrom<SecretKey<'a>> for SecretKeyWords<'a, WordT> {
    type Error = bytemuck::PodCastError;

    fn try_from(value: SecretKey<'a>) -> Result<Self, Self::Error> {
        // TODO: could probably have Cow<[WordT]> and lengthen in the case that the buffer doesn't fit a whole number of words
        // have I just not read the spec carefully enough?
        let buffer = bytemuck::try_cast_slice(value.buffer)?;
        Ok(Self {
            buffer: Cow::Borrowed(buffer),
        })
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

// could we just have a static table for num_rounds = 255 for each type? probably - would save us allocating
fn make_constant_working_array<WordT: Word + num::Zero + Clone + num::traits::WrappingAdd>(
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

fn make_s_array<WordT: Word + num::PrimInt + Clone + bytemuck::Pod + num::traits::WrappingAdd>(
    key: SecretKey,
    num_rounds: u8,
) -> Vec<WordT> {
    let mut L = make_secret_key_working_array::<WordT>(key);
    let mut S = make_constant_working_array::<WordT>(num_rounds);

    let (mut i, mut j) = (0, 0);
    let (mut A, mut B) = (WordT::zero(), WordT::zero());

    let c = NonZeroUsize::new(L.len())
        .unwrap_or(NonZeroUsize::new(1).unwrap())
        .get();
    let t = 2 * (num_rounds as usize + 1);

    for _ in 0..(std::cmp::max(t, c) * 3) {
        S[i] = (S[i].wrapping_add(&A).wrapping_add(&B)).rotate_left(3);
        A = S[i];
        L[j] = (L[j].wrapping_add(&A).wrapping_add(&B))
            .rotate_left(A.wrapping_add(&B).to_u32().expect("word is too wide"));
        B = L[j];
        i = (i + 1) % t;
        j = (j + 1) % c;
    }
    S
}

// Could overwrite plaintext in place... maybe the optimizer will notice? ;)
pub fn encode_block<WordT: Word + ToOwned + Clone + num::traits::WrappingAdd + num::PrimInt>(
    // so could just accept [Word; 255] here
    S: &[WordT],
    plaintext: &[WordT; 2],
    num_rounds: u8,
) -> [WordT; 2] {
    let mut A = plaintext[0].wrapping_add(&S[0]);
    let mut B = plaintext[1].wrapping_add(&S[1]);
    for i in 1..=num_rounds as usize {
        A = (A ^ B)
            .rotate_left(B.to_u32().expect("word is too wide"))
            .wrapping_add(&S[2 * i]);
        B = (B ^ A)
            .rotate_left(A.to_u32().expect("word is too wide"))
            .wrapping_add(&S[2 * i + 1]);
    }
    [A, B]
}

pub fn decode_block<WordT: Word + ToOwned + Clone + num::traits::WrappingSub + num::PrimInt>(
    S: &[WordT],
    ciphertext: &[WordT; 2],
    num_rounds: u8,
) -> [WordT; 2] {
    let mut B = ciphertext[1];
    let mut A = ciphertext[0];

    for i in (1..=num_rounds as usize).rev() {
        B = (B.wrapping_sub(&S[2 * i + 1])).rotate_right(A.to_u32().expect("word is too wide")) ^ A;
        A = (A.wrapping_sub(&S[2 * i])).rotate_right(B.to_u32().expect("word is too wide")) ^ B;
    }
    B = B.wrapping_sub(&S[1]);
    A = A.wrapping_sub(&S[0]);
    [A, B]
}

/*
 * This function should return a cipher text for a given key and plaintext
 *
 */
pub fn encode_block_rc5_32_12_16(key: SecretKey, plaintext: impl AsRef<[u8]>) -> Vec<u8> {
    type Word = u32;
    let r = 12; // The number of rounds to use when encrypting data.

    let S = make_s_array(key, r as _);
    let plaintext: &[Word; 2] = bytemuck::cast_slice(plaintext.as_ref()).try_into().unwrap();
    bytemuck::cast_slice(&encode_block(&S, plaintext, r)).to_owned()
}

/*
 * This function should return a plaintext for a given key and ciphertext
 *
 */
pub fn decode_block_rc5_32_12_16(key: SecretKey, ciphertext: impl AsRef<[u8]>) -> Vec<u8> {
    type Word = u32;
    let r = 12; // The number of rounds to use when encrypting data.

    let S = make_s_array(key, r as _);
    let ciphertext: &[Word; 2] = bytemuck::cast_slice(ciphertext.as_ref())
        .try_into()
        .unwrap();
    bytemuck::cast_slice(&decode_block(&S, ciphertext, r)).to_owned()
}
