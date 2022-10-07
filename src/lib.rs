#![allow(non_snake_case)]
#![feature(const_for, const_mut_refs, const_trait_impl)]
use std::{
    borrow::Cow,
    mem::{align_of, size_of},
    num::NonZeroUsize,
};
// TODO:
// - test endianness
// - move as much as possible to compile time

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

impl<'a, WordT> From<SecretKey<'a>> for Cow<'a, [WordT]>
where
    WordT: Word + num::Zero,
    WordT: bytemuck::Pod,
    [WordT]: ToOwned,
{
    fn from(value: SecretKey<'a>) -> Self {
        use bytemuck::PodCastError::{
            AlignmentMismatch, OutputSliceWouldHaveSlop, SizeMismatch,
            TargetAlignmentGreaterAndInputNotAligned,
        };
        match bytemuck::try_cast_slice(value.buffer) {
            Ok(words) => Cow::Borrowed(words),
            Err(TargetAlignmentGreaterAndInputNotAligned) => {
                unreachable!("alignment should fit - see implementation of sealed trait Word")
            }
            Err(AlignmentMismatch) => unreachable!("slice not a Box or Vec"),
            Err(OutputSliceWouldHaveSlop) => {
                let b = value.buffer.len();
                assert_ne!(
                    b, 0,
                    "empty slices should have been caught in Cow::Borrowed branch"
                );
                // make L at least as many bytes long as secret_key
                let mut backing_words =
                    vec![WordT::zero(); num::integer::div_ceil(b, size_of::<WordT>())];
                for (src, dst) in value.buffer.iter().zip(
                    bytemuck::try_cast_slice_mut::<_, u8>(&mut backing_words)
                        .expect("WordT is Pod, so should be find to cast to bytes"),
                ) {
                    *dst = *src
                }
                Cow::from(backing_words)
            }
            Err(SizeMismatch) => unreachable!("both pointers are thick"), // doesn't seem right - double check bytemuch for what this actually means
        }
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

macro_rules! impl_word {
    ($ty:ty, P = $p:expr, Q = $q:expr) => {
        impl Word for $ty {
            const P: Self = $p;
            const Q: Self = $q;
        }
        static_assertions::const_assert_eq!(align_of::<$ty>() % align_of::<u8>(), 0);
    };
}

impl_word!(u16, P = 0xB7E1, Q = 0x9E37);
impl_word!(u32, P = 0xB7E15163, Q = 0x9E3779B9);
impl_word!(u64, P = 0xB7E151628AED2A6B, Q = 0x9E3779B97F4A7C15);

trait ConstZero {
    const ZERO: Self;
}

impl ConstZero for u16 {
    const ZERO: Self = 0;
}
impl ConstZero for u32 {
    const ZERO: Self = 0;
}
impl ConstZero for u64 {
    const ZERO: Self = 0;
}

#[const_trait]
trait ConstWrappingAdd {
    fn wrapping_add(self, rhs: Self) -> Self;
}

macro_rules! impl_const_wrapping_add {
    ($ty:ty) => {
        impl const ConstWrappingAdd for $ty {
            fn wrapping_add(self, rhs: Self) -> Self {
                <$ty>::wrapping_add(self, rhs)
            }
        }
    };
}

impl_const_wrapping_add!(u16);
impl_const_wrapping_add!(u32);
impl_const_wrapping_add!(u64);

mod sealed {
    pub trait Sealed {}
    impl Sealed for u16 {}
    impl Sealed for u32 {}
    impl Sealed for u64 {}
}

const fn t(num_rounds: u8) -> usize {
    2 * (num_rounds as usize + 1)
}
const T_MAX: usize = t(u8::MAX);

// save a heap allocation for the s array
// array size could be const N, but since it depends on `num_rounds`, jumping from a runtime num_rounds (which we want) to a compile time num_rounds (which we don't want) is hard
const fn prepare_s_array<WordT: Word + ConstZero + Copy + ~const ConstWrappingAdd>(
    num_rounds: u8,
) -> [WordT; T_MAX] {
    let mut S = [WordT::ZERO; T_MAX];
    S[0] = WordT::P;
    let mut i = 1;
    while i < t(num_rounds) {
        S[i] = S[i - 1].wrapping_add(WordT::Q);
        i += 1;
    }
    S
}

fn mix_secret_key_into_s_array<
    WordT: Word + num::PrimInt + Clone + bytemuck::Pod + ConstZero + ~const ConstWrappingAdd,
>(
    key: SecretKey,
    num_rounds: u8,
) -> Vec<WordT> {
    let mut L = Cow::<[WordT]>::from(key).to_vec();
    let mut S = prepare_s_array::<WordT>(num_rounds);

    let (mut i, mut j) = (0, 0);
    let (mut A, mut B) = (WordT::zero(), WordT::zero());

    let c = NonZeroUsize::new(L.len())
        .unwrap_or(NonZeroUsize::new(1).unwrap())
        .get();

    for _ in 0..(std::cmp::max(t(num_rounds), c) * 3) {
        S[i] = (S[i].wrapping_add(A).wrapping_add(B)).rotate_left(3);
        A = S[i];
        L[j] = (L[j].wrapping_add(A).wrapping_add(B))
            .rotate_left(A.wrapping_add(B).to_u32().expect("word is too wide"));
        B = L[j];
        i = (i + 1) % t(num_rounds);
        j = (j + 1) % c;
    }
    S.into()
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

    let S = mix_secret_key_into_s_array(key, r as _);
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

    let S = mix_secret_key_into_s_array(key, r as _);
    let ciphertext: &[Word; 2] = bytemuck::cast_slice(ciphertext.as_ref())
        .try_into()
        .unwrap();
    bytemuck::cast_slice(&decode_block(&S, ciphertext, r)).to_owned()
}
