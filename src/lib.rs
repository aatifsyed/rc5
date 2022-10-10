//! [`RC5`](https://www.grc.com/r&d/rc5.pdf) is a codec parameterized by the following:
//! - word size. This crate supports word sizes [u8], [u16], [u32], [u64] and [u128]
//! - number of encryption rounds, `0..=255`
//! - key length, `0..=255` bytes
//!
//! This is often written as RC5/`word size`/`num rounds`/`key length`.
//!
//! For one time use, use the [encode_all] and [decode_all] functions.

// I've stuck to the names of constants in the paper where it makes sense
// (despite the publishers apparantly charging per-letter...)
// # TODO:
// - public utilities for bytes -> Block -> bytes, including finishers for padding
// - Iterator<Item = u8> adaptors
// - test on a little-endian machine
// - add a compile time API - see the commit history for some of this being `const fn` etc
//   lots of potential (particularly on nightly) for num_rounds, S etc being compile time
// - io::{Read, Write} adaptors

use array_macro::array;
use smallvec::{smallvec, SmallVec};
use std::{
    borrow::Cow,
    fmt,
    mem::{align_of, size_of},
};

pub const MAX_KEY_LEN: usize = u8::MAX as _;

/// rc5 encode the given `plaintext`.
/// ```
/// # fn main() -> Result<(), hex::FromHexError> {
/// // rc5/32/12/16 example from Rivest's original paper
/// let key = hex::decode("915F4619BE41B2516355A50110A9CE91")?;
/// let plaintext = hex::decode("21A5DBEE154B8F6D")?;
/// let ciphertext = rc5::encode_all::<u32>(key, plaintext, 12);
/// assert_eq!(ciphertext, hex::decode("F7C013AC5B2B8952")?);
/// # Ok(())
/// # }
/// ```
/// # Panics
/// If the key is longer than [MAX_KEY_LEN] bytes
pub fn encode_all<WordT>(
    key: impl AsRef<[u8]>,
    plaintext: impl AsRef<[u8]>,
    num_rounds: u8,
) -> Vec<u8>
where
    WordT: Word
        + bytemuck::Pod
        + num::PrimInt
        + num::traits::WrappingAdd
        + num::traits::WrappingSub
        + zeroize::Zeroize,
{
    let key = SecretKey::try_from(key.as_ref()).unwrap();
    let transcoder = BlockTranscoder::new(key, num_rounds);
    blocks::<WordT>(plaintext.as_ref())
        .map(|plaintext_block| transcoder.encode_block(&plaintext_block))
        .flat_map(|[a, b]| a.to_le_bytes().into_iter().chain(b.to_le_bytes()))
        .collect()
}

/// rc5 decode the given `ciphertext`.
/// ```
/// # fn main() -> Result<(), hex::FromHexError> {
/// // rc5/32/12/16 example from Rivest's original paper
/// let key = hex::decode("915F4619BE41B2516355A50110A9CE91")?;
/// let ciphertext = hex::decode("F7C013AC5B2B8952")?;
/// let plaintext = rc5::decode_all::<u32>(key, ciphertext, 12);
/// assert_eq!(plaintext, hex::decode("21A5DBEE154B8F6D")?);
/// # Ok(())
/// # }
/// ```
/// # Panics
/// If the key is longer than [MAX_KEY_LEN] bytes
pub fn decode_all<WordT>(
    key: impl AsRef<[u8]>,
    ciphertext: impl AsRef<[u8]>,
    num_rounds: u8,
) -> Vec<u8>
where
    WordT: Word
        + bytemuck::Pod
        + num::PrimInt
        + num::traits::WrappingAdd
        + num::traits::WrappingSub
        + zeroize::Zeroize,
{
    let key = SecretKey::try_from(key.as_ref()).unwrap();
    let transcoder = BlockTranscoder::new(key, num_rounds);
    blocks::<WordT>(ciphertext.as_ref())
        .map(|ciphertext_block| transcoder.decode_block(&ciphertext_block))
        .flat_map(|[a, b]| a.to_le_bytes().into_iter().chain(b.to_le_bytes()))
        .collect()
}

/// Rc5 is a block cipher, where bytes are broken into blocks, and each block is two words
type Block<WordT> = [WordT; 2];

/// Yields blocks, zero-padding the last block.
/// We don't go through a [Cow] like with [SecretKey] because:
/// - [SecretKey] must be indexable - see [mixed_s]
/// - We don't want to reallocate `bytes` in the (likely!) case that it's not a multiple of size_of::<WordT>()
// TODO: custom padding
fn blocks<WordT: bytemuck::Pod + num::Zero>(
    bytes: &[u8],
) -> impl Iterator<Item = Block<WordT>> + '_ {
    bytes.chunks(size_of::<Block<WordT>>()).map(|chunk| {
        if chunk.len() == size_of::<Block<WordT>>() {
            bytemuck::cast_slice::<_, WordT>(chunk)
                .try_into()
                .expect("already checked len")
        } else {
            let mut padded_final_word = array![WordT::zero(); 2];
            for (src, dst) in chunk
                .iter()
                .zip(bytemuck::bytes_of_mut(&mut padded_final_word))
            {
                *dst = *src;
            }
            padded_final_word
        }
    })
}

/// A constant used in the encryption algorithm
const fn t(num_rounds: u8) -> usize {
    2 * (num_rounds as usize + 1)
}

/// The constant part of `S` - only dependant on word size
/// The encryption has the following steps:
/// - make an `S` array: [unmixed_s]
/// - mix in the secret key: [mixed_s]
/// - for each block in the output:
///   - do encode scrambling: [BlockTranscoder::encode_block]
///   - do decode scrambling: [BlockTranscoder::decode_block]
// we could trade off the heap allocation by returning `[WordT; t(u8::MAX)]`, but that could be 2K for a 64 bit word size
// we could also have `fn unmixed_s<const N: u8, ..>(..) -> [WordT; t(N)]` but `generic_const_exprs` isn't usable,
//     and jumping from runtime num_rounds to compile time will be a pain
fn unscheduled<WordT: Word + Copy + num::Zero + num::traits::WrappingAdd>(
    num_rounds: u8,
) -> SmallVec<[WordT; 20]> {
    #![allow(non_snake_case)]
    let mut S: SmallVec<[WordT; 20]> = smallvec![WordT::zero(); t(num_rounds)];
    S[0] = WordT::P;
    let mut i = 1;
    while i < t(num_rounds) {
        S[i] = S[i - 1].wrapping_add(&WordT::Q);
        i += 1;
    }
    S
}

/// Create and return the `S` array, with the secret key mixed in
fn scheduled<WordT: Word + num::PrimInt + Clone + bytemuck::Pod + num::traits::WrappingAdd>(
    key: SecretKey,
    num_rounds: u8,
) -> SmallVec<[WordT; 20]> {
    #![allow(non_snake_case)]
    // The secret key as an array of words, zero padded if there is any slack
    let mut L = Cow::<[WordT]>::from(key).to_vec();
    let mut S = unscheduled::<WordT>(num_rounds);

    let (mut i, mut j) = (0, 0);
    let (mut A, mut B) = (WordT::zero(), WordT::zero());

    let c = match L.len() {
        0 => 1, // must be at least one
        other => other,
    };

    for _ in 0..(std::cmp::max(t(num_rounds), c) * 3) {
        S[i] = (S[i].wrapping_add(&A).wrapping_add(&B)).rotate_left(3);
        A = S[i];
        L[j] = (L[j].wrapping_add(&A).wrapping_add(&B))
            .rotate_left(A.wrapping_add(&B).to_u128().expect("word is too wide") as _);
        B = L[j];
        i = (i + 1) % t(num_rounds);
        j = (j + 1) % c;
    }
    S
}

impl<WordT: zeroize::Zeroize> BlockTranscoder<WordT>
where
    WordT: num::PrimInt + num::traits::WrappingAdd,
{
    /// Encrypt the given word block using the secret key stored in the [BlockTranscoder]
    //                                         ^ A white lie
    // We could overwrite plaintext in place, but the optimizer will probably notice for us, so this becomes the caller's decision
    // Method rather than pub fn so we guarantee that our indices into S are in-bounds
    pub fn encode_block(&self, plaintext: &Block<WordT>) -> Block<WordT> {
        #![allow(non_snake_case)]
        let mut A = plaintext[0].wrapping_add(&self.S[0]);
        let mut B = plaintext[1].wrapping_add(&self.S[1]);

        for i in 1..=self.num_rounds as usize {
            A = (A ^ B)
                .rotate_left(B.to_u128().expect("word is too wide") as _)
                .wrapping_add(&self.S[2 * i]);
            B = (B ^ A)
                .rotate_left(A.to_u128().expect("word is too wide") as _)
                .wrapping_add(&self.S[2 * i + 1]);
        }

        [A, B]
    }
}
impl<WordT: zeroize::Zeroize> BlockTranscoder<WordT>
where
    WordT: num::PrimInt + num::traits::WrappingSub,
{
    /// Decrypt the given word block using the secret key stored in the [BlockTranscoder]
    pub fn decode_block(&self, ciphertext: &Block<WordT>) -> Block<WordT> {
        #![allow(non_snake_case)]
        let mut B = ciphertext[1];
        let mut A = ciphertext[0];

        for i in (1..=self.num_rounds as usize).rev() {
            B = (B.wrapping_sub(&self.S[2 * i + 1]))
                .rotate_right(A.to_u128().expect("word is too wide") as _)
                ^ A;
            A = (A.wrapping_sub(&self.S[2 * i]))
                .rotate_right(B.to_u128().expect("word is too wide") as _)
                ^ B;
        }

        B = B.wrapping_sub(&self.S[1]);
        A = A.wrapping_sub(&self.S[0]);
        [A, B]
    }
}

/// Contains all the information required to encode or decode a block.
/// Implements [zeroize::Zeroize], so you can wrap in [zeroize::Zeroizing] to clear the key on [Drop].
/// In general, this implementation is *not* robust to side-channel attacks
/// - the rust compiler makes no guarantees about constant time operations.
#[derive(Clone)]
#[allow(non_snake_case)]
pub struct BlockTranscoder<WordT: zeroize::Zeroize> {
    // TODO: newtype so can use SmallVec + Zeroize here
    S: zeroize::Zeroizing<Vec<WordT>>,
    num_rounds: u8,
}

impl<WordT: zeroize::Zeroize> fmt::Debug for BlockTranscoder<WordT> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transcoder").finish_non_exhaustive()
    }
}

impl<WordT> BlockTranscoder<WordT>
where
    WordT: Word
        + zeroize::Zeroize
        + num::PrimInt
        + Clone
        + bytemuck::Pod
        + num::traits::WrappingAdd
        + num::traits::WrappingSub,
{
    pub fn new(key: SecretKey, num_rounds: u8) -> Self {
        Self {
            S: zeroize::Zeroizing::new(scheduled(key, num_rounds).to_vec()),
            num_rounds,
        }
    }
    pub fn try_new(key: impl AsRef<[u8]>, num_rounds: u8) -> Result<Self, SecretKeyTooLarge> {
        let key = SecretKey::try_from(key.as_ref())?;
        Ok(Self::new(key, num_rounds))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("secret key length {0} is not in range 0..={MAX_KEY_LEN}")]
pub struct SecretKeyTooLarge(pub usize);

/// Secret key guaranteed to be of a valid length for RC5
/// ```
/// let key = vec![0u8; rc5::MAX_KEY_LEN];
/// rc5::SecretKey::try_from(&key[..]).expect("this key is short enough");
/// let key = vec![0u8; rc5::MAX_KEY_LEN + 1];
/// rc5::SecretKey::try_from(&key[..]).expect_err("this key is too long");
/// # //                                         how satisfying is that! ^
/// ```
#[derive(Debug, Clone, Copy)]
pub struct SecretKey<'a> {
    // we could do a bunch of Cow magic here, and have nice constructors,
    // but [Transcoder] is owned, and is what the user really wants anyway
    buffer: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for SecretKey<'a> {
    type Error = SecretKeyTooLarge;

    fn try_from(buffer: &'a [u8]) -> Result<Self, Self::Error> {
        let num_bytes = buffer.len();
        match num_bytes {
            0..=MAX_KEY_LEN => Ok(Self { buffer }),
            _ => Err(SecretKeyTooLarge(num_bytes)),
        }
    }
}

// 0-pad the secret key for use as an array of words
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
            Err(AlignmentMismatch) => unreachable!("slice not a Box or Vec"),
            Err(OutputSliceWouldHaveSlop) | Err(TargetAlignmentGreaterAndInputNotAligned) => {
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
                        .expect("WordT is Pod, so should be fine to cast to bytes"),
                ) {
                    *dst = *src
                }
                Cow::from(backing_words)
            }
            Err(SizeMismatch) => unreachable!("both pointers are thick"), // doesn't seem right - double check bytemuch for what this actually means
        }
    }
}

/// Supported word sizes for this crate
// Seal the trait because I am *not* doing arbitrary bit width arithmetic.
// Could be persuaded once `awint` and `num` are better friends.
pub trait Word: sealed::Sealed {
    /// A magic constant
    // my `const fn` implementation of this had floating point errors - see commit history
    const P: Self;
    /// A magic constant
    const Q: Self;

    type LeBytes: IntoIterator<Item = u8>; // TODO rustc 1.65 - can we remove this?

    /// Avoid an allocation when flattening the output block stream by returning a known type
    fn to_le_bytes(self) -> Self::LeBytes;
}

macro_rules! impl_word {
    ($ty:ty, P = $p:expr, Q = $q:expr $(,)?) => {
        impl Word for $ty {
            const P: Self = $p;
            const Q: Self = $q;
            type LeBytes = [u8; size_of::<$ty>()];
            fn to_le_bytes(self) -> Self::LeBytes {
                self.to_le_bytes()
            }
        }
        static_assertions::const_assert_eq!(align_of::<$ty>() % align_of::<u8>(), 0);
        impl sealed::Sealed for $ty {}
    };
}

impl_word!(u8, P = 0xB7, Q = 0x9F);
impl_word!(u16, P = 0xB7E1, Q = 0x9E37);
impl_word!(u32, P = 0xB7E15163, Q = 0x9E3779B9);
impl_word!(u64, P = 0xB7E151628AED2A6B, Q = 0x9E3779B97F4A7C15);
impl_word!(
    u128,
    P = 0xb7e151628aed2a6abf7158809cf4f3c7, // wolfram alpha
    Q = 0x9e3779b97f4a7c15f39cc0605cedc835,
);

mod sealed {
    pub trait Sealed {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test<WordT>(num_rounds: u8, key: &str, input: &str, output: &str)
    where
        WordT: bytemuck::Pod
            + num::PrimInt
            + Word
            + num::traits::WrappingAdd
            + num::traits::WrappingSub
            + zeroize::Zeroize,
    {
        let key = hex::decode(key).unwrap();
        let input = hex::decode(input).unwrap();
        let output = hex::decode(output).unwrap();
        let encoded_input = encode_all::<WordT>(&key, &input, num_rounds);
        assert_eq!(output, encoded_input);
        let decoded_output = decode_all::<WordT>(&key, &output, num_rounds);
        assert_eq!(input, decoded_output);
    }

    /// from https://datatracker.ietf.org/doc/html/draft-krovetz-rc6-rc5-vectors-00#section-4
    #[test]
    fn test_rc5_8_12_4() {
        test::<u8>(12, "00010203", "0001", "212A")
    }

    /// from https://datatracker.ietf.org/doc/html/draft-krovetz-rc6-rc5-vectors-00#section-4
    #[test]
    fn test_rc5_16_16_8() {
        test::<u16>(16, "0001020304050607", "00010203", "23A8D72E")
    }

    /// from https://datatracker.ietf.org/doc/html/draft-krovetz-rc6-rc5-vectors-00#section-4
    #[test]
    fn test_rc5_32_20_16() {
        test::<u32>(
            20,
            "000102030405060708090A0B0C0D0E0F",
            "0001020304050607",
            "2A0EDC0E9431FF73",
        )
    }

    /// from https://datatracker.ietf.org/doc/html/draft-krovetz-rc6-rc5-vectors-00#section-4
    #[test]
    fn test_rc5_64_24_24() {
        test::<u64>(
            24,
            "000102030405060708090A0B0C0D0E0F1011121314151617",
            "000102030405060708090A0B0C0D0E0F",
            "A46772820EDBCE0235ABEA32AE7178DA",
        )
    }

    /// from https://datatracker.ietf.org/doc/html/draft-krovetz-rc6-rc5-vectors-00#section-4
    #[test]
    fn rc5_128_28_32() {
        test::<u128>(
            28,
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "ECA5910921A4F4CFDD7AD7AD20A1FCBA068EC7A7CD752D68FE914B7FE180B440",
        )
    }
}
