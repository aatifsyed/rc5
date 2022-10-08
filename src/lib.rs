use std::{
    borrow::Cow,
    fmt,
    mem::{align_of, size_of},
};
mod decoder;
mod encoder;
pub use decoder::Decoder;
pub use encoder::Encoder;

// TODO:
// - test endianness
// - add a compile time API for num_rounds

#[derive(Debug, thiserror::Error)]
#[error("secret key length must be in range 0..=255")]
pub struct SecretKeyTooLarge;

#[derive(Debug, Clone, Copy)]
/// Buffer guaranteed to be of a valid length for RC5
pub struct SecretKey<'a> {
    buffer: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for SecretKey<'a> {
    type Error = SecretKeyTooLarge;

    fn try_from(buffer: &'a [u8]) -> Result<Self, Self::Error> {
        let num_bytes = buffer.len();
        match num_bytes {
            0..=255 => Ok(Self { buffer }),
            _ => Err(SecretKeyTooLarge),
        }
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

// impl_word!(u8, P = ???, Q = ???);
impl_word!(u16, P = 0xB7E1, Q = 0x9E37);
impl_word!(u32, P = 0xB7E15163, Q = 0x9E3779B9);
impl_word!(u64, P = 0xB7E151628AED2A6B, Q = 0x9E3779B97F4A7C15);
// impl_word!(u128, P = ???, Q = ???);

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

#[derive(Clone, Copy, zeroize::Zeroize)]
#[allow(non_snake_case)]
pub struct Transcoder<WordT> {
    S: [WordT; T_MAX],
    num_rounds: u8,
}

impl<WordT> fmt::Debug for Transcoder<WordT> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transcoder").finish_non_exhaustive()
    }
}

impl<WordT> Transcoder<WordT>
where
    WordT: Word
        + num::PrimInt
        + Clone
        + bytemuck::Pod
        + num::traits::WrappingAdd
        + num::traits::WrappingSub,
{
    pub fn new(key: SecretKey, num_rounds: u8) -> Self {
        Self {
            S: mixed_s(key, num_rounds),
            num_rounds,
        }
    }
    pub fn try_new(key: impl AsRef<[u8]>, num_rounds: u8) -> Result<Self, SecretKeyTooLarge> {
        let key = SecretKey::try_from(key.as_ref())?;
        Ok(Self::new(key, num_rounds))
    }
}
impl<WordT> Transcoder<WordT>
where
    WordT: num::PrimInt + num::traits::WrappingAdd,
{
    // We could overwrite plaintext in place, but the optimizer will probably notice for us, so this becomes the caller's decision
    // Method rather than pub fn so we guarantee that we can index into S
    pub fn encode_block(&self, plaintext: &[WordT; 2]) -> [WordT; 2] {
        #![allow(non_snake_case)]
        let mut A = plaintext[0].wrapping_add(&self.S[0]);
        let mut B = plaintext[1].wrapping_add(&self.S[1]);

        for i in 1..=self.num_rounds as usize {
            A = (A ^ B)
                .rotate_left(B.to_u32().expect("word is too wide"))
                .wrapping_add(&self.S[2 * i]);
            B = (B ^ A)
                .rotate_left(A.to_u32().expect("word is too wide"))
                .wrapping_add(&self.S[2 * i + 1]);
        }

        [A, B]
    }
}
impl<WordT> Transcoder<WordT>
where
    WordT: num::PrimInt + num::traits::WrappingSub,
{
    pub fn decode_block(&self, ciphertext: &[WordT; 2]) -> [WordT; 2] {
        #![allow(non_snake_case)]
        let mut B = ciphertext[1];
        let mut A = ciphertext[0];

        for i in (1..=self.num_rounds as usize).rev() {
            B = (B.wrapping_sub(&self.S[2 * i + 1]))
                .rotate_right(A.to_u32().expect("word is too wide"))
                ^ A;
            A = (A.wrapping_sub(&self.S[2 * i]))
                .rotate_right(B.to_u32().expect("word is too wide"))
                ^ B;
        }

        B = B.wrapping_sub(&self.S[1]);
        A = A.wrapping_sub(&self.S[0]);
        [A, B]
    }
}

// save a heap allocation for the s array
// array size could be const N, but since it depends on `num_rounds`, but jumping from a runtime num_rounds (which we want) to a compile time num_rounds (which we don't want) is hard
fn unmixed_s<WordT: Word + Copy + num::Zero + num::traits::WrappingAdd>(
    num_rounds: u8,
) -> [WordT; T_MAX] {
    #![allow(non_snake_case)]
    let mut S = [WordT::zero(); T_MAX];
    S[0] = WordT::P;
    let mut i = 1;
    while i < t(num_rounds) {
        S[i] = S[i - 1].wrapping_add(&WordT::Q);
        i += 1;
    }
    S
}

fn mixed_s<WordT: Word + num::PrimInt + Clone + bytemuck::Pod + num::traits::WrappingAdd>(
    key: SecretKey,
    num_rounds: u8,
) -> [WordT; T_MAX] {
    #![allow(non_snake_case)]
    let mut L = Cow::<[WordT]>::from(key).to_vec();
    let mut S = unmixed_s::<WordT>(num_rounds);

    let (mut i, mut j) = (0, 0);
    let (mut A, mut B) = (WordT::zero(), WordT::zero());

    let c = match L.len() {
        0 => 1,
        other => other,
    };

    for _ in 0..(std::cmp::max(t(num_rounds), c) * 3) {
        S[i] = (S[i].wrapping_add(&A).wrapping_add(&B)).rotate_left(3);
        A = S[i];
        L[j] = (L[j].wrapping_add(&A).wrapping_add(&B))
            .rotate_left(A.wrapping_add(&B).to_u32().expect("word is too wide"));
        B = L[j];
        i = (i + 1) % t(num_rounds);
        j = (j + 1) % c;
    }
    S
}

pub fn encode<WordT>(key: impl AsRef<[u8]>, plaintext: impl AsRef<[u8]>, num_rounds: u8) -> Vec<u8>
where
    WordT: Word
        + Clone
        + bytemuck::Pod
        + num::PrimInt
        + num::traits::WrappingAdd
        + num::traits::WrappingSub,
{
    Encoder::new(
        Transcoder::<WordT>::try_new(key, num_rounds).expect("key is too large"),
        plaintext.as_ref(),
    )
    .collect()
}

pub fn decode<WordT>(key: impl AsRef<[u8]>, ciphertext: impl AsRef<[u8]>, num_rounds: u8) -> Vec<u8>
where
    WordT: Word
        + Clone
        + bytemuck::Pod
        + num::PrimInt
        + num::traits::WrappingAdd
        + num::traits::WrappingSub,
{
    Decoder::new(
        Transcoder::<WordT>::try_new(key, num_rounds).expect("key is too large"),
        ciphertext.as_ref(),
    )
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// vectors from https://datatracker.ietf.org/doc/html/draft-krovetz-rc6-rc5-vectors-00#section-4
    fn test<WordT>(num_rounds: u8, key: &str, input: &str, output: &str)
    where
        WordT: Clone,
        WordT: bytemuck::Pod,
        WordT: num::PrimInt,
        WordT: Word,
        WordT: num::traits::WrappingAdd,
        WordT: num::traits::WrappingSub,
    {
        let key = hex::decode(key).unwrap();
        let input = hex::decode(input).unwrap();
        let output = hex::decode(output).unwrap();
        let encoded_input = encode::<WordT>(&key, &input, num_rounds);
        assert_eq!(output, encoded_input);
        let decoded_output = decode::<WordT>(&key, &output, num_rounds);
        assert_eq!(input, decoded_output);
    }

    // TODO impl Word for u8
    // #[test]
    // fn test_rc5_8_12_4() {
    //     test::<u8>(12, "00010203", "0001", "212A")
    // }

    #[test]
    fn test_rc5_16_16_8() {
        test::<u16>(16, "0001020304050607", "00010203", "23A8D72E")
    }

    #[test]
    fn test_rc5_32_20_16() {
        test::<u32>(
            20,
            "000102030405060708090A0B0C0D0E0F",
            "0001020304050607",
            "2A0EDC0E9431FF73",
        )
    }

    #[test]
    fn test_rc5_64_24_24() {
        test::<u64>(
            24,
            "000102030405060708090A0B0C0D0E0F1011121314151617",
            "000102030405060708090A0B0C0D0E0F",
            "A46772820EDBCE0235ABEA32AE7178DA",
        )
    }

    // TODO impl Word for u128
    // #[test]
    // fn rc5_128_28_32() {
    //     test::<u128>(
    //         28,
    //         "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
    //         "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
    //         "ECA5910921A4F4CFDD7AD7AD20A1FCBA
    //               068EC7A7CD752D68FE914B7FE180B440",
    //     )
    // }
}
