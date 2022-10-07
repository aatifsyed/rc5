use std::mem::{size_of, size_of_val};

use anyhow::ensure;

#[derive(Debug, PartialEq, Eq)]
#[repr(packed)]
pub struct ControlBlock {
    pub header: ControlBlockHeader,
    pub key: [u8],
}

impl ControlBlock {
    // oh we love to wrangle lifetimes
    pub fn encoder<'inner, 'iter, InnerT>(
        &self,
        inner: InnerT,
    ) -> Box<dyn Iterator<Item = u8> + 'inner>
    where
        InnerT: 'inner,
        InnerT: IntoIterator<Item = &'iter u8>,
    {
        macro_rules! iter_encoder {
            ($ty:ty) => {
                Box::new(crate::IterEncoder::new(
                    crate::Transcoder::<$ty>::new(
                        crate::SecretKey { buffer: &self.key },
                        self.header.num_rounds,
                    ),
                    inner,
                ))
            };
        }
        match self.header.bits_per_word {
            Width::_8 => iter_encoder!(u8),
            Width::_16 => iter_encoder!(u16),
            Width::_32 => iter_encoder!(u32),
            Width::_64 => iter_encoder!(u64),
            Width::_128 => iter_encoder!(u128),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(packed)]
pub struct ControlBlockHeader {
    pub version: Version,
    pub bits_per_word: Width,
    pub num_rounds: u8,
    pub key_length: u8,
}

static_assertions::assert_eq_size!(ControlBlockHeader, [u8; 4]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, num_enum::TryFromPrimitive)]
#[repr(u8)]
pub enum Version {
    _1 = 0x10,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, num_enum::TryFromPrimitive)]
#[repr(u8)]
pub enum Width {
    _8 = u8::BITS as _,
    _16 = u16::BITS as _,
    _32 = u32::BITS as _,
    _64 = u64::BITS as _,
    _128 = u128::BITS as _,
}

impl TryFrom<&[u8]> for &ControlBlock {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        ensure!(
            value.len() >= size_of::<ControlBlockHeader>(),
            "header is too short"
        );
        let apparent_version = value[0];
        ensure!(
            Version::try_from(apparent_version).is_ok(),
            "unsupported version {apparent_version}",
        );
        let apparent_bits_per_word = value[1];
        ensure!(
            Width::try_from(apparent_bits_per_word).is_ok(),
            "unsupported word width {apparent_bits_per_word}",
        );
        let apparent_key_length = value[3];
        let key_length = size_of_val(value) - size_of::<ControlBlockHeader>();
        ensure!(
            key_length == usize::from(apparent_key_length),
            "key length in header ({apparent_key_length}) does not match given key length ({key_length})"
        );
        // here's a little lesson in trickery
        // should really use #![feature(ptr_metadata)] and feature gate on crate
        let control_block = &value[..value.len() - size_of::<ControlBlockHeader>()] as *const [u8]
            as *const ControlBlock;
        Ok(unsafe { &*control_block })
    }
}

impl<const N: usize> TryFrom<&[u8; N]> for &ControlBlock {
    type Error = anyhow::Error;

    fn try_from(value: &[u8; N]) -> Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Width {
        fn of<T>() -> Self {
            let num_bits = size_of::<T>() * 8;
            let num_bits = u8::try_from(num_bits).unwrap();
            Self::try_from(num_bits).unwrap()
        }
    }

    #[test]
    fn empty_key() {
        let backing_storage = [Version::_1 as u8, 16, 0, 0];
        let control_block = <&ControlBlock>::try_from(&backing_storage).unwrap();
        assert_eq!(
            control_block.header,
            ControlBlockHeader {
                version: Version::_1,
                bits_per_word: Width::_16,
                num_rounds: 0,
                key_length: 0
            }
        );
        assert_eq!(control_block.key.len(), 0);
    }

    #[test]
    fn key_length_too_small() {
        let backing_storage = [Version::_1 as u8, 16, 0, 0, 0xAA];
        <&ControlBlock>::try_from(&backing_storage).unwrap_err();
    }

    #[test]
    fn key_length_too_big() {
        let backing_storage = [Version::_1 as u8, 16, 0, 1];
        <&ControlBlock>::try_from(&backing_storage).unwrap_err();
    }

    #[test]
    fn key_length1() {
        let backing_storage = [Version::_1 as u8, 16, 0, 1, 0xAA];
        let control_block = <&ControlBlock>::try_from(&backing_storage).unwrap();
        assert_eq!(
            control_block.header,
            ControlBlockHeader {
                version: Version::_1,
                bits_per_word: Width::_16,
                num_rounds: 0,
                key_length: 1,
            }
        );
        assert_eq!(control_block.key, [0xAA]);
    }

    fn test<T>(num_rounds: u8, key: &str, input: &str, output: &str) {
        let key = hex::decode(key).unwrap();
        let bits_per_word = size_of::<T>() * 8;
        let input = hex::decode(input).unwrap();
        let output = hex::decode(output).unwrap();

        let hex_encoded = format!(
            "{version:02x?}{bits_per_word:02x?}{num_rounds:02x?}{key_length:02x?}{key}",
            version = Version::_1 as u8,
            key_length = key.len(),
            key = hex::encode(&key),
        );

        let backing_storage = hex::decode(hex_encoded).unwrap();
        let control_block = <&ControlBlock>::try_from(&backing_storage[..]).unwrap();
        assert_eq!(usize::from(control_block.header.key_length), key.len());
        assert_eq!(control_block.header.bits_per_word, Width::of::<T>());
        assert_eq!(control_block.header.num_rounds, num_rounds);
        assert_eq!(&control_block.key, key);

        let encoded_input = control_block.encoder(&input[..]).collect::<Vec<_>>();
        assert_eq!(encoded_input, output);
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
