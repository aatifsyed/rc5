use std::mem::{size_of, size_of_val};

use anyhow::ensure;

#[derive(Debug, PartialEq, Eq)]
#[repr(packed)]
pub struct ControlBlock {
    pub header: ControlBlockHeader,
    pub key: [u8],
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
}
