#![allow(unused)]
use std::io;

pub struct IoDecoder<WordT: zeroize::Zeroize, InnerT> {
    transcoder: crate::Transcoder<WordT>,
    inner: InnerT,
}

impl<WordT: zeroize::Zeroize, InnerT> IoDecoder<WordT, InnerT> {
    pub fn new(transcoder: crate::Transcoder<WordT>, inner: InnerT) -> Self {
        Self { transcoder, inner }
    }
}

impl<WordT: zeroize::Zeroize, InnerT> io::Read for IoDecoder<WordT, InnerT>
where
    InnerT: io::Read,
    WordT: num::Zero + bytemuck::Pod + num::PrimInt + num::traits::WrappingSub,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unimplemented!()
    }
}

impl<WordT: zeroize::Zeroize, InnerT> io::Write for IoDecoder<WordT, InnerT>
where
    InnerT: io::Write,
    WordT: num::Zero + bytemuck::Pod + num::PrimInt + num::traits::WrappingSub,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unimplemented!()
    }

    fn flush(&mut self) -> io::Result<()> {
        unimplemented!()
    }
}

pub struct IoEncoder<WordT: zeroize::Zeroize, InnerT> {
    transcoder: crate::Transcoder<WordT>,
    inner: InnerT,
}

impl<WordT: zeroize::Zeroize, InnerT> IoEncoder<WordT, InnerT> {
    pub fn new(transcoder: crate::Transcoder<WordT>, inner: InnerT) -> Self {
        Self { transcoder, inner }
    }
}

impl<WordT: zeroize::Zeroize, InnerT> io::Read for IoEncoder<WordT, InnerT>
where
    InnerT: io::Read,
    WordT: num::Zero + bytemuck::Pod + num::PrimInt + num::traits::WrappingAdd,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unimplemented!()
    }
}

impl<WordT: zeroize::Zeroize, InnerT> io::Write for IoEncoder<WordT, InnerT>
where
    InnerT: io::Write,
    WordT: num::Zero + bytemuck::Pod + num::PrimInt + num::traits::WrappingAdd,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unimplemented!()
    }

    fn flush(&mut self) -> io::Result<()> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;
    #[test]
    #[ignore = "unimplemented"]
    fn test() {
        let num_rounds = 12;
        let key = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let input = [0x96u8, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
        let output = [0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];

        let mut decoded_output = Vec::new();
        IoDecoder::new(
            crate::Transcoder::<u32>::try_new(key, num_rounds).unwrap(),
            &output[..],
        )
        .read_to_end(&mut decoded_output)
        .unwrap();
        assert_eq!(decoded_output, input);
    }
}
