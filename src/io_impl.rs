#![allow(unused)]
use std::{
    io::{self, BufRead},
    mem::size_of,
};

use tap::{Pipe, TryConv};

// https://github.com/rust-lang/rust/issues/86423
fn is_done(reader: &mut impl io::BufRead) -> io::Result<bool> {
    Ok(reader.fill_buf()?.is_empty())
}

pub struct IoDecoder<WordT: zeroize::Zeroize, InnerT> {
    transcoder: crate::BlockTranscoder<WordT>,
    inner: InnerT,
}

impl<WordT: zeroize::Zeroize, InnerT> IoDecoder<WordT, InnerT> {
    const BLOCK_SIZE: usize = size_of::<WordT>() * 2;
}

impl<WordT: zeroize::Zeroize, InnerT> IoDecoder<WordT, io::BufReader<InnerT>>
where
    InnerT: io::Read,
{
    pub fn new_reader(transcoder: crate::BlockTranscoder<WordT>, inner: InnerT) -> Self {
        Self {
            transcoder,
            inner: io::BufReader::with_capacity(Self::BLOCK_SIZE, inner),
        }
    }
}

impl<WordT: zeroize::Zeroize, InnerT> IoDecoder<WordT, io::BufWriter<InnerT>>
where
    InnerT: io::Write,
{
    pub fn new_writer(transcoder: crate::BlockTranscoder<WordT>, inner: InnerT) -> Self {
        Self {
            transcoder,
            inner: io::BufWriter::with_capacity(Self::BLOCK_SIZE, inner),
        }
    }
}

// could be for IoDecoder<WordT, InnerT> where InnerT: io::BufRead, but I'd have to think about it
impl<WordT: zeroize::Zeroize, InnerT> io::Read for IoDecoder<WordT, io::BufReader<InnerT>>
where
    InnerT: io::Read,
    WordT: num::Zero + bytemuck::Pod + num::PrimInt + num::traits::WrappingSub,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // TODO shit code

        // loop { // but we'll always panic if e.g the caller is a BufReader which doesn't have a buffer of Self::BLOCK_SIZE * N
        let buffer = self.inner.fill_buf()?;
        if buffer.len() == Self::BLOCK_SIZE {
            let plain_block = buffer
                .pipe(bytemuck::cast_slice::<_, WordT>)
                .try_conv::<&[WordT; 2]>()
                .expect("already checked size") // something something alignment
                .pipe(|ciphertext| self.transcoder.decode_block(ciphertext));
            buf.get_mut(0..Self::BLOCK_SIZE)
                .expect("buffer is too small to fit a block in") // could handle with our own buffer
                .copy_from_slice(bytemuck::cast_slice(&plain_block));
            self.inner.consume(Self::BLOCK_SIZE);
            return Ok(Self::BLOCK_SIZE);
        }
        // } so just do one block per read

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
    transcoder: crate::BlockTranscoder<WordT>,
    inner: InnerT,
}

impl<WordT: zeroize::Zeroize, InnerT> IoEncoder<WordT, InnerT> {
    pub fn new(transcoder: crate::BlockTranscoder<WordT>, inner: InnerT) -> Self {
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
        IoDecoder::new_reader(
            crate::BlockTranscoder::<u32>::try_new(key, num_rounds).unwrap(),
            &output[..],
        )
        .read_to_end(&mut decoded_output)
        .unwrap();
        assert_eq!(decoded_output, input);
    }
}
