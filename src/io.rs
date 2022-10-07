use std::{collections::VecDeque, io};

pub struct IoDecoder<WordT: zeroize::Zeroize, InnerT> {
    transcoder: crate::Transcoder<WordT>,
    inner: InnerT,
    unfinished: Option<VecDeque<u8>>,
}

impl<WordT: zeroize::Zeroize, InnerT> IoDecoder<WordT, InnerT> {
    pub fn new(transcoder: crate::Transcoder<WordT>, inner: InnerT) -> Self {
        Self {
            transcoder,
            inner,
            unfinished: Some(VecDeque::new()),
        }
    }
}

fn drain_vecdeque_to_slice<T>(src: &mut VecDeque<T>, mut dst: &mut [T]) -> usize {
    let mut count = 0;
    while dst.len() != 0 {
        match src.pop_front() {
            Some(t) => {
                dst[0] = t;
                dst = &mut dst[1..];
                count += 1;
            }
            None => return count,
        }
    }
    count
}

impl<WordT: zeroize::Zeroize, InnerT> io::Read for IoDecoder<WordT, InnerT>
where
    InnerT: io::Read,
    WordT: num::Zero + bytemuck::Pod + num::PrimInt + num::traits::WrappingSub,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.unfinished {
            Some(unfinished) => {
                if !unfinished.is_empty() {
                    dbg!("unfinished business");
                    return Ok(dbg!(drain_vecdeque_to_slice(unfinished, buf)));
                }
                let mut block = [WordT::zero(), WordT::zero()];
                if let Err(io_err) =
                    dbg!(self.inner.read_exact(bytemuck::cast_slice_mut(&mut block)))
                {
                    dbg!("inner error");
                    if io_err.kind() == io::ErrorKind::UnexpectedEof {
                        dbg!("ignore UnexpectedEof");
                        // fine to continue with padded zeroes
                    } else {
                        return Err(io_err);
                    }
                }
                let decoded = self.transcoder.decode_block(&block);
                unfinished.extend(bytemuck::cast_slice(&decoded));
                let drained = drain_vecdeque_to_slice(unfinished, buf);
                if drained == unfinished.len() {
                    self.unfinished = None;
                }
                Ok(drained)
            }
            None => return Ok(0),
        }
    }
}

impl<WordT: zeroize::Zeroize, InnerT> io::Write for IoDecoder<WordT, InnerT>
where
    InnerT: io::Write,
    WordT: num::Zero + bytemuck::Pod + num::PrimInt + num::traits::WrappingSub,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        todo!()
        // // TODO: optimize
        // self.unfinished.extend(buf);
        // Ok(buf.len())
    }

    /// Return [io::ErrorKind::WriteZero] when we need more bytes to make a block
    fn flush(&mut self) -> io::Result<()> {
        todo!()
        // // TODO: optimize
        // match bytemuck::try_cast_slice_mut::<_, [WordT; 2]>(self.unfinished.make_contiguous()) {
        //     Ok(word_pairs) => {
        //         for word_pair in word_pairs {
        //             let decoded = self.transcoder.decode_block(word_pair);
        //             self.inner.write_all(bytemuck::cast_slice(&decoded))?;
        //         }
        //         self.inner.flush()
        //     }
        //     Err(_) => Err(io::Error::from(io::ErrorKind::WriteZero)),
        // }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;
    #[test]
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
