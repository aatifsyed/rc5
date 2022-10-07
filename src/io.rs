use std::{collections::VecDeque, io};

pub struct IoDecoder<WordT: zeroize::Zeroize, InnerT> {
    transcoder: crate::Transcoder<WordT>,
    inner: InnerT,
    unfinished: VecDeque<u8>,
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
        if !self.unfinished.is_empty() {
            return Ok(drain_vecdeque_to_slice(&mut self.unfinished, buf));
        }
        let mut block = [WordT::zero(), WordT::zero()];
        if let Err(io_err) = self.inner.read_exact(bytemuck::cast_slice_mut(&mut block)) {
            if io_err.kind() == io::ErrorKind::UnexpectedEof {
                // fine to continue with padded zeroes
            } else {
                return Err(io_err);
            }
        }
        let decoded = self.transcoder.decode_block(&block);
        self.unfinished.extend(bytemuck::cast_slice(&decoded));
        Ok(drain_vecdeque_to_slice(&mut self.unfinished, buf))
    }
}

impl<WordT: zeroize::Zeroize, InnerT> io::Write for IoDecoder<WordT, InnerT>
where
    InnerT: io::Write,
    WordT: num::Zero + bytemuck::Pod + num::PrimInt + num::traits::WrappingSub,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // TODO: optimize
        self.unfinished.extend(buf);
        Ok(buf.len())
    }

    /// Return [io::ErrorKind::WriteZero] when we need more bytes to make a block
    fn flush(&mut self) -> io::Result<()> {
        // TODO: optimize
        match bytemuck::try_cast_slice_mut::<_, [WordT; 2]>(self.unfinished.make_contiguous()) {
            Ok(word_pairs) => {
                for word_pair in word_pairs {
                    let decoded = self.transcoder.decode_block(word_pair);
                    self.inner.write_all(bytemuck::cast_slice(&decoded))?;
                }
                self.inner.flush()
            }
            Err(_) => Err(io::Error::from(io::ErrorKind::WriteZero)),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test() {}
}
