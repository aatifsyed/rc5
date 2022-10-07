use std::{
    collections::VecDeque,
    fmt,
    iter::{Fuse, FusedIterator},
    mem::size_of,
};

use crate::Transcoder;

/// An iterator adaptor that decodes bytes that pass through it
pub struct Decoder<WordT, InnerT> {
    word_encoder: WordDecoder<WordT, InnerT>,
    buffer: VecDeque<u8>,
}

impl<'a, WordT, InnerT> FusedIterator for Decoder<WordT, InnerT>
where
    InnerT: Iterator<Item = &'a u8>,
    WordT: bytemuck::Pod + num::PrimInt + num::traits::WrappingSub,
{
}

impl<WordT, InnerT> fmt::Debug for Decoder<WordT, InnerT> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decoder").finish_non_exhaustive()
    }
}

impl<WordT, InnerT> Decoder<WordT, InnerT>
where
    InnerT: Iterator,
{
    pub fn new(transcoder: Transcoder<WordT>, inner: impl IntoIterator<IntoIter = InnerT>) -> Self {
        Self {
            word_encoder: WordDecoder::new(transcoder, inner),
            buffer: Default::default(),
        }
    }
}

impl<'a, WordT, InnerT> Iterator for Decoder<WordT, InnerT>
where
    InnerT: Iterator<Item = &'a u8>,
    WordT: bytemuck::Pod + num::PrimInt + num::traits::WrappingSub,
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer.is_empty() {
            self.buffer
                .extend(bytemuck::cast_slice(&self.word_encoder.next()?))
        }
        self.buffer.pop_front()
    }
}

struct WordDecoder<WordT, InnerT> {
    transcoder: Transcoder<WordT>,
    // reuse allocation
    buffer: Vec<u8>,
    inner: Fuse<InnerT>,
    pad_with: u8,
}

impl<WordT, InnerT> WordDecoder<WordT, InnerT>
where
    InnerT: Iterator,
{
    fn new(transcoder: Transcoder<WordT>, inner: impl IntoIterator<IntoIter = InnerT>) -> Self {
        Self {
            transcoder,
            buffer: Vec::new(),
            inner: inner.into_iter().fuse(),
            pad_with: 0,
        }
    }
}

impl<'a, WordT, InnerT> Iterator for WordDecoder<WordT, InnerT>
where
    InnerT: Iterator<Item = &'a u8>,
    WordT: bytemuck::Pod + num::PrimInt + num::traits::WrappingSub,
{
    type Item = [WordT; 2];

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.buffer.len() == size_of::<WordT>() * 2 {
                let plaintext: [WordT; 2] = bytemuck::cast_slice(&self.buffer)
                    .try_into()
                    .expect("we've already checked the length");
                let ciphertext = self.transcoder.decode_block(&plaintext);
                self.buffer.clear();
                return Some(ciphertext);
            }

            match self.inner.next() {
                Some(byte) => self.buffer.push(*byte),
                None => match self.buffer.is_empty() {
                    true => return None,
                    // need to fuse
                    false => self.buffer.push(self.pad_with),
                },
            }
        }
    }
}
