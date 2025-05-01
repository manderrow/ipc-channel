#[derive(Default)]
pub struct CountingWriter {
    pub len: usize,
}

impl rkyv::ser::Positional for CountingWriter {
    #[inline]
    fn pos(&self) -> usize {
        self.len
    }
}

impl<E: rkyv::rancor::Source> rkyv::ser::Writer<E> for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> Result<(), E> {
        self.len = self.len.checked_add(bytes.len()).ok_or_else(|| {
            #[derive(Debug, thiserror::Error)]
            #[error("overflowed counter while adding {write_len} bytes to existing count {len}")]
            struct BufferOverflow {
                write_len: usize,
                len: usize,
            }

            E::new(BufferOverflow {
                write_len: bytes.len(),
                len: self.len,
            })
        })?;
        Ok(())
    }
}
