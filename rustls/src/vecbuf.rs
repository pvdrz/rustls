use alloc::collections::VecDeque;
use core::cmp;
use std::io;
use std::io::Read;

/// This is a byte buffer that is built from a vector
/// of byte vectors.  This avoids extra copies when
/// appending a new byte vector, at the expense of
/// more complexity when reading out.
pub(crate) struct ChunkVecBuffer {
    chunks: VecDeque<Vec<u8>>,
    limit: Option<usize>,
}

impl ChunkVecBuffer {
    pub(crate) fn new(limit: Option<usize>) -> Self {
        Self {
            chunks: VecDeque::new(),
            limit,
        }
    }

    /// Sets the upper limit on how many bytes this
    /// object can store.
    ///
    /// Setting a lower limit than the currently stored
    /// data is not an error.
    ///
    /// A [`None`] limit is interpreted as no limit.
    pub(crate) fn set_limit(&mut self, new_limit: Option<usize>) {
        self.limit = new_limit;
    }

    /// If we're empty
    pub(crate) fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    pub(crate) fn is_full(&self) -> bool {
        self.limit
            .map(|limit| self.len() > limit)
            .unwrap_or_default()
    }

    /// How many bytes we're storing
    pub(crate) fn len(&self) -> usize {
        let mut len = 0;
        for ch in &self.chunks {
            len += ch.len();
        }
        len
    }

    /// For a proposed append of `len` bytes, how many
    /// bytes should we actually append to adhere to the
    /// currently set `limit`?
    pub(crate) fn apply_limit(&self, len: usize) -> usize {
        if let Some(limit) = self.limit {
            let space = limit.saturating_sub(self.len());
            cmp::min(len, space)
        } else {
            len
        }
    }

    /// Append a copy of `bytes`, perhaps a prefix if
    /// we're near the limit.
    pub(crate) fn append_limited_copy(&mut self, bytes: &[u8]) -> usize {
        let scope = crate::Scope::current();
        eprintln!(
            "{scope}ChunkVecBuffer::append_limited_copy(bytes.len={}) <<<BUFFERING>>>",
            bytes.len()
        );

        let take = self.apply_limit(bytes.len());
        self.append(bytes[..take].to_vec());
        take
    }

    /// Take and append the given `bytes`.
    pub(crate) fn append(&mut self, bytes: Vec<u8>) -> usize {
        let scope = crate::Scope::current();
        eprintln!(
            "{scope}ChunkVecBuffer::append(bytes.len={}) <<<BUFFERING>>>",
            bytes.len()
        );

        let len = bytes.len();

        if !bytes.is_empty() {
            self.chunks.push_back(bytes);
        }

        len
    }

    /// Take one of the chunks from this object.  This
    /// function panics if the object `is_empty`.
    pub(crate) fn pop(&mut self) -> Option<Vec<u8>> {
        self.chunks.pop_front()
    }

    /// Read data out of this object, writing it into `buf`
    /// and returning how many bytes were written there.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut offs = 0;

        while offs < buf.len() && !self.is_empty() {
            let used = self.chunks[0]
                .as_slice()
                .read(&mut buf[offs..])?;

            self.consume(used);
            offs += used;
        }

        Ok(offs)
    }

    #[cfg(read_buf)]
    /// Read data out of this object, writing it into `cursor`.
    pub(crate) fn read_buf(&mut self, mut cursor: io::BorrowedCursor<'_>) -> io::Result<()> {
        while !self.is_empty() && cursor.capacity() > 0 {
            let chunk = self.chunks[0].as_slice();
            let used = core::cmp::min(chunk.len(), cursor.capacity());
            cursor.append(&chunk[..used]);
            self.consume(used);
        }

        Ok(())
    }

    fn consume(&mut self, mut used: usize) {
        while let Some(mut buf) = self.chunks.pop_front() {
            if used < buf.len() {
                self.chunks
                    .push_front(buf.split_off(used));
                break;
            } else {
                used -= buf.len();
            }
        }
    }

    /// Read data out of this object, passing it `wr`
    pub(crate) fn write_to(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        if self.is_empty() {
            return Ok(0);
        }

        let scope = crate::Scope::current();

        let mut bufs = [io::IoSlice::new(&[]); 64];
        for (iov, chunk) in bufs.iter_mut().zip(self.chunks.iter()) {
            *iov = io::IoSlice::new(chunk);
        }
        let len = cmp::min(bufs.len(), self.chunks.len());
        let used = wr.write_vectored(&bufs[..len])?;
        eprintln!("{scope}ChunkVecBuf::write_to() -> {used} <<<IO>>>");
        self.consume(used);
        Ok(used)
    }
}
