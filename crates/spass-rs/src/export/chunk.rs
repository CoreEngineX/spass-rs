use std::io::{self, Write};

use zeroize::Zeroizing;

const CHUNK_LEN: usize = 64 * 1024;

/// Collects an exporter's output in a zeroizing chunk and passes it to `inner` a chunk at a time.
pub(super) struct Chunked<W: Write> {
    inner: W,
    chunk: Zeroizing<Vec<u8>>,
    filled: usize,
}

impl<W: Write> Chunked<W> {
    pub(super) fn new(inner: W) -> Self {
        Self {
            inner,
            chunk: Zeroizing::new(vec![0; CHUNK_LEN]),
            filled: 0,
        }
    }

    /// Room left in the chunk; never empty.
    #[cfg(feature = "export-csv")]
    pub(super) fn spare(&mut self) -> &mut [u8] {
        &mut self.chunk[self.filled..]
    }

    /// Marks `written` bytes of the spare room as filled.
    #[cfg(feature = "export-csv")]
    pub(super) fn advance(&mut self, written: usize) {
        self.filled += written;
    }

    /// Writes the chunk out and empties it.
    pub(super) fn drain(&mut self) -> io::Result<()> {
        self.inner.write_all(&self.chunk[..self.filled])?;
        self.filled = 0;
        Ok(())
    }

    /// Writes out what is left and flushes `inner`.
    pub(super) fn finish(mut self) -> io::Result<()> {
        self.drain()?;
        self.inner.flush()
    }
}

impl<W: Write> Write for Chunked<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.filled == CHUNK_LEN {
            self.drain()?;
        }
        let room = &mut self.chunk[self.filled..];
        let len = data.len().min(room.len());
        room[..len].copy_from_slice(&data[..len]);
        self.filled += len;
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.drain()?;
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_larger_than_a_chunk_reaches_the_writer_whole() {
        let data: Vec<u8> = (0..CHUNK_LEN * 2 + 17).map(|i| (i % 251) as u8).collect();
        let mut sink = Vec::new();

        let mut chunked = Chunked::new(&mut sink);
        chunked.write_all(&data).unwrap();
        chunked.finish().unwrap();

        assert_eq!(sink, data);
    }

    #[test]
    fn a_failing_writer_fails_the_flush() {
        struct Refuses;
        impl Write for Refuses {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let mut chunked = Chunked::new(Refuses);
        chunked.write_all(b"data").unwrap();

        assert_eq!(
            chunked.finish().unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }
}
