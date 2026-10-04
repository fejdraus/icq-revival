//! A bounds-checked big-endian byte cursor.
//!
//! Shared by the IQE1 container ([`crate::container`]) and the OSCAR parsers
//! ([`crate::snac`] re-exports it). It knows no protocol: the container is
//! read with it, so the container does not depend on OSCAR code.

/// A minimal big-endian cursor over a byte slice. Every read is checked; a read
/// past the end returns `None` so callers stop rather than panic.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
    pub fn u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    pub fn u16(&mut self) -> Option<u16> {
        let hi = *self.data.get(self.pos)?;
        let lo = *self.data.get(self.pos + 1)?;
        self.pos += 2;
        Some(u16::from_be_bytes([hi, lo]))
    }
    pub fn u32(&mut self) -> Option<u32> {
        if self.pos + 4 > self.data.len() {
            return None;
        }
        let v = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Some(v)
    }
    pub fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.data.len() {
            return None;
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
    /// A byte run prefixed by a u8 length.
    pub fn len8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()? as usize;
        self.bytes(n)
    }
    pub fn skip(&mut self, n: usize) -> Option<()> {
        if self.pos + n > self.data.len() {
            return None;
        }
        self.pos += n;
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::Reader;

    #[test]
    fn reads_big_endian_values_in_order() {
        let mut r = Reader::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x02, 0xAA, 0xBB]);
        assert_eq!(r.u8(), Some(0x01));
        assert_eq!(r.u16(), Some(0x0203));
        assert_eq!(r.u32(), Some(0x0405_0607));
        assert_eq!(r.len8(), Some(&[0xAA, 0xBB][..]));
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn a_read_past_the_end_is_none_and_moves_nothing() {
        let mut r = Reader::new(&[0x01, 0x02, 0x03]);
        assert_eq!(r.u32(), None);
        assert_eq!(r.bytes(4), None);
        assert_eq!(r.skip(4), None);
        assert_eq!(r.remaining(), 3);
        assert_eq!(r.skip(1), Some(()));
        assert_eq!(r.u16(), Some(0x0203));
        assert_eq!(r.u8(), None);
        assert_eq!(r.u16(), None);
    }

    #[test]
    fn a_length_prefix_longer_than_the_data_is_none() {
        let mut r = Reader::new(&[0x05, 0xAA, 0xBB]);
        assert_eq!(r.len8(), None);
    }
}
