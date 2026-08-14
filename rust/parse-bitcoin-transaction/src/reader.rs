use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{self, Cursor, Read};

#[derive(Debug)]
pub struct Reader<'a> {
    pub cursor: Cursor<&'a [u8]>,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            cursor: Cursor::new(data),
        }
    }
    pub fn read_u8(&mut self) -> io::Result<u8> {
        self.cursor.read_u8()
    }
    pub fn read_compact_integer(&mut self) -> io::Result<u64> {
        Ok(42)
    }
}
