//! A small, bounds-checked reader of a PE image as the Windows loader maps
//! it: every RVA is an offset into one byte slice, `[base, base +
//! SizeOfImage)`, and every read is checked against that slice with checked
//! arithmetic. A header, a table or a name that does not fit is an error or
//! `None`, never a read past the image (fourth review, finding C).
//!
//! Only what the hooks need: the import directory of a 32-bit module (its
//! descriptors, the names or ordinals of its lookup table and the slots of
//! its address table) and the export table's name for an ordinal. Plain Rust,
//! no Windows: the hooks build the slice over a loaded module, the tests over
//! a buffer.

use std::fmt;

/// `MZ`.
const DOS_MAGIC: u16 = 0x5A4D;
/// `PE\0\0`.
const NT_SIGNATURE: u32 = 0x0000_4550;
const PE32_MAGIC: u16 = 0x010B;
const PE32_PLUS_MAGIC: u16 = 0x020B;
/// Where `e_lfanew` sits in the DOS header.
const E_LFANEW_AT: usize = 0x3C;
/// The optional header starts after the signature and the file header.
const OPTIONAL_AT: usize = 0x18;
/// `SizeOfImage` within the optional header (the same for PE32 and PE32+).
const SIZE_OF_IMAGE_AT: usize = 0x38;
/// `NumberOfRvaAndSizes` and the data directories, PE32 and PE32+.
const DIRS_COUNT_AT: [usize; 2] = [0x5C, 0x6C];
const DIRS_AT: [usize; 2] = [0x60, 0x70];
const DIR_EXPORT: usize = 0;
const DIR_IMPORT: usize = 1;
/// One import descriptor.
const DESCRIPTOR_LEN: usize = 20;

/// No more than this many import descriptors are read: a real module has a
/// few dozen, and a table without its terminator must still end.
pub const MAX_DESCRIPTORS: usize = 1024;
/// No more than this many thunks per imported DLL.
pub const MAX_THUNKS: usize = 8192;
/// No more than this many bytes of a DLL or function name.
pub const MAX_NAME: usize = 256;
/// No more than this many exported names are searched.
pub const MAX_EXPORT_NAMES: usize = 65_536;
/// `e_lfanew` must leave the headers within the first page or so.
const MAX_E_LFANEW: usize = 0x1000;

/// Why an image cannot be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeError {
    /// No `MZ` at the start.
    NoDosHeader,
    /// `e_lfanew` points outside the image, or past the first page.
    BadNtOffset(usize),
    /// No `PE\0\0` where `e_lfanew` points.
    NoNtSignature,
    /// An optional header magic that is neither PE32 nor PE32+.
    UnknownMagic(u16),
    /// `SizeOfImage` larger than the bytes there are, or too small.
    BadSizeOfImage(usize),
    /// A 64-bit image where a 32-bit one is needed (the import thunks).
    NotPe32,
    /// The module has no import directory.
    NoImports,
    /// An import directory, descriptor, table or name outside the image.
    OutOfRange(&'static str),
    /// A table that does not end within the limits above.
    TooLong(&'static str),
}

impl fmt::Display for PeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeError::NoDosHeader => write!(f, "no MZ signature"),
            PeError::BadNtOffset(o) => write!(f, "e_lfanew {o:#x} is outside the headers"),
            PeError::NoNtSignature => write!(f, "no PE signature"),
            PeError::UnknownMagic(m) => write!(f, "optional header magic {m:#06x}"),
            PeError::BadSizeOfImage(s) => write!(f, "SizeOfImage {s:#x} does not fit"),
            PeError::NotPe32 => write!(f, "not PE32"),
            PeError::NoImports => write!(f, "no import directory"),
            PeError::OutOfRange(what) => write!(f, "{what} is outside the image"),
            PeError::TooLong(what) => write!(f, "{what} does not end"),
        }
    }
}

/// A function in an import lookup table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Import {
    Name(String),
    Ordinal(u16),
}

/// One slot of a module's import address table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thunk {
    /// The RVA of the slot in the import address table.
    pub slot_rva: usize,
    /// What the lookup table says the slot is for.
    pub import: Import,
    /// The lookup table's entry, which the slot also holds until the loader
    /// binds it.
    pub lookup: u32,
    /// What the slot holds now.
    pub bound: u32,
}

impl Thunk {
    /// Whether the loader has filled the slot with an address.
    pub fn is_bound(&self) -> bool {
        self.bound != self.lookup
    }
}

/// One imported DLL and its slots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedDll {
    pub name: String,
    /// Empty when the descriptor has no lookup table (a bound-only import):
    /// its slots cannot be told apart.
    pub thunks: Vec<Thunk>,
    /// Whether the descriptor had a lookup table.
    pub has_lookup: bool,
}

/// A mapped PE image.
#[derive(Clone, Copy)]
pub struct Image<'a> {
    bytes: &'a [u8],
    /// Where the optional header starts.
    optional: usize,
    pe32plus: bool,
}

/// `a + b`, or `None` on overflow.
fn add(a: usize, b: usize) -> Option<usize> {
    a.checked_add(b)
}

fn read_u16(b: &[u8], at: usize) -> Option<u16> {
    let end = add(at, 2)?;
    let s = b.get(at..end)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32(b: &[u8], at: usize) -> Option<u32> {
    let end = add(at, 4)?;
    let s = b.get(at..end)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

impl<'a> Image<'a> {
    /// `SizeOfImage` from the headers at the start of a mapped image, read
    /// only from `header` (its first page). The caller then makes the slice
    /// of that size and parses it.
    pub fn size_of_image(header: &[u8]) -> Result<usize, PeError> {
        let (optional, _) = Self::headers(header)?;
        let at = add(optional, SIZE_OF_IMAGE_AT).ok_or(PeError::OutOfRange("SizeOfImage"))?;
        let size = read_u32(header, at).ok_or(PeError::OutOfRange("SizeOfImage"))? as usize;
        if size < header.len().min(0x200) {
            return Err(PeError::BadSizeOfImage(size));
        }
        Ok(size)
    }

    /// The optional header's offset, and whether it is PE32+.
    fn headers(b: &[u8]) -> Result<(usize, bool), PeError> {
        if read_u16(b, 0) != Some(DOS_MAGIC) {
            return Err(PeError::NoDosHeader);
        }
        let nt = read_u32(b, E_LFANEW_AT).ok_or(PeError::NoDosHeader)? as usize;
        if !(0x40..=MAX_E_LFANEW).contains(&nt) || nt % 4 != 0 {
            return Err(PeError::BadNtOffset(nt));
        }
        if read_u32(b, nt) != Some(NT_SIGNATURE) {
            return Err(PeError::NoNtSignature);
        }
        let optional = add(nt, OPTIONAL_AT).ok_or(PeError::BadNtOffset(nt))?;
        match read_u16(b, optional) {
            Some(PE32_MAGIC) => Ok((optional, false)),
            Some(PE32_PLUS_MAGIC) => Ok((optional, true)),
            Some(m) => Err(PeError::UnknownMagic(m)),
            None => Err(PeError::OutOfRange("optional header")),
        }
    }

    /// Reads the headers of an image that is all of `bytes`. A
    /// `SizeOfImage` larger than `bytes` is an error: every RVA the image
    /// names must then lie inside what is mapped.
    pub fn parse(bytes: &'a [u8]) -> Result<Image<'a>, PeError> {
        let (optional, pe32plus) = Self::headers(bytes)?;
        let at = add(optional, SIZE_OF_IMAGE_AT).ok_or(PeError::OutOfRange("SizeOfImage"))?;
        let size = read_u32(bytes, at).ok_or(PeError::OutOfRange("SizeOfImage"))? as usize;
        if size > bytes.len() || size < at {
            return Err(PeError::BadSizeOfImage(size));
        }
        Ok(Image {
            bytes: &bytes[..size],
            optional,
            pe32plus,
        })
    }

    /// The image's bytes.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn u16_at(&self, rva: usize) -> Option<u16> {
        read_u16(self.bytes, rva)
    }

    pub fn u32_at(&self, rva: usize) -> Option<u32> {
        read_u32(self.bytes, rva)
    }

    /// The NUL-terminated string at `rva`, at most `max` bytes before the
    /// NUL; `None` when it does not end within that or within the image.
    pub fn cstr_at(&self, rva: usize, max: usize) -> Option<&'a [u8]> {
        let rest = self.bytes.get(rva..)?;
        let window = &rest[..rest.len().min(add(max, 1)?)];
        let n = window.iter().position(|&c| c == 0)?;
        Some(&rest[..n])
    }

    /// Data directory `index`: (RVA, size), when the header has that many.
    fn data_dir(&self, index: usize) -> Option<(usize, usize)> {
        let k = usize::from(self.pe32plus);
        let count = self.u32_at(add(self.optional, DIRS_COUNT_AT[k])?)? as usize;
        if index >= count.min(16) {
            return None;
        }
        let at = add(add(self.optional, DIRS_AT[k])?, index.checked_mul(8)?)?;
        let rva = self.u32_at(at)? as usize;
        let size = self.u32_at(add(at, 4)?)? as usize;
        Some((rva, size))
    }

    /// Every imported DLL with the slots of its address table. 32-bit images
    /// only (4-byte thunks), which is what both clients are.
    pub fn imports(&self) -> Result<Vec<ImportedDll>, PeError> {
        if self.pe32plus {
            return Err(PeError::NotPe32);
        }
        let (dir, _) = self
            .data_dir(DIR_IMPORT)
            .filter(|(rva, _)| *rva != 0)
            .ok_or(PeError::NoImports)?;
        let mut out = Vec::new();
        for i in 0..=MAX_DESCRIPTORS {
            if i == MAX_DESCRIPTORS {
                return Err(PeError::TooLong("import descriptor table"));
            }
            let d = i
                .checked_mul(DESCRIPTOR_LEN)
                .and_then(|o| add(dir, o))
                .ok_or(PeError::OutOfRange("import descriptor"))?;
            if self.bytes.len() < add(d, DESCRIPTOR_LEN).unwrap_or(usize::MAX) {
                return Err(PeError::OutOfRange("import descriptor"));
            }
            let lookup = self.u32_at(d).unwrap_or(0) as usize;
            let name_rva = self.u32_at(d + 12).unwrap_or(0) as usize;
            let first_thunk = self.u32_at(d + 16).unwrap_or(0) as usize;
            if name_rva == 0 && first_thunk == 0 {
                break;
            }
            let name = self
                .cstr_at(name_rva, MAX_NAME)
                .ok_or(PeError::OutOfRange("imported DLL name"))?;
            let name = String::from_utf8_lossy(name).into_owned();
            let mut thunks = Vec::new();
            if lookup != 0 {
                for k in 0..=MAX_THUNKS {
                    if k == MAX_THUNKS {
                        return Err(PeError::TooLong("import lookup table"));
                    }
                    let off = k * 4;
                    let entry = add(lookup, off)
                        .and_then(|a| self.u32_at(a))
                        .ok_or(PeError::OutOfRange("import lookup table"))?;
                    if entry == 0 {
                        break;
                    }
                    let slot_rva =
                        add(first_thunk, off).ok_or(PeError::OutOfRange("import address table"))?;
                    let bound = self
                        .u32_at(slot_rva)
                        .ok_or(PeError::OutOfRange("import address table"))?;
                    let import = if entry & 0x8000_0000 != 0 {
                        Import::Ordinal((entry & 0xFFFF) as u16)
                    } else {
                        // A hint (2 bytes), then the name.
                        let n = add(entry as usize, 2)
                            .and_then(|a| self.cstr_at(a, MAX_NAME))
                            .ok_or(PeError::OutOfRange("imported function name"))?;
                        Import::Name(String::from_utf8_lossy(n).into_owned())
                    };
                    thunks.push(Thunk {
                        slot_rva,
                        import,
                        lookup: entry,
                        bound,
                    });
                }
            }
            out.push(ImportedDll {
                name,
                thunks,
                has_lookup: lookup != 0,
            });
        }
        Ok(out)
    }

    /// The name the export table gives `ordinal`, if it has one.
    pub fn export_name(&self, ordinal: u16) -> Option<String> {
        let (dir, _) = self.data_dir(DIR_EXPORT).filter(|(rva, _)| *rva != 0)?;
        let base = self.u32_at(add(dir, 0x10)?)? as usize;
        let count = (self.u32_at(add(dir, 0x18)?)? as usize).min(MAX_EXPORT_NAMES);
        let names = self.u32_at(add(dir, 0x20)?)? as usize;
        let ords = self.u32_at(add(dir, 0x24)?)? as usize;
        let index = (ordinal as usize).checked_sub(base)?;
        for i in 0..count {
            let o = self.u16_at(add(ords, i.checked_mul(2)?)?)? as usize;
            if o == index {
                let at = self.u32_at(add(names, i.checked_mul(4)?)?)? as usize;
                let n = self.cstr_at(at, MAX_NAME)?;
                return Some(String::from_utf8_lossy(n).into_owned());
            }
        }
        None
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal PE32 image of `len` bytes with headers at 0x80, its import
    /// directory at 0x1000, one descriptor for `dll` and `entries` in its
    /// lookup table, the address table pre-filled with recognisable
    /// "bound" addresses.
    pub(crate) fn image(dll: &str, entries: &[u32], len: usize) -> Vec<u8> {
        let mut img = vec![0u8; len];
        img[0] = b'M';
        img[1] = b'Z';
        img[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        img[0x80..0x84].copy_from_slice(&NT_SIGNATURE.to_le_bytes());
        img[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes());
        let opt = 0x80 + OPTIONAL_AT;
        img[opt..opt + 2].copy_from_slice(&PE32_MAGIC.to_le_bytes());
        img[opt + SIZE_OF_IMAGE_AT..opt + SIZE_OF_IMAGE_AT + 4]
            .copy_from_slice(&(len as u32).to_le_bytes());
        img[opt + DIRS_COUNT_AT[0]..opt + DIRS_COUNT_AT[0] + 4]
            .copy_from_slice(&16u32.to_le_bytes());
        let import = 0x1000usize;
        let at = opt + DIRS_AT[0] + DIR_IMPORT * 8;
        img[at..at + 4].copy_from_slice(&(import as u32).to_le_bytes());
        img[at + 4..at + 8].copy_from_slice(&40u32.to_le_bytes());
        let (name, int, iat) = (import + 0x40, import + 0x80, import + 0x100);
        img[import..import + 4].copy_from_slice(&(int as u32).to_le_bytes());
        img[import + 12..import + 16].copy_from_slice(&(name as u32).to_le_bytes());
        img[import + 16..import + 20].copy_from_slice(&(iat as u32).to_le_bytes());
        img[name..name + dll.len()].copy_from_slice(dll.as_bytes());
        for (i, e) in entries.iter().enumerate() {
            img[int + i * 4..int + i * 4 + 4].copy_from_slice(&e.to_le_bytes());
            img[iat + i * 4..iat + i * 4 + 4]
                .copy_from_slice(&(0x7FFF_0000u32 + i as u32).to_le_bytes());
        }
        img
    }

    fn put_u32(img: &mut [u8], at: usize, v: u32) {
        img[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn a_well_formed_image_reads() {
        let img = image("WSOCK32.dll", &[0x8000_0013, 0x8000_0010], 0x2000);
        let pe = Image::parse(&img).unwrap();
        let dlls = pe.imports().unwrap();
        assert_eq!(dlls.len(), 1);
        assert_eq!(dlls[0].name, "WSOCK32.dll");
        assert_eq!(
            dlls[0].thunks.iter().map(|t| &t.import).collect::<Vec<_>>(),
            vec![&Import::Ordinal(19), &Import::Ordinal(16)]
        );
        assert_eq!(dlls[0].thunks[1].slot_rva, 0x1104);
        assert!(dlls[0].thunks[0].is_bound());
        assert_eq!(Image::size_of_image(&img[..0x1000]), Ok(0x2000));
    }

    /// Every way the headers can be cut short or point elsewhere is an error,
    /// never a read past the buffer.
    #[test]
    fn truncated_and_broken_headers_are_refused() {
        let good = image("WSOCK32.dll", &[0x8000_0013], 0x2000);
        // Cut anywhere in the headers.
        for cut in [0usize, 1, 2, 0x3C, 0x3F, 0x80, 0x83, 0x98, 0x99, 0xD0] {
            assert!(Image::parse(&good[..cut]).is_err(), "cut at {cut:#x}");
        }
        // SizeOfImage larger than the buffer.
        let short = &good[..0x1800];
        assert_eq!(
            Image::parse(short).err(),
            Some(PeError::BadSizeOfImage(0x2000))
        );
        // e_lfanew out of range, misaligned, or huge.
        for lfanew in [0u32, 0x10, 0x81, 0x2000, 0xFFFF_FFFC] {
            let mut b = good.clone();
            put_u32(&mut b, 0x3C, lfanew);
            assert!(Image::parse(&b).is_err(), "e_lfanew {lfanew:#x}");
        }
        // Wrong magic.
        let mut b = good.clone();
        b[0x80 + OPTIONAL_AT] = 0x07;
        assert!(matches!(Image::parse(&b), Err(PeError::UnknownMagic(_))));
    }

    /// RVAs past the end, at the very end, or wrapping around: an error.
    #[test]
    fn out_of_range_rvas_are_refused() {
        let base = image("WSOCK32.dll", &[0x8000_0013], 0x2000);
        let opt = 0x80 + OPTIONAL_AT;
        let dir_at = opt + DIRS_AT[0] + DIR_IMPORT * 8;
        // The import directory itself.
        for rva in [0x1FF0u32, 0x2000, 0xFFFF_FFF0, u32::MAX] {
            let mut b = base.clone();
            put_u32(&mut b, dir_at, rva);
            let pe = Image::parse(&b).unwrap();
            assert!(pe.imports().is_err(), "directory at {rva:#x}");
        }
        // The DLL name, the lookup table, the address table.
        for (field, rva) in [
            (12usize, 0x2000u32),
            (12, u32::MAX),
            (0, 0x1FFE),
            (0, u32::MAX - 2),
            (16, 0x1FFE),
            (16, u32::MAX),
        ] {
            let mut b = base.clone();
            put_u32(&mut b, 0x1000 + field, rva);
            let pe = Image::parse(&b).unwrap();
            assert!(pe.imports().is_err(), "field {field} = {rva:#x}");
        }
        // A by-name entry whose hint/name lies past the end.
        let mut b = image("WSOCK32.dll", &[0x1FFF], 0x2000);
        b[0x1FFF] = b'x';
        let pe = Image::parse(&b).unwrap();
        assert!(pe.imports().is_err());
        // A name without its terminator up to the end of the image.
        let mut b = base.clone();
        put_u32(&mut b, 0x1000 + 12, 0x1F00);
        for i in 0x1F00..0x2000 {
            b[i] = b'a';
        }
        assert!(Image::parse(&b).unwrap().imports().is_err());
    }

    /// Tables that overlap each other or the headers still read only inside
    /// the image, and a table without its terminator stops at the limit.
    #[test]
    fn overlapping_and_endless_tables_end() {
        // The lookup table and the address table are the same table: every
        // slot looks unbound, nothing is read outside.
        let mut b = image("WSOCK32.dll", &[0x8000_0013, 0x8000_0010], 0x2000);
        put_u32(&mut b, 0x1000 + 16, 0x1080);
        let dlls = Image::parse(&b).unwrap().imports().unwrap();
        assert!(dlls[0].thunks.iter().all(|t| !t.is_bound()));
        // The descriptor table points at the headers: reads as garbage
        // names, but within the image or refused.
        let mut b = image("WSOCK32.dll", &[0x8000_0013], 0x2000);
        let dir_at = 0x80 + OPTIONAL_AT + DIRS_AT[0] + DIR_IMPORT * 8;
        put_u32(&mut b, dir_at, 0x0);
        assert_eq!(
            Image::parse(&b).unwrap().imports().err(),
            Some(PeError::NoImports)
        );
        put_u32(&mut b, dir_at, 0x4);
        let _ = Image::parse(&b).unwrap().imports();
        // A lookup table of non-zero entries to the end of the image.
        let mut b = image("WSOCK32.dll", &[], 0x8000);
        for at in (0x1080..0x8000).step_by(4) {
            put_u32(&mut b, at, 0x8000_0013);
        }
        assert!(Image::parse(&b).unwrap().imports().is_err());
        // A descriptor table with no terminator.
        let mut b = image("WSOCK32.dll", &[0x8000_0013], 0x10000);
        for d in 1..2000 {
            let at = 0x1000 + d * 20;
            if at + 20 > 0x10000 {
                break;
            }
            put_u32(&mut b, at + 12, 0x1040);
            put_u32(&mut b, at + 16, 0x1100);
        }
        assert!(Image::parse(&b).unwrap().imports().is_err());
    }

    /// Fuzz-ish: random bytes over the headers and tables of a valid image,
    /// a thousand times; every parse ends with an answer and no panic.
    #[test]
    fn random_damage_never_reads_outside() {
        let good = image("WSOCK32.dll", &[0x8000_0013, 0x8000_0010, 0x1200], 0x3000);
        let mut seed = 0x1234_5678_9ABC_DEF0u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..2000 {
            let mut b = good.clone();
            for _ in 0..(next() % 8 + 1) {
                let at = (next() as usize) % 0x1200;
                b[at] = next() as u8;
            }
            let len = if next() % 4 == 0 {
                (next() as usize) % b.len()
            } else {
                b.len()
            };
            if let Ok(pe) = Image::parse(&b[..len]) {
                let _ = pe.imports();
                let _ = pe.export_name((next() % 300) as u16);
            }
        }
    }

    #[test]
    fn a_pe32_plus_image_has_no_32_bit_imports() {
        let mut b = image("WSOCK32.dll", &[0x8000_0013], 0x2000);
        b[0x80 + OPTIONAL_AT..0x80 + OPTIONAL_AT + 2]
            .copy_from_slice(&PE32_PLUS_MAGIC.to_le_bytes());
        let pe = Image::parse(&b).unwrap();
        assert_eq!(pe.imports().err(), Some(PeError::NotPe32));
    }
}
