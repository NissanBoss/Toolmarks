// Opening an executable far enough to look inside it.
//
// Three container formats hold everything worth reading here: ELF on Linux
// and the BSDs, PE on Windows, Mach-O on macOS. None of them is understood
// fully. What each one has to give up is the list of sections and where in
// the file their bytes sit, plus the handful of header fields that name a
// person on their own.
//
// Every read below is bounds checked and hands back None instead of
// panicking. These files were written by somebody else's compiler and some
// of them will arrive truncated, padded or deliberately wrong; a privacy
// tool that dies on the first odd input is a tool nobody runs twice.

use crate::error::{Result, bail};
use crate::finding::Finding;
use crate::{elf, macho, pe};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Elf,
    Pe,
    MachO,
}

impl Format {
    pub fn name(self) -> &'static str {
        match self {
            Format::Elf => "ELF",
            Format::Pe => "PE",
            Format::MachO => "Mach-O",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

/// A named run of bytes in the file. `offset` is where they start on disk,
/// not where they will sit in memory once loaded, because everything this
/// program does happens without running anything.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub offset: usize,
    pub size: usize,
}

impl Section {
    pub fn bytes<'a>(&self, file: &'a [u8]) -> &'a [u8] {
        let end = self.offset.saturating_add(self.size).min(file.len());
        let start = self.offset.min(end);
        &file[start..end]
    }
}

#[derive(Debug)]
pub struct Opened {
    pub format: Format,
    pub sections: Vec<Section>,
    /// What the headers gave up on their own, before anybody went looking
    /// through the section bytes.
    pub findings: Vec<Finding>,
}

pub fn open(file: &[u8]) -> Result<Opened> {
    match detect(file) {
        Some(Format::Elf) => elf::open(file),
        Some(Format::Pe) => pe::open(file),
        Some(Format::MachO) => macho::open(file),
        None => bail!(
            "not an executable this understands: expected ELF, PE or Mach-O, \
             found {}",
            describe_start(file)
        ),
    }
}

fn detect(file: &[u8]) -> Option<Format> {
    if file.starts_with(b"\x7fELF") {
        return Some(Format::Elf);
    }
    if file.starts_with(b"MZ") {
        return Some(Format::Pe);
    }
    match file.get(..4)? {
        // Thin Mach-O, either width, either byte order.
        [0xfe, 0xed, 0xfa, 0xce] | [0xce, 0xfa, 0xed, 0xfe] => Some(Format::MachO),
        [0xfe, 0xed, 0xfa, 0xcf] | [0xcf, 0xfa, 0xed, 0xfe] => Some(Format::MachO),
        // A fat archive of several of them, which Apple still ships.
        [0xca, 0xfe, 0xba, 0xbe] | [0xbe, 0xba, 0xfe, 0xca] => Some(Format::MachO),
        _ => None,
    }
}

/// Names what the file looks like instead, so the error tells somebody they
/// pointed at a shell script or a zip rather than just refusing.
fn describe_start(file: &[u8]) -> String {
    if file.is_empty() {
        return "an empty file".into();
    }
    if file.starts_with(b"#!") {
        return "a script".into();
    }
    if file.starts_with(b"PK\x03\x04") {
        return "a zip archive".into();
    }
    if file.starts_with(b"!<arch>") {
        return "a static library".into();
    }
    if file.starts_with(b"\x1f\x8b") {
        return "a gzip archive".into();
    }
    let head: Vec<String> = file.iter().take(4).map(|b| format!("{b:02x}")).collect();
    format!("a file starting {}", head.join(" "))
}

pub fn u16_at(file: &[u8], at: usize, e: Endian) -> Option<u16> {
    let b: [u8; 2] = file.get(at..at + 2)?.try_into().ok()?;
    Some(match e {
        Endian::Little => u16::from_le_bytes(b),
        Endian::Big => u16::from_be_bytes(b),
    })
}

pub fn u32_at(file: &[u8], at: usize, e: Endian) -> Option<u32> {
    let b: [u8; 4] = file.get(at..at + 4)?.try_into().ok()?;
    Some(match e {
        Endian::Little => u32::from_le_bytes(b),
        Endian::Big => u32::from_be_bytes(b),
    })
}

pub fn u64_at(file: &[u8], at: usize, e: Endian) -> Option<u64> {
    let b: [u8; 8] = file.get(at..at + 8)?.try_into().ok()?;
    Some(match e {
        Endian::Little => u64::from_le_bytes(b),
        Endian::Big => u64::from_be_bytes(b),
    })
}

/// A NUL terminated string, which is how all three formats write names.
/// `limit` stops a missing terminator from walking the rest of the file.
pub fn cstr_at(file: &[u8], at: usize, limit: usize) -> Option<String> {
    let rest = file.get(at..)?;
    let end = rest.iter().take(limit).position(|&b| b == 0)?;
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}

/// A fixed width name field, padded with NULs, which is how PE and Mach-O
/// write section names. Unlike `cstr_at` a full field with no terminator is
/// legal and means the name uses every byte.
pub fn fixed_name(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).trim().to_string()
}
