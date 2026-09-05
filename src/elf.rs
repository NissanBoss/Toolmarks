// Reading an ELF far enough to list its sections and read the compiler note.
//
// ELF keeps two tables of the same bytes: the program headers, which say how
// to load the file, and the section headers, which say what the pieces were
// called. Only the second is interesting here, and it is also the one that
// `strip` throws away, so its absence is a finding of its own rather than a
// reason to give up.

use crate::binary::{Endian, Format, Opened, Section, cstr_at, u16_at, u32_at, u64_at};
use crate::error::{Result, bail};
use crate::finding::{Finding, Kind};

/// A section that occupies no bytes on disk. `.bss` is the usual one: it has
/// a size and an address, and reading at its offset gives whatever happens
/// to be there.
const SHT_NOBITS: u32 = 8;

pub fn open(file: &[u8]) -> Result<Opened> {
    let wide = match file.get(4) {
        Some(1) => false,
        Some(2) => true,
        _ => bail!("ELF header does not say whether the file is 32 or 64 bit"),
    };
    let endian = match file.get(5) {
        Some(1) => Endian::Little,
        Some(2) => Endian::Big,
        _ => bail!("ELF header does not say which byte order it uses"),
    };

    let mut findings = Vec::new();
    let sections = match read_sections(file, wide, endian) {
        Some(s) if !s.is_empty() => s,
        _ => {
            findings.push(Finding::unread(
                Kind::HomePath,
                "section table",
                "the section headers are gone, which is what strip removes, \
                     so the search below ran over the raw file instead of over \
                     named sections",
            ));
            vec![Section {
                name: "whole file".into(),
                offset: 0,
                size: file.len(),
            }]
        }
    };

    for section in &sections {
        if section.name == ".comment" {
            for note in notes(section.bytes(file)) {
                findings.push(
                    Finding::measured(Kind::CompilerVersion, ".comment", note).fix(
                        "pass -Wl,--build-id=none and strip the section with \
                         objcopy --remove-section=.comment if you do not want it",
                    ),
                );
            }
        }
    }
    findings.extend(build_id(file, &sections, endian));

    Ok(Opened {
        format: Format::Elf,
        sections,
        findings,
    })
}

fn read_sections(file: &[u8], wide: bool, e: Endian) -> Option<Vec<Section>> {
    let (table_at, entry_size, count, names_index) = if wide {
        (
            u64_at(file, 0x28, e)? as usize,
            u16_at(file, 0x3a, e)? as usize,
            u16_at(file, 0x3c, e)? as usize,
            u16_at(file, 0x3e, e)? as usize,
        )
    } else {
        (
            u32_at(file, 0x20, e)? as usize,
            u16_at(file, 0x2e, e)? as usize,
            u16_at(file, 0x30, e)? as usize,
            u16_at(file, 0x32, e)? as usize,
        )
    };
    if table_at == 0 || entry_size == 0 || count == 0 {
        return None;
    }

    // The names of every section live inside one of the sections, so it has
    // to be located before any of them can be given a name.
    let names_at = entry(file, table_at, entry_size, names_index, wide, e)?.1;

    let mut sections = Vec::with_capacity(count);
    for index in 0..count {
        let (name_offset, offset, size, kind) =
            match entry(file, table_at, entry_size, index, wide, e) {
                Some(fields) => (fields.0, fields.1, fields.2, fields.3),
                None => continue,
            };
        if kind == SHT_NOBITS {
            continue;
        }
        let name = cstr_at(file, names_at + name_offset, 256)
            .unwrap_or_else(|| format!("section {index}"));
        sections.push(Section { name, offset, size });
    }
    Some(sections)
}

/// One row of the section table, as (name offset, file offset, size, type).
fn entry(
    file: &[u8],
    table_at: usize,
    entry_size: usize,
    index: usize,
    wide: bool,
    e: Endian,
) -> Option<(usize, usize, usize, u32)> {
    let at = table_at.checked_add(entry_size.checked_mul(index)?)?;
    let name_offset = u32_at(file, at, e)? as usize;
    let kind = u32_at(file, at + 4, e)?;
    let (offset, size) = if wide {
        (
            u64_at(file, at + 24, e)? as usize,
            u64_at(file, at + 32, e)? as usize,
        )
    } else {
        (
            u32_at(file, at + 16, e)? as usize,
            u32_at(file, at + 20, e)? as usize,
        )
    };
    Some((name_offset, offset, size, kind))
}

/// `.comment` holds one or more NUL separated strings, one per tool that
/// touched the file. A binary linked from several objects can name the same
/// compiler twice, so repeats are dropped.
fn notes(bytes: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for piece in bytes.split(|&b| b == 0) {
        if piece.is_empty() {
            continue;
        }
        let text = String::from_utf8_lossy(piece).trim().to_string();
        if !text.is_empty() && !out.contains(&text) {
            out.push(text);
        }
    }
    out
}

/// The note type a linker uses for the build id.
const NT_GNU_BUILD_ID: u32 = 3;

/// build_id reads the hash a linker writes so a binary and its separate
/// debug file can be matched up.
///
/// It is not a name and it does not describe the machine, so it sits with
/// the compiler version rather than with the leaks. What it does is match
/// two copies of one build: a file published under a handle and the same
/// file found on a machine that belongs to somebody.
pub(crate) fn build_id(file: &[u8], sections: &[Section], endian: Endian) -> Option<Finding> {
    let note = sections.iter().find(|s| s.name == ".note.gnu.build-id")?;
    let body = note.bytes(file);

    // A note is three lengths, then a name padded to four bytes, then the
    // description padded the same way.
    let name_size = u32_at(body, 0, endian)? as usize;
    let desc_size = u32_at(body, 4, endian)? as usize;
    let kind = u32_at(body, 8, endian)?;
    if kind != NT_GNU_BUILD_ID || desc_size == 0 || desc_size > 64 {
        return None;
    }
    let at = 12 + name_size.next_multiple_of(4);
    let hash = body.get(at..at.checked_add(desc_size)?)?;

    let text: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    Some(
        Finding::measured(Kind::BuildId, ".note.gnu.build-id", text).fix(
            "link with -Wl,--build-id=none if the binary is published without \
             its debug information, since then there is nothing for it to match",
        ),
    )
}
