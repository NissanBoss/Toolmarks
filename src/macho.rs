// Reading a Mach-O far enough to list its sections and its SDK.
//
// Mach-O has no section table at a fixed place. It has a run of load
// commands, each saying how long it is, and the sections are nested inside
// the segment commands. Walking that run is the whole job: every command
// whose kind is not understood is stepped over by its own length, which is
// what lets a reader from years ago still open a file from today.
//
// Apple also ships several architectures glued into one file. Only the first
// is read here, and the report says so rather than quietly covering half of
// what was handed over.

use crate::binary::{Endian, Format, Opened, Section, fixed_name, u32_at, u64_at};
use crate::error::{Result, bail};
use crate::finding::{Finding, Kind};

const LC_SEGMENT: u32 = 0x01;
const LC_SEGMENT_64: u32 = 0x19;
const LC_BUILD_VERSION: u32 = 0x32;

pub fn open(file: &[u8]) -> Result<Opened> {
    let mut findings = Vec::new();
    let start = match fat_slice(file) {
        Some((at, count)) => {
            findings.push(Finding::unread(
                Kind::HomePath,
                "fat header",
                format!(
                    "the file glues {count} architectures together and only the \
                     first was read; the others may carry paths of their own"
                ),
            ));
            at
        }
        None => 0,
    };

    let (wide, endian) = match file.get(start..start + 4) {
        Some([0xfe, 0xed, 0xfa, 0xcf]) => (true, Endian::Big),
        Some([0xcf, 0xfa, 0xed, 0xfe]) => (true, Endian::Little),
        Some([0xfe, 0xed, 0xfa, 0xce]) => (false, Endian::Big),
        Some([0xce, 0xfa, 0xed, 0xfe]) => (false, Endian::Little),
        _ => bail!("no Mach-O header where the file said one would be"),
    };

    let command_count = u32_at(file, start + 16, endian).unwrap_or(0) as usize;
    let mut at = start + if wide { 32 } else { 28 };
    let mut sections = Vec::new();

    for _ in 0..command_count {
        let Some(kind) = u32_at(file, at, endian) else {
            break;
        };
        let Some(length) = u32_at(file, at + 4, endian) else {
            break;
        };
        // A command claiming no length would spin here forever, and a file
        // can claim that.
        if length < 8 {
            findings.push(Finding::unread(
                Kind::HomePath,
                "load commands",
                "a load command claims an impossible length, so the rest of \
                 them were not read",
            ));
            break;
        }

        match kind {
            LC_SEGMENT_64 => segment(file, at, endian, true, &mut sections),
            LC_SEGMENT => segment(file, at, endian, false, &mut sections),
            LC_BUILD_VERSION => {
                if let Some(sdk) = u32_at(file, at + 16, endian) {
                    findings.push(Finding::measured(
                        Kind::CompilerVersion,
                        "LC_BUILD_VERSION",
                        format!("built against SDK {}", version(sdk)),
                    ));
                }
            }
            _ => {}
        }
        at += length as usize;
    }

    Ok(Opened {
        format: Format::MachO,
        sections,
        findings,
    })
}

/// The offset of the first architecture in a fat file, and how many there
/// are. A fat header is always big endian, whatever the slices inside are.
fn fat_slice(file: &[u8]) -> Option<(usize, u32)> {
    match file.get(..4)? {
        [0xca, 0xfe, 0xba, 0xbe] => {}
        _ => return None,
    }
    let count = u32_at(file, 4, Endian::Big)?;
    if count == 0 {
        return None;
    }
    let offset = u32_at(file, 16, Endian::Big)? as usize;
    Some((offset, count))
}

fn segment(file: &[u8], at: usize, e: Endian, wide: bool, sections: &mut Vec<Section>) {
    let (count_at, first, stride) = if wide { (64, 72, 80) } else { (48, 56, 68) };
    let Some(count) = u32_at(file, at + count_at, e) else {
        return;
    };
    for index in 0..count as usize {
        let row = at + first + index * stride;
        let Some(section_name) = file.get(row..row + 16).map(fixed_name) else {
            return;
        };
        let Some(segment_name) = file.get(row + 16..row + 32).map(fixed_name) else {
            return;
        };
        let (size, offset) = if wide {
            match (u64_at(file, row + 40, e), u32_at(file, row + 48, e)) {
                (Some(size), Some(offset)) => (size as usize, offset as usize),
                _ => return,
            }
        } else {
            match (u32_at(file, row + 36, e), u32_at(file, row + 40, e)) {
                (Some(size), Some(offset)) => (size as usize, offset as usize),
                _ => return,
            }
        };
        sections.push(Section {
            name: format!("{segment_name},{section_name}"),
            offset,
            size,
        });
    }
}

/// Apple packs a version into one word as major, minor, patch.
fn version(packed: u32) -> String {
    format!(
        "{}.{}.{}",
        packed >> 16,
        (packed >> 8) & 0xff,
        packed & 0xff
    )
}
