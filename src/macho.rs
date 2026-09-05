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

use crate::binary::{Endian, Format, Opened, Section, cstr_at, fixed_name, u32_at, u64_at};
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
            // The command holds only where the signature is; the signature
            // itself sits at the end of the file, past everything loaded.
            LC_CODE_SIGNATURE => {
                let where_at = u32_at(file, at + 8, endian).unwrap_or(0) as usize;
                let size = u32_at(file, at + 12, endian).unwrap_or(0) as usize;
                if where_at != 0 && size != 0 {
                    findings.extend(signing(file, where_at, size));
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

/// The load command that points at the signature.
const LC_CODE_SIGNATURE: u32 = 0x1d;

/// A code signature is a superblob: a count, then an index of what is in
/// it, then the pieces. Everything in it is big endian whatever the
/// architecture, because it came from a different part of Apple.
const SUPERBLOB: u32 = 0xfade_0cc0;
const CODE_DIRECTORY: u32 = 0xfade_0c02;

/// The two pieces worth reading: the directory, which carries the identifier
/// and the team, and the signature itself, which is a PKCS#7 like the one a
/// PE carries.
const SLOT_DIRECTORY: u32 = 0;
const SLOT_SIGNATURE: u32 = 0x1_0000;

/// signing reads what a Mach-O's code signature says about who made it.
fn signing(file: &[u8], at: usize, size: usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(blob) = file.get(at..at.saturating_add(size)) else {
        return vec![Finding::unread(
            Kind::TeamId,
            "LC_CODE_SIGNATURE",
            "the signature is said to be outside the file",
        )];
    };
    let big = Endian::Big;
    if u32_at(blob, 0, big) != Some(SUPERBLOB) {
        return vec![Finding::unread(
            Kind::TeamId,
            "LC_CODE_SIGNATURE",
            "there is a signature here and it does not start like one",
        )];
    }
    let count = u32_at(blob, 8, big).unwrap_or(0) as usize;
    if count > 64 {
        return vec![Finding::unread(
            Kind::TeamId,
            "LC_CODE_SIGNATURE",
            "the signature says it holds more pieces than any signature holds",
        )];
    }

    for i in 0..count {
        let entry = 12 + i * 8;
        let (Some(kind), Some(offset)) = (
            u32_at(blob, entry, big),
            u32_at(blob, entry + 4, big).map(|v| v as usize),
        ) else {
            break;
        };
        match kind {
            SLOT_DIRECTORY => findings.extend(directory(blob, offset)),
            SLOT_SIGNATURE => {
                // The same structure a signed PE carries, so the same
                // reader takes it apart.
                let Some(length) = u32_at(blob, offset + 4, big).map(|v| v as usize) else {
                    continue;
                };
                let Some(cms) = blob.get(offset + 8..offset.saturating_add(length)) else {
                    continue;
                };
                if cms.is_empty() {
                    // An ad hoc signature has the slot and nothing in it,
                    // which says the binary was signed on the machine that
                    // built it rather than by an account.
                    findings.push(
                        Finding::measured(
                            Kind::SignedBy,
                            "LC_CODE_SIGNATURE",
                            "signed on the machine that built it, by no account",
                        )
                        .anonymous(),
                    );
                    continue;
                }
                findings.extend(crate::pe::describe(cms, "LC_CODE_SIGNATURE"));
            }
            _ => {}
        }
    }
    findings
}

/// directory reads the identifier and the team out of the code directory.
fn directory(blob: &[u8], at: usize) -> Vec<Finding> {
    let big = Endian::Big;
    if u32_at(blob, at, big) != Some(CODE_DIRECTORY) {
        return Vec::new();
    }
    let version = u32_at(blob, at + 8, big).unwrap_or(0);
    let mut findings = Vec::new();

    // The identifier is the bundle name for something built by Xcode and
    // very often the full path for something built by hand, which is the
    // same leak the debug record is on Windows.
    if let Some(id) = text_at(blob, at, at + 20, big, 512) {
        if id.contains('/') {
            findings.push(Finding::measured(
                Kind::HomePath,
                "code signing identifier",
                id,
            ));
        } else {
            findings.push(
                Finding::measured(Kind::ModulePath, "code signing identifier", id).anonymous(),
            );
        }
    }

    // The team came in with version 0x20200 and the field is not there at
    // all in anything older, so the version has to be checked rather than
    // the bytes read hopefully.
    if version >= 0x2_0200
        && let Some(team) = text_at(blob, at, at + 48, big, 128)
    {
        {
            findings.push(Finding::measured(Kind::TeamId, "code directory", team).fix(
                "nothing, if the binary has to be signed for anybody else \
                 to run it. Worth knowing that this is registered to a name",
            ));
        }
    }
    findings
}

/// text_at reads a string the code directory points at. Every one of those
/// is an offset counted from the start of the directory rather than from
/// the start of the signature, and a zero means the field is not there.
fn text_at(blob: &[u8], base: usize, field: usize, e: Endian, limit: usize) -> Option<String> {
    let offset = u32_at(blob, field, e)? as usize;
    if offset == 0 {
        return None;
    }
    cstr_at(blob, base.checked_add(offset)?, limit).filter(|s| !s.is_empty())
}
