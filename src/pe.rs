// Reading a PE far enough to find the debug record and the link time.
//
// PE is the format with the worst default. The linker writes the absolute
// path of the debug file into a record inside the binary, and it does that
// whether or not you ship the debug file, whether or not you asked for one.
// That path holds a Windows account name, so a great many programs handed
// out under a pseudonym carry their author's real login in aisle six.

use crate::binary::{Endian, Format, Opened, Section, cstr_at, fixed_name, u16_at, u32_at};
use crate::error::{Result, bail};
use crate::finding::{Finding, Kind};
use crate::signature;

/// PE is little endian on every machine anybody still builds for.
const E: Endian = Endian::Little;

/// The debug directory is the seventh entry in the table of data
/// directories, counting from zero.
const DEBUG_DIRECTORY: usize = 6;

/// And the certificate table is the fifth. It is the one directory whose
/// entry is a file offset rather than an address, because it is not loaded
/// into memory: the signature is not part of the running program.
const CERTIFICATE_TABLE: usize = 4;

/// The only kind of certificate entry anybody writes.
const PKCS_SIGNED: u16 = 0x0002;

/// The debug record that carries a path. The other types point at split
/// symbol files or vendor blobs and say nothing about the builder.
const CODEVIEW: u32 = 2;

/// Where a section sits once loaded against where it sits on disk. The
/// headers give addresses and the file has offsets, so anything followed
/// from a header has to be translated first. This is kept apart from
/// `Section` because only PE needs it, and the shared type should not grow
/// a field for one format's benefit.
struct Span {
    address: usize,
    size: usize,
    offset: usize,
}

pub fn open(file: &[u8]) -> Result<Opened> {
    let pe_at = match u32_at(file, 0x3c, E) {
        Some(at) => at as usize,
        None => bail!("the file starts with MZ but is too short to hold a PE header"),
    };
    if file.get(pe_at..pe_at + 4) != Some(b"PE\0\0") {
        bail!("the file starts with MZ but there is no PE header where it points");
    }

    let coff = pe_at + 4;
    let section_count = u16_at(file, coff + 2, E).unwrap_or(0) as usize;
    let optional_size = u16_at(file, coff + 16, E).unwrap_or(0) as usize;
    let optional = coff + 20;

    // The string table sits after the symbols, and long section names are
    // offsets into it. Without it every debug section in a mingw build is
    // reported as `/70` and the reader is left guessing where a leak came
    // from.
    let symbols = u32_at(file, coff + 8, E).unwrap_or(0) as usize;
    let symbol_count = u32_at(file, coff + 12, E).unwrap_or(0) as usize;
    let strings = if symbols == 0 {
        0
    } else {
        symbols + symbol_count * 18
    };

    let (sections, spans) = read_sections(file, optional + optional_size, section_count, strings);

    let mut findings = Vec::new();
    match link_time(file, coff) {
        Some(finding) => findings.push(finding),
        None => findings.push(Finding::unread(
            Kind::BuildTime,
            "COFF header",
            "the timestamp field could not be read",
        )),
    }
    findings.extend(debug_records(file, optional, &spans));
    findings.extend(signing(file, optional));

    Ok(Opened {
        format: Format::Pe,
        sections,
        findings,
    })
}

fn read_sections(
    file: &[u8],
    table_at: usize,
    count: usize,
    strings: usize,
) -> (Vec<Section>, Vec<Span>) {
    let mut sections = Vec::with_capacity(count);
    let mut spans = Vec::with_capacity(count);
    for index in 0..count {
        let at = table_at + index * 40;
        let short = match file.get(at..at + 8) {
            Some(field) => fixed_name(field),
            None => break,
        };
        let name = long_name(file, &short, strings).unwrap_or(short);
        let address = u32_at(file, at + 12, E).unwrap_or(0) as usize;
        let size = u32_at(file, at + 16, E).unwrap_or(0) as usize;
        let offset = u32_at(file, at + 20, E).unwrap_or(0) as usize;
        sections.push(Section { name, offset, size });
        spans.push(Span {
            address,
            size,
            offset,
        });
    }
    (sections, spans)
}

/// A section name too long for the eight byte field is written as a slash
/// and a number, which is an offset into the string table. The sections
/// that need this are the debug ones, and those are exactly the sections a
/// report most needs to be able to name.
fn long_name(file: &[u8], short: &str, strings: usize) -> Option<String> {
    if strings == 0 {
        return None;
    }
    let offset: usize = short.strip_prefix('/')?.parse().ok()?;
    cstr_at(file, strings + offset, 256).filter(|name| !name.is_empty())
}

fn link_time(file: &[u8], coff: usize) -> Option<Finding> {
    let stamp = u32_at(file, coff + 4, E)?;
    if stamp == 0 {
        return None;
    }
    // Reproducible builds put a hash of the inputs in this field instead of
    // a time. A value that lands outside the years anybody could have built
    // a PE is the tell, and calling that a build time would be a lie.
    if !(315_532_800..=4_102_444_800).contains(&stamp) {
        return Some(Finding::inferred(
            Kind::BuildTime,
            "COFF header",
            format!(
                "{stamp}, which is not a plausible date and is most likely a \
                 reproducible build hash rather than a clock reading"
            ),
        ));
    }
    Some(
        Finding::measured(Kind::BuildTime, "COFF header", utc(stamp)).fix(
            "set SOURCE_DATE_EPOCH, or link with /Brepro, to put a hash here \
             instead of the hour you were working",
        ),
    )
}

fn debug_records(file: &[u8], optional: usize, spans: &[Span]) -> Vec<Finding> {
    let directories = match u16_at(file, optional, E) {
        Some(0x10b) => optional + 96,
        Some(0x20b) => optional + 112,
        _ => {
            return vec![Finding::unread(
                Kind::PdbPath,
                "optional header",
                "the header does not say whether this is a 32 or 64 bit image, \
                 so the debug record could not be located",
            )];
        }
    };

    let entry = directories + DEBUG_DIRECTORY * 8;
    let size = u32_at(file, entry + 4, E).unwrap_or(0) as usize;
    if size == 0 {
        return Vec::new();
    }
    let rva = u32_at(file, entry, E).unwrap_or(0) as usize;
    let Some(table) = to_offset(rva, spans) else {
        return vec![Finding::unread(
            Kind::PdbPath,
            "debug directory",
            "the debug directory points outside every section, so it could \
             not be followed",
        )];
    };

    let mut findings = Vec::new();
    for index in 0..size / 28 {
        let at = table + index * 28;
        if u32_at(file, at + 12, E) != Some(CODEVIEW) {
            continue;
        }
        let data = u32_at(file, at + 24, E).unwrap_or(0) as usize;
        if let Some(path) = codeview_path(file, data) {
            // A record holding a bare file name is one where somebody
            // already dealt with this. It is still worth printing, because
            // it ties the binary to a particular build, but there is no
            // account in it and nothing left to fix.
            let bare = !path.contains('\\') && !path.contains('/');
            let finding = Finding::measured(Kind::PdbPath, "CodeView debug record", path);
            findings.push(if bare {
                finding.anonymous()
            } else {
                finding.fix(
                    "link with /PDBALTPATH:%_PDB% to write just the file name. \
                     In Rust that is RUSTFLAGS=\"-Clink-arg=/PDBALTPATH:%_PDB%\"",
                )
            });
        }
    }
    findings
}

/// The path sits at the end of a CodeView record, after a signature and a
/// build identity whose length depends on which of the two layouts this is.
fn codeview_path(file: &[u8], at: usize) -> Option<String> {
    match file.get(at..at + 4)? {
        b"RSDS" => cstr_at(file, at + 24, 4096),
        b"NB10" => cstr_at(file, at + 16, 4096),
        _ => None,
    }
}

fn to_offset(rva: usize, spans: &[Span]) -> Option<usize> {
    for span in spans {
        if span.size > 0 && rva >= span.address && rva < span.address + span.size {
            return Some(span.offset + (rva - span.address));
        }
    }
    None
}

/// Seconds since 1970 written the way a person reads a date. Doing this by
/// hand rather than pulling in a calendar crate keeps the promise that the
/// program builds from nothing but the standard library.
pub(crate) fn utc(stamp: u32) -> String {
    let (days, rest) = (stamp as i64 / 86_400, stamp as i64 % 86_400);
    let (hour, minute, second) = (rest / 3600, (rest % 3600) / 60, rest % 60);

    // Shift the epoch to the first of March so the leap day falls at the end
    // of the year and the month lengths settle into a repeating run.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

/// signing reads the certificate table, which is where a signed PE keeps
/// the block that names whoever signed it.
///
/// The table is the one data directory whose address is a plain file
/// offset. Everything else in the optional header is an address in the
/// image as loaded, and translating one of those needs the sections;
/// this one needs nothing, because the signature is never loaded.
fn signing(file: &[u8], optional: usize) -> Vec<Finding> {
    let directories = match u16_at(file, optional, E) {
        Some(0x10b) => optional + 96,
        Some(0x20b) => optional + 112,
        _ => return Vec::new(), // already said, by the debug reader
    };
    let entry = directories + CERTIFICATE_TABLE * 8;
    let at = u32_at(file, entry, E).unwrap_or(0) as usize;
    let size = u32_at(file, entry + 4, E).unwrap_or(0) as usize;
    if at == 0 || size == 0 {
        return Vec::new(); // not signed, which is not a finding
    }
    let Some(table) = file.get(at..at.saturating_add(size)) else {
        return vec![Finding::unread(
            Kind::SignedBy,
            "certificate table",
            "the table is said to be outside the file",
        )];
    };

    // The table is a run of entries, each with its own length. In practice
    // there is one, and reading the run rather than assuming that costs
    // four lines.
    let mut walked = 0usize;
    let mut findings = Vec::new();
    while walked + 8 <= table.len() && findings.is_empty() {
        let length = u32_at(table, walked, E).unwrap_or(0) as usize;
        let kind = u16_at(table, walked + 6, E).unwrap_or(0);
        if length < 8 || walked + length > table.len() {
            break;
        }
        if kind == PKCS_SIGNED {
            findings = describe(&table[walked + 8..walked + length], "certificate table");
        }
        // Entries are padded to a multiple of eight.
        walked += length.next_multiple_of(8).max(8);
    }
    if findings.is_empty() {
        findings.push(Finding::unread(
            Kind::SignedBy,
            "certificate table",
            "there is a signature here and it is not in a shape this reads",
        ));
    }
    findings
}

pub(crate) fn describe(block: &[u8], site: &str) -> Vec<Finding> {
    let signed = signature::read(block);
    let mut findings = Vec::new();

    if let Some(why) = &signed.trouble {
        findings.push(Finding::unread(Kind::SignedBy, site, why));
        return findings;
    }

    let who = signed.who();
    if !who.is_empty() {
        let issued = signed.issued_by();
        let mut finding = Finding::measured(Kind::SignedBy, site, &who);
        if !signed.personal() {
            // A company name is not a person's name, and failing somebody's
            // build over their employer's certificate would be crying wolf.
            finding = finding.anonymous();
        }
        if !issued.is_empty() {
            finding = finding.fix(format!(
                "issued by {issued}. Nothing to do about it if the file has to be \
                 signed, and worth knowing that this name travels in every copy"
            ));
        }
        findings.push(finding);
    }

    if !signed.serial.is_empty() {
        findings.push(Finding::measured(
            Kind::SignedWith,
            site,
            format!("serial {}", signed.serial),
        ));
    }

    match (&signed.signed_at, signed.timestamped) {
        (Some(when), _) => findings.push(
            Finding::measured(Kind::SignedAt, "countersignature", when).fix(
                "there is no flag for this one. A timestamp is a reading of \
                 somebody else's clock at the moment you signed, so setting \
                 SOURCE_DATE_EPOCH hides the link time and leaves this",
            ),
        ),
        (None, true) => findings.push(Finding::unread(
            Kind::SignedAt,
            "countersignature",
            "this is timestamped and the time is in a shape this does not read",
        )),
        (None, false) => {}
    }
    findings
}
