// Enough DER to walk a signature.
//
// Everything in a code signing block is ASN.1 in its distinguished encoding:
// a tag byte, a length, and either a value or more of the same nested
// inside. That is the whole of it, and it is why this is a hundred and fifty
// lines rather than a dependency.
//
// The one rule it does not bend is that nothing here trusts a length. A
// length in a signature is a number somebody else wrote, and a reader that
// takes one at face value can be walked off the end of the file by a binary
// that was built to do it.

/// One tag, length and value, with the value still undecoded.
#[derive(Debug, Clone, Copy)]
pub struct Value<'a> {
    pub tag: u8,
    pub body: &'a [u8],
    /// Where this value ended in the slice it was read from, so a caller
    /// walking a sequence knows where the next one starts.
    pub end: usize,
}

impl<'a> Value<'a> {
    pub fn is(&self, tag: u8) -> bool {
        self.tag == tag
    }

    /// True for a tag that holds more values rather than bytes.
    pub fn nested(&self) -> bool {
        self.tag & 0x20 != 0
    }
}

pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;
pub const INTEGER: u8 = 0x02;
pub const OID: u8 = 0x06;

pub const UTC_TIME: u8 = 0x17;
pub const GENERAL_TIME: u8 = 0x18;

/// read takes the value at the front of a slice.
pub fn read(data: &[u8]) -> Option<Value<'_>> {
    at_depth(data, 0)
}

fn at_depth(data: &[u8], depth: usize) -> Option<Value<'_>> {
    if depth > 32 {
        return None;
    }
    let tag = *data.first()?;
    // A tag number of 31 means the number carries on into the bytes that
    // follow. Nothing in a signature uses one, so meeting it means this is
    // not the structure it was said to be.
    if tag & 0x1f == 0x1f {
        return None;
    }
    let first = *data.get(1)?;

    // A length byte of exactly 0x80 says the value runs until a pair of
    // zero bytes rather than for a stated number of them. That is BER
    // rather than DER, and the encoding rules for a signature say DER, and
    // Apple writes it anyway: the signature inside a Mach-O opens with
    // 30 80. A reader that only takes DER reads no Apple signature at all.
    if first == 0x80 {
        let mut at = 2;
        loop {
            match data.get(at..at + 2) {
                Some([0, 0]) => {
                    return Some(Value {
                        tag,
                        body: &data[2..at],
                        end: at + 2,
                    });
                }
                Some(_) => {}
                None => return None,
            }
            let inner = at_depth(&data[at..], depth + 1)?;
            at = at.checked_add(inner.end)?;
        }
    }

    let (start, len) = if first < 0x80 {
        (2, first as usize)
    } else {
        let count = (first & 0x7f) as usize;
        // A length of a length longer than four bytes describes something
        // bigger than any file this will ever be given.
        if count > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..count {
            len = (len << 8) | *data.get(2 + i)? as usize;
        }
        (2 + count, len)
    };

    let end = start.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some(Value {
        tag,
        body: &data[start..end],
        end,
    })
}

/// items walks a constructed value and hands back what is inside it, in
/// order. A value that will not read stops the walk rather than being
/// skipped, because half a sequence read as a whole one is how a reader
/// ends up reporting the wrong field.
pub fn items(data: &[u8]) -> Vec<Value<'_>> {
    let mut out = Vec::new();
    let mut at = 0;
    // A structure with more parts than this is not a signature.
    while at < data.len() && out.len() < 4096 {
        // The marker that closes an indefinite length is not a value.
        if data[at..].starts_with(&[0, 0]) {
            break;
        }
        let Some(value) = read(&data[at..]) else {
            break;
        };
        at += value.end;
        out.push(value);
    }
    out
}

/// oid renders an object identifier in the dotted form everything else
/// writes it in.
pub fn oid(body: &[u8]) -> String {
    let Some(&first) = body.first() else {
        return String::new();
    };
    let mut out = format!("{}.{}", first / 40, first % 40);
    let mut part: u64 = 0;
    for &byte in &body[1..] {
        // Seven bits at a time, the top bit saying whether more follow.
        part = match part.checked_mul(128) {
            Some(shifted) => shifted | (byte & 0x7f) as u64,
            None => return out, // a component this long is nobody's identifier
        };
        if byte & 0x80 == 0 {
            out.push('.');
            out.push_str(&part.to_string());
            part = 0;
        }
    }
    out
}

/// text reads the several string types a name can be written in. The one
/// worth care is BMPString, which is UTF-16 and turns up in certificates
/// issued to anybody whose name does not fit in ASCII.
pub fn text(value: &Value) -> String {
    match value.tag {
        // BMPString
        0x1e => {
            let mut out = String::new();
            let mut at = 0;
            while at + 1 < value.body.len() {
                let point = u16::from_be_bytes([value.body[at], value.body[at + 1]]);
                out.push(char::from_u32(point as u32).unwrap_or('\u{fffd}'));
                at += 2;
            }
            out
        }
        // UTF8String, PrintableString, IA5String, T61String, UTCTime,
        // GeneralizedTime, NumericString, VisibleString.
        0x0c | 0x13 | 0x16 | 0x14 | 0x17 | 0x18 | 0x12 | 0x1a => {
            String::from_utf8_lossy(value.body).into_owned()
        }
        _ => String::new(),
    }
}

/// integer renders a serial number, which is the one integer in here too
/// big to be a number. Certificates carry twenty byte serials and everybody
/// writes them as hexadecimal.
pub fn integer(body: &[u8]) -> String {
    let digits: Vec<u8> = body.iter().copied().skip_while(|&b| b == 0).collect();
    if digits.is_empty() {
        return "0".into();
    }
    digits.iter().map(|b| format!("{b:02X}")).collect()
}

/// walk visits every value in a tree, handing each to a closure. It is for
/// the attributes, which sit at a depth that depends on how the file was
/// signed: an ordinary countersignature puts the signing time two levels
/// down and a timestamp token puts it six.
pub fn walk<'a>(data: &'a [u8], depth: usize, seen: &mut usize, f: &mut impl FnMut(&Value<'a>)) {
    // Bounded twice over, because a signature is somebody else's structure:
    // once on how deep it goes and once on how much of it is looked at.
    if depth > 24 || *seen > 200_000 {
        return;
    }
    for value in items(data) {
        *seen += 1;
        f(&value);
        if value.nested() {
            walk(value.body, depth + 1, seen, f);
        }
    }
}
