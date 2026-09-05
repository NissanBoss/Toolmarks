// The certificate a signed binary carries, and when it was signed.
//
// A signature is the one part of a binary that names somebody on purpose.
// That is what it is for, and it is also why nobody thinks about it: the
// name is meant to be there, so it does not read as a leak. It is still a
// name, it is still in every copy of the file, and when the certificate was
// issued to one person rather than to a company it is their legal name
// rather than the handle they publish under.
//
// The signing time is the other half and it is the part that undoes the
// advice this program already gives. Toolmarks tells you to put a hash in
// the link timestamp so the hour you were working does not go out with the
// file. If you do that and then sign, the countersignature writes the hour
// straight back in, because it is a reading of a clock that a timestamping
// service took and neither SOURCE_DATE_EPOCH nor /Brepro reaches it.

use crate::asn1::{self, Value};

/// A name as its parts, which is how every distinguished name here travels.
type Parts = Vec<(String, String)>;

/// What was read out of a signature block.
#[derive(Debug, Default)]
pub struct Signed {
    /// The subject of the signer's certificate, as its parts.
    pub subject: Parts,
    pub issuer: Parts,
    pub serial: String,
    /// The time a countersignature says the signing happened.
    pub signed_at: Option<String>,
    /// True when a timestamping service was involved, whether or not its
    /// time could be read.
    pub timestamped: bool,
    pub trouble: Option<String>,
}

/// The attribute types worth naming in a distinguished name, and what to
/// call them.
fn attribute(id: &str) -> Option<&'static str> {
    Some(match id {
        "2.5.4.3" => "common name",
        "2.5.4.6" => "country",
        "2.5.4.7" => "town",
        "2.5.4.8" => "region",
        "2.5.4.9" => "street",
        "2.5.4.10" => "organisation",
        "2.5.4.11" => "unit",
        "2.5.4.5" => "registration number",
        "2.5.4.15" => "kind of entity",
        "2.5.4.17" => "postcode",
        "1.2.840.113549.1.9.1" => "email address",
        _ => return None,
    })
}

const SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
const COUNTERSIGNATURE: &str = "1.2.840.113549.1.9.6";
const MS_TIMESTAMP: &str = "1.3.6.1.4.1.311.3.3.1";
const TIMESTAMP_TOKEN: &str = "1.2.840.113549.1.9.16.2.14";

/// read takes a PKCS#7 signature block and works out who signed and when.
pub fn read(block: &[u8]) -> Signed {
    let mut out = Signed::default();

    // ContentInfo, then the SignedData inside it. Two unwrappings that are
    // the same shape, so they are done the same way.
    let Some(content) = asn1::read(block) else {
        out.trouble = Some("the signature block is not a structure this reads".into());
        return out;
    };
    let inside = asn1::items(content.body);
    let Some(signed_data) = inside
        .iter()
        .find(|v| v.nested() && v.tag != asn1::SEQUENCE)
        .and_then(|v| asn1::items(v.body).into_iter().next())
    else {
        out.trouble = Some("the signature block holds no signed data".into());
        return out;
    };

    let parts = asn1::items(signed_data.body);
    // The chain is in a context tagged set, and the signers are in the
    // plain one at the end.
    let chain: Vec<Value> = parts
        .iter()
        .find(|v| v.tag == 0xa0)
        .map(|v| asn1::items(v.body))
        .unwrap_or_default();
    let signers: Vec<Value> = parts
        .iter()
        .rev()
        .find(|v| v.tag == asn1::SET)
        .map(|v| asn1::items(v.body))
        .unwrap_or_default();

    // Which certificate belongs to the signer is not a guess: the signer
    // says so, by naming the issuer and serial of the one it used.
    let wanted = signers.first().and_then(|s| issuer_and_serial(s));
    let mut chosen = None;
    for cert in &chain {
        let Some(read) = certificate(cert) else {
            continue;
        };
        match &wanted {
            Some((issuer, serial)) if &read.1 == issuer && &read.2 == serial => {
                chosen = Some(read);
                break;
            }
            None if chosen.is_none() => chosen = Some(read),
            _ => {}
        }
    }
    match chosen {
        Some((subject, issuer, serial)) => {
            out.subject = subject;
            out.issuer = issuer;
            out.serial = serial;
        }
        None => out.trouble = Some("the certificate the signer named is not in the file".into()),
    }

    // The signing time is an attribute, and an attribute is a sequence of
    // an identifier and a set. Where it sits depends on how the file was
    // timestamped, so rather than guess at a depth this looks at every
    // attribute in the block and picks the ones it knows.
    let mut seen = 0usize;
    asn1::walk(block, 0, &mut seen, &mut |value| {
        if !value.is(asn1::SEQUENCE) {
            return;
        }
        let inner = asn1::items(value.body);
        let (Some(id), Some(values)) = (inner.first(), inner.get(1)) else {
            return;
        };
        if !id.is(asn1::OID) || !values.is(asn1::SET) {
            return;
        }
        match asn1::oid(id.body).as_str() {
            SIGNING_TIME => {
                if let Some(when) = asn1::items(values.body).first() {
                    let text = asn1::text(when);
                    if out.signed_at.is_none() && !text.is_empty() {
                        out.signed_at = Some(readable(&text, when.tag));
                    }
                }
            }
            COUNTERSIGNATURE | MS_TIMESTAMP | TIMESTAMP_TOKEN => out.timestamped = true,
            _ => {}
        }
    });

    // A timestamp token keeps its time as a plain generalised time inside
    // the token rather than as an attribute, so when the attributes gave
    // nothing and there was a token, that is where the time is.
    if out.signed_at.is_none() && out.timestamped {
        let mut seen = 0usize;
        let mut found: Option<String> = None;
        asn1::walk(block, 0, &mut seen, &mut |value| {
            if found.is_none() && value.is(asn1::GENERAL_TIME) {
                let text = asn1::text(value);
                if !text.is_empty() {
                    found = Some(readable(&text, asn1::GENERAL_TIME));
                }
            }
        });
        out.signed_at = found;
    }
    out
}

/// issuer_and_serial pulls the pair a signer uses to say which certificate
/// it signed with.
fn issuer_and_serial(signer: &Value) -> Option<(Parts, String)> {
    let parts = asn1::items(signer.body);
    // version, then issuerAndSerialNumber.
    let pair = parts.iter().find(|v| v.is(asn1::SEQUENCE))?;
    let inside = asn1::items(pair.body);
    let issuer = inside.iter().find(|v| v.is(asn1::SEQUENCE))?;
    let serial = inside.iter().find(|v| v.is(asn1::INTEGER))?;
    Some((name(issuer.body), asn1::integer(serial.body)))
}

/// certificate reads the three fields of a certificate this cares about.
fn certificate(cert: &Value) -> Option<(Parts, Parts, String)> {
    let tbs = asn1::items(cert.body).into_iter().next()?;
    let fields = asn1::items(tbs.body);

    // The version is optional and context tagged, so the serial is
    // whichever integer comes first and the names are the second and third
    // sequences: signature algorithm, issuer, validity, subject.
    let serial = fields.iter().find(|v| v.is(asn1::INTEGER))?;
    let sequences: Vec<&Value> = fields.iter().filter(|v| v.is(asn1::SEQUENCE)).collect();
    let issuer = sequences.get(1)?;
    let subject = sequences.get(3)?;
    Some((
        name(subject.body),
        name(issuer.body),
        asn1::integer(serial.body),
    ))
}

/// name takes a distinguished name apart into the pairs it is made of.
fn name(body: &[u8]) -> Parts {
    let mut out = Vec::new();
    for group in asn1::items(body) {
        for pair in asn1::items(group.body) {
            let inner = asn1::items(pair.body);
            let (Some(id), Some(value)) = (inner.first(), inner.get(1)) else {
                continue;
            };
            if !id.is(asn1::OID) {
                continue;
            }
            let id = asn1::oid(id.body);
            let text = asn1::text(value);
            if text.is_empty() {
                continue;
            }
            out.push((attribute(&id).unwrap_or(&id).to_string(), text));
        }
    }
    out
}

/// readable turns the two time forms a signature uses into one shape.
/// A UTCTime writes the year with two digits, which is how a file signed in
/// 2019 can be read as one signed in 2119.
fn readable(text: &str, tag: u8) -> String {
    let digits: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
    let (year, rest) = if tag == asn1::UTC_TIME {
        if digits.len() < 10 {
            return text.into();
        }
        let two: u32 = digits[0..2].parse().unwrap_or(0);
        // The format says a year under fifty is this century.
        let year = if two < 50 { 2000 + two } else { 1900 + two };
        (year.to_string(), &digits[2..])
    } else {
        if digits.len() < 12 {
            return text.into();
        }
        (digits[0..4].to_string(), &digits[4..])
    };
    if rest.len() < 8 {
        return text.into();
    }
    format!(
        "{}-{}-{} {}:{}:{} UTC",
        year,
        &rest[0..2],
        &rest[2..4],
        &rest[4..6],
        &rest[6..8],
        rest.get(8..10).unwrap_or("00"),
    )
}

impl Signed {
    /// who renders the subject the way a person reads it: the common name
    /// first, then whatever else the certificate says about them.
    pub fn who(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for want in [
            "common name",
            "organisation",
            "email address",
            "street",
            "town",
            "region",
            "postcode",
            "country",
            "registration number",
        ] {
            for (key, value) in &self.subject {
                if key == want {
                    parts.push(value.clone());
                }
            }
        }
        parts.dedup();
        parts.join(", ")
    }

    /// issued_by is the authority, which is worth a line because it says
    /// what kind of certificate this is and so what was checked to get it.
    pub fn issued_by(&self) -> String {
        self.issuer
            .iter()
            .find(|(key, _)| key == "common name")
            .map(|(_, value)| value.clone())
            .unwrap_or_default()
    }

    /// personal says whether the certificate was issued to one person
    /// rather than to a company. The exit code turns on it, so it is drawn
    /// conservatively: an organisation field means a company.
    ///
    /// The tempting rule is that a common name equal to the organisation is
    /// a sole trader signing under their own name. It is also what
    /// Microsoft's certificate looks like, and a check that fails a build
    /// for shipping a Microsoft binary is a check people turn off. So the
    /// only thing counted as a person here is a certificate with a common
    /// name and no organisation at all, which is the shape a certificate
    /// issued to an individual has.
    pub fn personal(&self) -> bool {
        self.field("common name").is_some() && self.field("organisation").is_none()
    }

    fn field(&self, want: &str) -> Option<&str> {
        self.subject
            .iter()
            .find(|(key, _)| key == want)
            .map(|(_, value)| value.as_str())
    }
}
