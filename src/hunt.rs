// Going through the bytes looking for the things nobody meant to send.
//
// The headers are read by the format modules. This is the other half: a
// walk over the section contents once the structure is understood, because
// most of what gives a builder away is not in a field with a name. It is a
// string that somebody's compiler wrote into the middle of a blob.
//
// One rule shapes the whole file. A binary with debug information repeats
// the same source path thousands of times, so the report does not list
// paths: it lists the home directories those paths were rooted at, says how
// many distinct paths carried each one, and shows a few as examples. The
// count is what tells you whether a leak is one stray string or your entire
// build tree.

use std::collections::{BTreeMap, BTreeSet};

use crate::binary::Section;
use crate::finding::{Finding, Kind};

/// The account directories a personal name sits under. `/root/` is not
/// here: it names no one, since everybody's root is called root, and a
/// build done as root is a fact about a machine rather than about a person.
const MARKERS: [&str; 3] = ["\\Users\\", "/Users/", "/home/"];

/// A run of text longer than this is not a path. It is a data blob that
/// happens to be made of printable bytes.
const LONGEST_RUN: usize = 4096;

/// No account name is longer than this. The limit is what stops a run of
/// text with no separator in it from being read as one enormous name.
const LONGEST_NAME: usize = 64;

/// Enough examples to show the shape of a leak. Past this the report is
/// only repeating itself.
const KEEP_EXAMPLES: usize = 3;

/// Everything the sweep collected, kept in ordered maps so that two runs
/// over the same file produce the same report and can be compared.
#[derive(Default)]
struct Tally {
    /// The distinct whole paths seen under each home directory root.
    homes: BTreeMap<String, BTreeSet<String>>,
    /// Which sections each root turned up in.
    sites: BTreeMap<String, BTreeSet<String>>,
    registry: BTreeSet<String>,
    toolchains: BTreeSet<String>,
    compilers: BTreeSet<String>,
    modules: BTreeSet<String>,
    revisions: BTreeSet<String>,
    dirty: bool,
}

pub fn through(file: &[u8], sections: &[Section]) -> Vec<Finding> {
    let go = looks_like_go(file);
    let mut tally = Tally::default();
    for section in sections {
        sweep(section.bytes(file), &section.name, go, &mut tally);
    }
    tally.into_findings()
}

/// Whether this is a Go binary at all.
///
/// The build settings are searched for by name, and those names are string
/// constants in this program, which means a scan of this very binary finds
/// them sitting in its own data and reports a Go revision for a Rust
/// program. Every real Go binary stamps its runtime version in as well, and
/// this one does not, so that string is what separates the two.
fn looks_like_go(file: &[u8]) -> bool {
    occurrences(file, b"go1.")
        .into_iter()
        .any(|at| file.get(at + 4).is_some_and(u8::is_ascii_digit))
}

fn sweep(bytes: &[u8], site: &str, go: bool, tally: &mut Tally) {
    for marker in MARKERS {
        for at in occurrences(bytes, marker.as_bytes()) {
            let Some((run, position)) = printable_run(bytes, at) else {
                continue;
            };
            let Some(root) = root_of(&run, position, marker) else {
                continue;
            };
            tally.homes.entry(root.clone()).or_default().insert(run);
            tally
                .sites
                .entry(root)
                .or_default()
                .insert(site.to_string());
        }
    }

    for at in occurrences(bytes, b".cargo/registry/") {
        if let Some((run, position)) = printable_run(bytes, at)
            && let Some(path) = path_at(&run, position)
        {
            tally.registry.insert(path);
        }
    }

    for at in occurrences(bytes, b"/rustc/") {
        if let Some((run, position)) = printable_run(bytes, at)
            && let Some(hash) = toolchain_hash(&run, position)
        {
            tally.toolchains.insert(hash);
        }
    }

    for needle in ["rustc version ", "clang version ", "GCC: ("] {
        for at in occurrences(bytes, needle.as_bytes()) {
            if let Some((run, position)) = printable_run(bytes, at)
                && let Some(version) = version_at(&run, position, needle)
            {
                tally.compilers.insert(version);
            }
        }
    }

    if !go {
        return;
    }

    // Go writes its build settings as plain text, one per line, so the ones
    // that matter can be picked out without decoding the whole record.
    for at in occurrences(bytes, b"vcs.revision=") {
        if let Some((run, position)) = printable_run(bytes, at)
            && let Some(value) = after(&run, position, "vcs.revision=")
        {
            tally.revisions.insert(value);
        }
    }
    if !occurrences(bytes, b"vcs.modified=true").is_empty() {
        tally.dirty = true;
    }
    for at in occurrences(bytes, b"\tpath\t") {
        if let Some((run, position)) = printable_run(bytes, at)
            && let Some(value) = after(&run, position, "\tpath\t")
        {
            tally.modules.insert(value);
        }
    }
}

impl Tally {
    fn into_findings(self) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (root, paths) in &self.homes {
            let sites = match self.sites.get(root) {
                Some(names) => names.iter().cloned().collect::<Vec<_>>().join(", "),
                None => String::from("section contents"),
            };
            let examples: Vec<&str> = paths
                .iter()
                .take(KEEP_EXAMPLES)
                .map(String::as_str)
                .collect();
            let detail = format!(
                "{root}, in {} distinct {}: {}",
                paths.len(),
                if paths.len() == 1 { "path" } else { "paths" },
                examples.join("  |  ")
            );
            findings.push(Finding::inferred(Kind::HomePath, sites, detail).fix(
                "build with --remap-path-prefix, or from a directory that is \
                 not under your home, so the paths written into the binary do \
                 not start at your account",
            ));
        }

        if !self.registry.is_empty() {
            let example = self
                .registry
                .iter()
                .next()
                .map(String::as_str)
                .unwrap_or("");
            findings.push(
                Finding::inferred(
                    Kind::CargoRegistry,
                    "section contents",
                    format!(
                        "{} {} into the crate registry, for example {example}",
                        self.registry.len(),
                        if self.registry.len() == 1 {
                            "path"
                        } else {
                            "paths"
                        }
                    ),
                )
                .fix(
                    "set RUSTFLAGS with --remap-path-prefix=$HOME=~ before a \
                     release build, and check the result rather than assuming",
                ),
            );
        }

        for hash in self.toolchains {
            findings.push(Finding::inferred(
                Kind::ToolchainHash,
                "section contents",
                hash,
            ));
        }
        for compiler in self.compilers {
            findings.push(Finding::inferred(
                Kind::CompilerVersion,
                "section contents",
                compiler,
            ));
        }
        for module in self.modules {
            findings.push(Finding::inferred(Kind::ModulePath, "Go build info", module));
        }
        for revision in self.revisions {
            findings.push(
                Finding::inferred(Kind::Revision, "Go build info", revision)
                    .fix("build with -buildvcs=false to leave it out"),
            );
        }
        if self.dirty {
            findings.push(Finding::inferred(
                Kind::DirtyTree,
                "Go build info",
                "vcs.modified=true",
            ));
        }

        findings
    }
}

/// Every place a needle starts in a haystack. None of the needles used here
/// can overlap itself, so the search moves past each hit rather than one
/// byte on.
fn occurrences(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    let mut found = Vec::new();
    let mut at = 0;
    while at + needle.len() <= haystack.len() {
        if &haystack[at..at + needle.len()] == needle {
            found.push(at);
            at += needle.len();
        } else {
            at += 1;
        }
    }
    found
}

/// The longest stretch of printable text containing `at`, and where inside
/// that stretch `at` landed. Strings in a binary are not delimited in any
/// one way, so their edges have to be found by noticing where the text
/// stops being text.
fn printable_run(bytes: &[u8], at: usize) -> Option<(String, usize)> {
    let printable = |b: u8| (0x20..0x7f).contains(&b) || b == b'\t';
    if !bytes.get(at).copied().is_some_and(printable) {
        return None;
    }
    let mut start = at;
    while start > 0 && printable(bytes[start - 1]) && at - start < LONGEST_RUN {
        start -= 1;
    }
    let mut end = at;
    while end < bytes.len() && printable(bytes[end]) && end - at < LONGEST_RUN {
        end += 1;
    }
    Some((
        String::from_utf8_lossy(&bytes[start..end]).into_owned(),
        at - start,
    ))
}

/// The part of a path that names the account, given where the marker was
/// found inside it. On Windows this reaches back to take in the drive
/// letter, because a root printed as `\Users\someone` reads like a fragment
/// of something rather than a place.
fn root_of(run: &str, position: usize, marker: &str) -> Option<String> {
    if !is_one_path(run) {
        return None;
    }
    let bytes = run.as_bytes();
    let start = if marker.starts_with('\\') && position >= 2 && bytes[position - 1] == b':' {
        position - 2
    } else {
        position
    };
    let name_at = position + marker.len();
    let name = run.get(name_at..)?;
    let end = name
        .char_indices()
        .take(LONGEST_NAME + 1)
        .find(|(_, c)| !in_a_name(*c))
        .map(|(n, _)| n)
        .unwrap_or(name.len());
    if end == 0 || end > LONGEST_NAME {
        return None;
    }
    run.get(start..name_at + end).map(String::from)
}

/// Whether a run of text is a single path rather than several strings that
/// happen to sit next to each other.
///
/// This program keeps the markers it searches for as string constants, and
/// the compiler lays those out end to end with nothing in between. Run it
/// on itself and that blob reads as a path rooted at four accounts at once.
/// Any binary that mentions more than one of these in one unbroken run is
/// doing the same thing, so the whole run is thrown away.
fn is_one_path(run: &str) -> bool {
    MARKERS.iter().filter(|m| run.contains(*m)).count() <= 1
}

/// Characters that can appear in an account name. Anything else ends it,
/// which keeps a name from running on into whatever text follows when the
/// path is embedded in a longer string.
fn in_a_name(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ')
}

/// The path starting at a position, ending where a path stops being one.
///
/// A registry path has no spaces or quotes in it and is several levels
/// deep. Requiring both is what keeps a match that ran straight into the
/// prose beside it from being reported as somewhere on disk.
fn path_at(run: &str, position: usize) -> Option<String> {
    let rest = run.get(position..)?;
    let end = rest.find([' ', '"', '\t', '\'']).unwrap_or(rest.len());
    let path = rest.get(..end)?;
    if path.matches('/').count() < 3 {
        return None;
    }
    Some(path.to_string())
}

/// A compiler version starting at a needle, cut to a readable length.
///
/// The digit is what makes this worth reporting. Without it the match is
/// the needle itself sitting in some program's constants, which is how this
/// tool first reported its own search terms as a finding.
fn version_at(run: &str, position: usize, needle: &str) -> Option<String> {
    let rest = run.get(position..)?;
    let end = rest
        .char_indices()
        .take_while(|(n, _)| *n < 160)
        .last()
        .map(|(n, c)| n + c.len_utf8())
        .unwrap_or(0);
    let text = rest.get(..end)?.trim();
    if !text
        .get(needle.len()..)?
        .chars()
        .take(40)
        .any(|c| c.is_ascii_digit())
    {
        return None;
    }
    Some(balanced(text))
}

/// Drops closing brackets left dangling by starting to read in the middle
/// of somebody else's sentence. Rust writes its version inside a wider
/// string, so cutting at the needle takes the tail of a bracket that was
/// opened before the cut.
fn balanced(text: &str) -> String {
    let mut open = text.matches('(').count();
    let mut out = text.to_string();
    while out.ends_with(')') && out.matches(')').count() > open {
        out.pop();
        open = out.matches('(').count();
    }
    out
}

/// The commit the Rust standard library was built from, which sits between
/// `/rustc/` and the next separator. Anything there that is not forty hex
/// characters is some other path that happens to start the same way.
fn toolchain_hash(run: &str, position: usize) -> Option<String> {
    let rest = run.get(position + "/rustc/".len()..)?;
    let end = rest.find('/').unwrap_or(rest.len());
    let hash = rest.get(..end)?;
    if hash.len() == 40 && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(hash.to_string())
    } else {
        None
    }
}

/// The value following a key inside a run of text, stopping at the next
/// separator Go puts between settings.
fn after(run: &str, position: usize, key: &str) -> Option<String> {
    let rest = run.get(position + key.len()..)?;
    let end = rest.find(['\n', '\t', ' ']).unwrap_or(rest.len());
    let value = rest.get(..end)?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}
