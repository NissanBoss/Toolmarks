// Toolmarks: what the binary you are about to publish says about you.
//
// In forensics a toolmark is the trace a tool leaves in the thing it made:
// the striations a barrel cuts into a bullet, the notch a crowbar leaves in
// a frame. They are used to identify the particular tool. A compiler does
// the same to a binary, and almost nobody looks before they upload.
//
// The exit code is the point of the program as much as the report is. Zero
// when nothing in the file names a person, one when something does, so that
// a release workflow can refuse to publish a binary with its author's home
// directory inside it. Two is reserved for not being able to read the file,
// which must never be confused with the file being clean.

mod binary;
mod elf;
mod error;
mod finding;
mod hunt;
mod macho;
mod mask;
mod pe;
mod report;

#[cfg(test)]
mod tests;

use std::process::ExitCode;

/// What this build calls itself. `build.sh` puts the tag in the environment
/// when there is one, so the tag is what a release reports rather than a
/// number sitting in Cargo.toml that somebody forgot to raise. A build with
/// no tag falls back to Cargo.toml, which is how a copy built at home stays
/// honest about not being a release.
const VERSION: &str = match option_env!("TOOLMARKS_VERSION") {
    Some(tag) => tag,
    None => env!("CARGO_PKG_VERSION"),
};

const USAGE: &str = "\
toolmarks: what a compiled binary says about the machine that built it.

    toolmarks [options] <file>...

Reads ELF, PE and Mach-O executables and reports the build paths, account
names, source revisions and compiler versions left inside them. It only
reads: the files handed to it are never written to, and nothing is sent
anywhere.

Options:
    -r, --reveal    print names in full instead of masking them
    -h, --help      show this
    -V, --version   show the version

Exit codes:
    0   nothing in the file names a person
    1   something in the file names a person
    2   a file could not be read at all
";

fn main() -> ExitCode {
    let mut reveal = false;
    let mut paths: Vec<String> = Vec::new();

    for argument in std::env::args().skip(1) {
        match argument.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "-V" | "--version" => {
                println!("toolmarks {VERSION}");
                return ExitCode::SUCCESS;
            }
            "-r" | "--reveal" => reveal = true,
            other if other.starts_with('-') && other.len() > 1 => {
                eprintln!("toolmarks: no option called {other}");
                eprint!("{USAGE}");
                return ExitCode::from(2);
            }
            other => paths.push(other.to_string()),
        }
    }

    if paths.is_empty() {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    }

    let mut named_somebody = false;
    let mut unreadable = false;

    for (index, path) in paths.iter().enumerate() {
        if index > 0 {
            println!();
        }
        match examine(path, reveal) {
            Ok((text, named)) => {
                print!("{text}");
                named_somebody |= named;
            }
            Err(message) => {
                eprintln!("toolmarks: {path}: {message}");
                unreadable = true;
            }
        }
    }

    // A file that could not be read outranks a clean report on the files
    // that could. Saying nothing was found would be true and useless.
    if unreadable {
        ExitCode::from(2)
    } else if named_somebody {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Reads one file and returns its report, along with whether anything in it
/// named a person.
fn examine(path: &str, reveal: bool) -> error::Result<(String, bool)> {
    let bytes = std::fs::read(path)?;
    let opened = binary::open(&bytes)?;

    let mut findings = opened.findings.clone();
    findings.extend(hunt::through(&bytes, &opened.sections));
    finding::arrange(&mut findings);

    let named = findings.iter().any(|f| f.names);
    let name = display_name(path);
    Ok((report::render(&name, &opened, &findings, reveal), named))
}

/// The file name on its own. The directory the file happens to sit in on
/// this machine is not part of what the file says about anybody, and
/// printing it would put a fresh path into output people paste around.
fn display_name(path: &str) -> String {
    path.rsplit(['/', '\\'])
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or(path)
        .to_string()
}
