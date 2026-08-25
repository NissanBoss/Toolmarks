// The tests, including the ones that hold the README to its word.
//
// Two kinds live here. Most are ordinary: give a function an input, check
// what comes back. The last group is different. It reads this program's own
// source and fails if the code has grown the ability to write a file or
// open a socket, because the README promises it cannot, and a promise that
// only a person checks is a promise that quietly stops being true.

use crate::binary::{self, Section};
use crate::finding::{Certainty, Finding, Kind};
use crate::{hunt, mask, pe};

fn section(bytes: &[u8]) -> Vec<Section> {
    vec![Section {
        name: ".rdata".into(),
        offset: 0,
        size: bytes.len(),
    }]
}

#[test]
fn a_masked_name_keeps_its_length_and_first_letter() {
    assert_eq!(mask::identifier("kamat"), "k****");
    assert_eq!(mask::identifier("ana"), "a**");
}

#[test]
fn a_name_too_short_to_hint_at_is_hidden_whole() {
    assert_eq!(mask::identifier("jo"), "**");
    assert_eq!(mask::identifier("j"), "*");
    assert_eq!(mask::identifier(""), "*");
}

#[test]
fn masking_a_path_hides_the_account_and_leaves_the_folders() {
    assert_eq!(
        mask::path("C:\\Users\\kamat\\source\\repos\\Foo\\Foo.pdb"),
        "C:\\Users\\k****\\source\\repos\\Foo\\Foo.pdb"
    );
    assert_eq!(
        mask::path("/home/ana/work/thing/src/main.rs"),
        "/home/a**/work/thing/src/main.rs"
    );
}

#[test]
fn masking_leaves_a_path_with_nobody_in_it_alone() {
    let path = "/usr/lib/gcc/x86_64-linux-gnu/12/crtbegin.o";
    assert_eq!(mask::path(path), path);
}

#[test]
fn revealing_gives_the_text_back_untouched() {
    let path = "/home/ana/work";
    assert_eq!(mask::apply(path, true), path);
    assert_ne!(mask::apply(path, false), path);
}

#[test]
fn a_windows_home_path_is_found_and_rooted_at_the_drive() {
    let mut bytes = vec![0u8; 8];
    bytes.extend_from_slice(b"C:\\Users\\kamat\\source\\repos\\Foo\\src\\main.rs");
    bytes.extend_from_slice(&[0u8; 8]);

    let findings = hunt::through(&bytes, &section(&bytes));
    let home = findings
        .iter()
        .find(|f| f.kind == Kind::HomePath)
        .expect("the home path should have been found");

    assert!(home.value.starts_with("C:\\Users\\kamat,"));
    assert_eq!(home.certainty, Certainty::Inferred);
    assert!(home.remedy.is_some());
}

#[test]
fn the_same_account_reached_by_many_paths_is_reported_once() {
    let mut bytes = Vec::new();
    for name in ["main.rs", "lib.rs", "hunt.rs"] {
        bytes.extend_from_slice(format!("/home/ana/thing/src/{name}").as_bytes());
        bytes.push(0);
    }

    let findings = hunt::through(&bytes, &section(&bytes));
    let homes: Vec<_> = findings
        .iter()
        .filter(|f| f.kind == Kind::HomePath)
        .collect();

    assert_eq!(homes.len(), 1, "three paths, one account, one finding");
    assert!(
        homes[0].value.contains("3 distinct paths"),
        "the count is what shows how far the leak reaches: {}",
        homes[0].value
    );
}

#[test]
fn a_toolchain_commit_is_only_taken_when_it_looks_like_one() {
    let real = b"/rustc/88d9e12ae2a2b1a4c1d8f4e3b7a0c5d6e9f01234/library/std/src/rt.rs";
    let found = hunt::through(real, &section(real));
    assert!(found.iter().any(|f| f.kind == Kind::ToolchainHash));

    let decoy = b"/rustc/nightly/library/std/src/rt.rs";
    let found = hunt::through(decoy, &section(decoy));
    assert!(!found.iter().any(|f| f.kind == Kind::ToolchainHash));
}

#[test]
fn a_go_binary_gives_up_its_revision_and_its_dirty_tree() {
    let bytes = b"go1.23.4\n\tpath\tgithub.com/someone/thing\nbuild\tvcs.revision=9f3c2ab1\nbuild\tvcs.modified=true\n";
    let findings = hunt::through(bytes, &section(bytes));

    let revision = findings.iter().find(|f| f.kind == Kind::Revision);
    assert_eq!(revision.map(|f| f.value.as_str()), Some("9f3c2ab1"));
    assert!(findings.iter().any(|f| f.kind == Kind::DirtyTree));
    assert!(
        findings
            .iter()
            .any(|f| f.kind == Kind::ModulePath && f.value == "github.com/someone/thing")
    );
}

#[test]
fn go_settings_are_ignored_in_something_that_is_not_a_go_binary() {
    // This program keeps those setting names as constants, so without the
    // check it reports a Go revision and a dirty tree when pointed at
    // itself. The absence of a runtime version is what rules it out.
    let bytes = b"vcs.revision=9f3c2ab1 vcs.modified=true \tpath\t";
    let findings = hunt::through(bytes, &section(bytes));

    assert!(
        !findings
            .iter()
            .any(|f| { matches!(f.kind, Kind::Revision | Kind::DirtyTree | Kind::ModulePath) }),
        "got {findings:?}"
    );
}

#[test]
fn a_registry_match_that_runs_into_prose_is_not_a_path() {
    let bytes = b".cargo/registry/clang version GCC: (rustc version";
    let findings = hunt::through(bytes, &section(bytes));
    assert!(
        !findings.iter().any(|f| f.kind == Kind::CargoRegistry),
        "got {findings:?}"
    );

    let real =
        b"/home/ana/.cargo/registry/src/index.crates.io-6f17d22bba15001f/libc-0.2.155/src/lib.rs";
    let findings = hunt::through(real, &section(real));
    assert!(findings.iter().any(|f| f.kind == Kind::CargoRegistry));
}

#[test]
fn several_markers_in_one_run_are_this_tools_own_constants() {
    // Laid out end to end by the compiler, the search terms read as a path
    // rooted at three accounts at once. No real path looks like that.
    let bytes = b"\\Users\\/Users//home/";
    let findings = hunt::through(bytes, &section(bytes));
    assert!(
        !findings.iter().any(|f| f.kind == Kind::HomePath),
        "got {findings:?}"
    );
}

#[test]
fn a_version_cut_out_of_a_longer_string_does_not_keep_a_stray_bracket() {
    let bytes = b"clang LLVM (rustc version 1.98.0 (88d9e12ae 2026-08-18))";
    let findings = hunt::through(bytes, &section(bytes));
    let version = findings
        .iter()
        .find(|f| f.kind == Kind::CompilerVersion)
        .expect("the rustc version should have been found");
    assert_eq!(version.value, "rustc version 1.98.0 (88d9e12ae 2026-08-18)");
}

#[test]
fn nothing_is_found_in_bytes_that_are_not_text() {
    let bytes: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let findings = hunt::through(&bytes, &section(&bytes));
    assert!(findings.is_empty(), "got {findings:?}");
}

#[test]
fn seconds_since_the_epoch_become_a_date_a_person_can_read() {
    assert_eq!(pe::utc(0), "1970-01-01 00:00:00 UTC");
    assert_eq!(pe::utc(1_000_000_000), "2001-09-09 01:46:40 UTC");
    assert_eq!(pe::utc(1_709_164_800), "2024-02-29 00:00:00 UTC");
}

#[test]
fn a_file_that_is_not_an_executable_is_named_for_what_it_is() {
    let message = binary::open(b"#!/bin/sh\necho hello\n")
        .expect_err("a shell script is not an executable this reads")
        .to_string();
    assert!(message.contains("a script"), "{message}");

    let message = binary::open(b"PK\x03\x04rest of a zip")
        .expect_err("a zip is not an executable this reads")
        .to_string();
    assert!(message.contains("zip"), "{message}");
}

#[test]
fn an_empty_file_does_not_panic() {
    assert!(binary::open(b"").is_err());
}

#[test]
fn a_truncated_header_does_not_panic() {
    // Every one of these announces a format and then stops, which is the
    // shape of input that makes a careless parser index past the end.
    for stub in [
        b"\x7fELF\x02\x01".as_slice(),
        b"MZ",
        b"MZ\x00\x00\x00\x00",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe\x00\x00\x00\x02",
    ] {
        let _ = binary::open(stub);
    }
}

/// The source of every module, so the promise tests can read the program
/// rather than trust it. `tests.rs` is left out on purpose: it is the file
/// naming the forbidden things, and it is not compiled into a release.
fn shipped_source() -> Vec<(&'static str, &'static str)> {
    vec![
        ("main.rs", include_str!("main.rs")),
        ("binary.rs", include_str!("binary.rs")),
        ("elf.rs", include_str!("elf.rs")),
        ("pe.rs", include_str!("pe.rs")),
        ("macho.rs", include_str!("macho.rs")),
        ("hunt.rs", include_str!("hunt.rs")),
        ("finding.rs", include_str!("finding.rs")),
        ("mask.rs", include_str!("mask.rs")),
        ("report.rs", include_str!("report.rs")),
        ("error.rs", include_str!("error.rs")),
    ]
}

#[test]
fn the_program_cannot_write_to_a_file() {
    for (name, source) in shipped_source() {
        for forbidden in [
            "fs::write",
            "fs::create",
            "fs::remove",
            "fs::rename",
            "File::create",
            "OpenOptions",
            "set_permissions",
        ] {
            assert!(
                !source.contains(forbidden),
                "{name} uses {forbidden}, and the README says this program only reads"
            );
        }
    }
}

#[test]
fn the_program_cannot_open_a_socket() {
    for (name, source) in shipped_source() {
        for forbidden in ["TcpStream", "TcpListener", "UdpSocket", "std::net"] {
            assert!(
                !source.contains(forbidden),
                "{name} uses {forbidden}, and the README says nothing leaves the machine"
            );
        }
    }
}

#[test]
fn the_program_has_no_dependencies() {
    let manifest = include_str!("../Cargo.toml");
    let after = manifest
        .split_once("[dependencies]")
        .map(|(_, rest)| rest.trim())
        .unwrap_or("");
    assert!(
        after.is_empty(),
        "the README says this builds from the standard library alone, but \
         Cargo.toml lists: {after}"
    );
}

#[test]
fn a_debug_record_holding_only_a_file_name_names_nobody() {
    let with_path = Finding::measured(
        Kind::PdbPath,
        "CodeView debug record",
        "C:\\Users\\ana\\repos\\thing\\thing.pdb",
    );
    assert!(with_path.names);

    let bare = Finding::measured(Kind::PdbPath, "CodeView debug record", "thing.pdb").anonymous();
    assert!(!bare.names, "a file name on its own gives away no account");
}

#[test]
fn something_that_could_not_be_read_never_counts_as_naming_anybody() {
    let unread = Finding::unread(Kind::PdbPath, "debug directory", "it could not be followed");
    assert!(
        !unread.names,
        "a place that could not be read has not told us anything, either way"
    );
}

#[test]
fn every_kind_of_finding_says_why_it_matters() {
    for kind in [
        Kind::HomePath,
        Kind::PdbPath,
        Kind::CargoRegistry,
        Kind::ModulePath,
        Kind::Revision,
        Kind::DirtyTree,
        Kind::ToolchainHash,
        Kind::CompilerVersion,
        Kind::BuildTime,
    ] {
        assert!(!kind.title().is_empty());
        assert!(
            kind.matters().len() > 40,
            "{:?} needs a sentence explaining what a stranger learns from it",
            kind
        );
    }
}
