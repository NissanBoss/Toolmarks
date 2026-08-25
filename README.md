# Toolmarks

What the binary you are about to publish says about you.

In forensics a toolmark is the trace a tool leaves in the thing it made: the
striations a barrel cuts into a bullet, the notch a crowbar leaves in a door
frame. They are used to identify the particular tool that did the work. A
compiler does the same to a binary, and almost nobody looks before they
upload.

```
toolmarks ./target/release/thing
```

```
thing: ELF, 28 sections read

Home directory path                                               inferred
  /home/a**, in 412 distinct paths: /home/a**/work/thing/src/main.rs  |
  /home/a**/work/thing/src/scan.rs  |  /home/a**/.cargo/registry/src
  found in: .debug_str, .debug_line_str
  This is the account name on the machine that built the file. If you
  publish under a handle, it does not match this.
  to fix: build with --remap-path-prefix, or from a directory that is not
  under your home, so the paths written into the binary do not start at
  your account

1 finding names a person. 3 more describe the machine it was built on.
Names are masked. Pass --reveal to print them whole.
```

## What it reads

ELF, PE and Mach-O. It never runs the file, and it never needs to: everything
here is a matter of reading the bytes and knowing where the format keeps
things.

**The debug symbol path.** MSVC writes the absolute path of the `.pdb` into
every binary it links, by default, whether or not you ship the `.pdb` and
whether or not you asked for one. It reads
`C:\Users\yourname\source\repos\Thing\x64\Release\Thing.pdb`. This is the
single most common way a project published under a handle carries its
author's real Windows login.

**Home directory paths.** Rust keeps the source path of every panic site, so
`/home/yourname/work/thing/src/main.rs` survives a stripped release build.
GCC and clang put the build directory in DWARF. The report does not list the
paths, which number in the thousands: it lists the accounts they were rooted
at, and says how many distinct paths carried each one, because that count is
what tells you whether a leak is one stray string or your whole build tree.

**Go build settings.** `vcs.revision` ties the binary to one commit.
`vcs.modified=true` says the tree had uncommitted changes, which means the
code you published is not the code that produced the file. The module path
names your account and repository even when the binary is passed on with no
other context.

**The build environment.** The compiler version, the exact commit the Rust
standard library was built from, the SDK a Mach-O was built against, and the
timestamp in the PE header. None of these names anybody on its own. Gathered
across a few releases, the timestamps outline the hours somebody keeps, and
so their time zone.

## In a release workflow

The exit code is the point of the program as much as the report is.

| Code | Meaning |
| ---- | ------- |
| 0 | nothing in the file names a person |
| 1 | something in the file names a person |
| 2 | a file could not be read at all |

```yaml
- name: Check the binaries before uploading them
  run: toolmarks target/release/thing
```

A build that would have published your home directory now fails instead. That
is the whole idea.

## What it will not do

- **It only reads.** The files you hand it are never written to, never moved,
  never renamed. It offers you flags to pass to your linker and leaves the
  binary alone, because a privacy tool that rewrites your release artifact is
  a tool you cannot use on a release artifact.
- **Nothing leaves the machine.** No sockets, no lookups, no telemetry.
- **Names are masked** unless you pass `--reveal`. The output of this program
  is a list of things somebody did not mean to publish, and printing it whole
  by default would only move the leak into a terminal that gets pasted into
  an issue.
- **It says when it could not look.** A stripped section is not a clean
  section. Findings are labelled `measured` when they were read out of a
  structure the format defines, `inferred` when they were recognised by
  shape, and `unread` when the place they live could not be reached. The
  closing line counts the third separately, because a file with nothing found
  and a file with nothing readable look identical from the outside and are
  not the same file.

The first three of those are held up by tests that read this program's own
source and fail if the code has grown the ability to write a file or open a
socket. A promise only a person checks is a promise that quietly stops being
true.

## Building

Rust, and nothing else. No crates, no C libraries, no build script.

```
cargo build --release
```

## A note on scanning itself

Toolmarks searches for a handful of strings, and those strings are constants
inside Toolmarks. Point it at its own binary and, without care, it finds its
own search terms sitting in `.rdata` and reports a Go revision for a Rust
program. Two rules deal with it: a run of text mentioning several account
roots at once is the compiler's string pool rather than a path, and Go build
settings are only believed in a file that also carries a Go runtime version.
It was worth fixing rather than documenting away, because any binary that
embeds a scanner has the same problem.

## Licence

MIT.
