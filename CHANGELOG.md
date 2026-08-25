# Changelog

## v1

The first release.

Reads a compiled binary and reports what it says about the machine that
built it, so that a release can be checked before it goes out rather than
after somebody else reads it.

- ELF, PE and Mach-O, all three parsed here rather than pulled in, far
  enough to list the sections and read the fields that name a person.
- The CodeView debug record, which is where MSVC writes the absolute path
  of the `.pdb` into every binary it links, by default, carrying a Windows
  account name with it.
- Home directory paths, grouped by the account they were rooted at and
  counted, because a binary with debug information repeats the same path
  thousands of times and the count is what shows how far a leak reaches.
- Cargo registry paths, which survive a stripped release build because
  panic messages keep the path they were compiled from.
- Go build settings: the source revision, the module path, and whether the
  tree had uncommitted changes when the binary was made.
- The compiler version, the commit the Rust standard library was built
  from, the SDK a Mach-O was built against, and the link timestamp.
- An exit code a workflow can act on: zero when nothing names a person, one
  when something does, two when a file could not be read at all.

Names are masked unless `--reveal` is passed, because the report is itself a
list of things somebody did not mean to publish. Findings say whether they
were measured, inferred, or could not be read at all, and the closing line
counts the third separately: a file with nothing found and a file with
nothing readable look the same from outside and are not the same file.

The files handed to it are never written to, no socket is ever opened, and
there are no dependencies at all. Tests read the source and fail the build
if any of that stops being true.

Builds for Windows, Linux and both kinds of Mac.
