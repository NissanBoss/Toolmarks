# Changelog

## v1.1

**The signature was not being read, and a signature is the one part of a
binary that names somebody on purpose.**

Pointed at a signed binary, v1 said this:

    AsusDownLoadLicense.exe: PE, 2 sections read
      Build timestamp  2019-10-31 04:09:38 UTC
      Nothing in this file names a person.

What that same file carries, in its certificate:

    CN=ASUSTeK Computer Inc., O=ASUSTeK Computer Inc., L=Taipei City,
    C=TW, SERIALNUMBER=23638777

A name, a town, a country and a company registration number. For a company
all of that is public. For one person publishing under a handle, an
individual code signing certificate carries their legal name, and that is
precisely what this program exists to find.

So there is an ASN.1 reader in here now, and a walk through PKCS#7 to the
certificate the signer named. It reports:

- **Who signed it**, from the certificate's own subject. A certificate with
  no organisation on it was issued to a person, and only that counts as
  naming one: Microsoft's certificate has a common name equal to its
  organisation, and a check that failed a build for shipping a Microsoft
  binary is a check people turn off.
- **The certificate's serial**, which every binary signed with it carries.
  Two projects published under two names and signed with one certificate
  are one person.
- **When it was signed.**

**That last one undoes advice this program was already giving.** v1 tells you
the link timestamp outlines the hours you keep, and to set SOURCE_DATE_EPOCH
or link with /Brepro to put a hash there instead. Do that, then sign, and the
countersignature writes the hour straight back in, because it is a reading of
a timestamping service's clock and no build flag reaches it. Nothing said so.

**The same reader works on a Mach-O**, because Apple's code signature holds a
PKCS#7 of its own. That took handling lengths that are not stated but run
until a pair of zero bytes: Apple writes its signatures that way, and a
reader that takes only the stated kind reads no Apple signature at all. Along
with it come the **Apple developer team**, which is registered to a named
account, and the **code signing identifier**, which for something built by
hand is a full path.

**And on ELF, the build id**, which is the same in every copy of a build and
so matches a published file against one found somewhere else.

Checked against twenty signed binaries on a Windows machine, with certutil
for the answers: twenty out of twenty, name for name and serial for serial.
None of them is reported as naming a person, which is the half that decides
whether a check like this is usable.

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
