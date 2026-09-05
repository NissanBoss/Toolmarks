// What Toolmarks has to say about a binary.
//
// A finding answers three questions: what was found, where it was found,
// and how sure we are of it. The third one matters most. A section that was
// stripped is not a section that came back clean, and a report that blurs
// those two together is worse than no report at all.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Certainty {
    /// Read out of a structure the format defines, at the offset the format
    /// says it lives at.
    Measured,
    /// Recognised by its shape in a run of bytes. Nearly always right, and
    /// once in a while a coincidence, which is why it is labelled apart.
    Inferred,
    /// The place this would live could not be read: stripped, packed, or in
    /// a shape this version does not know yet.
    Unread,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    HomePath,
    PdbPath,
    CargoRegistry,
    ModulePath,
    Revision,
    DirtyTree,
    ToolchainHash,
    CompilerVersion,
    BuildTime,
    SignedBy,
    SignedWith,
    SignedAt,
    BuildId,
    TeamId,
}

impl Kind {
    pub fn title(self) -> &'static str {
        match self {
            Kind::HomePath => "Home directory path",
            Kind::PdbPath => "Debug symbol path",
            Kind::CargoRegistry => "Cargo registry path",
            Kind::ModulePath => "Module path",
            Kind::Revision => "Source revision",
            Kind::DirtyTree => "Built from an uncommitted tree",
            Kind::ToolchainHash => "Toolchain commit",
            Kind::CompilerVersion => "Compiler version",
            Kind::BuildTime => "Build timestamp",
            Kind::SignedBy => "Who signed it",
            Kind::SignedWith => "The certificate it was signed with",
            Kind::SignedAt => "When it was signed",
            Kind::BuildId => "Build id",
            Kind::TeamId => "Apple developer team",
        }
    }

    /// One sentence on what a stranger learns from this. The report prints
    /// it under the finding, because knowing a path is in there is useless
    /// without knowing what it gives away.
    pub fn matters(self) -> &'static str {
        match self {
            Kind::HomePath => {
                "This is the account name on the machine that built the file. \
                 If you publish under a handle, it does not match this."
            }
            Kind::PdbPath => {
                "MSVC writes the full path of the debug file into every binary \
                 by default. It carries your Windows user name and the folder \
                 layout you keep your work in."
            }
            Kind::CargoRegistry => {
                "Panic messages keep the path they were compiled from, so the \
                 home directory survives even a stripped release build."
            }
            Kind::ModulePath => {
                "The import path names the account and the repository, even \
                 when the binary is handed out with no other context."
            }
            Kind::Revision => {
                "The exact commit this was built from. It ties the binary to \
                 one point in a history that may be public."
            }
            Kind::DirtyTree => {
                "The tree had uncommitted changes when this was built, so the \
                 published code is not the code that produced this file."
            }
            Kind::ToolchainHash => {
                "The commit of the compiler itself, which pins the exact \
                 toolchain build and narrows down when the machine was set up."
            }
            Kind::CompilerVersion => {
                "The compiler and version, which on Linux usually narrows the \
                 distribution and its release."
            }
            Kind::SignedBy => {
                "A signature names whoever signed, on purpose, in every copy \
                 of the file. A certificate issued to a company names the \
                 company; one issued to a person names that person, by their \
                 legal name rather than the handle they publish under."
            }
            Kind::SignedWith => {
                "The certificate's own number. Every binary signed with this \
                 certificate carries it, so two projects published under two \
                 names and signed with one certificate are one person."
            }
            Kind::SignedAt => {
                "A timestamping service read its clock at the moment this was \
                 signed. Unlike the link time it cannot be made reproducible, \
                 because it is not written by your build."
            }
            Kind::BuildId => {
                "A hash the linker writes to tie a binary to its debug \
                 information. It is the same in every copy of this build, so \
                 it matches a published file against one found anywhere else."
            }
            Kind::TeamId => {
                "The identifier of the Apple developer account this was signed \
                 under, which is registered to a named person or company."
            }
            Kind::BuildTime => {
                "When the file was linked. Gathered across several releases it \
                 outlines the hours somebody keeps, and so their time zone."
            }
        }
    }

    /// Whether this finding names a person rather than describing a
    /// machine. The exit code turns on it, so a build can be failed for
    /// carrying somebody's name and not merely for carrying a compiler
    /// version, which every binary does.
    pub fn identifies(self) -> bool {
        matches!(
            self,
            Kind::HomePath | Kind::PdbPath | Kind::CargoRegistry | Kind::SignedBy | Kind::TeamId
        )
    }

    /// Identity first, then the build environment, then timing. Someone
    /// reading a long report should meet the thing that names them before
    /// the thing that names their compiler.
    fn rank(self) -> u8 {
        match self {
            Kind::HomePath | Kind::PdbPath | Kind::CargoRegistry => 0,
            Kind::SignedBy | Kind::TeamId => 0,
            Kind::ModulePath | Kind::Revision | Kind::DirtyTree | Kind::SignedWith => 1,
            Kind::ToolchainHash | Kind::CompilerVersion | Kind::BuildId => 2,
            Kind::BuildTime | Kind::SignedAt => 3,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub kind: Kind,
    pub certainty: Certainty,
    /// Where this came from, said in the file's own vocabulary: a section
    /// name, a header field, a load command.
    pub site: String,
    /// The leak itself, unmasked. Masking happens on the way to the screen
    /// and nowhere else, so that the code doing the looking never has to
    /// think about who is going to read the result.
    pub value: String,
    /// What to do about it, or None when there is nothing to do but know.
    pub remedy: Option<String>,
    /// Whether this particular finding names a person. It follows from the
    /// kind most of the time, but not always: a debug record holding only a
    /// file name gives away a build identity and no account at all, and
    /// counting that as a name would be crying wolf.
    pub names: bool,
}

impl Finding {
    fn new(kind: Kind, certainty: Certainty, site: String, value: String) -> Self {
        Finding {
            names: certainty != Certainty::Unread && kind.identifies(),
            kind,
            certainty,
            site,
            value,
            remedy: None,
        }
    }

    pub fn measured(kind: Kind, site: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new(kind, Certainty::Measured, site.into(), value.into())
    }

    pub fn inferred(kind: Kind, site: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new(kind, Certainty::Inferred, site.into(), value.into())
    }

    pub fn unread(kind: Kind, site: impl Into<String>, why: impl Into<String>) -> Self {
        Self::new(kind, Certainty::Unread, site.into(), why.into())
    }

    pub fn fix(mut self, remedy: impl Into<String>) -> Self {
        self.remedy = Some(remedy.into());
        self
    }

    /// Says that this finding, of a kind that usually names somebody, does
    /// not this time.
    pub fn anonymous(mut self) -> Self {
        self.names = false;
        self
    }
}

/// Puts the report in reading order: identity before environment before
/// timing, findings of one kind together, and inside a kind the order they
/// were found in, which follows the file from front to back.
pub fn arrange(findings: &mut [Finding]) {
    findings.sort_by_key(|f| (f.kind.rank(), f.kind));
}
