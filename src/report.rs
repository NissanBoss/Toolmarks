// Putting the findings on the screen.
//
// The shape of this report is an argument. Each finding leads with what was
// found, then says where it came from, then says what a stranger learns
// from it, and only then offers a fix. Somebody who stops reading after the
// first line still knows the important part, and somebody who reads to the
// end knows what to type.
//
// The closing line counts three things separately: what names a person,
// what merely describes a machine, and what could not be read at all. That
// last number is the one this program exists to keep honest. A file with
// nothing found and a file with nothing readable look identical from the
// outside, and they are not the same file.

use crate::binary::Opened;
use crate::finding::{Certainty, Finding};
use crate::mask;

/// Wide enough to read comfortably, narrow enough to survive being pasted
/// into an issue with a quote bar down the left.
const WIDTH: usize = 74;

pub fn render(name: &str, opened: &Opened, findings: &[Finding], reveal: bool) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "{name}: {}, {} {} read\n",
        opened.format.name(),
        opened.sections.len(),
        if opened.sections.len() == 1 {
            "section"
        } else {
            "sections"
        }
    ));

    if findings.is_empty() {
        out.push_str(
            "\nNothing found. Every place that usually carries a name was read \
             and none of them had one.\n",
        );
        return out;
    }

    for finding in findings {
        out.push('\n');
        out.push_str(&heading(finding));
        out.push('\n');

        match finding.certainty {
            Certainty::Unread => {
                out.push_str(&wrap(&finding.value, "  "));
            }
            _ => {
                out.push_str(&wrap(&mask::apply(&finding.value, reveal), "  "));
                out.push_str(&format!("  found in: {}\n", finding.site));
                out.push_str(&wrap(finding.kind.matters(), "  "));
                if let Some(remedy) = &finding.remedy {
                    out.push_str(&wrap(&format!("to fix: {remedy}"), "  "));
                }
            }
        }
    }

    out.push('\n');
    out.push_str(&summary(findings, reveal));
    out
}

/// The title on the left and how sure we are on the right, so that a column
/// of findings can be skimmed for the word `unread` without reading any of
/// the text.
fn heading(finding: &Finding) -> String {
    let label = match finding.certainty {
        Certainty::Measured => "measured",
        Certainty::Inferred => "inferred",
        Certainty::Unread => "unread",
    };
    let title = finding.kind.title();
    let gap = WIDTH.saturating_sub(title.len() + label.len()).max(1);
    format!("{title}{}{label}", " ".repeat(gap))
}

fn summary(findings: &[Finding], reveal: bool) -> String {
    let unread = findings
        .iter()
        .filter(|f| f.certainty == Certainty::Unread)
        .count();
    let naming = findings.iter().filter(|f| f.names).count();
    let rest = findings.len() - unread - naming;

    let mut lines = Vec::new();
    lines.push(match naming {
        0 => "Nothing in this file names a person.".to_string(),
        1 => "One finding names a person.".to_string(),
        n => format!("{n} findings name a person."),
    });
    // "One more" only reads as English when there was a first one, and with
    // nothing naming anybody there was not.
    if rest > 0 {
        let more = if naming > 0 { "more " } else { "" };
        lines.push(match rest {
            1 => format!("One {more}describes the machine it was built on."),
            n => format!("{n} {more}describe the machine it was built on."),
        });
    }
    if unread > 0 {
        lines.push(match unread {
            1 => "One place could not be read, so it is not a clean result.".to_string(),
            n => format!("{n} places could not be read, so this is not a clean result."),
        });
    }
    if naming > 0 && !reveal {
        lines.push("Names are masked. Pass --reveal to print them whole.".to_string());
    }

    wrap(&lines.join(" "), "")
}

/// Greedy word wrap. A word longer than the line gets its own line rather
/// than being broken, because the long words here are paths and a path
/// split across two lines cannot be copied.
fn wrap(text: &str, indent: &str) -> String {
    let width = WIDTH.saturating_sub(indent.len());
    let mut out = String::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if line.is_empty() {
            line.push_str(word);
        } else if line.len() + 1 + word.len() <= width {
            line.push(' ');
            line.push_str(word);
        } else {
            out.push_str(indent);
            out.push_str(&line);
            out.push('\n');
            line.clear();
            line.push_str(word);
        }
    }
    if !line.is_empty() {
        out.push_str(indent);
        out.push_str(&line);
        out.push('\n');
    }
    out
}
