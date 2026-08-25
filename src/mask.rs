// Hiding the names in a report that is itself made of hidden names.
//
// The output of this program is a list of things somebody did not mean to
// publish, so printing it in full by default would only move the leak into
// a terminal that gets pasted into an issue. Everything identifying goes
// out masked, and --reveal is the deliberate act of asking for it whole.
//
// Masking keeps the shape and drops the content. Seeing `k****` is enough
// to know a real name was found, and enough to recognise your own; it is
// not enough for a stranger to learn it.

/// The account directories worth masking: the ones where a personal name
/// follows. `/root` is deliberately absent. Everybody's root is called
/// root, so hiding it would cost readability and reveal nothing.
const ROOTS: [&str; 3] = ["/home/", "/Users/", "\\Users\\"];

pub fn identifier(name: &str) -> String {
    let count = name.chars().count();
    if count <= 2 {
        return "*".repeat(count.max(1));
    }
    name.chars()
        .enumerate()
        .map(|(i, c)| if i == 0 { c } else { '*' })
        .collect()
}

/// Masks the account name inside a path and leaves the rest of it standing.
/// The folders somebody keeps their work in are worth seeing and are not
/// what identifies them, so `\source\repos` survives while the name above
/// it does not.
pub fn path(text: &str) -> String {
    let mut out = String::from(text);
    for root in ROOTS {
        let mut from = 0;
        while let Some(at) = out.get(from..).and_then(|rest| rest.find(root)) {
            let start = from + at + root.len();
            // The name ends at the first character that cannot be part of
            // one. Stopping only at a separator would swallow everything up
            // to the next one when the path sits inside a longer sentence,
            // and the report puts several paths in a single line.
            let end = out
                .get(start..)
                .and_then(|rest| rest.find(|c: char| !in_a_name(c)))
                .map(|n| start + n)
                .unwrap_or(out.len());
            if end > start {
                let masked = identifier(&out[start..end]);
                out.replace_range(start..end, &masked);
                from = start + masked.len();
            } else {
                from = start;
            }
            if from >= out.len() {
                break;
            }
        }
    }
    out
}

/// Characters an account name is made of. The same rule the search uses,
/// kept here as well so that what gets masked is exactly what got found.
fn in_a_name(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ')
}

/// The one switch the rest of the program turns, so callers say what they
/// want printed and never how to hide it.
pub fn apply(text: &str, reveal: bool) -> String {
    if reveal { text.to_string() } else { path(text) }
}
