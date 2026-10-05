//! Sanitizing strings that came from other people.

/// Invisible / direction-changing characters that enable spoofing
/// (e.g. U+202E flips text so "gnp.exe" reads as "exe.png").
fn is_format(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{061C}' | '\u{180E}'
        | '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{206F}'
        | '\u{FEFF}'
        | '\u{FFF9}'..='\u{FFFB}')
}

/// Replace control and formatting characters so remote text can't inject
/// terminal escape sequences or reorder what's displayed.
pub fn clean(s: &str) -> String {
    s.chars().map(|c| if c.is_control() || is_format(c) { '\u{FFFD}' } else { c }).collect()
}

/// Names (aliases, rooms) must already be clean, non-empty and bounded.
pub fn valid_name(s: &str, max: usize) -> bool {
    !s.trim().is_empty() && s.len() <= max && s == s.trim() && clean(s) == s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_escapes_and_bidi() {
        assert_eq!(clean("hi\x1b[2J"), "hi\u{FFFD}[2J");
        assert_eq!(clean("a\u{202E}b"), "a\u{FFFD}b");
        assert_eq!(clean("normal text ✓"), "normal text ✓");
        assert!(valid_name("ghost", 32));
        assert!(!valid_name("gh\u{200B}ost", 32));
        assert!(!valid_name(" ghost", 32));
        assert!(!valid_name("", 32));
    }
}
