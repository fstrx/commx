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

/// Longest file name kept from a peer (characters).
pub const MAX_FILE_NAME: usize = 128;

/// Reduce a peer-supplied file name to one harmless path component.
///
/// The name comes from another room member and ends up in `dir.join(name)`
/// on export, so it must never be able to reach outside `dir`. Separators of
/// *every* platform are treated as such (a Windows peer's `..\x` must be as
/// dead on macOS as on Windows), only the last component survives, and names
/// that are special to some filesystem are defused.
pub fn safe_file_name(name: &str) -> String {
    let last = name.rsplit(['/', '\\']).next().unwrap_or("");
    let mut s: String = clean(last)
        .chars()
        .map(|c| if matches!(c, ':' | '\0' | '<' | '>' | '"' | '|' | '?' | '*') { '_' } else { c })
        .collect();
    // Windows silently drops trailing dots/spaces, which can turn names into
    // other names; leading dots make hidden/dot files (".zshenv").
    s = s.trim().trim_end_matches(['.', ' ']).to_string();
    if s.starts_with('.') {
        s = format!("_{}", s.trim_start_matches('.'));
    }
    let stem = s.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit());
    if reserved {
        s = format!("_{s}");
    }
    let s: String = s.chars().take(MAX_FILE_NAME).collect();
    if s.is_empty() || s == "_" {
        "file".into()
    } else {
        s
    }
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

    #[test]
    fn file_names_cannot_escape_or_trick_the_filesystem() {
        for (evil, want) in [
            ("../Library/LaunchAgents/com.apple.update.plist", "com.apple.update.plist"),
            ("..\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x.bat", "x.bat"),
            ("/etc/passwd", "passwd"),
            ("C:\\Windows\\evil.dll", "evil.dll"),
            ("C:evil.dll", "C_evil.dll"),
            ("../.ssh/authorized_keys", "authorized_keys"),
            (".zshenv", "_zshenv"),
            ("..", "file"),
            (".", "file"),
            ("", "file"),
            ("a/b/", "file"),
            ("CON", "_CON"),
            ("com1.txt", "_com1.txt"),
            ("report.pdf. . ", "report.pdf"),
            ("invoice.pdf\u{202E}fdp.exe", "invoice.pdf\u{FFFD}fdp.exe"),
            ("ok name (1).txt", "ok name (1).txt"),
        ] {
            assert_eq!(safe_file_name(evil), want, "{evil:?}");
        }
        let long = "a".repeat(500) + "/../x";
        assert_eq!(safe_file_name(&long), "x");
        assert_eq!(safe_file_name(&"b".repeat(500)).chars().count(), MAX_FILE_NAME);
        // Whatever goes in, the result is exactly one normal path component.
        for evil in ["../../x", "/abs", "\\\\server\\share\\f", "x/..", "./.", "~/.bashrc"] {
            let out = safe_file_name(evil);
            let comps: Vec<_> = std::path::Path::new(&out).components().collect();
            assert!(matches!(comps.as_slice(), [std::path::Component::Normal(_)]), "{evil:?} -> {out:?}");
        }
    }
}
