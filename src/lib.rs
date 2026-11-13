//! Sealbox: encrypt files and folders into a single password-protected
//! `.sbx` file, from a GUI or the command line.

pub mod archive;
pub mod cli;
pub mod crypto;
pub mod gui;

/// Minimum password length accepted when creating a new sealbox.
pub const MIN_PASSWORD_LEN: usize = 8;

/// Minimum zxcvbn score (0-4) accepted when creating a new sealbox.
/// 3 means "safely unguessable": roughly 10^10 guesses needed, which together
/// with Argon2id puts offline cracking out of practical reach.
pub const MIN_PASSWORD_SCORE: u8 = 3;

/// Strength assessment of a candidate password for a new sealbox.
pub struct Strength {
    /// zxcvbn score, 0 (terrible) to 4 (very strong).
    pub score: u8,
    pub acceptable: bool,
    /// Short human-readable verdict or advice.
    pub message: String,
}

/// Judge a new password: at least [`MIN_PASSWORD_LEN`] characters and a
/// zxcvbn score of at least [`MIN_PASSWORD_SCORE`].
pub fn password_strength(password: &str) -> Strength {
    if password.chars().count() < MIN_PASSWORD_LEN {
        let score = if password.is_empty() {
            0
        } else {
            u8::from(zxcvbn::zxcvbn(password, &[]).score()).min(1)
        };
        return Strength {
            score,
            acceptable: false,
            message: format!("Use at least {MIN_PASSWORD_LEN} characters."),
        };
    }
    let est = zxcvbn::zxcvbn(password, &["sealbox", "sbx"]);
    let score = u8::from(est.score());
    let acceptable = score >= MIN_PASSWORD_SCORE;
    let message = if acceptable {
        if score == 4 {
            "Very strong password."
        } else {
            "Strong password."
        }
        .to_string()
    } else {
        let fb = est.feedback();
        let warning = fb.and_then(|f| f.warning()).map(|w| w.to_string());
        let tip = fb
            .and_then(|f| f.suggestions().first())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Add more words or characters.".into());
        match warning {
            Some(w) => format!("Too easy to guess: {w} {tip}"),
            None => format!("Too easy to guess. {tip}"),
        }
    };
    Strength {
        score,
        acceptable,
        message,
    }
}

/// Is this an existing file with a `.sbx` extension? Sealbox files contain
/// no recognisable signature, so the extension is the only way to spot them.
pub fn is_sealbox_path(p: &std::path::Path) -> bool {
    p.is_file() && p.extension().is_some_and(|e| e.eq_ignore_ascii_case("sbx"))
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_policy() {
        for weak in [
            "",
            "short",
            "password",
            "password123",
            "qwertyuiop",
            "aaaaaaaaaaaa",
        ] {
            assert!(!password_strength(weak).acceptable, "{weak:?} accepted");
        }
        for strong in [
            "correct horse battery",
            "tE8#vQ!29zLp",
            "maple-orbit-violin-cactus",
        ] {
            assert!(password_strength(strong).acceptable, "{strong:?} rejected");
        }
    }
}
