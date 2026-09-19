//! Secret scrubbing, applied at the wire boundary.
//!
//! The aim is to drop secrets without dropping signal: Jev still has to see
//! that a command targets production, so matches keep their structure and
//! only the value is replaced.

use std::sync::OnceLock;

use regex::{Captures, Regex};

pub const REDACTED: &str = "[REDACTED]";

/// One pass, one automaton. Branches are ordered most-specific first, which
/// is the order a leftmost-first engine prefers at the same offset.
///
/// Two traps to keep in mind when editing:
///   - `(?x)` strips whitespace inside character classes too, so `[ \t]`
///     silently means tab-only. Hence `[\x20\t]`.
///   - Branches whose value could already be a `[REDACTED]` accept it
///     explicitly. That is what keeps a second pass a no-op.
const PATTERN: &str = r#"(?x)
    # PEM private keys pasted inline.
      -----BEGIN[\sA-Z]*PRIVATE\sKEY-----[\s\S]*?-----END[\sA-Z]*PRIVATE\sKEY-----
    |
    # Connection-string userinfo. Scheme, user and host stay; password goes.
      (?P<url_scheme>[a-zA-Z][a-zA-Z0-9+.\-]*://)
      (?P<url_user>[^:/@\s]+) : [^@/\s]+ @
    |
    # `Authorization: Bearer <token>`. The scheme is signal; the token is not.
      (?P<hdr>(?i-u:authorization)\s*:\s*(?:(?i-u:bearer|basic|token)\s+)?)
      (?: [A-Za-z0-9\-._~+/=]+ | \[REDACTED\] )
    |
    # A bare bearer/basic credential, e.g. inside a quoted header argument.
      (?P<scheme>\b(?i-u:bearer|basic)\s+) (?: [A-Za-z0-9\-._~+/=]{8,} | \[REDACTED\] )
    |
    # Credential-looking name assigned with `=`. Covers both
    # `AWS_SECRET_ACCESS_KEY=...` and `--password=...`.
      (?P<kv>(?i-u:[\w.\-]*(?: password | passwd | passphrase | secret | token
                          | credential | api[_\-]?key | access[_\-]?key
                          | private[_\-]?key | encryption[_\-]?key )[\w.\-]*))
      = \S+
    |
    # The same names as a flag with a spaced value. The value may not start
    # with `-`, so `--token --verbose` does not eat the next flag.
      (?P<flag>--?(?i-u:[\w\-]*(?: password | passwd | passphrase | secret | token
                              | credential | api[_\-]?key | access[_\-]?key
                              | private[_\-]?key )[\w\-]*))
      [\x20\t]+ (?: "[^"]*" | '[^']*' | [^\s\-]\S* )
    |
    # `-u user:pass`. The colon distinguishes credentials from `sort -u file`;
    # rejecting a following `/` leaves `-u redis://u:p@host` to the userinfo
    # branch above, which keeps the host.
      (?P<u_lead>^|\s) (?P<u_flag>--user|-u) [\x20\t]+ [^\s/:]+ : [^\s/] \S*
    |
    # Shapes that are self-evidently secret with no surrounding name.
      \b(?: sk-ant-[A-Za-z0-9_\-]{16,}
          | sk-[A-Za-z0-9]{16,}
          | gh[pousr]_[A-Za-z0-9]{16,}
          | github_pat_[A-Za-z0-9_]{20,}
          | glpat-[A-Za-z0-9_\-]{16,}
          | xox[baprs]-[A-Za-z0-9\-]{10,}
          | (?: AKIA | ASIA )[0-9A-Z]{16}
          | AIza[A-Za-z0-9_\-]{35}
          | npm_[A-Za-z0-9]{36}
          | hf_[A-Za-z0-9]{30,}
          | (?: sk | pk | rk )_(?: live | test )_[A-Za-z0-9]{16,}
          | eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}
      )
"#;

/// The hook spawns a fresh process per command, so this cache amortises
/// nothing — every command that reaches Jev pays the compile. ASCII folding
/// (`(?i-u:)`) instead of Unicode cut that from 4.4ms to 1.4ms.
///
/// `None` would mean we cannot scrub, so `redact` withholds everything rather
/// than guess. The test suite compiles `PATTERN` on every run.
fn pattern() -> Option<&'static Regex> {
    static CELL: OnceLock<Option<Regex>> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(PATTERN).ok()).as_ref()
}

pub fn redact(command: &str) -> String {
    let Some(pattern) = pattern() else {
        return REDACTED.to_string();
    };

    pattern
        .replace_all(command, |caps: &Captures| {
            if let (Some(scheme), Some(user)) = (caps.name("url_scheme"), caps.name("url_user")) {
                format!("{}{}:{}@", scheme.as_str(), user.as_str(), REDACTED)
            } else if let Some(hdr) = caps.name("hdr") {
                format!("{}{}", hdr.as_str(), REDACTED)
            } else if let Some(scheme) = caps.name("scheme") {
                format!("{}{}", scheme.as_str(), REDACTED)
            } else if let Some(kv) = caps.name("kv") {
                format!("{}={}", kv.as_str(), REDACTED)
            } else if let Some(flag) = caps.name("flag") {
                format!("{} {}", flag.as_str(), REDACTED)
            } else if let (Some(lead), Some(flag)) = (caps.name("u_lead"), caps.name("u_flag")) {
                format!("{}{} {}", lead.as_str(), flag.as_str(), REDACTED)
            } else {
                REDACTED.to_string()
            }
        })
        .into_owned()
}
