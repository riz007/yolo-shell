//! Local allowlist filter. Decides whether a command is safe enough to skip
//! evaluation entirely.
//!
//! Anything we can't cheaply prove safe goes to Evaluate. A wrong Evaluate
//! costs latency; a wrong Allow costs a filesystem.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastPath {
    Allow,
    Evaluate,
}

/// Read-only commands. Kept sorted for `binary_search`.
///
/// `env`, `command`, `xargs`, `time` and `nice` are excluded because they run
/// another program. `less`, `man` and `vi` have `!cmd` shell escapes. `find`
/// has `-exec` and `-delete`.
pub const ALLOWLIST: &[&str] = &[
    "basename", "cat", "cd", "clear", "date", "df", "dirname", "dirs", "du", "echo", "file",
    "groups", "head", "history", "hostname", "id", "ls", "printenv", "pwd", "stat", "tail", "tree",
    "tty", "type", "uname", "uptime", "wc", "whatis", "which", "whoami",
];

/// Kept sorted for `binary_search`.
///
/// `branch`, `tag`, `config`, `stash` and `remote` are excluded — each has a
/// destructive flag (`-D`, `--unset`, `drop`, `remove`).
pub const GIT_READ_ONLY_SUBCOMMANDS: &[&str] = &[
    "blame",
    "cat-file",
    "describe",
    "diff",
    "grep",
    "log",
    "ls-files",
    "ls-remote",
    "ls-tree",
    "reflog",
    "rev-parse",
    "shortlog",
    "show",
    "status",
    "whatchanged",
];

pub fn classify(command: &str) -> FastPath {
    let command = command.trim();

    if command.is_empty() {
        return FastPath::Allow;
    }

    if has_disqualifying_syntax(command) {
        return FastPath::Evaluate;
    }

    for segment in segments(command) {
        if !segment_is_allowlisted(segment) {
            return FastPath::Evaluate;
        }
    }

    FastPath::Allow
}

/// Syntax that lets a command mean more than its literal words. Bailing here
/// is what makes the naive tokenizing below sound: with redirection,
/// substitution and subshells gone, a segment's first word is the program
/// that runs.
fn has_disqualifying_syntax(command: &str) -> bool {
    let bytes = command.as_bytes();

    for (i, &byte) in bytes.iter().enumerate() {
        match byte {
            b'>' | b'<' => return true,
            b'`' | b'(' | b')' => return true,
            b'&' => {
                // `cmd &` backgrounds. `&&` is just a list separator.
                let prev_is_amp = i > 0 && bytes[i - 1] == b'&';
                let next_is_amp = bytes.get(i + 1) == Some(&b'&');
                if !prev_is_amp && !next_is_amp {
                    return true;
                }
            }
            _ => {}
        }
    }

    false
}

/// Splitting inside quotes is safe: over-splitting only yields more segments
/// that each have to be allowlisted, and a quoted fragment never matches a
/// bare command name.
fn segments(command: &str) -> impl Iterator<Item = &str> {
    command
        .split([';', '|', '&', '\n'])
        .filter(|segment| !segment.trim().is_empty())
}

fn segment_is_allowlisted(segment: &str) -> bool {
    let mut tokens = segment.split_ascii_whitespace();

    let Some(program) = tokens.next() else {
        return true;
    };

    // `./ls` is whatever sits in this directory, and a leading `FOO=bar` can
    // rewrite PATH out from under us.
    if program.contains('/') || program.contains('=') {
        return false;
    }

    if program == "git" {
        // Subcommand must come first, or `git --exec-path=/tmp log` runs an
        // attacker's `git-log`.
        return tokens.next().is_some_and(is_read_only_git_subcommand);
    }

    if program == "history" {
        // `-c` clears it, `-d` deletes an entry, `-w` rewrites the file.
        // A bare count (`history 20`) only reads.
        return !tokens.any(has_letter_flag);
    }

    is_read_only_command(program)
}

fn has_letter_flag(token: &str) -> bool {
    token
        .strip_prefix('-')
        .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_alphabetic()))
}

pub fn is_read_only_command(program: &str) -> bool {
    ALLOWLIST.binary_search(&program).is_ok()
}

pub fn is_read_only_git_subcommand(subcommand: &str) -> bool {
    GIT_READ_ONLY_SUBCOMMANDS.binary_search(&subcommand).is_ok()
}
