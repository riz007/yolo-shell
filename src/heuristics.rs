//! Offline decision engine. Used whenever Jev times out, is unreachable, or
//! has no key configured.
//!
//! Bands follow the decision schema: 1–3 low, 4–7 moderate, 8–10 severe. A
//! rule sets a base score, context escalates it, highest match wins. This is
//! allowed to block — the escape hatch is `yolo `, not a permissive default.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::RegexSet;

use crate::jev_client::{band_action, Context, Decision, Outcome, Source};

const MODERATE: u8 = 4;
const SEVERE: u8 = 8;

struct Rule {
    pattern: &'static str,
    score: u8,
    reason: &'static str,
    /// Score rises when a protected branch is involved.
    branch_sensitive: bool,
}

const fn rule(pattern: &'static str, score: u8, reason: &'static str) -> Rule {
    Rule {
        pattern,
        score,
        reason,
        branch_sensitive: false,
    }
}

const fn branch_rule(pattern: &'static str, score: u8, reason: &'static str) -> Rule {
    Rule {
        pattern,
        score,
        reason,
        branch_sensitive: true,
    }
}

/// Patterns are ASCII-only (`(?i)`) for the same reason the redactor's are:
/// this table is compiled from scratch in every process that reaches it.
static RULES: &[Rule] = &[
    // ---- Unrecoverable: destroys the machine or its filesystems. ----
    rule(
        r#"(?i)\brm\s+(?:-\S+\s+)*(?:/|/\*|~|~/\*|\$HOME)\s*(?:$|['"`]|[;&|])"#,
        10,
        "recursive delete of the filesystem root or home directory",
    ),
    rule(
        r"(?i)\brm\b[^;&]*--no-preserve-root",
        10,
        "delete with root protection disabled",
    ),
    rule(r"(?i)\bmkfs(?:\.\w+)?\s", 10, "formats a filesystem"),
    rule(
        r"(?i)\bdd\b[^|;&]*\bof=/dev/",
        10,
        "raw write to a block device",
    ),
    rule(
        r"(?i)>\s*/dev/(?:sd|hd|disk|nvme|vd)",
        10,
        "redirects over a block device",
    ),
    rule(
        r"(?i)\b(?:shred|wipefs)\b[^|;&]*/dev/",
        10,
        "wipes a block device",
    ),
    rule(
        r"(?i)\bchmod\s+(?:-\S+\s+)*(?:777|a\+rwx)\s+/\s*$",
        10,
        "opens up the entire filesystem",
    ),
    rule(r":\(\)\s*\{[^}]*\|[^}]*&[^}]*\}", 10, "fork bomb"),
    rule(
        r"(?i)\brm\s+(?:-\S*[rR]\S*\s+)+/(?:etc|usr|var|bin|sbin|lib|opt|boot|dev|proc|sys|System|Library|Applications)\b",
        9,
        "recursive delete of a system directory",
    ),
    // ---- Severe: unrecoverable state, or production assets. ----
    rule(
        r"(?i)\bdrop\s+(?:database|table|schema)\b",
        8,
        "drops a database object",
    ),
    rule(r"(?i)\btruncate\s+table\b", 8, "truncates a table"),
    rule(
        r"(?i)\bkubectl\s+delete\s+(?:namespace|ns)\b",
        8,
        "deletes a Kubernetes namespace",
    ),
    rule(
        r"(?i)\bterraform\s+destroy\b",
        8,
        "tears down infrastructure",
    ),
    rule(
        r"(?i)\baws\s+s3\s+(?:rb\b|rm\b[^|;&]*--recursive)",
        8,
        "recursively deletes an S3 bucket",
    ),
    // ---- Moderate: recoverable, but worth a look. ----
    rule(r"(?i)\bdelete\s+from\b", 7, "deletes rows"),
    // Jev scored `rails db:drop` at 8 in production where the rule table said
    // 1, so offline the database was dropped without a prompt.
    //
    // `(?x)` because a raw string has no line continuation: a trailing `\`
    // becomes part of the pattern, and the rule compiles but never matches.
    rule(
        r"(?ix)
          \b(?:
              (?: rails | rake | bundle \s+ exec \s+ rails ) \s+ db:(?: drop | reset | purge )
            | prisma \s+ migrate \s+ reset
            | sequelize \s+ db:drop
            | alembic \s+ downgrade \s+ base
            | manage\.py \s+ flush
          )\b",
        7,
        "drops or resets the application database",
    ),
    branch_rule(
        r"(?i)\bgit\s+push\b[^|;&]*\s(?:--force|-f)(?:\s|$)",
        6,
        "force-push rewrites remote history",
    ),
    branch_rule(
        r"(?i)\bgit\s+push\b[^|;&]*\s--force-with-lease\b",
        4,
        "force-push (lease-checked) rewrites remote history",
    ),
    branch_rule(
        r"(?i)\bgit\s+push\b[^|;&]*\s--delete\b",
        7,
        "deletes a remote branch",
    ),
    rule(
        r"(?i)\b(?:npm|cargo|gem)\s+publish\b",
        7,
        "publishes a package, which cannot be unpublished",
    ),
    rule(
        r"(?i)\b(?:curl|wget)\b.*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b",
        7,
        "pipes a remote script into a shell",
    ),
    rule(
        r"(?i)\bgit\s+reset\s+(?:-\S+\s+)*--hard\b",
        6,
        "discards uncommitted work",
    ),
    rule(
        r"(?i)\bgit\s+clean\b[^|;&]*\s-\S*[fd]",
        6,
        "deletes untracked files",
    ),
    rule(r"(?i)\bterraform\s+apply\b", 6, "changes infrastructure"),
    rule(
        r"(?i)\bkubectl\s+delete\b",
        6,
        "deletes a Kubernetes resource",
    ),
    rule(
        r"(?i)\bfind\b[^|;&]*(?:-delete\b|-exec\s+rm\b)",
        6,
        "deletes matched files",
    ),
    rule(
        r"(?i)>\s*[^\s|;&]*(?:\.env|\.zshrc|\.bashrc|\.profile|\.ssh/|authorized_keys|id_rsa)",
        6,
        "overwrites a shell or credential file",
    ),
    rule(
        r"(?i)\brm\s+(?:-\S*[rRf]\S*\s+)",
        5,
        "recursive or forced delete",
    ),
    branch_rule(
        r"(?i)\bgit\s+branch\s+(?:-D|-d|--delete)\b",
        5,
        "deletes a branch",
    ),
    rule(
        r"(?i)\bgit\s+(?:checkout|restore)\s+(?:--\s+)?\.\s*$",
        5,
        "discards local changes",
    ),
    rule(
        r"(?i)\bgit\s+stash\s+(?:drop|clear)\b",
        5,
        "discards stashed work",
    ),
    rule(
        r"(?i)\bdocker\s+(?:system\s+prune|volume\s+rm|rmi)\b",
        5,
        "removes Docker state",
    ),
    rule(
        r"(?i)\bch(?:mod|own)\b[^|;&]*\s-\S*R",
        5,
        "recursive permission change",
    ),
    rule(
        r"(?i)\b(?:apt|apt-get|yum|dnf)\s+(?:remove|purge|autoremove)\b",
        5,
        "removes system packages",
    ),
    rule(
        r"(?i)\bsystemctl\s+(?:stop|disable|mask)\b",
        5,
        "stops a system service",
    ),
    rule(r"(?i)\b(?:killall|pkill)\b", 4, "kills processes by name"),
    rule(
        r"(?i)\bhistory\s+-\S*[cdwa]",
        4,
        "clears or rewrites shell history",
    ),
    rule(r"(?i)\bbrew\s+uninstall\b", 4, "uninstalls a package"),
    rule(r"^\s*sudo\b", 4, "runs as root"),
    // ---- Low: noted, but allowed through. ----
    rule(r"(?i)\brm\s", 3, "deletes files"),
];

/// Programs whose quoted arguments are text to search, print or record -
/// never code to run. Without this, `grep -r "DROP TABLE" migrations/` reads
/// as a database drop and gets blocked.
///
/// Deliberately an allowlist, and kept sorted. An unrecognised program keeps
/// its quotes, so a missing entry costs a false positive, never a miss -
/// which is why `psql -c`, `mysql -e` and `sh -c` are absent: those really do
/// execute what they are handed.
pub const DATA_ARG_COMMANDS: &[&str] = &[
    "ack", "awk", "column", "comm", "cut", "echo", "fgrep", "fold", "grep", "jq", "printf", "rev",
    "rg", "sed", "sort", "strings", "tee", "tr", "uniq",
];

/// Blank the contents of quoted arguments that are plainly data, so the rule
/// table scores what a command *does*, not what it mentions.
fn scorable(command: &str) -> Cow<'_, str> {
    if !command.contains('"') && !command.contains('\'') {
        return Cow::Borrowed(command);
    }

    let mut out = String::with_capacity(command.len());
    let mut start = 0;

    for (i, &byte) in command.as_bytes().iter().enumerate() {
        if matches!(byte, b';' | b'|' | b'&' | b'\n') {
            push_segment(&command[start..i], &mut out);
            out.push(byte as char);
            start = i + 1;
        }
    }
    push_segment(&command[start..], &mut out);

    Cow::Owned(out)
}

fn push_segment(segment: &str, out: &mut String) {
    if takes_data_arguments(segment) {
        blank_quoted(segment, out);
    } else {
        out.push_str(segment);
    }
}

fn takes_data_arguments(segment: &str) -> bool {
    let mut tokens = segment.split_ascii_whitespace();
    let Some(program) = tokens.next() else {
        return false;
    };
    let program = program.rsplit('/').next().unwrap_or(program);

    if DATA_ARG_COMMANDS.binary_search(&program).is_ok() {
        return true;
    }

    // `git commit -m "remove rm -rf from deploy"` records a message. git's
    // destructive subcommands take no quoted code.
    program == "git" && matches!(tokens.next(), Some("commit" | "tag" | "notes"))
}

/// Leaves an unterminated quote alone, which keeps the command scorable as
/// written rather than silently swallowing the rest of the line.
fn blank_quoted(segment: &str, out: &mut String) {
    let mut rest = segment;

    while let Some(open) = rest.find(['"', '\'']) {
        let quote = rest.as_bytes()[open] as char;
        out.push_str(&rest[..=open]);

        match rest[open + 1..].find(quote) {
            Some(close) => {
                out.push(quote);
                rest = &rest[open + 1 + close + 1..];
            }
            None => {
                out.push_str(&rest[open + 1..]);
                return;
            }
        }
    }

    out.push_str(rest);
}

fn is_protected_branch(name: &str) -> bool {
    matches!(name, "main" | "master" | "prod" | "production" | "release")
        || name.starts_with("release/")
}

/// Catches `git push origin main --force` typed from a feature branch.
fn command_names_protected_branch(command: &str) -> bool {
    command.split_ascii_whitespace().any(is_protected_branch)
}

/// Returns the variable name rather than a bool so the reason can cite it.
fn production_marker(env: &BTreeMap<String, String>) -> Option<&str> {
    const NOT_PRODUCTION: &[&str] = &["nonprod", "non-prod", "preprod", "pre-prod"];

    env.iter().find_map(|(key, value)| {
        let value = value.to_ascii_lowercase();
        let looks_prod =
            value.contains("prod") && !NOT_PRODUCTION.iter().any(|n| value.contains(n));
        looks_prod.then_some(key.as_str())
    })
}

/// Asserted in the test suite: a compile failure here is silent and total.
pub fn engine_ready() -> bool {
    rule_set().is_some()
}

fn rule_set() -> Option<&'static RegexSet> {
    static SET: OnceLock<Option<RegexSet>> = OnceLock::new();
    SET.get_or_init(|| RegexSet::new(RULES.iter().map(|r| r.pattern)).ok())
        .as_ref()
}

/// Scores the command as typed — redaction guards the network boundary, and
/// nothing here leaves the machine.
pub fn evaluate(context: &Context) -> Decision {
    let Some(set) = rule_set() else {
        return Decision::fail_open();
    };

    let command = scorable(&context.command);
    let matched = set
        .matches(&command)
        .into_iter()
        .filter_map(|index| RULES.get(index))
        .max_by_key(|rule| rule.score);

    let Some(rule) = matched else {
        return Decision::fail_open();
    };

    let mut score = rule.score;
    let mut reasons = vec![rule.reason.to_string()];

    if rule.branch_sensitive {
        let on_protected = context
            .git_branch
            .as_deref()
            .is_some_and(is_protected_branch);

        if on_protected || command_names_protected_branch(&command) {
            score = score.saturating_add(3);
            reasons.push("on a protected branch".to_string());
        }
    }

    // Production sharpens an already-risky command; it doesn't make a
    // harmless one risky.
    if score >= MODERATE {
        if let Some(marker) = production_marker(&context.env_context) {
            score = score.saturating_add(2);
            reasons.push(format!("production context ({marker})"));
        }
    }

    let score = score.clamp(1, 10);

    Decision {
        is_destructive: score >= MODERATE,
        risk_score: score,
        action: band_action(score),
        reason: Some(reasons.join("; ")),
    }
}

/// Hold a Jev decision to the local engine's severe rules.
///
/// The local rules are deterministic and encode the spec's own examples, so a
/// model must not talk us out of one. Jev stays free to relax anything below
/// the severe band - that is where its judgement earns its keep, as with
/// `rm -rf ./build`, which a rebuild restores.
///
/// Observed live: `git push --force origin main` scored 7 from Jev and 9
/// locally, so the block the spec calls for became a y/N prompt.
pub fn apply_severe_floor(outcome: Outcome, context: &Context) -> Outcome {
    if outcome.source != Source::Jev || outcome.decision.risk_score >= SEVERE {
        return outcome;
    }

    let local = evaluate(context);
    if local.risk_score < SEVERE || local.risk_score <= outcome.decision.risk_score {
        return outcome;
    }

    let jev_score = outcome.decision.risk_score;
    Outcome {
        decision: Decision {
            is_destructive: true,
            risk_score: local.risk_score,
            action: outcome.decision.action.max(band_action(local.risk_score)),
            reason: local.reason,
        },
        note: Some(match outcome.note {
            Some(note) => format!(
                "{note}; local rule raised {jev_score} to {}",
                local.risk_score
            ),
            None => format!("local rule raised {jev_score} to {}", local.risk_score),
        }),
        ..outcome
    }
}
