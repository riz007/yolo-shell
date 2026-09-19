//! CLI entry point and action dispatcher.
//!
//! The hook invokes this with the command the user just typed and branches on
//! the exit code. Anything other than 125 or 126 means we misbehaved, and the
//! hooks treat it as allow.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, IsTerminal, Write};

use yolo_shell::daemon;
use yolo_shell::fastpath::{self, FastPath};
use yolo_shell::jev_client::{self, Action, Context, Decision, Outcome, CONTEXT_ENV_VARS};

const EXIT_ALLOW: i32 = 0;
/// `--no-prompt` only: the caller asks for confirmation itself.
const EXIT_CONFIRM: i32 = 125;
const EXIT_BLOCK: i32 = 126;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
yolo — evaluate a shell command before it runs

USAGE:
    yolo [eval] [--no-prompt] <command>...
    yolo daemon [--idle-timeout <secs>]

OPTIONS:
    --no-prompt   never read from the terminal; report `warn_and_confirm`
                  as exit code 125 and let the caller do the asking

EXIT CODES:
    0      allow    — run the command
    125    confirm  — needs a y/N prompt (--no-prompt only)
    126    block    — abort the command

ENVIRONMENT:
    YOLO_BYPASS=1   skip evaluation entirely
    YOLO_DEBUG=1    trace decisions to stderr
    YOLO_SOCKET     daemon socket path
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        None => exit_with(EXIT_ALLOW),
        Some("-h" | "--help") => {
            eprint!("{USAGE}");
            exit_with(EXIT_ALLOW);
        }
        Some("-V" | "--version") => {
            eprintln!("yolo {VERSION}");
            exit_with(EXIT_ALLOW);
        }
        Some("daemon") => exit_with(run_daemon(&args[1..])),
        _ => {}
    }

    let mut rest = args.as_slice();
    if rest.first().is_some_and(|a| a == "eval") {
        rest = &rest[1..];
    }

    // ZLE holds the terminal in raw mode, where a child can't read a line
    // back, so the zsh widget prompts for itself.
    let no_prompt = rest.first().is_some_and(|a| a == "--no-prompt");
    if no_prompt {
        rest = &rest[1..];
    }

    // Hooks pass one argument; `cargo run -- rm -rf /` passes many.
    let command = rest.join(" ");

    exit_with(run(&command, no_prompt));
}

fn run(command: &str, no_prompt: bool) -> i32 {
    let command = command.trim();

    if let Some(bypassed) = bypass_reason(command) {
        trace(&format!("bypass ({bypassed})"));
        return EXIT_ALLOW;
    }

    if fastpath::classify(command) == FastPath::Allow {
        trace("fast-path: allowlisted");
        return EXIT_ALLOW;
    }

    let context = gather_context(command);
    let outcome = decide(&context);

    trace(&format!(
        "{} decided in {}ms: risk {}/10{}",
        outcome.source,
        outcome.elapsed.as_millis(),
        outcome.decision.risk_score,
        outcome
            .note
            .as_deref()
            .map(|note| format!(" ({note})"))
            .unwrap_or_default(),
    ));

    dispatch(&outcome.decision, command, no_prompt)
}

/// The daemon when one is listening, the in-process path otherwise. Both end
/// at local heuristics if Jev cannot answer.
fn decide(context: &Context) -> Outcome {
    match daemon::decide(context, jev_client::deadline()) {
        Some(outcome) => outcome,
        None => jev_client::evaluate(context),
    }
}

fn run_daemon(args: &[String]) -> i32 {
    let idle = args
        .iter()
        .position(|a| a == "--idle-timeout")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(daemon::DEFAULT_IDLE_TIMEOUT_SECS);

    match daemon::serve(std::time::Duration::from_secs(idle)) {
        Ok(()) => EXIT_ALLOW,
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "yolo-daemon: {err}");
            1
        }
    }
}

fn bypass_reason(command: &str) -> Option<&'static str> {
    if std::env::var_os("YOLO_BYPASS").is_some_and(|v| !v.is_empty() && v != "0") {
        return Some("YOLO_BYPASS");
    }
    if command == "yolo" || command.starts_with("yolo ") {
        return Some("yolo prefix");
    }
    None
}

fn dispatch(decision: &Decision, command: &str, no_prompt: bool) -> i32 {
    match decision.action {
        Action::AllowImmediately => EXIT_ALLOW,
        Action::WarnAndConfirm => {
            warn_banner(decision, command);
            if no_prompt {
                return EXIT_CONFIRM;
            }
            match confirm() {
                Some(true) => EXIT_ALLOW,
                Some(false) => EXIT_BLOCK,
                // No terminal to ask on. Fail open rather than silently
                // swallowing the command.
                None => {
                    trace("no tty for confirmation; failing open");
                    EXIT_ALLOW
                }
            }
        }
        Action::BlockCompletely => {
            block_banner(decision, command);
            EXIT_BLOCK
        }
    }
}

fn warn_banner(decision: &Decision, command: &str) {
    let (bold, yellow, dim, reset) = palette();
    let mut err = std::io::stderr();
    let _ = writeln!(
        err,
        "\n{yellow}{bold}⚠  YOLO-Shell{reset} {yellow}risk {}/10{reset}  {dim}{command}{reset}",
        decision.risk_score
    );
    if let Some(reason) = &decision.reason {
        let _ = writeln!(err, "   {reason}");
    }
}

fn block_banner(decision: &Decision, command: &str) {
    let (bold, _, dim, reset) = palette();
    let red = if reset.is_empty() { "" } else { "\x1b[31m" };
    let mut err = std::io::stderr();
    let _ = writeln!(
        err,
        "\n{red}{bold}⛔ YOLO-Shell blocked{reset} {red}risk {}/10{reset}  {dim}{command}{reset}",
        decision.risk_score
    );
    if let Some(reason) = &decision.reason {
        let _ = writeln!(err, "   {reason}");
    }
    let _ = writeln!(
        err,
        "   {dim}override: prefix the command with `yolo `{reset}"
    );
}

/// Reads `/dev/tty`, not stdin: the hook may be inside a pipeline, and
/// consuming stdin would corrupt it.
fn confirm() -> Option<bool> {
    let (bold, yellow, _, reset) = palette();
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()?;

    let mut out = tty.try_clone().ok()?;
    let _ = write!(out, "   {yellow}{bold}Run anyway?{reset} [y/N] ");
    let _ = out.flush();

    let mut answer = String::new();
    BufReader::new(tty).read_line(&mut answer).ok()?;

    Some(matches!(answer.trim(), "y" | "Y" | "yes" | "Yes"))
}

fn gather_context(command: &str) -> Context {
    let pwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default();

    let env_context = CONTEXT_ENV_VARS
        .iter()
        .filter_map(|key| {
            std::env::var(key)
                .ok()
                .map(|value| (key.to_string(), value))
        })
        .collect::<BTreeMap<_, _>>();

    Context {
        command: command.to_string(),
        git_branch: current_git_branch(),
        pwd,
        env_context,
    }
}

/// Reads `.git/HEAD` directly. Shelling out to `git rev-parse` costs ~10ms
/// of process spawn, which is the entire local budget.
fn current_git_branch() -> Option<String> {
    let mut dir = std::env::current_dir().ok()?;

    loop {
        let git = dir.join(".git");
        if git.is_dir() {
            let head = std::fs::read_to_string(git.join("HEAD")).ok()?;
            // "ref: refs/heads/main\n", or a raw SHA when detached.
            let branch = head.trim().strip_prefix("ref: refs/heads/")?;
            return Some(branch.to_string());
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// `(bold, accent, dim, reset)`, empty when stderr isn't a terminal.
fn palette() -> (&'static str, &'static str, &'static str, &'static str) {
    if std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none() {
        ("\x1b[1m", "\x1b[33m", "\x1b[2m", "\x1b[0m")
    } else {
        ("", "", "", "")
    }
}

/// stderr only, so `cmd1 | cmd2` stays intact.
fn trace(message: &str) {
    if std::env::var_os("YOLO_DEBUG").is_some() {
        let _ = writeln!(std::io::stderr(), "yolo: {message}");
    }
}

fn exit_with(code: i32) -> ! {
    let _ = std::io::stderr().flush();
    std::process::exit(code)
}
