//! A resident process holding a warm connection to Jev.
//!
//! The hook spawns a fresh `yolo` per command, so the in-process path repeats
//! DNS + TCP + TLS every time — measured at ~590ms against us-west-2, on top
//! of a ~358ms warm round trip. The daemon pays the handshake once and answers
//! over a unix socket.
//!
//! It is strictly an accelerator. If the socket is missing, stale, or slow,
//! the CLI falls back to the in-process path and then to local heuristics, so
//! nothing here can prevent a decision being made.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::heuristics;
use crate::jev_client::{Context, Decision, JevClient, Outcome, Source};
use crate::redact;

/// Exit if nothing asks for a decision for this long.
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 8 * 60 * 60;

/// The command is redacted before it reaches the socket, so a raw command
/// never leaves the process that read it — same rule as the network boundary.
/// The daemon redacts again on the way out, which is a no-op because
/// redaction is idempotent.
#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub command: String,
    pub pwd: String,
    pub git_branch: Option<String>,
    pub env_context: BTreeMap<String, String>,
}

impl Request {
    pub fn from_context(context: &Context) -> Self {
        Self {
            command: redact::redact(&context.command),
            pwd: context.pwd.clone(),
            git_branch: context.git_branch.clone(),
            env_context: context.env_context.clone(),
        }
    }

    fn into_context(self) -> Context {
        Context {
            command: self.command,
            pwd: self.pwd,
            git_branch: self.git_branch,
            env_context: self.env_context,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Decided {
        decision: Decision,
        elapsed_ms: u64,
    },
    /// Jev could not answer. The caller runs its own heuristics rather than
    /// having the daemon duplicate that engine.
    Unavailable {
        error: String,
    },
}

/// `YOLO_SOCKET`, else a per-user runtime directory.
pub fn socket_path() -> PathBuf {
    if let Some(path) = std::env::var_os("YOLO_SOCKET") {
        return PathBuf::from(path);
    }
    for key in ["XDG_RUNTIME_DIR", "TMPDIR"] {
        if let Some(dir) = std::env::var_os(key) {
            return PathBuf::from(dir).join("yolo-shell.sock");
        }
    }
    let user = std::env::var("USER").unwrap_or_else(|_| "nobody".to_string());
    PathBuf::from(format!("/tmp/yolo-shell-{user}.sock"))
}

/// Refuse to talk to a socket someone else created. `$TMPDIR` is per-user on
/// macOS, but the `/tmp` fallback is not, and connecting there blindly would
/// hand another user's process our commands.
fn owned_by_current_user(path: &std::path::Path) -> bool {
    let Ok(home) = std::env::var("HOME") else {
        return false;
    };
    match (fs::metadata(home), fs::metadata(path)) {
        (Ok(ours), Ok(theirs)) => ours.uid() == theirs.uid(),
        _ => false,
    }
}

/// Ask the daemon.
///
/// `None` means no daemon is listening, so the caller should take the
/// in-process path. Once the socket accepts, every failure is answered from
/// local heuristics instead: falling through would spend the deadline a
/// second time on the network, and a sick daemon would cost double.
pub fn decide(context: &Context, deadline: Duration) -> Option<Outcome> {
    let started = Instant::now();

    // The daemon holds its own key, so it answers for callers that have none.
    // That makes an unset `JEV_API_KEY` mean "ask the daemon" instead of
    // "heuristics only" — which silently turned the rubric harness's local
    // column into a second Jev column. Consult it only when this process is
    // configured to call Jev itself.
    if !crate::jev_client::configured() {
        return None;
    }

    let path = socket_path();

    if !path.exists() || !owned_by_current_user(&path) {
        return None;
    }

    let stream = UnixStream::connect(&path).ok()?;

    Some(match exchange(&stream, context, deadline) {
        Ok(Response::Decided { decision, .. }) => Outcome {
            decision,
            source: Source::Jev,
            elapsed: started.elapsed(),
            note: Some("via daemon".to_string()),
        },
        Ok(Response::Unavailable { error }) => {
            locally(context, started, format!("daemon: {error}"))
        }
        Err(error) => locally(context, started, daemon_note(&error, deadline)),
    })
}

/// A socket read that hits `SO_RCVTIMEO` surfaces as `WouldBlock`, which
/// prints as "Resource temporarily unavailable (os error 35)" and tells the
/// reader nothing. Name the deadline instead — it is the actionable part.
fn daemon_note(error: &std::io::Error, deadline: Duration) -> String {
    match error.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
            format!("daemon: no response within {}ms", deadline.as_millis())
        }
        _ => format!("daemon: {error}"),
    }
}

fn locally(context: &Context, started: Instant, note: String) -> Outcome {
    Outcome {
        decision: heuristics::evaluate(context),
        source: Source::Local,
        elapsed: started.elapsed(),
        note: Some(note),
    }
}

fn exchange(
    stream: &UnixStream,
    context: &Context,
    deadline: Duration,
) -> std::io::Result<Response> {
    stream.set_read_timeout(Some(deadline))?;
    stream.set_write_timeout(Some(deadline))?;

    let mut line = serde_json::to_string(&Request::from_context(context))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    line.push('\n');

    let mut writer = stream;
    writer.write_all(line.as_bytes())?;
    writer.flush()?;

    let mut answer = String::new();
    BufReader::new(stream).read_line(&mut answer)?;

    serde_json::from_str(&answer)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Run the daemon until idle. Blocks.
pub fn serve(idle_timeout: Duration) -> std::io::Result<()> {
    let path = socket_path();

    // sun_path is 104 bytes on macOS, 108 on Linux. The OS error for an
    // overlong path names neither the path nor the fix.
    if path.as_os_str().len() >= 100 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "socket path is {} bytes, too long for a unix socket: {}\n\
                 set YOLO_SOCKET to something shorter, e.g. /tmp/yolo.sock",
                path.as_os_str().len(),
                path.display()
            ),
        ));
    }

    let listener = bind(&path)?;

    // 0600: the daemon holds the API key, so anyone who can reach the socket
    // can spend it.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

    let client = match JevClient::from_env() {
        Ok(client) => {
            match client.warm() {
                Ok(()) => eprintln!(
                    "yolo-daemon: connection warm, listening on {}",
                    path.display()
                ),
                Err(err) => {
                    eprintln!("yolo-daemon: warm-up failed ({err}); will retry per request")
                }
            }
            Arc::new(client)
        }
        Err(err) => {
            let _ = fs::remove_file(&path);
            eprintln!("yolo-daemon: {err}");
            return Ok(());
        }
    };

    let last_seen = Arc::new(AtomicU64::new(now_secs()));
    spawn_idle_watchdog(Arc::clone(&last_seen), idle_timeout, path.clone());

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        last_seen.store(now_secs(), Ordering::Relaxed);

        let client = Arc::clone(&client);
        thread::spawn(move || handle(stream, &client));
    }

    Ok(())
}

/// Bind, clearing a socket left behind by a daemon that died. A socket with
/// a live listener means another daemon owns it.
fn bind(path: &std::path::Path) -> std::io::Result<UnixListener> {
    match UnixListener::bind(path) {
        Ok(listener) => Ok(listener),
        Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {
            if UnixStream::connect(path).is_ok() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    "another yolo daemon is already running",
                ));
            }
            fs::remove_file(path)?;
            UnixListener::bind(path)
        }
        Err(err) => Err(err),
    }
}

fn handle(stream: UnixStream, client: &JevClient) {
    let mut line = String::new();
    if BufReader::new(&stream).read_line(&mut line).is_err() {
        return;
    }

    let Ok(request) = serde_json::from_str::<Request>(&line) else {
        return;
    };

    let started = Instant::now();
    let response = match client.decide(&request.into_context()) {
        Ok(decision) => Response::Decided {
            decision: decision.sanitized(),
            elapsed_ms: started.elapsed().as_millis() as u64,
        },
        Err(err) => Response::Unavailable {
            error: err.to_string(),
        },
    };

    let Ok(mut body) = serde_json::to_string(&response) else {
        return;
    };
    body.push('\n');

    let mut writer = &stream;
    let _ = writer.write_all(body.as_bytes());
    let _ = writer.flush();
}

fn spawn_idle_watchdog(last_seen: Arc<AtomicU64>, idle_timeout: Duration, path: PathBuf) {
    if idle_timeout.is_zero() {
        return;
    }

    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(30));
        let idle = now_secs().saturating_sub(last_seen.load(Ordering::Relaxed));
        if idle >= idle_timeout.as_secs() {
            let _ = fs::remove_file(&path);
            eprintln!("yolo-daemon: idle for {idle}s, exiting");
            std::process::exit(0);
        }
    });
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
