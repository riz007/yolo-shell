use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use yolo_shell::daemon::{self, Request, Response};
use yolo_shell::jev_client::{Action, Context, Source};

fn ctx(command: &str) -> Context {
    Context {
        command: command.to_string(),
        pwd: "/Users/dev/projects/billing-service".to_string(),
        git_branch: Some("main".to_string()),
        env_context: BTreeMap::new(),
    }
}

/// `YOLO_SOCKET` and `JEV_API_KEY` are process-wide and cargo runs these
/// tests as threads in one process, so they take turns.
///
/// Taking the guard also gives the process a key: `decide` consults the
/// daemon only for a caller that could have called Jev itself.
fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    std::env::set_var("JEV_API_KEY", "test-key");
    guard
}

/// Unix socket paths are capped near 104 bytes, so tests stay in /tmp rather
/// than a long scratch directory.
fn socket(name: &str) -> PathBuf {
    let path = PathBuf::from(format!("/tmp/yolo-t-{}-{name}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

/// A stand-in daemon that answers one request with `reply`.
fn fake_daemon(path: &PathBuf, reply: Response) -> thread::JoinHandle<String> {
    let listener = UnixListener::bind(path).expect("bind");
    thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).expect("read");

        let mut body = serde_json::to_string(&reply).expect("encode");
        body.push('\n');
        let mut writer = &stream;
        writer.write_all(body.as_bytes()).expect("write");
        writer.flush().expect("flush");
        line
    })
}

#[test]
fn the_command_is_redacted_before_it_reaches_the_socket() {
    let request = Request::from_context(&ctx(
        "psql postgres://admin:hunter2@prod-db.internal/billing -c 'DROP TABLE users'",
    ));

    assert!(!request.command.contains("hunter2"), "{}", request.command);
    assert!(request.command.contains("REDACTED"), "{}", request.command);
    assert!(
        request.command.contains("prod-db.internal"),
        "lost the host"
    );
}

#[test]
fn no_socket_means_no_daemon() {
    let _guard = env_guard();
    std::env::set_var("YOLO_SOCKET", socket("absent"));
    assert!(
        daemon::decide(&ctx("rm -rf /"), Duration::from_millis(200)).is_none(),
        "should fall through to the in-process path"
    );
    std::env::remove_var("YOLO_SOCKET");
}

#[test]
fn a_decision_from_the_daemon_is_used() {
    let _guard = env_guard();
    let path = socket("decided");
    let handle = fake_daemon(
        &path,
        Response::Decided {
            decision: yolo_shell::jev_client::Decision {
                is_destructive: true,
                risk_score: 9,
                action: Action::BlockCompletely,
                reason: Some("targets production".to_string()),
            },
            elapsed_ms: 340,
        },
    );

    std::env::set_var("YOLO_SOCKET", &path);
    let outcome = daemon::decide(&ctx("kubectl delete ns billing"), Duration::from_secs(2))
        .expect("daemon was listening");
    std::env::remove_var("YOLO_SOCKET");

    assert_eq!(outcome.source, Source::Jev);
    assert_eq!(outcome.decision.action, Action::BlockCompletely);
    assert_eq!(outcome.decision.risk_score, 9);

    let sent = handle.join().expect("server thread");
    let parsed: serde_json::Value = serde_json::from_str(&sent).expect("valid request json");
    assert_eq!(parsed["command"], "kubectl delete ns billing");
    assert_eq!(parsed["git_branch"], "main");

    let _ = std::fs::remove_file(&path);
}

/// When the daemon cannot reach Jev, the caller scores locally rather than
/// having the daemon carry a second copy of the rule engine.
#[test]
fn an_unavailable_daemon_falls_back_to_local_heuristics() {
    let _guard = env_guard();
    let path = socket("unavailable");
    let handle = fake_daemon(
        &path,
        Response::Unavailable {
            error: "transport: connection refused".to_string(),
        },
    );

    std::env::set_var("YOLO_SOCKET", &path);
    let outcome =
        daemon::decide(&ctx("rm -rf /"), Duration::from_secs(2)).expect("daemon was listening");
    std::env::remove_var("YOLO_SOCKET");

    assert_eq!(outcome.source, Source::Local);
    assert_eq!(outcome.decision.action, Action::BlockCompletely);
    assert!(outcome
        .note
        .is_some_and(|n| n.contains("connection refused")));

    let _ = handle.join();
    let _ = std::fs::remove_file(&path);
}

/// A daemon that accepts and then stalls must not hold the terminal, and
/// must not send the caller off to spend the deadline again on the network.
#[test]
fn a_silent_daemon_is_answered_locally_within_the_deadline() {
    let _guard = env_guard();
    let path = socket("silent");
    let listener = UnixListener::bind(&path).expect("bind");
    thread::spawn(move || {
        let _accepted = listener.accept();
        thread::sleep(Duration::from_secs(10));
    });

    std::env::set_var("YOLO_SOCKET", &path);
    let started = std::time::Instant::now();
    let outcome = daemon::decide(&ctx("rm -rf /"), Duration::from_millis(200));
    let elapsed = started.elapsed();
    std::env::remove_var("YOLO_SOCKET");

    let outcome = outcome.expect("a connected daemon must answer, not fall through");
    assert_eq!(outcome.source, Source::Local);
    assert_eq!(outcome.decision.action, Action::BlockCompletely);
    assert!(
        elapsed < Duration::from_millis(600),
        "read timeout not enforced: {elapsed:?}"
    );
    // A bare `WouldBlock` prints as "Resource temporarily unavailable
    // (os error 35)", which names neither the cause nor the fix.
    assert_eq!(
        outcome.note.as_deref(),
        Some("daemon: no response within 200ms"),
        "a stalled daemon should report the deadline, not an errno"
    );

    let _ = std::fs::remove_file(&path);
}

/// The daemon holds a key of its own, so without this gate an unset
/// `JEV_API_KEY` still reached Jev. That is how `verify-rubric.py` — which
/// drops the key to produce its "local" column — was silently comparing Jev
/// against Jev whenever a daemon happened to be running.
#[test]
fn an_unconfigured_caller_does_not_consult_the_daemon() {
    let _guard = env_guard();
    let path = socket("unconfigured");
    let _listener = UnixListener::bind(&path).expect("bind");

    std::env::set_var("YOLO_SOCKET", &path);
    std::env::remove_var("JEV_API_KEY");
    let outcome = daemon::decide(&ctx("rm -rf /"), Duration::from_millis(200));
    std::env::remove_var("YOLO_SOCKET");

    assert!(
        outcome.is_none(),
        "a caller with no key must take the in-process path, not borrow the \
         daemon's key"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn the_socket_path_is_overridable() {
    let _guard = env_guard();
    std::env::set_var("YOLO_SOCKET", "/tmp/yolo-explicit.sock");
    assert_eq!(
        daemon::socket_path(),
        PathBuf::from("/tmp/yolo-explicit.sock")
    );
    std::env::remove_var("YOLO_SOCKET");

    // Falls back to a per-user runtime directory, never a shared fixed name.
    let path = daemon::socket_path();
    assert!(path.to_string_lossy().contains("yolo-shell"), "{path:?}");
}
