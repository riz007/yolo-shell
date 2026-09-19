use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use yolo_shell::jev_client::{
    band_action, deadline, evaluate, Action, Context, Source, DEFAULT_TIMEOUT_MS,
};

/// A well-formed SystemOne response. The rubric position is zero-based, so
/// `"score": 8.0` becomes a risk of 9.
const BLOCK_PROD: &str = r#"{"model":"jev-latest","answers":{
    "is_destructive":{"type":"noul","noul":0.97},
    "risk_score":{"type":"score","score":8.0,"confidence":0.9,
                  "legend":{"8":"targets production"},"probabilities":{}},
    "action":{"type":"choice","choice":"block_completely","confidence":0.94,"probabilities":{}}},
    "usage":{"input_tokens":310,"output_tokens":9}}"#;

const ALLOW_TRIVIAL: &str = r#"{"model":"jev-latest","answers":{
    "is_destructive":{"type":"noul","noul":0.01},
    "risk_score":{"type":"score","score":0.0,"legend":{"0":"reads only"},"probabilities":{}},
    "action":{"type":"choice","choice":"allow_immediately","confidence":0.99,"probabilities":{}}},
    "usage":{"input_tokens":300,"output_tokens":9}}"#;

fn ctx(command: &str) -> Context {
    Context {
        command: command.to_string(),
        pwd: "/Users/dev/projects/billing-service".to_string(),
        git_branch: Some("main".to_string()),
        env_context: BTreeMap::new(),
    }
}

/// One-shot HTTP server. `delay` pushes the response past the deadline;
/// `body` is returned verbatim so malformed payloads can be tested. The
/// receiver yields the request body the client sent.
///
/// The request body must be drained before responding: closing a socket with
/// unread data queued makes the kernel send an RST, which can discard a
/// response the client has not read yet. That showed up as a flaky test.
fn serve(delay: Duration, body: &'static str) -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        let mut reader = BufReader::new(&stream);

        let mut length = 0usize;
        let mut line = String::new();
        while reader.read_line(&mut line).is_ok_and(|n| n > 0) {
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                length = value.trim().parse().unwrap_or(0);
            }
            if line.trim().is_empty() {
                break;
            }
            line.clear();
        }

        let mut request_body = vec![0u8; length];
        let _ = reader.read_exact(&mut request_body);
        let _ = tx.send(String::from_utf8_lossy(&request_body).into_owned());

        thread::sleep(delay);

        let mut stream = &stream;
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK{CRLF}Content-Type: application/json{CRLF}Content-Length: {}{CRLF}Connection: close{CRLF}{CRLF}{}",
            body.len(),
            body,
            CRLF = "\r\n",
        );
        let _ = stream.flush();
    });

    (format!("http://127.0.0.1:{port}/v1/systemone"), rx)
}

fn serve_once(delay: Duration, body: &'static str) -> String {
    serve(delay, body).0
}

fn capture_once(body: &'static str) -> (String, mpsc::Receiver<String>) {
    serve(Duration::ZERO, body)
}

/// These drive the client through process-wide env vars, and cargo runs an
/// integration binary's tests as threads in one process. Hence the mutex.
fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn with_jev<T>(url: &str, key: &str, body: impl FnOnce() -> T) -> T {
    let _guard = env_guard();
    std::env::set_var("JEV_API_URL", url);
    std::env::set_var("JEV_API_KEY", key);
    let out = body();
    std::env::remove_var("JEV_API_URL");
    std::env::remove_var("JEV_API_KEY");
    out
}

#[test]
fn without_an_api_key_the_local_engine_decides() {
    let _guard = env_guard();
    std::env::remove_var("JEV_API_KEY");

    let outcome = evaluate(&ctx("rm -rf /"));
    assert_eq!(outcome.source, Source::Local);
    assert_eq!(outcome.decision.action, Action::BlockCompletely);
    assert!(outcome.note.is_some_and(|n| n.contains("JEV_API_KEY")));
}

#[test]
fn a_prompt_response_is_used_as_given() {
    let url = serve_once(Duration::ZERO, BLOCK_PROD);

    let outcome = with_jev(&url, "test-key", || {
        evaluate(&ctx("kubectl delete ns billing"))
    });

    assert_eq!(outcome.source, Source::Jev, "note: {:?}", outcome.note);
    assert_eq!(outcome.decision.action, Action::BlockCompletely);
    assert!(outcome.decision.is_destructive);
    assert_eq!(outcome.decision.risk_score, 9, "rubric level 8 is risk 9");
    assert_eq!(
        outcome.decision.reason.as_deref(),
        Some("targets production")
    );
}

/// Jev overrides the local engine in both directions: a command the
/// heuristics would flag can be waved through.
#[test]
fn jev_can_allow_what_the_local_engine_would_flag() {
    let url = serve_once(Duration::ZERO, ALLOW_TRIVIAL);

    let outcome = with_jev(&url, "test-key", || evaluate(&ctx("rm -rf ./build")));

    assert_eq!(outcome.source, Source::Jev, "note: {:?}", outcome.note);
    assert_eq!(outcome.decision.action, Action::AllowImmediately);
    assert!(!outcome.decision.is_destructive);
    assert_eq!(outcome.decision.risk_score, 1);
}

#[test]
fn a_slow_response_falls_back_to_the_local_engine_within_budget() {
    let url = serve_once(Duration::from_secs(5), ALLOW_TRIVIAL);

    // Timed inside the guard: `with_jev` may block on the env mutex, and that
    // wait is test scheduling, not Jev latency.
    let (outcome, elapsed) = with_jev(&url, "test-key", || {
        let started = Instant::now();
        let outcome = evaluate(&ctx("rm -rf /"));
        (outcome, started.elapsed())
    });

    assert_eq!(
        outcome.source,
        Source::Local,
        "should not have waited for Jev"
    );
    assert_eq!(outcome.decision.action, Action::BlockCompletely);

    // A hung server must not hold the terminal hostage.
    assert!(
        elapsed < Duration::from_millis(DEFAULT_TIMEOUT_MS + 150),
        "deadline overshot: {elapsed:?}"
    );
}

#[test]
fn an_unreachable_endpoint_falls_back_to_the_local_engine() {
    // Port 1 on loopback: refused immediately.
    let outcome = with_jev("http://127.0.0.1:1/v1/systemone", "test-key", || {
        evaluate(&ctx("git push origin main --force"))
    });

    assert_eq!(outcome.source, Source::Local);
    assert_eq!(outcome.decision.action, Action::BlockCompletely);
}

#[test]
fn a_malformed_response_falls_back_to_the_local_engine() {
    let url = serve_once(Duration::ZERO, "not json at all");

    let outcome = with_jev(&url, "test-key", || evaluate(&ctx("terraform destroy")));

    assert_eq!(outcome.source, Source::Local);
    assert_eq!(outcome.decision.action, Action::BlockCompletely);
}

/// A well-formed envelope missing one of the three answers is unusable.
#[test]
fn a_missing_answer_falls_back_to_the_local_engine() {
    const NO_ACTION: &str = r#"{"model":"jev-latest","answers":{
        "is_destructive":{"type":"noul","noul":0.9},
        "risk_score":{"type":"score","score":8.0,"legend":{},"probabilities":{}}},
        "usage":{"input_tokens":1,"output_tokens":1}}"#;

    let url = serve_once(Duration::ZERO, NO_ACTION);
    let outcome = with_jev(&url, "test-key", || evaluate(&ctx("terraform destroy")));

    assert_eq!(outcome.source, Source::Local);
    assert!(
        outcome.note.is_some_and(|n| n.contains("action")),
        "unhelpful note"
    );
}

#[test]
fn an_unknown_action_falls_back_to_the_local_engine() {
    const BAD_CHOICE: &str = r#"{"model":"jev-latest","answers":{
        "is_destructive":{"type":"noul","noul":0.9},
        "risk_score":{"type":"score","score":8.0,"legend":{},"probabilities":{}},
        "action":{"type":"choice","choice":"launch_missiles","confidence":1.0,"probabilities":{}}},
        "usage":{"input_tokens":1,"output_tokens":1}}"#;

    let url = serve_once(Duration::ZERO, BAD_CHOICE);
    let outcome = with_jev(&url, "test-key", || evaluate(&ctx("terraform destroy")));

    assert_eq!(outcome.source, Source::Local);
    assert_eq!(outcome.decision.action, Action::BlockCompletely);
}

/// The rubric has ten levels, so any score maps into the 1-10 band.
#[test]
fn an_out_of_range_score_is_clamped_into_the_risk_band() {
    const ABSURD: &str = r#"{"model":"jev-latest","answers":{
        "is_destructive":{"type":"noul","noul":0.9},
        "risk_score":{"type":"score","score":250.0,"legend":{},"probabilities":{}},
        "action":{"type":"choice","choice":"warn_and_confirm","confidence":0.5,"probabilities":{}}},
        "usage":{"input_tokens":1,"output_tokens":1}}"#;

    let url = serve_once(Duration::ZERO, ABSURD);
    let outcome = with_jev(&url, "test-key", || evaluate(&ctx("rm -rf build")));

    assert_eq!(outcome.source, Source::Jev, "note: {:?}", outcome.note);
    assert_eq!(outcome.decision.risk_score, 10);
}

/// `noul` is a probability, not a boolean.
#[test]
fn the_destructive_probability_is_thresholded() {
    const UNSURE: &str = r#"{"model":"jev-latest","answers":{
        "is_destructive":{"type":"noul","noul":0.31},
        "risk_score":{"type":"score","score":3.0,"legend":{},"probabilities":{}},
        "action":{"type":"choice","choice":"warn_and_confirm","confidence":0.6,"probabilities":{}}},
        "usage":{"input_tokens":1,"output_tokens":1}}"#;

    let url = serve_once(Duration::ZERO, UNSURE);
    let outcome = with_jev(&url, "test-key", || evaluate(&ctx("rm -rf build")));

    assert_eq!(outcome.source, Source::Jev, "note: {:?}", outcome.note);
    assert!(!outcome.decision.is_destructive, "0.31 should read as no");
    assert_eq!(outcome.decision.risk_score, 4);
}

#[test]
fn control_characters_in_a_reason_cannot_reach_the_terminal() {
    // The reason comes from the rubric legend, which is server-supplied. A
    // hostile or buggy service must not smuggle ANSI escapes into the banner.
    const INJECTED: &str = r#"{"model":"jev-latest","answers":{
        "is_destructive":{"type":"noul","noul":0.9},
        "risk_score":{"type":"score","score":4.0,
                      "legend":{"4":"safe\u001binjected"},"probabilities":{}},
        "action":{"type":"choice","choice":"warn_and_confirm","confidence":0.9,"probabilities":{}}},
        "usage":{"input_tokens":1,"output_tokens":1}}"#;

    let url = serve_once(Duration::ZERO, INJECTED);
    let outcome = with_jev(&url, "test-key", || evaluate(&ctx("rm -rf build")));

    let reason = outcome.decision.reason.unwrap_or_default();
    assert!(
        !reason.contains(char::is_control),
        "control char survived: {reason:?}"
    );
    assert!(reason.contains("injected"), "over-stripped: {reason:?}");
}

/// The security-critical property: anything reaching Jev went through the
/// redactor first.
#[test]
fn secrets_are_redacted_before_the_request_leaves() {
    let (url, requests) = capture_once(ALLOW_TRIVIAL);

    let command = "psql postgres://admin:hunter2@prod-db.internal/billing -c 'DROP TABLE users'";
    let outcome = with_jev(&url, "test-key", || evaluate(&ctx(command)));
    assert_eq!(outcome.source, Source::Jev, "note: {:?}", outcome.note);

    let sent = requests
        .recv_timeout(Duration::from_secs(2))
        .expect("server captured no request");

    assert!(!sent.contains("hunter2"), "secret was sent to Jev: {sent}");
    assert!(sent.contains("REDACTED"), "nothing was redacted: {sent}");
    assert!(sent.contains("prod-db.internal"), "lost the host: {sent}");
    assert!(
        sent.contains("DROP TABLE users"),
        "lost the statement: {sent}"
    );
}

/// The request must match the published SystemOne schema, or the API answers
/// 422 and every command silently runs on heuristics.
#[test]
fn the_request_matches_the_systemone_schema() {
    let (url, requests) = capture_once(ALLOW_TRIVIAL);
    let outcome = with_jev(&url, "test-key", || evaluate(&ctx("terraform destroy")));
    assert_eq!(outcome.source, Source::Jev, "note: {:?}", outcome.note);

    let sent: serde_json::Value = serde_json::from_str(
        &requests
            .recv_timeout(Duration::from_secs(2))
            .expect("no request"),
    )
    .expect("request body was not valid JSON");

    assert_eq!(sent["model"], "jev-latest");
    assert!(
        sent["state"]["command"].is_string(),
        "state.command missing"
    );
    assert!(sent["state"]["pwd"].is_string(), "state.pwd missing");

    assert_eq!(sent["questions"]["is_destructive"]["type"], "noul");
    assert_eq!(sent["questions"]["risk_score"]["type"], "score");
    assert_eq!(sent["questions"]["action"]["type"], "choice");

    // Position is the score, so the rubric must cover all ten bands.
    let rubric = sent["questions"]["risk_score"]["criteria"]
        .as_array()
        .expect("rubric must be an ordered array");
    assert_eq!(rubric.len(), 10, "rubric must map onto risk 1-10");

    // Choice names are the wire values of Action.
    let choices = &sent["questions"]["action"]["criteria"];
    for name in ["allow_immediately", "warn_and_confirm", "block_completely"] {
        assert!(choices[name].is_string(), "missing choice {name}");
    }
}

#[test]
fn the_model_is_overridable() {
    let (url, requests) = capture_once(ALLOW_TRIVIAL);

    let outcome = with_jev(&url, "test-key", || {
        std::env::set_var("JEV_MODEL", "jev-preview");
        let out = evaluate(&ctx("terraform destroy"));
        std::env::remove_var("JEV_MODEL");
        out
    });
    assert_eq!(outcome.source, Source::Jev, "note: {:?}", outcome.note);

    let sent = requests
        .recv_timeout(Duration::from_secs(2))
        .expect("no request");
    assert!(
        sent.contains("jev-preview"),
        "model override ignored: {sent}"
    );
}

#[test]
fn the_deadline_is_configurable_and_clamped() {
    let _guard = env_guard();

    std::env::remove_var("JEV_TIMEOUT_MS");
    assert_eq!(deadline(), Duration::from_millis(DEFAULT_TIMEOUT_MS));

    std::env::set_var("JEV_TIMEOUT_MS", "1500");
    assert_eq!(deadline(), Duration::from_millis(1500));

    // A typo must not disable the budget or wedge the terminal.
    std::env::set_var("JEV_TIMEOUT_MS", "0");
    assert_eq!(deadline(), Duration::from_millis(50));

    std::env::set_var("JEV_TIMEOUT_MS", "999999");
    assert_eq!(deadline(), Duration::from_millis(5_000));

    std::env::set_var("JEV_TIMEOUT_MS", "not-a-number");
    assert_eq!(deadline(), Duration::from_millis(DEFAULT_TIMEOUT_MS));

    std::env::remove_var("JEV_TIMEOUT_MS");
}

/// A slow endpoint that fits inside a raised deadline must reach Jev. This is
/// the knob for diagnosing a distant region.
#[test]
fn raising_the_deadline_lets_a_slow_endpoint_answer() {
    let url = serve_once(Duration::from_millis(400), BLOCK_PROD);

    let outcome = with_jev(&url, "test-key", || {
        std::env::set_var("JEV_TIMEOUT_MS", "2000");
        let out = evaluate(&ctx("kubectl delete namespace billing"));
        std::env::remove_var("JEV_TIMEOUT_MS");
        out
    });

    assert_eq!(outcome.source, Source::Jev, "note: {:?}", outcome.note);
    assert_eq!(
        outcome.decision.reason.as_deref(),
        Some("targets production")
    );
}

/// The three questions are answered independently, so Jev can return a severe
/// score beside a permissive action. This is the case seen live:
/// `kubectl delete namespace billing` came back risk 8 with warn_and_confirm.
#[test]
fn a_severe_score_is_not_left_with_a_permissive_action() {
    const MISMATCH: &str = r#"{"model":"jev-latest","answers":{
        "is_destructive":{"type":"noul","noul":0.95},
        "risk_score":{"type":"score","score":7.0,
                      "legend":{"7":"changes production"},"probabilities":{}},
        "action":{"type":"choice","choice":"warn_and_confirm","confidence":0.6,"probabilities":{}}},
        "usage":{"input_tokens":1,"output_tokens":1}}"#;

    let url = serve_once(Duration::ZERO, MISMATCH);
    let outcome = with_jev(&url, "test-key", || {
        evaluate(&ctx("kubectl delete namespace billing"))
    });

    assert_eq!(outcome.source, Source::Jev, "note: {:?}", outcome.note);
    assert_eq!(outcome.decision.risk_score, 8);
    assert_eq!(
        outcome.decision.action,
        Action::BlockCompletely,
        "risk 8 must not run on a confirm prompt"
    );
}

/// The floor only tightens. Jev staying stricter than the band is respected.
#[test]
fn a_stricter_action_than_the_band_is_respected() {
    const STRICT: &str = r#"{"model":"jev-latest","answers":{
        "is_destructive":{"type":"noul","noul":0.6},
        "risk_score":{"type":"score","score":1.0,"legend":{"1":"minor"},"probabilities":{}},
        "action":{"type":"choice","choice":"block_completely","confidence":0.9,"probabilities":{}}},
        "usage":{"input_tokens":1,"output_tokens":1}}"#;

    let url = serve_once(Duration::ZERO, STRICT);
    let outcome = with_jev(&url, "test-key", || evaluate(&ctx("weird-binary --go")));

    assert_eq!(outcome.decision.risk_score, 2);
    assert_eq!(outcome.decision.action, Action::BlockCompletely);
}

#[test]
fn the_risk_bands_match_the_schema() {
    for risk in 1..=3 {
        assert_eq!(band_action(risk), Action::AllowImmediately, "risk {risk}");
    }
    for risk in 4..=7 {
        assert_eq!(band_action(risk), Action::WarnAndConfirm, "risk {risk}");
    }
    for risk in 8..=10 {
        assert_eq!(band_action(risk), Action::BlockCompletely, "risk {risk}");
    }
}

/// Levels describe blast radius, not named operations, so the legend shown to
/// the user reads sensibly whatever the command was.
#[test]
fn the_rubric_legend_reads_as_a_reason_for_any_command() {
    let (url, requests) = capture_once(ALLOW_TRIVIAL);
    let _ = with_jev(&url, "test-key", || {
        evaluate(&ctx("kubectl delete ns billing"))
    });

    let sent: serde_json::Value = serde_json::from_str(
        &requests
            .recv_timeout(Duration::from_secs(2))
            .expect("no request"),
    )
    .expect("bad json");
    let rubric = sent["questions"]["risk_score"]["criteria"]
        .as_array()
        .expect("array");

    for level in rubric {
        let text = level.as_str().expect("rubric level must be a string");
        for leaked in ["git ", "kubectl", "npm ", "terraform", "remote branch"] {
            assert!(
                !text.to_lowercase().contains(leaked),
                "rubric level names a specific tool, which mismatches other commands: {text:?}"
            );
        }
    }
}

/// A rejected request must carry the API's own explanation. Without it the
/// note reads `http status: 422` and says nothing about which field is wrong.
#[test]
fn an_api_rejection_carries_the_servers_explanation() {
    let path = "/v1/systemone";
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();

    thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        let mut reader = BufReader::new(&stream);
        let (mut length, mut line) = (0usize, String::new());
        while reader.read_line(&mut line).is_ok_and(|n| n > 0) {
            if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                length = v.trim().parse().unwrap_or(0);
            }
            if line.trim().is_empty() {
                break;
            }
            line.clear();
        }
        let mut body = vec![0u8; length];
        let _ = reader.read_exact(&mut body);

        let detail = r#"{"detail":[{"loc":["body","questions","risk_score","criteria"],"msg":"Field required"}]}"#;
        let mut stream = &stream;
        let _ = write!(
            stream,
            "HTTP/1.1 422 Unprocessable Entity\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            detail.len(),
            detail
        );
        let _ = stream.flush();
    });

    let url = format!("http://127.0.0.1:{port}{path}");
    let outcome = with_jev(&url, "test-key", || evaluate(&ctx("terraform destroy")));

    assert_eq!(outcome.source, Source::Local);
    let note = outcome.note.unwrap_or_default();
    assert!(note.contains("422"), "status missing: {note}");
    assert!(
        note.contains("risk_score"),
        "server detail was dropped: {note}"
    );
}

/// The rubric must give force-push its own rung per branch class. Widening
/// the severe level to catch `main` once pulled feature branches up with it.
#[test]
fn the_rubric_separates_force_push_by_branch_class() {
    let (url, requests) = capture_once(ALLOW_TRIVIAL);
    let _ = with_jev(&url, "test-key", || evaluate(&ctx("git push --force")));

    let sent: serde_json::Value = serde_json::from_str(
        &requests
            .recv_timeout(Duration::from_secs(2))
            .expect("no request"),
    )
    .expect("bad json");
    let rubric: Vec<String> = sent["questions"]["risk_score"]["criteria"]
        .as_array()
        .expect("array")
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_lowercase())
        .collect();

    let moderate = rubric[6].as_str();
    let severe = rubric[7].as_str();

    assert!(
        moderate.contains("feature branch") || moderate.contains("personal"),
        "no rung for force-pushing a personal branch: {moderate:?}"
    );
    assert!(
        severe.contains("protected") || severe.contains("main"),
        "the severe rung must name protected branches: {severe:?}"
    );
}
