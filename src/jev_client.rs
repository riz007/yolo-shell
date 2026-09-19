//! Jev Decision API client and the shared decision schema.
//!
//! `evaluate` always returns a decision. Jev answers when it can, the local
//! engine does otherwise, and the caller is told which.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::heuristics;

pub const DEFAULT_TIMEOUT_MS: u64 = 200;

/// Clamped so a typo cannot disable the budget or wedge the terminal.
const MIN_TIMEOUT_MS: u64 = 50;
pub const MAX_TIMEOUT_MS: u64 = 5_000;

/// The 200ms default assumes a warm connection to a nearby endpoint. A fresh
/// process per command means a full DNS + TCP + TLS handshake every time, so
/// a distant region can cost more than that before the request is even sent.
/// `JEV_TIMEOUT_MS` exists to measure that, not to paper over it.
pub fn deadline() -> Duration {
    let ms = std::env::var("JEV_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map_or(DEFAULT_TIMEOUT_MS, |ms| {
            ms.clamp(MIN_TIMEOUT_MS, MAX_TIMEOUT_MS)
        });

    Duration::from_millis(ms)
}

const DEFAULT_ENDPOINT: &str = "https://api.typesafe.ai/v1/systemone";
/// `GET /v1/models` lists what an account can use. `jev-preview` is the other.
const DEFAULT_MODEL: &str = "jev-latest";

/// A reason goes straight to the terminal, so it is treated as untrusted:
/// bounded, and stripped of anything that could smuggle in ANSI escapes.
const MAX_REASON_CHARS: usize = 240;

/// Low-cardinality deployment markers. Never credentials.
pub const CONTEXT_ENV_VARS: &[&str] = &[
    "AWS_PROFILE",
    "CLOUDSDK_ACTIVE_CONFIG_NAME",
    "KUBECONFIG",
    "KUBE_CONTEXT",
    "NODE_ENV",
    "RAILS_ENV",
    "VERCEL_ENV",
];

/// Ordered by strictness: `AllowImmediately < WarnAndConfirm < BlockCompletely`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    AllowImmediately,
    WarnAndConfirm,
    BlockCompletely,
}

/// The action the schema's risk bands call for on their own.
pub fn band_action(risk_score: u8) -> Action {
    match risk_score {
        8..=u8::MAX => Action::BlockCompletely,
        4..=7 => Action::WarnAndConfirm,
        _ => Action::AllowImmediately,
    }
}

/// The three Jev primitives, returned in a single pass.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Decision {
    pub is_destructive: bool,
    /// 1-10, where 8+ is severe.
    pub risk_score: u8,
    pub action: Action,
    /// Shown in the banner.
    #[serde(default)]
    pub reason: Option<String>,
}

impl Decision {
    pub fn fail_open() -> Self {
        Self {
            is_destructive: false,
            risk_score: 1,
            action: Action::AllowImmediately,
            reason: None,
        }
    }

    /// Clamp a network-supplied decision before anything acts on it.
    pub fn sanitized(mut self) -> Self {
        self.risk_score = self.risk_score.clamp(1, 10);
        self.reason = self.reason.take().map(|reason| {
            reason
                .chars()
                .filter(|c| !c.is_control())
                .take(MAX_REASON_CHARS)
                .collect()
        });
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Jev,
    Local,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Jev => "jev",
            Self::Local => "local",
        })
    }
}

pub struct Outcome {
    pub decision: Decision,
    pub source: Source,
    pub elapsed: Duration,
    /// Why Jev didn't answer, when it didn't.
    pub note: Option<String>,
}

/// Everything the decision depends on, with the command exactly as typed.
///
/// Deliberately not `Serialize`: `Payload` is the only shape that can leave
/// this process, and building one redacts. An unredacted command therefore
/// can't be sent by accident.
#[derive(Debug, Clone, PartialEq)]
pub struct Context {
    pub command: String,
    pub pwd: String,
    pub git_branch: Option<String>,
    pub env_context: BTreeMap<String, String>,
}

/// `state` for the SystemOne request. Constructing one redacts the command.
#[derive(Debug, Serialize)]
struct State<'a> {
    command: String,
    pwd: &'a str,
    git_branch: Option<&'a str>,
    env_context: &'a BTreeMap<String, String>,
}

impl<'a> State<'a> {
    fn from_context(context: &'a Context) -> Self {
        Self {
            command: crate::redact::redact(&context.command),
            pwd: &context.pwd,
            git_branch: context.git_branch.as_deref(),
            env_context: &context.env_context,
        }
    }
}

#[derive(Debug, Serialize)]
struct SystemOneRequest<'a> {
    state: State<'a>,
    model: &'a str,
    questions: Questions,
}

/// The three primitives, asked in one pass. Response answers come back keyed
/// by these field names.
#[derive(Debug, Serialize)]
struct Questions {
    is_destructive: NoulQuestion,
    risk_score: ScoreQuestion,
    action: ChoiceQuestion,
}

#[derive(Debug, Serialize)]
struct NoulQuestion {
    #[serde(rename = "type")]
    kind: &'static str,
    instructions: &'static str,
    criteria: NoulCriteria,
}

#[derive(Debug, Serialize)]
struct NoulCriteria {
    #[serde(rename = "true")]
    yes: &'static str,
    #[serde(rename = "false")]
    no: &'static str,
}

#[derive(Debug, Serialize)]
struct ScoreQuestion {
    #[serde(rename = "type")]
    kind: &'static str,
    instructions: &'static str,
    /// Ordered rubric. Position is the score, starting at zero.
    criteria: &'static [&'static str],
}

#[derive(Debug, Serialize)]
struct ChoiceQuestion {
    #[serde(rename = "type")]
    kind: &'static str,
    instructions: &'static str,
    criteria: ActionCriteria,
}

/// Field names are the wire values of [`Action`], so the answer maps straight
/// back onto the enum.
#[derive(Debug, Serialize)]
struct ActionCriteria {
    allow_immediately: &'static str,
    warn_and_confirm: &'static str,
    block_completely: &'static str,
}

/// Ten levels, so the API's zero-based position maps onto the schema's 1-10
/// risk bands by adding one. Bands: 1-3 low, 4-7 moderate, 8-10 severe.
///
/// Levels describe blast radius and reversibility, not specific commands. An
/// earlier version listed example operations per level, which forced Jev to
/// pick a nearest match and produced legend text unrelated to the command the
/// user actually ran.
const RISK_RUBRIC: &[&str] = &[
    "Reads or displays information. Changes nothing.",
    "Creates or edits files that are disposable or regenerated on demand.",
    "Changes local state that version control or a rebuild restores.",
    "Deletes or overwrites local work that is not backed up elsewhere.",
    "Changes the local environment's tools, dependencies, or configuration.",
    "Discards uncommitted work, or rewrites history nobody else has pulled.",
    "Changes shared non-production systems, or publishes something that cannot be withdrawn.",
    "Changes production systems or data in a way that could be rolled back with effort.",
    "Destroys production data, infrastructure, or history. Recovery depends on backups.",
    "Irreversible destruction at scale: a filesystem, a device, or a production datastore with no recovery path.",
];

fn questions() -> Questions {
    Questions {
        is_destructive: NoulQuestion {
            kind: "noul",
            instructions: "Would running this shell command destroy data, push \
                           unrecoverable state, or act on production assets?",
            criteria: NoulCriteria {
                yes: "Destroys data, pushes state that cannot be undone, or targets production.",
                no: "Reads, inspects, or makes a change that is trivially reversible.",
            },
        },
        risk_score: ScoreQuestion {
            kind: "score",
            instructions: "Rate the blast radius of running this shell command in \
                           the given directory, branch, and environment.",
            criteria: RISK_RUBRIC,
        },
        action: ChoiceQuestion {
            kind: "choice",
            instructions: "Should this shell command run, be confirmed with the \
                           user first, or be refused?",
            criteria: ActionCriteria {
                allow_immediately: "Low risk (1-3). Routine and reversible. Run it \
                                    without interrupting the user.",
                warn_and_confirm: "Moderate risk (4-7). Legitimate but consequential. \
                                   Show the risk and ask before running.",
                block_completely: "Severe risk (8-10). Destroys production assets or \
                                   unrecoverable state. Refuse it.",
            },
        },
    }
}

#[derive(Debug, Deserialize)]
struct SystemOneResponse {
    answers: BTreeMap<String, Answer>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Answer {
    /// Probability of yes, not a boolean.
    Noul {
        noul: f64,
    },
    Score {
        score: f64,
        #[serde(default)]
        legend: BTreeMap<String, serde_json::Value>,
    },
    Choice {
        choice: String,
    },
}

impl SystemOneResponse {
    fn into_decision(mut self) -> Result<Decision, JevError> {
        let missing = |name: &str| JevError::Malformed(format!("missing {name} answer"));

        let Some(Answer::Noul { noul }) = self.answers.remove("is_destructive") else {
            return Err(missing("is_destructive"));
        };
        let Some(Answer::Score { score, legend }) = self.answers.remove("risk_score") else {
            return Err(missing("risk_score"));
        };
        let Some(Answer::Choice { choice }) = self.answers.remove("action") else {
            return Err(missing("action"));
        };

        let action = match choice.as_str() {
            "allow_immediately" => Action::AllowImmediately,
            "warn_and_confirm" => Action::WarnAndConfirm,
            "block_completely" => Action::BlockCompletely,
            other => return Err(JevError::Malformed(format!("unknown action {other:?}"))),
        };

        // Rubric positions are zero-based; the risk bands are 1-10. A NaN
        // score casts to 0, which lands on the lowest band rather than
        // panicking.
        let level = score.round().clamp(0.0, 9.0) as u8;

        let reason = legend
            .get(&level.to_string())
            .and_then(|entry| entry.as_str())
            .map(str::to_string);

        let risk_score = level + 1;

        Ok(Decision {
            is_destructive: noul > 0.5,
            risk_score,
            // The questions are answered independently, so a severe score can
            // come back beside a permissive action. The bands are part of the
            // schema, so hold the action to them. Tightens, never loosens.
            action: action.max(band_action(risk_score)),
            reason,
        })
    }
}

/// Every variant falls back to the local engine rather than failing the
/// command.
#[derive(Debug)]
pub enum JevError {
    /// No key, so nothing to call. Expected: heuristics work on their own.
    NotConfigured,
    Timeout(u64),
    Transport(String),
    Malformed(String),
}

impl fmt::Display for JevError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConfigured => f.write_str("JEV_API_KEY not set"),
            Self::Timeout(ms) => write!(f, "no response within {ms}ms"),
            Self::Transport(detail) => write!(f, "transport: {detail}"),
            Self::Malformed(detail) => write!(f, "malformed response: {detail}"),
        }
    }
}

/// A configured connection to Jev.
///
/// Holds the HTTP agent, which pools connections: built once per process it
/// buys nothing, but held open by the daemon it removes the DNS + TCP + TLS
/// handshake from every command.
pub struct JevClient {
    agent: ureq::Agent,
    endpoint: String,
    key: String,
    model: String,
}

impl JevClient {
    /// `Err(NotConfigured)` when there is no key, which is the normal
    /// heuristics-only setup rather than a failure.
    pub fn from_env() -> Result<Self, JevError> {
        let key = std::env::var("JEV_API_KEY")
            .ok()
            .filter(|key| !key.is_empty())
            .ok_or(JevError::NotConfigured)?;

        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_millis(MAX_TIMEOUT_MS)))
            .build()
            .into();

        Ok(Self {
            agent,
            endpoint: std::env::var("JEV_API_URL").unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string()),
            key: key.clone(),
            model: std::env::var("JEV_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.to_string()),
        })
    }

    /// Open the connection and check the key, so the first real command does
    /// not pay the handshake. Called by the daemon at startup.
    pub fn warm(&self) -> Result<(), JevError> {
        let models = self.endpoint.replace("/v1/systemone", "/v1/models");
        let mut response = self
            .agent
            .get(&models)
            .header("authorization", &format!("Bearer {}", self.key))
            .call()
            .map_err(|e| JevError::Transport(e.to_string()))?;

        // The body must be drained or the connection is dropped instead of
        // returned to the pool, and the first real command pays the
        // handshake anyway - which is the whole point of warming.
        response
            .body_mut()
            .read_to_vec()
            .map(|_| ())
            .map_err(|e| JevError::Transport(e.to_string()))
    }

    pub fn decide(&self, context: &Context) -> Result<Decision, JevError> {
        let payload = SystemOneRequest {
            state: State::from_context(context),
            model: &self.model,
            questions: questions(),
        };
        let body =
            serde_json::to_string(&payload).map_err(|e| JevError::Malformed(e.to_string()))?;

        let mut response = self
            .agent
            .post(&self.endpoint)
            .header("authorization", &format!("Bearer {}", self.key))
            .header("content-type", "application/json")
            .send(&body)
            .map_err(|e| JevError::Transport(e.to_string()))?;

        response
            .body_mut()
            .read_json::<SystemOneResponse>()
            .map_err(|e| JevError::Malformed(e.to_string()))?
            .into_decision()
    }
}

/// Jev if it answers in time, the local engine if not.
///
/// This is the in-process path: a fresh agent, so a full handshake. The
/// daemon path in [`crate::daemon`] reuses a warm one.
pub fn evaluate(context: &Context) -> Outcome {
    let started = Instant::now();

    match call_jev(context) {
        Ok(decision) => Outcome {
            decision: decision.sanitized(),
            source: Source::Jev,
            elapsed: started.elapsed(),
            note: None,
        },
        Err(err) => Outcome {
            decision: heuristics::evaluate(context),
            source: Source::Local,
            elapsed: started.elapsed(),
            note: Some(err.to_string()),
        },
    }
}

/// Runs the request on a worker thread and waits with a wall-clock cap.
///
/// ureq's own timeout only covers the phases it knows about — a stalled DNS
/// lookup outlasts it. Waiting on a channel makes the deadline a property of
/// this function instead. The abandoned thread dies with the process.
fn call_jev(context: &Context) -> Result<Decision, JevError> {
    let client = JevClient::from_env()?;

    // Only point where anything leaves the machine, and only reached when
    // there's somewhere to send it - an offline shell never compiles the
    // redactor's patterns.
    let context = context.clone();
    let (tx, rx) = mpsc::sync_channel(1);

    thread::Builder::new()
        .name("jev-request".to_string())
        .spawn(move || {
            // Receiver is gone once the deadline passes; that send is
            // expected to fail.
            let _ = tx.send(client.decide(&context));
        })
        .map_err(|e| JevError::Transport(e.to_string()))?;

    let deadline = deadline();
    rx.recv_timeout(deadline)
        .unwrap_or(Err(JevError::Timeout(deadline.as_millis() as u64)))
}
