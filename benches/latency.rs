//! Latency budget check for the local stages. Hand-rolled rather than
//! criterion-based: we want a pass/fail against a budget, not a distribution.

use std::hint::black_box;
use std::time::Instant;

use yolo_shell::fastpath::classify;
use yolo_shell::heuristics;
use yolo_shell::jev_client::Context;
use yolo_shell::redact::redact;

/// Anything near this means the filter has picked up real work.
const BUDGET_NS: u128 = 1_000_000;

/// Redaction only runs on commands already headed for a network round-trip,
/// so it gets the rest of the 10ms local budget.
const REDACT_BUDGET_NS: u128 = 9_000_000;

const SAMPLES: u32 = 100_000;

const CORPUS: &[(&str, &str)] = &[
    ("allowlisted, no args", "ls"),
    ("allowlisted, flags", "ls -la /var/log/nginx"),
    ("allowlisted pipeline", "cat SPEC.md | head -n 40 | wc -l"),
    ("read-only git", "git log --oneline --graph -n 20"),
    ("escalates: unknown", "cargo build --release"),
    ("escalates: destructive", "git push origin main --force"),
    ("escalates: redirection", "echo '' > ~/.zshrc"),
];

const REDACT_CORPUS: &[(&str, &str)] = &[
    (
        "clean, nothing to scrub",
        "kubectl delete namespace billing-prod",
    ),
    (
        "flag credential",
        "gh auth login --token ghp_16C7e42F292c6912E7710c",
    ),
    (
        "env credential",
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI aws s3 rm s3://b --recursive",
    ),
    (
        "connection string",
        "psql postgres://admin:hunter2@prod-db.internal:5432/billing -c 'DROP TABLE users'",
    ),
];

fn heuristics_context(command: &str) -> Context {
    Context {
        command: command.to_string(),
        pwd: "/Users/dev/projects/billing-service".to_string(),
        git_branch: Some("main".to_string()),
        env_context: Default::default(),
    }
}

fn main() {
    // A fresh process per command means neither compile amortises. Report
    // them separately rather than letting them hide inside a mean.
    let start = Instant::now();
    black_box(redact(black_box("warm up the regex")));
    println!(
        "redactor   one-time compile: {}us",
        start.elapsed().as_micros()
    );

    let start = Instant::now();
    black_box(heuristics::evaluate(black_box(&heuristics_context(
        "warm up",
    ))));
    println!(
        "heuristics one-time compile: {}us\n",
        start.elapsed().as_micros()
    );

    println!("fast-path latency  ({SAMPLES} samples/case, budget {BUDGET_NS}ns)\n");

    let mut worst = 0u128;

    for (label, command) in CORPUS {
        // Warm caches and branch predictors before measuring.
        for _ in 0..1_000 {
            black_box(classify(black_box(command)));
        }

        let start = Instant::now();
        for _ in 0..SAMPLES {
            black_box(classify(black_box(command)));
        }
        let mean_ns = start.elapsed().as_nanos() / u128::from(SAMPLES);
        worst = worst.max(mean_ns);

        let verdict = if mean_ns <= BUDGET_NS {
            "ok"
        } else {
            "OVER BUDGET"
        };
        println!("  {mean_ns:>7} ns  {verdict:<11}  {label:<24} {command}");
    }

    println!("\nworst case: {worst}ns of {BUDGET_NS}ns budget");

    assert!(
        worst <= BUDGET_NS,
        "fast-path exceeded its {BUDGET_NS}ns budget ({worst}ns)"
    );

    println!("\nredaction latency  ({SAMPLES} samples/case, budget {REDACT_BUDGET_NS}ns)\n");

    let mut redact_worst = 0u128;

    for (label, command) in REDACT_CORPUS {
        for _ in 0..1_000 {
            black_box(redact(black_box(command)));
        }

        let start = Instant::now();
        for _ in 0..SAMPLES {
            black_box(redact(black_box(command)));
        }
        let mean_ns = start.elapsed().as_nanos() / u128::from(SAMPLES);
        redact_worst = redact_worst.max(mean_ns);

        let verdict = if mean_ns <= REDACT_BUDGET_NS {
            "ok"
        } else {
            "OVER BUDGET"
        };
        println!("  {mean_ns:>7} ns  {verdict:<11}  {label:<24} {command}");
    }

    println!("\nworst case: {redact_worst}ns of {REDACT_BUDGET_NS}ns budget");

    assert!(
        redact_worst <= REDACT_BUDGET_NS,
        "redaction exceeded its {REDACT_BUDGET_NS}ns budget ({redact_worst}ns)"
    );
}
