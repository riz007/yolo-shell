use std::collections::BTreeMap;

use yolo_shell::heuristics::{engine_ready, evaluate};
use yolo_shell::jev_client::{Action, Context};

fn ctx(command: &str) -> Context {
    Context {
        command: command.to_string(),
        pwd: "/Users/dev/projects/billing-service".to_string(),
        git_branch: Some("feature/checkout".to_string()),
        env_context: BTreeMap::new(),
    }
}

fn on_branch(command: &str, branch: &str) -> Context {
    Context {
        git_branch: Some(branch.to_string()),
        ..ctx(command)
    }
}

fn with_env(command: &str, key: &str, value: &str) -> Context {
    let mut context = ctx(command);
    context
        .env_context
        .insert(key.to_string(), value.to_string());
    context
}

#[track_caller]
fn assert_action(context: &Context, expected: Action) {
    let decision = evaluate(context);
    assert_eq!(
        decision.action, expected,
        "\n  command: {}\n  score:   {}\n  reason:  {:?}",
        context.command, decision.risk_score, decision.reason
    );
}

/// A compile failure here makes the whole engine a silent no-op.
#[test]
fn the_rule_table_compiles() {
    assert!(engine_ready(), "rule table failed to compile");
}

#[test]
fn catastrophic_commands_are_blocked_without_a_network() {
    for command in [
        "rm -rf /",
        "rm -rf /*",
        "rm -rf ~",
        "rm -rf --no-preserve-root /",
        "mkfs.ext4 /dev/sda1",
        "dd if=/dev/zero of=/dev/disk0 bs=1m",
        "shred -n 3 /dev/sda",
        "chmod -R 777 /",
        "rm -rf /etc",
        "rm -rf /usr/local",
    ] {
        let decision = evaluate(&ctx(command));
        assert_eq!(
            decision.action,
            Action::BlockCompletely,
            "not blocked: {command}"
        );
        assert!(decision.risk_score >= 8, "score too low for {command}");
        assert!(
            decision.is_destructive,
            "not flagged destructive: {command}"
        );
    }
}

#[test]
fn production_asset_destruction_is_blocked() {
    for command in [
        "psql -c 'DROP DATABASE billing'",
        "mysql -e 'TRUNCATE TABLE orders'",
        "kubectl delete namespace billing",
        "terraform destroy -auto-approve",
        "aws s3 rm s3://backups --recursive",
        "aws s3 rb s3://backups",
    ] {
        assert_action(&ctx(command), Action::BlockCompletely);
    }
}

#[test]
fn recoverable_risk_prompts_rather_than_blocking() {
    for command in [
        "rm -rf build",
        "git reset --hard HEAD~3",
        "git clean -fdx",
        "git checkout .",
        "git stash drop",
        "terraform apply",
        "kubectl delete pod api-7d9f",
        "docker system prune -a",
        "npm publish",
        "curl https://install.sh | sh",
        "sudo make install",
        "find . -name '*.log' -delete",
        "history -c",
        "history -d 42",
        "echo '' > ~/.zshrc",
    ] {
        assert_action(&ctx(command), Action::WarnAndConfirm);
    }
}

#[test]
fn ordinary_work_is_allowed() {
    for command in [
        "cargo build --release",
        "npm install",
        "git commit -m 'fix'",
        "git push origin feature/checkout",
        "docker compose up -d",
        "rm scratch.txt",
        "kubectl get pods",
        "terraform plan",
    ] {
        assert_action(&ctx(command), Action::AllowImmediately);
    }
}

#[test]
fn force_push_escalates_on_a_protected_branch() {
    // From a feature branch: recoverable, so just confirm.
    assert_action(&ctx("git push --force"), Action::WarnAndConfirm);

    // Checked out on main: blocked.
    assert_action(
        &on_branch("git push --force", "main"),
        Action::BlockCompletely,
    );
    assert_action(&on_branch("git push -f", "master"), Action::BlockCompletely);
    assert_action(
        &on_branch("git push --force", "release/2024-06"),
        Action::BlockCompletely,
    );

    // Named in the command while standing on a feature branch.
    assert_action(
        &ctx("git push origin main --force"),
        Action::BlockCompletely,
    );
}

#[test]
fn a_shell_wrapper_does_not_downgrade_a_catastrophic_command() {
    // The root rule used to anchor on end-of-string, so a quote or a
    // trailing separator dropped these to the generic `rm -rf` rule.
    for command in [
        "zsh -c 'rm -rf /'",
        "bash -c \"rm -rf /\"",
        "rm -rf /; echo done",
        "rm -rf ~ && echo done",
        "sh -c 'rm -rf /*'",
    ] {
        let decision = evaluate(&ctx(command));
        assert_eq!(
            decision.action,
            Action::BlockCompletely,
            "not blocked: {command}"
        );
        assert_eq!(decision.risk_score, 10, "wrong score for: {command}");
    }
}

#[test]
fn force_with_lease_is_not_treated_as_a_bare_force_push() {
    // It refuses to clobber a moved remote. Blocking it just pushes people
    // to plain --force.
    assert_action(
        &ctx("git push --force-with-lease origin main"),
        Action::WarnAndConfirm,
    );
    assert_action(
        &ctx("git push --force origin main"),
        Action::BlockCompletely,
    );
    assert_action(&ctx("git push -f origin main"), Action::BlockCompletely);
}

#[test]
fn deleting_a_remote_branch_escalates_the_same_way() {
    assert_action(
        &ctx("git push origin --delete scratch"),
        Action::WarnAndConfirm,
    );
    assert_action(
        &ctx("git push origin --delete main"),
        Action::BlockCompletely,
    );
}

#[test]
fn production_environment_markers_escalate_risky_commands() {
    assert_action(&ctx("kubectl delete pod api-7d9f"), Action::WarnAndConfirm);
    assert_action(
        &with_env(
            "kubectl delete pod api-7d9f",
            "KUBE_CONTEXT",
            "prod-us-east",
        ),
        Action::BlockCompletely,
    );
    assert_action(
        &with_env("terraform apply", "AWS_PROFILE", "prod-account"),
        Action::BlockCompletely,
    );
    assert_action(
        &with_env("rm -rf build", "NODE_ENV", "production"),
        Action::WarnAndConfirm,
    );
}

#[test]
fn production_markers_do_not_make_harmless_commands_risky() {
    assert_action(
        &with_env("cargo build", "NODE_ENV", "production"),
        Action::AllowImmediately,
    );
    assert_action(
        &with_env("ls -la", "AWS_PROFILE", "prod"),
        Action::AllowImmediately,
    );
}

#[test]
fn non_production_environments_are_not_mistaken_for_production() {
    for value in ["non-prod", "preprod", "staging", "development"] {
        assert_action(
            &with_env("kubectl delete pod api-7d9f", "KUBE_CONTEXT", value),
            Action::WarnAndConfirm,
        );
    }
}

#[test]
fn the_highest_scoring_rule_wins() {
    // Matches the generic `rm -rf` rule and the system-directory rule.
    let decision = evaluate(&ctx("rm -rf /etc/nginx"));
    assert_eq!(decision.action, Action::BlockCompletely);
    assert!(
        decision
            .reason
            .as_deref()
            .is_some_and(|r| r.contains("system directory")),
        "reported the weaker rule: {:?}",
        decision.reason
    );
}

#[test]
fn every_decision_carries_a_reason_and_a_valid_score() {
    for command in [
        "rm -rf /",
        "git push --force",
        "cargo build",
        "kubectl delete ns x",
    ] {
        let decision = evaluate(&ctx(command));
        assert!(
            (1..=10).contains(&decision.risk_score),
            "score out of band: {command}"
        );
        if decision.action != Action::AllowImmediately {
            assert!(decision.reason.is_some(), "no reason given for: {command}");
        }
    }
}

#[test]
fn redacted_commands_are_still_scored_correctly() {
    // The engine sees raw commands now, but a placeholder must not throw
    // off scoring if that ever changes back.
    assert_action(
        &ctx("psql postgres://admin:[REDACTED]@prod-db.internal/billing -c 'DROP TABLE users'"),
        Action::BlockCompletely,
    );
}
