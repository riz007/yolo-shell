use std::collections::BTreeMap;

use yolo_shell::heuristics::{apply_severe_floor, engine_ready, evaluate, DATA_ARG_COMMANDS};
use yolo_shell::jev_client::{Action, Context, Decision, Outcome, Source};

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

fn jev_said(risk: u8, action: Action) -> Outcome {
    Outcome {
        decision: Decision {
            is_destructive: risk >= 4,
            risk_score: risk,
            action,
            reason: Some("from jev".to_string()),
        },
        source: Source::Jev,
        elapsed: std::time::Duration::from_millis(400),
        note: None,
    }
}

/// Observed live: Jev scored `git push --force origin main` at 7, which is a
/// y/N prompt, where the spec and the local rules both call for a block.
#[test]
fn jev_cannot_downgrade_a_severe_local_rule() {
    let context = ctx("git push origin main --force");
    let floored = apply_severe_floor(jev_said(7, Action::WarnAndConfirm), &context);

    assert_eq!(floored.decision.action, Action::BlockCompletely);
    assert_eq!(
        floored.decision.risk_score, 9,
        "local rule score should win"
    );
    assert!(floored.decision.is_destructive);
    assert!(
        floored.note.is_some_and(|n| n.contains("raised 7 to 9")),
        "the override should be visible in the trace"
    );
}

/// Below the severe band Jev keeps full authority. This is where it beats the
/// rule table: `./build` is restored by a rebuild, so 3 is the better answer.
#[test]
fn jev_may_still_relax_a_moderate_local_rule() {
    let context = ctx("rm -rf ./build");
    assert_eq!(
        evaluate(&context).risk_score,
        5,
        "local scores this moderate"
    );

    let floored = apply_severe_floor(jev_said(3, Action::AllowImmediately), &context);
    assert_eq!(
        floored.decision.risk_score, 3,
        "Jev should keep the lower score"
    );
    assert_eq!(floored.decision.action, Action::AllowImmediately);
}

#[test]
fn the_floor_leaves_agreeing_decisions_alone() {
    let context = ctx("rm -rf /");
    let original = jev_said(10, Action::BlockCompletely);
    let floored = apply_severe_floor(original, &context);

    assert_eq!(floored.decision.risk_score, 10);
    assert_eq!(floored.decision.reason.as_deref(), Some("from jev"));
    assert!(floored.note.is_none(), "no override, so no note");
}

/// The floor is for Jev answers only; a local decision is already local.
#[test]
fn the_floor_does_not_touch_a_local_decision() {
    let context = ctx("git push origin main --force");
    let local = Outcome {
        source: Source::Local,
        ..jev_said(2, Action::AllowImmediately)
    };

    let floored = apply_severe_floor(local, &context);
    assert_eq!(floored.decision.risk_score, 2, "left as-is");
}

/// A command that *mentions* something dangerous is not doing it. Blocking
/// `grep -r "DROP TABLE" migrations/` is how a gatekeeper gets uninstalled.
#[test]
fn quoted_text_passed_to_a_text_tool_is_data_not_code() {
    for command in [
        r#"grep -r "DROP TABLE" migrations/"#,
        r#"grep -rn "rm -rf" scripts/"#,
        r#"echo "never run rm -rf /" | tee notes.txt"#,
        r#"sed -i "s/rm -rf/echo/" deploy.sh"#,
        r#"git commit -m "fix rm -rf bug in deploy script""#,
        r#"git commit -m "stop calling kubectl delete namespace""#,
        r#"printf "terraform destroy\n""#,
        r#"awk '/DROP DATABASE/ {print}' audit.log"#,
    ] {
        assert_action(&ctx(command), Action::AllowImmediately);
    }
}

/// The inverse must keep working: these programs really do run what they are
/// handed, so their quotes stay code.
#[test]
fn quoted_code_passed_to_an_interpreter_is_still_scored() {
    for command in [
        "psql -c 'DROP DATABASE billing'",
        "mysql -e 'TRUNCATE TABLE orders'",
        "zsh -c 'rm -rf /'",
        "bash -c \"rm -rf /\"",
        "sh -c 'rm -rf /*'",
    ] {
        assert_action(&ctx(command), Action::BlockCompletely);
    }
}

#[test]
fn an_unterminated_quote_is_left_scorable() {
    // Nothing is swallowed, so the command still scores on what it does.
    let decision = evaluate(&ctx("echo \"rm -rf / ; kubectl delete namespace prod"));
    assert!(
        decision.risk_score >= 4,
        "an unclosed quote hid the command"
    );
}

#[test]
fn the_data_command_table_is_sorted() {
    let mut sorted = DATA_ARG_COMMANDS.to_vec();
    sorted.sort_unstable();
    assert_eq!(DATA_ARG_COMMANDS, sorted.as_slice());

    // And every entry is reachable through the lookup.
    for program in DATA_ARG_COMMANDS {
        let command = format!(r#"{program} "rm -rf /" somefile"#);
        assert_eq!(
            evaluate(&ctx(&command)).action,
            Action::AllowImmediately,
            "lookup missed: {program}"
        );
    }
}

/// Jev scored `rails db:drop` at 8 with a production marker while the rule
/// table said 1, so offline the database went without a prompt.
#[test]
fn orm_database_destruction_is_caught_offline() {
    for command in [
        "rails db:drop",
        "rails db:reset",
        "rake db:purge",
        "bundle exec rails db:reset",
        "prisma migrate reset",
        "sequelize db:drop",
        "alembic downgrade base",
        "python manage.py flush",
    ] {
        assert_action(&ctx(command), Action::WarnAndConfirm);
    }

    assert_action(
        &with_env("rails db:drop", "NODE_ENV", "production"),
        Action::BlockCompletely,
    );
}

#[test]
fn ordinary_orm_commands_are_untouched() {
    for command in [
        "rails db:migrate",
        "rails server",
        "rake test",
        "prisma generate",
    ] {
        assert_action(&ctx(command), Action::AllowImmediately);
    }
}
