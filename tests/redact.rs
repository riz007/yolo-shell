use yolo_shell::redact::{redact, REDACTED};

#[track_caller]
fn assert_scrubbed(command: &str, secret: &str, kept: &[&str]) {
    let out = redact(command);
    assert!(
        !out.contains(secret),
        "secret survived redaction\n  in:  {command}\n  out: {out}"
    );
    assert!(out.contains(REDACTED), "nothing was redacted in: {command}");
    for fragment in kept {
        assert!(
            out.contains(fragment),
            "lost context {fragment:?}\n  in:  {command}\n  out: {out}"
        );
    }
}

#[track_caller]
fn assert_untouched(command: &str) {
    assert_eq!(redact(command), command, "redactor altered a clean command");
}

#[test]
fn credential_flags_with_equals() {
    assert_scrubbed(
        "mysql --host=prod-db --password=hunter2",
        "hunter2",
        &["mysql", "--host=prod-db", "--password="],
    );
    assert_scrubbed(
        "gh auth login --token=abc123xyz",
        "abc123xyz",
        &["gh auth login"],
    );
    assert_scrubbed(
        "deploy --api-key=k-9f3a2b --env=prod",
        "k-9f3a2b",
        &["--env=prod"],
    );
    assert_scrubbed(
        "cmd --client-secret=s3cr3t",
        "s3cr3t",
        &["--client-secret="],
    );
}

#[test]
fn credential_flags_with_spaced_values() {
    assert_scrubbed(
        "gh auth login --token abc123xyz",
        "abc123xyz",
        &["gh auth login"],
    );
    assert_scrubbed(
        "cmd --password \"my long pass\"",
        "my long pass",
        &["--password"],
    );
    assert_scrubbed(
        "cmd --password 'my long pass'",
        "my long pass",
        &["--password"],
    );
}

#[test]
fn a_credential_flag_does_not_swallow_the_next_flag() {
    let out = redact("deploy --token --verbose --force");
    assert!(
        out.contains("--verbose") && out.contains("--force"),
        "consumed a following flag: {out}"
    );
}

#[test]
fn secret_looking_env_assignments() {
    assert_scrubbed(
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI terraform destroy",
        "wJalrXUtnFEMI",
        &["AWS_SECRET_ACCESS_KEY=", "terraform destroy"],
    );
    assert_scrubbed(
        "DB_PASSWORD=hunter2 rails db:drop",
        "hunter2",
        &["rails db:drop"],
    );
    assert_scrubbed(
        "GITHUB_TOKEN=ghp_16C7e42F292c69 gh repo delete",
        "ghp_16C7e42F292c69",
        &["gh repo delete"],
    );
    assert_scrubbed(
        "export STRIPE_SECRET=sk_live_abc",
        "sk_live_abc",
        &["export"],
    );
}

#[test]
fn deployment_context_is_never_mistaken_for_a_secret() {
    // The Jev payload carries these as context; redacting them would blind
    // the decision engine.
    assert_untouched("NODE_ENV=production npm run deploy");
    assert_untouched("AWS_PROFILE=prod-account aws s3 rm s3://bucket --recursive");
    assert_untouched("KUBE_CONTEXT=prod kubectl delete namespace billing");
    assert_untouched("RAILS_ENV=production rails db:drop");
    assert_untouched("PWD=/tmp make install");
}

#[test]
fn ordinary_destructive_commands_pass_through_intact() {
    assert_untouched("rm -rf /");
    assert_untouched("git push origin main --force");
    assert_untouched("dd if=/dev/zero of=/dev/disk0");
    assert_untouched("kubectl delete namespace prod");
    assert_untouched("psql -h prod-db.internal -U admin -c 'DROP DATABASE billing'");
    assert_untouched("sort -u names.txt");
    assert_untouched("docker run -p 8080:80 nginx");
}

#[test]
fn recognisable_token_shapes_anywhere_in_the_line() {
    for (command, secret) in [
        (
            "curl -H x ghp_16C7e42F292c6912E7710c838347Ae178B4a",
            "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
        ),
        (
            "echo github_pat_11ABCDEFG0aBcDeFgHiJkL",
            "github_pat_11ABCDEFG0aBcDeFgHiJkL",
        ),
        ("aws configure AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
        ("send xoxb-2451-4561-abcdefgh", "xoxb-2451-4561-abcdefgh"),
        (
            "cmd glpat-ABCDEFGHIJKLMNOPQRST",
            "glpat-ABCDEFGHIJKLMNOPQRST",
        ),
        (
            "call sk-ant-api03-AbCdEfGhIjKlMnOpQrSt",
            "sk-ant-api03-AbCdEfGhIjKlMnOpQrSt",
        ),
        (
            "call sk-AbCdEfGhIjKlMnOpQrSt1234",
            "sk-AbCdEfGhIjKlMnOpQrSt1234",
        ),
        (
            "stripe pay sk_live_4eC39HqLyjWDarjtT1zdp7dc",
            "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
        ),
        (
            "gmaps AIzaSyD-1234567890abcdefghijklmnopqrstuvw",
            "AIzaSyD-1234567890abcdefghijklmnopqrstuvw",
        ),
    ] {
        assert_scrubbed(command, secret, &[]);
    }
}

#[test]
fn jwts_are_recognised() {
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.dBjftJeZ4CVPmB92K27uhbUJU1p1r";
    assert_scrubbed(
        &format!("curl -H \"Bearer {jwt}\" https://api.internal"),
        jwt,
        &["api.internal"],
    );
}

#[test]
fn connection_strings_keep_the_host_and_lose_the_password() {
    assert_scrubbed(
        "psql postgres://admin:hunter2@prod-db.internal:5432/billing -c 'DROP TABLE users'",
        "hunter2",
        &[
            "postgres://admin:",
            "@prod-db.internal:5432/billing",
            "DROP TABLE users",
        ],
    );
    assert_scrubbed(
        "redis-cli -u redis://default:s3cr3t@cache.prod:6379 FLUSHALL",
        "s3cr3t",
        &["cache.prod:6379", "FLUSHALL"],
    );
    assert_scrubbed(
        "git push https://user:ghp_abcdefghij1234567890@github.com/org/repo main",
        "ghp_abcdefghij1234567890",
        &["github.com/org/repo", "main"],
    );
}

#[test]
fn urls_without_credentials_are_left_alone() {
    assert_untouched("curl https://api.internal/v1/users");
    assert_untouched("git clone git@github.com:org/repo.git");
}

#[test]
fn authorization_headers_keep_their_scheme() {
    let out =
        redact("curl -X DELETE -H \"Authorization: Bearer abc123def456\" https://api.prod/orders");
    assert!(!out.contains("abc123def456"), "{out}");
    assert!(
        out.contains("Authorization: Bearer "),
        "lost the auth scheme: {out}"
    );
    assert!(
        out.contains("api.prod/orders") && out.contains("DELETE"),
        "{out}"
    );
}

#[test]
fn curl_style_basic_auth() {
    assert_scrubbed(
        "curl -u admin:hunter2 https://api.prod/reset",
        "hunter2",
        &["curl", "api.prod/reset"],
    );
    assert_scrubbed(
        "curl --user admin:hunter2 https://api.prod",
        "hunter2",
        &["curl"],
    );
}

#[test]
fn pem_private_keys() {
    let key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----";
    assert_scrubbed(
        &format!("echo \"{key}\" > id_rsa"),
        "MIIEowIBAAKCAQEA",
        &["id_rsa"],
    );
}

#[test]
fn several_secrets_in_one_command() {
    let out =
        redact("deploy --token abc123xyz --password=hunter2 --url postgres://u:p4ss@db.prod/x");
    for secret in ["abc123xyz", "hunter2", "p4ss"] {
        assert!(!out.contains(secret), "{secret} survived: {out}");
    }
    assert!(out.contains("db.prod/x"), "lost the host: {out}");
}

#[test]
fn redaction_is_idempotent() {
    for command in [
        "mysql --password=hunter2",
        "psql postgres://admin:hunter2@prod-db/billing",
        "curl -H \"Authorization: Bearer abc123def456\" https://api.prod",
        "rm -rf /",
    ] {
        let once = redact(command);
        assert_eq!(redact(&once), once, "second pass changed: {once}");
    }
}

#[test]
fn degenerate_input_is_handled() {
    assert_eq!(redact(""), "");
    assert_eq!(redact("   "), "   ");
    // No panic, no pathological blowup on a long line.
    let long = "a ".repeat(50_000);
    assert_eq!(redact(&long).len(), long.len());
}
