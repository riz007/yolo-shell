<div align="center">

# YOLO-Shell 🛡️⚡

**The Smart CLI Gatekeeper Powered by TypeSafe Jev**

_Sub-millisecond on safe commands. A hard 200ms ceiling on everything else._

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/riz007/yolo-shell/ci.yml?branch=main&label=build)](../../actions)
[![Fast path](https://img.shields.io/badge/fast%20path-%3C2ms-brightgreen.svg)](#-features-at-a-glance)
[![Jev deadline](https://img.shields.io/badge/jev%20deadline-200ms%20hard-orange.svg)](#-features-at-a-glance)
[![BYOK](https://img.shields.io/badge/BYOK-ready-8A2BE2.svg)](#byok-setup)

</div>

---

YOLO-Shell sits between the Enter key and your shell. It reads the command you
just typed, weighs it against where you are — working directory, Git branch,
`AWS_PROFILE`, `KUBE_CONTEXT` — and decides whether to get out of the way, ask
for confirmation, or refuse.

```console
$ rm -rf /

⛔ YOLO-Shell blocked  risk 10/10  rm -rf /
   recursive delete of the filesystem root or home directory
   override: prefix the command with `yolo `
```

---

## 🤔 Why Standard Shell Aliases Fail

### The Rule Explosion Problem

The usual defence is an alias or a wrapper function:

```bash
alias rm='rm -i'
```

Then you need one for `git push --force`. And `kubectl delete`. And
`terraform destroy`, `aws s3 rm --recursive`, `DROP DATABASE`, `dd of=/dev/…`.
Each tool brings its own flags, each flag its own edge cases, and every rule
has to know which of them are dangerous _in this directory, on this branch,
against this cluster_.

That is a combinatorial explosion of fragile regex, and it fails in both
directions at once: too noisy to keep enabled, too sparse to actually catch the
command that ruins your afternoon. `rm -rf /` is easy. `zsh -c 'rm -rf /'` is
the same command wearing a hat, and your alias never sees it.

### The Latency Problem

Handing the question to a general-purpose LLM solves the rule explosion and
creates a worse problem: 2–3 seconds of think-time on every command. A shell
that pauses before `ls` is a shell you will uninstall by lunchtime.

The budget for a gatekeeper is not "fast enough to be useful." It is **fast
enough to be invisible.**

---

## ⚡ The Solution: a System 1 AI Engine

YOLO-Shell splits the problem in two, the way you do.

**System 1 — reflex.** A local fast-path filter recognises commands that only
read or navigate (`ls`, `cd`, `cat`, `git status`) and lets them through with
no network call at all. This is a sorted-table lookup over the command's
tokens: **178ns** in-process, ~2ms including process spawn. It is the path the
overwhelming majority of your commands take.

**System 2 — judgement.** Anything else goes to **TypeSafe Jev**, a typed
decision engine. YOLO-Shell asks it three named questions in a single
`POST /v1/systemone` pass:

| Question | Type | Answer |
|---|---|---|
| `is_destructive` | `noul` | probability of yes, thresholded at `0.5` |
| `risk_score` | `score` | a ten-level rubric; position `0–9` maps to risk `1–10` |
| `action` | `choice` | `allow_immediately` \| `warn_and_confirm` \| `block_completely` |

No token generation, no prose — structured output rather than a chat
completion, which is what makes a sub-second round trip possible at all.

Jev gets a wall-clock deadline enforced on the calling side rather than
trusted to the HTTP stack. Miss it, and a deterministic local rule engine
answers instead. You are never waiting on a network you cannot reach.

### The connection daemon

The hook spawns a fresh `yolo` per command, so the naive path repeats DNS, TCP
and TLS every single time. Against us-west-2 that measured **~455ms of
handshake to wrap ~350ms of actual inference** — most of your wait was setup,
paid again and again.

`yolo daemon` holds one warm connection and answers over a unix socket:

| | per command |
|---|---|
| without daemon | ~850ms |
| with daemon | ~400ms |

The shell hooks start it for you when `JEV_API_KEY` is set. It exits when
idle, a second instance exits immediately, and the socket is `0600` because
the daemon holds your key. It is strictly an accelerator — if it is missing,
stale or slow, the CLI falls back to an in-process call and then to local
heuristics, so it can never stop a decision being made.

```bash
yolo daemon --idle-timeout 3600   # run it yourself
YOLO_NO_DAEMON=1                  # opt out
```

> [!NOTE]
> Even warm, a round trip is one RTT plus inference. From a machine ~220ms
> from the endpoint that is ~400ms, which is over the 250ms the spec budgets.
> The remaining fix is a closer region, not more local engineering.

---

## 🏗️ Architecture & Workflow

```mermaid
flowchart TD
    A[Terminal Command Input] --> B{Local Fast-Path Filter}
    B -->|allowlisted: ls, cd, git status| C[Execute · ~2ms, no network]
    B -->|everything else| D[Scrub secrets from payload]
    D --> E{Jev Decision Engine<br/>200ms deadline}
    E -->|answers in time| F[is_destructive · risk_score · action]
    E -->|timeout / offline / no key| G[Local heuristic engine]
    G --> F
    F --> H{Action}
    H -->|allow_immediately| I[Execute natively · exit 0]
    H -->|warn_and_confirm| J[Yellow banner + y/N · exit 0 or 126]
    H -->|block_completely| K[Red alert · exit 126]
```

Context sent to Jev on every evaluated command:

```json
{
  "command": "psql postgres://admin:[REDACTED]@prod-db.internal/billing -c 'DROP TABLE users'",
  "pwd": "/Users/dev/projects/billing-service",
  "git_branch": "main",
  "env_context": { "NODE_ENV": "production", "AWS_PROFILE": "prod-account" }
}
```

Note the `[REDACTED]`. The password never left the machine; the host, the
user and the statement did, because those are what the decision depends on.

---

## ✨ Features at a Glance

|                                   |                                                                                                                                                                   |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ⚡ **Invisible on safe commands** | 178ns filter, ~2ms end-to-end. No network call, no token spend.                                                                                                   |
| ⏱️ **Hard 200ms ceiling**         | Enforced by a wall-clock deadline in the client, not by the HTTP library's own timeout — a stalled DNS lookup cannot outlast it.                                  |
| 🔑 **BYOK**                       | Bring your own TypeSafe Jev key. No account required to start; heuristics work with no key at all.                                                                |
| 🧭 **Context-aware**              | Weighs working directory, Git branch, and `AWS_PROFILE` / `KUBE_CONTEXT` / `NODE_ENV`. `git push --force` is a warning on a feature branch and a block on `main`. |
| 📴 **Works offline**              | 40-rule deterministic engine takes over on timeout, network failure, or missing key. `rm -rf /` is blocked on a plane.                                            |
| 🔒 **Secrets scrubbed**           | Passwords, tokens, connection strings and `Authorization` headers are removed before transmission. The unredacted command is not a serialisable type.             |
| 🐚 **Real shells**                | Zsh, Bash and Fish, each verified driving a live pty — not just syntax-checked.                                                                                   |
| 📦 **One binary**                 | No Node, no Python, no runtime. 2.3MB, statically linked TLS.                                                                                                     |

---

## 🚀 Quickstart

### Install

```bash
curl -fsSL https://raw.githubusercontent.com/riz007/yolo-shell/main/install.sh | sh
```

> [!NOTE]
> That one-liner needs the repository to be public first. Until then — and if
> you would rather not pipe a remote script into your shell, which YOLO-Shell
> itself scores at 7/10 — clone and build:
>
> ```bash
> git clone https://github.com/riz007/yolo-shell.git ~/.yolo-shell
> cd ~/.yolo-shell && cargo build --release
> ```

### Shell integration

**Zsh** — add to `~/.zshrc`:

```zsh
source ~/.yolo-shell/hooks/yolo.zsh
```

**Bash** — add to `~/.bashrc`:

```bash
source ~/.yolo-shell/hooks/yolo.bash
```

**Fish** — add to `~/.config/fish/config.fish`:

```fish
source ~/.yolo-shell/hooks/yolo.fish
```

Open a new terminal. You are protected — on heuristics alone, with no key.

### BYOK Setup

To enable Jev's context-aware judgement, export your TypeSafe key:

```bash
mkdir -p ~/.config/yolo-shell
printf 'export JEV_API_KEY=%s\n' 'your_key_here' > ~/.config/yolo-shell/env
chmod 600 ~/.config/yolo-shell/env
```

Then source it from your rc file, **before** the hook line:

```bash
[ -f ~/.config/yolo-shell/env ] && source ~/.config/yolo-shell/env
```

> [!WARNING]
> `export` puts the key in the environment of every process your shell spawns,
> so any package postinstall script can read it. Keep it out of your dotfiles
> repo, and rotate it if it ever lands in one.

Confirm it is being used:

```bash
YOLO_DEBUG=1 ~/.yolo-shell/target/release/yolo eval "kubectl delete namespace billing"
# yolo: jev decided in 143ms: risk 9/10
```

`local decided in 200ms (no response within 200ms)` means the key or endpoint
is wrong and you are running on heuristics — decisions are still made, just
without Jev's context awareness.

---

## 🎬 Demo

**Safe — straight through, no network:**

```console
$ ls -la
total 48
drwxr-xr-x  12 dev  staff   384 Nov 14 09:22 .
-rw-r--r--   1 dev  staff  1823 Nov 14 09:21 Cargo.toml
```

_Fast-path hit. 178ns filter, ~2ms total. Jev never contacted._

**Risky — intercepted with a risk score:**

```console
$ git push origin main -f

⚠  YOLO-Shell  risk 9/10  git push origin main -f
   force-push rewrites remote history; on a protected branch
   Run anyway? [y/N]
```

_Answer `n` and the command is discarded, still on the prompt for editing._

**Catastrophic — blocked outright:**

```console
$ rm -rf /

⛔ YOLO-Shell blocked  risk 10/10  rm -rf /
   recursive delete of the filesystem root or home directory
   override: prefix the command with `yolo `
```

_Exit code 126. The command never reaches your shell._

---

## ⚙️ Configuration

| Variable        | Effect                                                       |
| --------------- | ------------------------------------------------------------ |
| `JEV_API_KEY`   | Enables Jev. Unset means heuristics-only.                    |
| `JEV_API_URL` | Decision endpoint. Defaults to `https://api.typesafe.ai/v1/systemone`. |
| `JEV_MODEL` | Model name. Defaults to `jev-latest`; `jev-preview` is the other. `GET /v1/models` lists what your account can use. |
| `JEV_TIMEOUT_MS` | Deadline for the Jev call. Default `200`, clamped to `50`-`5000`. Raise it to diagnose a slow endpoint: a fresh process per command means a full DNS + TCP + TLS handshake every time, so a distant region can burn the default before the request is even sent. |
| `YOLO_BYPASS=1` | Skip evaluation entirely for one command or a whole session. |
| `YOLO_DEBUG=1`  | Trace which engine decided, and how fast, to stderr.         |
| `YOLO_SOCKET` | Daemon socket path. Defaults to a per-user runtime directory. Unix sockets cap near 104 bytes, so keep it short. |
| `YOLO_NO_DAEMON=1` | Don't start the connection daemon. |
| `NO_COLOR`      | Suppress ANSI colour in banners.                             |

Two escape hatches, for when you know exactly what you are doing:

```bash
yolo rm -rf ./node_modules      # bypass this one command
YOLO_BYPASS=1 ./scary-script.sh # bypass for one invocation
```

### Exit codes

| Code  | Meaning                                                                 |
| ----- | ----------------------------------------------------------------------- |
| `0`   | Allow — run the command                                                 |
| `125` | Needs confirmation (`--no-prompt` only; the Zsh widget asks for itself) |
| `126` | Block — abort                                                           |

Any other code means YOLO-Shell itself misbehaved, and every hook treats it as
allow. A gatekeeper that locks you out of your own terminal is a worse bug than
the one it was trying to prevent.

---

## 🛠️ Development

```bash
cargo test                    # 59 tests
cargo bench                   # asserts against the latency budget
cargo clippy -- -D warnings
cargo fmt -- --check
```

```
src/
├── fastpath.rs     allowlist filter — no network, no allocation
├── redact.rs       secret scrubbing at the wire boundary
├── heuristics.rs   deterministic offline rule engine
├── jev_client.rs   Jev API client + decision schema
├── daemon.rs       warm-connection daemon and its client
└── main.rs         CLI and action dispatcher
hooks/              zsh, bash, fish integrations
```

### A note on the shell hooks

Zsh's `preexec` and Fish's `fish_preexec` both fire _after_ the shell has
committed to running the command, and neither can cancel it — a block could be
reported but not enforced. YOLO-Shell therefore wraps Zsh's `accept-line`
widget and rebinds Enter in Fish, both of which run while the line is still an
editable buffer. Bash's `DEBUG` trap _can_ cancel, but only with
`shopt -s extdebug`, which the hook sets.

---

## 📄 License

MIT. See [LICENSE](LICENSE).
