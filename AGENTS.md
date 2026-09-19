# AGENTS.md — Guidelines for AI Coding Agents

This file provides rules and constraints for AI agents (Claude Code, Cursor, Copilot, etc.) contributing to **YOLO-Shell**.

---

## 1. Primary Objectives & Rules

1. **Strict Performance Constraint:** Any code path added MUST NOT add more than $10\text{ms}$ of local processing latency. Network requests to Jev must time out strictly at $200\text{ms}$.
2. **Fail-Open by Default:** If an unhandled error, panic, or timeout occurs, YOLO-Shell must print a subtle warning and allow command execution (do not lock the developer out of their terminal).
3. **No External Runtime Dependencies:** Build self-contained scripts or static binaries. Do not require runtime environments like Node or Python unless explicitly configured.

---

## 2. Directory Layout Architecture

```
yolo-shell/
├── SPEC.md             # Project architecture specification
├── AGENTS.md           # Instructions for AI agents
├── CLAUDE.md           # Developer workflow commands & standards
├── src/                # Core interceptor logic
│   ├── fastpath.rs     # Local allowlist & fast regex checks
│   ├── redact.rs       # Secret scrubbing logic
│   ├── jev_client.rs   # Jev Decision API HTTP client
│   └── main.rs         # Entry point & CLI handler
├── hooks/              # Shell integration hooks
│   ├── yolo.zsh        # Zsh preexec hook
│   ├── yolo.bash       # Bash trap handler
│   └── yolo.fish       # Fish event listener
└── tests/              # End-to-end and benchmark tests
```

---

## 3. Implementation Priorities

When asked to code features, complete tasks in this order:

1. **Local Fast-Path Evaluator:** Check allowlist commands instantly ($<1\text{ms}$).
2. **Secret Redactor:** Regex matcher to scrub inline credentials before making network calls.
3. **Jev Client:** Async HTTP request with strict $200\text{ms}$ timeout + fallback local heuristic engine.
4. **Shell Hooks:** Native hook scripts for Zsh/Bash/Fish that exit cleanly with code `0` (allow) or `126` (block).
