# CLAUDE.md — Quick Reference & Commands

This file defines the commands, coding style, and testing requirements for working on **YOLO-Shell**.

---

## 1. Quick Commands

### Build & Run

```bash
cargo build --release               # Build release binary
cargo run -- "rm -rf /"             # Test intercepting a command directly
```

### Testing & Benchmarking

```bash
cargo test                          # Run unit & integration tests
cargo test -- --nocapture           # Run tests with console output
cargo bench                         # Run latency performance benchmarks
```

### Code Quality

```bash
cargo fmt -- --check                # Verify formatting
cargo clippy -- -D warnings         # Run linter
```

---

## 2. Code Style & Standards

- **Language:** Rust (edition 2021) or Go.
- **Error Handling:** Never panic in production hooks. Wrap errors and return fallback decisions.
- **Imports:** Keep dependencies minimal (`reqwest` with `native-tls` or `ureq`, `serde`, `regex`).
- **Logging:** Output to stderr only so standard terminal pipe chains (`cmd1 | cmd2`) remain unbroken.

---

## 3. Shell Hook Testing Commands

Test your local builds against real shell hooks using these isolated commands:

```bash
# Test Zsh hook locally
source ./hooks/yolo.zsh
ls -la                              # Should hit fast-path (<1ms)
git push origin main --force        # Should trigger Jev warning/block prompt
```
