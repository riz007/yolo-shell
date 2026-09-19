#!/bin/sh
# YOLO-Shell installer. Builds the binary and prints the line to add to your
# shell rc file. Safe to re-run.
set -eu

REPO_URL="${YOLO_REPO:-https://github.com/riz007/yolo-shell.git}"
PREFIX="${YOLO_PREFIX:-$HOME/.yolo-shell}"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v cargo >/dev/null 2>&1 || die "cargo not found. Install Rust: https://rustup.rs"

if [ -d "$PREFIX/.git" ]; then
  say "Updating $PREFIX"
  git -C "$PREFIX" pull --ff-only
elif [ -f "$PREFIX/Cargo.toml" ]; then
  say "Using existing checkout at $PREFIX"
else
  command -v git >/dev/null 2>&1 || die "git not found"
  say "Cloning into $PREFIX"
  git clone --depth 1 "$REPO_URL" "$PREFIX"
fi

say "Building release binary"
cargo build --release --manifest-path "$PREFIX/Cargo.toml"

case "${SHELL##*/}" in
  zsh)  RC="$HOME/.zshrc";        HOOK="$PREFIX/hooks/yolo.zsh"  ;;
  bash) RC="$HOME/.bashrc";       HOOK="$PREFIX/hooks/yolo.bash" ;;
  fish) RC="$HOME/.config/fish/config.fish"; HOOK="$PREFIX/hooks/yolo.fish" ;;
  *)    RC="your shell rc file";  HOOK="$PREFIX/hooks/yolo.<shell>" ;;
esac

say ""
say "Installed. Add this to $RC:"
say ""
say "    source $HOOK"
say ""
say "Then, to enable Jev (optional - heuristics work offline):"
say ""
say "    export JEV_API_KEY=\"your_key_here\""
say ""
