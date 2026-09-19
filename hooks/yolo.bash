# YOLO-Shell — bash integration.
#
#   source /path/to/yolo-shell/hooks/yolo.bash
#
# `extdebug` is what makes blocking possible: with it set, a DEBUG trap that
# returns 1 makes bash skip the command. Without it the trap can only watch.

[[ $- == *i* ]] || return 0

shopt -s extdebug

: "${YOLO_BIN:=${BASH_SOURCE[0]%/*}/../target/release/yolo}"

_yolo_eval() {
  local command=$1

  [[ -n ${YOLO_BYPASS:-} ]] && return 0
  [[ -x $YOLO_BIN ]] || return 0

  # The trap fires for every simple command, including inside functions,
  # loops and $PROMPT_COMMAND. Only judge what the user typed.
  (( ${#FUNCNAME[@]} > 2 )) && return 0
  [[ $command == _yolo_* ]] && return 0
  [[ -n ${PROMPT_COMMAND:-} && $command == "$PROMPT_COMMAND" ]] && return 0

  "$YOLO_BIN" eval "$command" < /dev/tty
  # Only an explicit 126 blocks; anything else fails open.
  (( $? == 126 )) && return 1
  return 0
}

trap '_yolo_eval "$BASH_COMMAND"' DEBUG

# Start the connection daemon if one is not already listening. It removes the
# TLS handshake from every command, exits on its own when idle, and a second
# instance exits immediately, so this is safe to run on every shell start.
# Everything works without it, just slower.
if [ -n "${JEV_API_KEY:-}" ] && [ -z "${YOLO_NO_DAEMON:-}" ]; then
  ( "$YOLO_BIN" daemon >/dev/null 2>&1 & ) 2>/dev/null
fi

# The bypass the block banner advertises. Shadows the binary for interactive
# use; the trap above always calls it by absolute path.
yolo() {
  if (( $# == 0 )); then
    echo "usage: yolo <command>" >&2
    return 2
  fi
  YOLO_BYPASS=1 "$@"
}
