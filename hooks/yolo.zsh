# YOLO-Shell — zsh integration.
#
#   source /path/to/yolo-shell/hooks/yolo.zsh
#
# Wraps `accept-line` rather than using `add-zsh-hook preexec`. preexec fires
# after zsh has committed to the command and cannot cancel it, so a block
# could only be reported. The widget runs while the line is still a buffer.

0=${(%):-%N}
: ${YOLO_BIN:=${0:A:h:h}/target/release/yolo}

_yolo_accept_line() {
  emulate -L zsh

  local buffer=$BUFFER

  if [[ -z ${buffer//[[:space:]]/} || -n ${YOLO_BYPASS:-} || ! -x $YOLO_BIN ]]; then
    zle .accept-line
    return
  fi

  zle -I  # let the banner share the screen with the prompt

  # --no-prompt: ZLE holds the tty in raw mode, so zsh reads the answer
  # below rather than the child process.
  "$YOLO_BIN" eval --no-prompt "$buffer"
  local verdict=$?

  case $verdict in
    125)  # warn_and_confirm
      local answered
      read -q "answered?   Run anyway? [y/N] "
      local confirmed=$?
      print

      # `read -q` takes one keypress and leaves the Enter behind, where it
      # would immediately re-submit the buffer. Drop what's pending.
      local discard
      while read -s -t 0 -k 1 discard 2>/dev/null; do
        :
      done

      if (( confirmed != 0 )); then
        zle .redisplay
        return 0
      fi
      ;;
    126)  # block_completely — leave BUFFER intact so it can be edited
      zle .redisplay
      return 0
      ;;
  esac

  # 0, or any unexpected code: fail open.
  zle .accept-line
}

zle -N accept-line _yolo_accept_line

# Start the connection daemon if one is not already listening. It removes the
# TLS handshake from every command, exits on its own when idle, and a second
# instance exits immediately, so this is safe to run on every shell start.
# Everything works without it, just slower.
if [ -n "${JEV_API_KEY:-}" ] && [ -z "${YOLO_NO_DAEMON:-}" ]; then
  ( "$YOLO_BIN" daemon >/dev/null 2>&1 & ) 2>/dev/null
fi

# The bypass the block banner advertises. Shadows the binary for interactive
# use; the hook above always calls it by absolute path.
yolo() {
  if (( $# == 0 )); then
    print -u2 "usage: yolo <command>"
    return 2
  fi
  YOLO_BYPASS=1 "$@"
}
