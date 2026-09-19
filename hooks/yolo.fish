# YOLO-Shell — fish integration.
#
#   source /path/to/yolo-shell/hooks/yolo.fish
#
# `--on-event fish_preexec` fires too late to cancel anything, so Enter is
# rebound instead and the check runs while the line is still a buffer.

if not set -q YOLO_BIN
    set -g YOLO_BIN (path resolve (status dirname))/../target/release/yolo
end

function _yolo_enter --description 'Evaluate the command line before executing it'
    set -l buffer (commandline)

    if test -z (string trim -- "$buffer")
        or set -q YOLO_BYPASS
        or not test -x "$YOLO_BIN"
        commandline -f execute
        return
    end

    echo
    $YOLO_BIN eval "$buffer" </dev/tty
    set -l verdict $status

    # Only an explicit 126 blocks; anything else fails open.
    if test $verdict -eq 126
        commandline -f repaint
        return
    end

    commandline -f execute
end

bind \r _yolo_enter
bind \n _yolo_enter

# Start the connection daemon if one is not already listening. It removes the
# TLS handshake from every command, exits on its own when idle, and a second
# instance exits immediately, so this is safe to run on every shell start.
# Everything works without it, just slower.
if set -q JEV_API_KEY; and not set -q YOLO_NO_DAEMON
    $YOLO_BIN daemon >/dev/null 2>&1 &
    disown
end

# The bypass the block banner advertises. Shadows the binary for interactive
# use; the binding above always calls it by absolute path.
function yolo --description 'Run a command without YOLO-Shell evaluation'
    if test (count $argv) -eq 0
        echo "usage: yolo <command>" >&2
        return 2
    end
    set -lx YOLO_BYPASS 1
    $argv
end
