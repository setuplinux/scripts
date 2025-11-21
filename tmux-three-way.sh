#!/usr/bin/env bash
set -euo pipefail

# Three-pane tmux helper: opens even horizontal splits, SSHes to three hosts,
# enables synchronized input, and attaches to the session.
# Usage: ./tmux-three-way.sh <host1> <host2> <host3> [session-name]
# - Hosts accept bare names or user@host; bare names default to root@<host>.
# - Session name defaults to "root-triplet" if omitted.

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <host1> <host2> <host3> [session-name]" >&2
  exit 1
fi

HOST_A="$1"
HOST_B="$2"
HOST_C="$3"
SESSION_NAME="${4:-root-triplet}"

# Default to root@ if no user is provided.
for idx in HOST_A HOST_B HOST_C; do
  val=${!idx}
  if [[ "$val" != *@* ]]; then
    printf -v "$idx" "root@%s" "$val"
  fi
done

tmux new-session -d -s "$SESSION_NAME" "ssh $HOST_A"
tmux split-window -h -t "$SESSION_NAME" "ssh $HOST_B"
tmux split-window -h -t "$SESSION_NAME" "ssh $HOST_C"
tmux select-layout -t "$SESSION_NAME" even-horizontal
tmux setw -t "$SESSION_NAME" synchronize-panes on
tmux attach -t "$SESSION_NAME"
