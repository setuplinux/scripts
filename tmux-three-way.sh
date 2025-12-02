#!/usr/bin/env bash
set -euo pipefail

# Three-pane tmux helper: opens even horizontal splits, SSHes to three hosts,
# enables synchronized input, and attaches to the session.
# Usage: ./tmux-three-way.sh <host1> <host2> <host3>
# - Hosts accept bare names or user@host; bare names default to root@<host>.
# - Session name is fixed to "three-way".

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <host1> <host2> <host3>" >&2
  exit 1
fi

HOST_A="$1"
HOST_B="$2"
HOST_C="$3"
SESSION_NAME="three-way"

# Default to root@ if no user is provided.
for idx in HOST_A HOST_B HOST_C; do
  val=${!idx}
  if [[ "$val" != *@* ]]; then
    printf -v "$idx" "root@%s" "$val"
  fi
done

# If the session already exists, let the user choose what to do.
if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
  echo "tmux session '$SESSION_NAME' already exists."
  while true; do
    read -rp "Attach (a), kill and recreate (k), or quit (q)? [a/k/q]: " choice
    case "${choice:-a}" in
      a|A)
        tmux attach -t "$SESSION_NAME"
        exit 0
        ;;
      k|K)
        tmux kill-session -t "$SESSION_NAME"
        break
        ;;
      q|Q)
        echo "Aborting."
        exit 0
        ;;
      *)
        echo "Please enter 'a', 'k', or 'q'."
        ;;
    esac
  done
fi

tmux new-session -d -s "$SESSION_NAME" "ssh $HOST_A"
tmux split-window -h -t "$SESSION_NAME" "ssh $HOST_B"
tmux split-window -h -t "$SESSION_NAME" "ssh $HOST_C"
tmux select-layout -t "$SESSION_NAME" even-horizontal
tmux setw -t "$SESSION_NAME" synchronize-panes on
tmux attach -t "$SESSION_NAME"
