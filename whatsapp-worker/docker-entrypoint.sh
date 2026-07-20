#!/bin/sh
set -eu

session_dir="${WA_SESSION_DIR:-/data/sessions}"
mkdir -p "$session_dir"
chown -R node:node "$session_dir"

exec gosu node "$@"
