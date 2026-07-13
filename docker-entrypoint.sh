#!/bin/sh
# Railway (and other hosts) mount persistent volumes root-owned. The app runs
# as the unprivileged `node` user, so the directory holding AVA_DIRECTORY_DATA
# must be made writable before we drop privileges. Runs as root, chowns the
# data dir, then execs the app as `node` via su-exec — the process itself never
# runs as root.
set -e

DATA_FILE="${AVA_DIRECTORY_DATA:-/data/directory.json}"
DATA_DIR=$(dirname "$DATA_FILE")

mkdir -p "$DATA_DIR"
# Only chown when we're root (i.e. a volume is mounted). Harmless no-op locally.
if [ "$(id -u)" = "0" ]; then
  chown -R node:node "$DATA_DIR"
  exec su-exec node "$@"
fi

exec "$@"
