#!/bin/sh
# Applies pending Prisma migrations before the server accepts traffic, then
# execs the app. Mirrors the API service's entrypoint pattern: all pre-start
# work happens here, and the app process replaces the shell.
#
# migrate deploy only ever applies committed migrations. It never generates
# one, never resets, and exits non-zero on a failure, which makes Railway fail
# the deploy instead of serving against a stale schema.
set -e

npx prisma migrate deploy

exec "$@"
