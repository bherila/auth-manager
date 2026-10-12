#!/usr/bin/env bash
#
# Runs ON THE HOST as the shared deploy action's pre-migrate-script, after the candidate is uploaded
# and its .env is installed from ~/.config/auth-manager/deployment.env:
#
#   pre-migrate.sh <candidate-path> <php> <stable-path>
#
# Database credentials for operator tooling live beside .env and are release-local: each candidate
# gets its own mode-600 copy of the private file, so they never depend on the previous release.
# Contents are never read or printed.
set -euo pipefail

app_dir=$1
stable_dir=$3
test "$stable_dir" = auth-manager

source_file="$HOME/.config/auth-manager/database.env"
test -f "$source_file"
test ! -L "$source_file"

cd "$HOME/$app_dir"
install -m 600 "$source_file" .db-credentials

# The signing pair is shared storage; the action refuses a partial pair, so only prove it is present.
test -s storage/app/private/oauth/oauth-private.key
test -s storage/app/private/oauth/oauth-public.key
