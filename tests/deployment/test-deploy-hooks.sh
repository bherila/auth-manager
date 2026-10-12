#!/usr/bin/env bash
# Exercises scripts/deploy/quiesce.sh against a synthetic process table. Needs bash 4+
# (mapfile), so it runs on CI rather than under macOS's system bash.
set -euo pipefail

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

make_process() {
    local pid=$1 uid=$2 cwd=$3
    shift 3
    mkdir -p "$temporary/proc/$pid"
    printf 'Name:\tfixture\nUid:\t%s\t%s\t%s\t%s\n' "$uid" "$uid" "$uid" "$uid" >"$temporary/proc/$pid/status"
    ln -s "$cwd" "$temporary/proc/$pid/cwd"
    ln -s "$temporary/bin/php" "$temporary/proc/$pid/exe"
    printf '%s\0' "$@" >"$temporary/proc/$pid/cmdline"
}

# The stable-directory layout keeps the application path a real directory.
home=$temporary/home
stable=$home/auth-manager
mkdir -p "$home/.deployments/auth-manager/releases/candidate" "$stable" "$temporary/bin" "$temporary/proc" "$temporary/sibling"
touch "$stable/artisan" "$temporary/bin/php" "$temporary/sibling/artisan"
chmod +x "$temporary/bin/php"

run_quiesce() {
    HOME=$home DEPLOY_QUIESCE_PROC_ROOT=$temporary/proc DEPLOY_QUIESCE_UID=123 \
        DEPLOY_QUIESCE_TIMEOUT_SECONDS=0 DEPLOY_QUIESCE_INTERVAL_SECONDS=1 \
        bash "$repository/scripts/deploy/quiesce.sh" "${1:-.deployments/auth-manager/releases/candidate}" "$temporary/bin/php" "${2:-auth-manager}"
}

run_quiesce >/dev/null || fail 'an empty process inventory was rejected'

make_process 100 123 "$temporary/sibling" php artisan queue:work
run_quiesce >/dev/null || fail 'a sibling application process was treated as provider-owned'

make_process 101 999 "$stable" php artisan schedule:run
run_quiesce >/dev/null || fail "another account's process was treated as this account's"

for invocation in bare relative; do
    case $invocation in
        bare) artisan=artisan ;;
        relative) artisan=./artisan ;;
    esac
    make_process 200 123 "$stable" php "$artisan" schedule:run
    if run_quiesce >/dev/null 2>&1; then
        fail "a running $invocation provider scheduler invocation was accepted"
    fi
    rm -r "$temporary/proc/200"
done

# An absolute script path identifies ownership even when PHP starts elsewhere.
make_process 201 123 "$temporary/sibling" php "$stable/artisan" identities:purge-tombstones
if run_quiesce >/dev/null 2>&1; then
    fail 'an absolute provider Artisan path outside the app directory was accepted'
fi
rm -r "$temporary/proc/201"

# Malformed hook arguments fail closed before any process inspection.
if run_quiesce .deployments/other-app/releases/candidate >/dev/null 2>&1; then
    fail 'a candidate outside the provider deployment area was accepted'
fi
if run_quiesce .deployments/auth-manager/releases/candidate other-app >/dev/null 2>&1; then
    fail 'a different stable path was accepted'
fi

run_quiesce >/dev/null || fail 'the inventory did not return to quiescent'
echo 'Deployment hook tests passed.'
