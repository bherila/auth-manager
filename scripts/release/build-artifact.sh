#!/usr/bin/env bash
# Build the deployable provider tree for one commit as a reproducible tarball.
#
#   scripts/release/build-artifact.sh TAG OUTPUT_DIRECTORY [COMMIT]
#
# The tree is the one the CI deploy jobs upload: locked production Composer
# dependencies (--no-dev --optimize-autoloader), the compiled frontend and the
# same application paths, with the same environment, credential and branding
# exclusions. Persistent storage is never packaged; every deployment supplies
# its own. The build starts from `git archive` of COMMIT, so untracked or
# ignored files in the working tree cannot reach the artifact.
#
# Entries are sorted, owned by 0:0, stamped with the commit time and written
# without a gzip name or timestamp, so the same commit built with the same
# toolchain produces byte-identical output. The archive is named after TAG but
# its contents depend only on COMMIT.
#
# Writes OUTPUT_DIRECTORY/auth-manager-TAG.tar.gz and OUTPUT_DIRECTORY/SHA256SUMS.
set -euo pipefail
export LC_ALL=C

fail() {
    echo "build-artifact: $*" >&2
    exit 1
}

[ "$#" -ge 2 ] && [ "$#" -le 3 ] || fail 'usage: build-artifact.sh TAG OUTPUT_DIRECTORY [COMMIT]'
tag=$1
output=$2
revision=${3:-HEAD}

[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] \
    || fail 'TAG must look like v1.2.3 or v1.2.3-rc.1.'

tar_binary=
for candidate in gtar tar; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" --version 2>/dev/null | grep -q 'GNU tar'; then
        tar_binary=$candidate
        break
    fi
done
[ -n "$tar_binary" ] || fail 'GNU tar is required for a reproducible archive.'

if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$1" | cut -d' ' -f1; }
else
    sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
fi

repository=$(git rev-parse --show-toplevel)
commit=$(git -C "$repository" rev-parse --verify --quiet "${revision}^{commit}") \
    || fail 'COMMIT does not name a commit.'
epoch=$(git -C "$repository" log -1 --format=%ct "$commit")

mkdir -p "$output"
output=$(cd "$output" && pwd)
name="auth-manager-$tag.tar.gz"

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
source_tree="$stage/source"
mkdir "$source_tree"
git -C "$repository" archive --format=tar "$commit" | "$tar_binary" -x -C "$source_tree"
cd "$source_tree"

composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader --no-progress
pnpm install --frozen-lockfile
pnpm run build

# Public revision marker, as the deployment engine contract requires. The
# per-deployment release marker is written by whoever activates the tree.
printf '%s\n' "$commit" >public/deployment-revision.txt

# The application paths the deploy jobs upload, without persistent storage.
paths=(app bootstrap config database public resources routes vendor artisan composer.json composer.lock)
# The upload's environment, deploy-state, credential and branding exclusions.
excludes=(.env .deploy-release .db-credentials public/branding public/hot public/storage)

for forbidden in .env bootstrap/cache/config.php public/hot; do
    [ ! -e "$forbidden" ] || fail "the build produced $forbidden."
done
for required in vendor/autoload.php public/build/manifest.json; do
    [ -f "$required" ] || fail "the build did not produce $required."
done
unusual=$(find "${paths[@]}" ! -type f ! -type d -print -quit)
[ -z "$unusual" ] || fail "the tree contains a symlink or special file: $unusual"

exclude_arguments=()
for pattern in "${excludes[@]}"; do
    exclude_arguments+=("--exclude=$pattern")
done

"$tar_binary" --create --format=gnu --sort=name \
    --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
    --mode='u+rwX,go+rX,go-w' --hard-dereference \
    "${exclude_arguments[@]}" \
    --file=- "${paths[@]}" | gzip -n -9 >"$output/$name"

# Check the archive itself, not only the staging tree it came from.
listing=$("$tar_binary" --list --gzip --file="$output/$name")
for entry in artisan vendor/autoload.php public/build/manifest.json public/deployment-revision.txt; do
    grep -qxF "$entry" <<<"$listing" || fail "the archive is missing $entry."
done
if grep -E '^(storage|node_modules|tests|\.git|\.github)(/|$)|(^|/)\.env$|^public/branding(/|$)' <<<"$listing" >/dev/null; then
    fail 'the archive contains storage, development, environment or branding files.'
fi

digest=$(sha256 "$output/$name")
printf '%s  %s\n' "$digest" "$name" >"$output/SHA256SUMS"
echo "Built $name for $commit"
echo "sha256 $digest"
