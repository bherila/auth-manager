#!/usr/bin/env bash
# Build the Composer-installable source archive for one commit.
#
#   scripts/release/build-source-archive.sh TAG OUTPUT_DIRECTORY [COMMIT]
#
# The archive holds the tracked source of COMMIT plus the compiled frontend
# (public/build), with `version` set in its composer.json from TAG so that a
# Composer `artifact` or `package` repository can install it. It never contains
# vendor/ or node_modules/: the host's own Composer run resolves dependencies.
# It is the embedded-mode counterpart of build-artifact.sh (see
# docs/embedded-mode.md), which packages the complete standalone deploy tree.
#
# Entries are sorted, carry fixed ownership and the commit's timestamp, so the
# same commit built with the same toolchain gives byte-identical output.
#
# Writes OUTPUT_DIRECTORY/auth-manager-source-TAG.zip and
# OUTPUT_DIRECTORY/SHA256SUMS-source.
set -euo pipefail
export LC_ALL=C

fail() {
    echo "build-source-archive: $*" >&2
    exit 1
}

[ "$#" -ge 2 ] && [ "$#" -le 3 ] || fail 'usage: build-source-archive.sh TAG OUTPUT_DIRECTORY [COMMIT]'
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
[ -n "$tar_binary" ] || fail 'GNU tar is required to unpack the source.'
command -v python3 >/dev/null 2>&1 || fail 'python3 is required to write the archive.'

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
name="auth-manager-source-$tag.zip"

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
source_tree="$stage/source"
mkdir "$source_tree"
git -C "$repository" archive --format=tar "$commit" | "$tar_binary" -x -C "$source_tree"
cd "$source_tree"

pnpm install --frozen-lockfile
pnpm run build

printf '%s\n' "$commit" >public/deployment-revision.txt

for required in composer.json public/build/manifest.json; do
    [ -f "$required" ] || fail "the build did not produce $required."
done

python3 -I - "$source_tree" "$output/$name" "$tag" "$epoch" <<'PY'
import json
import os
import sys
import time
import zipfile

root, target, tag, epoch = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])

with open(os.path.join(root, 'composer.json'), encoding='utf-8') as handle:
    manifest = json.load(handle)
manifest['version'] = tag[1:]
manifest_bytes = (json.dumps(manifest, indent=4, ensure_ascii=False) + '\n').encode('utf-8')

# Never package dependencies, caches, credentials or per-deployment files.
skipped_directories = {'vendor', 'node_modules', '.git', '.github', 'storage'}
skipped_files = {'.env', '.deploy-release', '.db-credentials'}
skipped_prefixes = ('public/branding', 'public/hot', 'public/storage')

entries = []
for directory, directories, files in os.walk(root):
    relative_directory = os.path.relpath(directory, root).replace(os.sep, '/')
    directories[:] = sorted(d for d in directories if not (relative_directory == '.' and d in skipped_directories))
    for file in sorted(files):
        relative = file if relative_directory == '.' else f'{relative_directory}/{file}'
        if file in skipped_files or relative.startswith(skipped_prefixes):
            continue
        path = os.path.join(root, relative)
        if os.path.islink(path) or not os.path.isfile(path):
            sys.exit(f'build-source-archive: unexpected symlink or special file: {relative}')
        entries.append(relative)

stamp = max(epoch, 315532800)  # the ZIP format cannot represent dates before 1980
date_time = time.gmtime(stamp)[:6]
with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for relative in sorted(entries):
        info = zipfile.ZipInfo(relative, date_time)
        info.compress_type = zipfile.ZIP_DEFLATED
        executable = os.stat(os.path.join(root, relative)).st_mode & 0o111
        info.external_attr = (0o100755 if executable else 0o100644) << 16
        if relative == 'composer.json':
            archive.writestr(info, manifest_bytes)
        else:
            with open(os.path.join(root, relative), 'rb') as handle:
                archive.writestr(info, handle.read())
PY

listing=$(python3 -I -c 'import sys, zipfile; print("\n".join(zipfile.ZipFile(sys.argv[1]).namelist()))' "$output/$name")
for entry in composer.json artisan public/build/manifest.json public/deployment-revision.txt; do
    grep -qxF "$entry" <<<"$listing" || fail "the archive is missing $entry."
done
if grep -E '^(vendor|node_modules|storage|\.git|\.github)(/|$)|(^|/)\.env$|^public/branding(/|$)' <<<"$listing" >/dev/null; then
    fail 'the archive contains dependencies, storage, environment or branding files.'
fi

digest=$(sha256 "$output/$name")
printf '%s  %s\n' "$digest" "$name" >"$output/SHA256SUMS-source"
echo "Built $name for $commit"
echo "sha256 $digest"
