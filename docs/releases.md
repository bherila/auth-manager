# Provider releases

A release is a prebuilt, attested provider tree that a relying deployment can pin
and install without building Auth Manager itself. Pushing a version tag runs
[`.github/workflows/release.yml`](../.github/workflows/release.yml), which tests
the tagged commit, builds the tree, records build provenance and publishes a
GitHub release. Consumers verify the asset, pin it in their own repository and
deploy it through their own pipeline.

## Cutting a release

Tag a commit that is already on `main` and push the tag:

```sh
git tag -a v1.2.3 -m v1.2.3 <commit-on-main>
git push origin v1.2.3
```

Tags look like `v1.2.3`, or `v1.2.3-rc.1` for a prerelease (published as a
GitHub prerelease, never marked latest). The workflow refuses a tag whose commit
is not reachable from `main`, so only reviewed code is released. The tagged
commit must contain the release workflow and build script; older commits cannot
be released this way.

The jobs run in order, and each one starts only when the previous one succeeded:

1. **resolve** validates the tag name and resolves it to a commit on `main`.
2. **verify** runs the same `composer setup`, `composer ci:check` and deployment
   hook tests that CI runs, on that commit.
3. **build** produces the tarball and `SHA256SUMS`, then attests the tarball with
   `actions/attest-build-provenance`.
4. **publish** checks that the tag still names the built commit and publishes the
   release with both files as assets. The release is assembled as a draft and
   made public only after its uploaded checksum file matches.
5. **notify** sends the consumer notification described below, when configured.

The workflow runs only in the canonical repository, from a tag push or from a
manual run of the workflow on `main`. It never runs for pull requests. Its
top-level token has no permissions; only **build** can request an OIDC token and
write attestations, and only **publish** can write repository contents.

**Re-running.** `workflow_dispatch` with a `tag` input rebuilds and republishes
an existing tag, for example after a failed upload. A draft left by an
interrupted run is replaced. A published release is never replaced: a re-run
that builds the identical artifact succeeds without changing anything, and one
that builds a different artifact fails. Delete a published release by hand only
when no consumer has pinned it.

Restrict who can create `v*` tags with a tag ruleset, because creating one
starts a release.

## The artifact

| Asset | Contents |
| --- | --- |
| `auth-manager-<tag>.tar.gz` | The deployable provider tree for the tagged commit |
| `SHA256SUMS` | One line, `<sha256>  auth-manager-<tag>.tar.gz` |

The tree is built by
[`scripts/release/build-artifact.sh`](../scripts/release/build-artifact.sh) the
same way the deploy jobs build theirs: locked production dependencies from
`composer install --no-dev --optimize-autoloader`, the compiled frontend from
`pnpm run build`, and the application paths the deploy jobs upload (`app`,
`bootstrap`, `config`, `database`, `public`, `resources`, `routes`, `vendor`,
`artisan`, `composer.json`, `composer.lock`). Entries sit at the archive root,
with no leading directory.

It never contains `.env`, database credential files, deployment branding under
`public/branding/`, a configuration cache, symlinks, development dependencies,
tests or `node_modules`. Persistent `storage/` is not packaged either: each
deployment supplies its own and keeps its signing keys there. The one added file
is `public/deployment-revision.txt`, holding the full commit SHA, as the
[deployment engine](deployment-engine.md) contract requires. The per-deployment
release marker belongs to whoever activates the tree.

The build is reproducible. It starts from `git archive` of the commit, so
untracked files cannot leak into it, and writes sorted entries owned by `0:0`
with the commit's timestamp and a gzip stream without name or time. The contents
depend only on the commit, not the tag. CI builds every change twice and compares
the checksums, and writes the result to the run summary, so a release's checksum
can be compared with the CI build of the same commit on `main`.

## Verifying a release

Run these before deploying an asset:

```sh
gh release download v1.2.3 --repo bherila/auth-manager \
  --pattern 'auth-manager-v1.2.3.tar.gz' --pattern SHA256SUMS
sha256sum --check SHA256SUMS
gh attestation verify auth-manager-v1.2.3.tar.gz --repo bherila/auth-manager
```

The last command is printed in every release's notes. For a stricter check, add
`--signer-workflow bherila/auth-manager/.github/workflows/release.yml` to require
the release workflow as the signer. A tag-push build is also signed for
`--source-ref refs/tags/<tag>` and `--source-digest <commit>`; a manual re-run is
signed for `refs/heads/main` instead, so check the commit against the release
notes and the lock rather than relying on those two flags.

## Consumer notification

After a release is published, the workflow sends a
[`repository_dispatch`](https://docs.github.com/en/rest/repos/repos#create-a-repository-dispatch-event)
event to every configured consumer repository:

```json
{
  "event_type": "auth-manager-release",
  "client_payload": {
    "tag": "v1.2.3",
    "sha256": "<64 lowercase hex characters: the tarball's SHA-256>",
    "commit": "<40 lowercase hex characters: the tagged commit>"
  }
}
```

Configure it with two repository secrets in this repository. Both live only in
secrets; neither the consumer list nor the token appears in files or logs.

| Secret | Value |
| --- | --- |
| `RELEASE_CONSUMERS` | A JSON array of `owner/repo` names, for example `["example-org/example-app"]` |
| `RELEASE_DISPATCH_TOKEN` | A fine-grained token limited to those repositories with **Contents: read and write**, which repository dispatch requires |

When either secret is absent the job reports that notification is not
configured and succeeds. Consumer names are masked, and a failed dispatch is
reported by its position in the list and its HTTP status only. A failed dispatch
fails the job after every consumer has been tried; the release itself stays
published. A re-run notifies again, so consumers must treat a repeated event as a
no-op.

The payload is a hint, not a trust anchor: anyone with dispatch access to a
consumer can send this event. A consumer re-downloads the asset from this
repository and verifies the checksum and attestation before acting on it.

### Sample consumer workflow

A consumer pins the release in its own `identity.lock` and reviews the bump like
any other dependency change. This sample opens that pull request. Replace
`example-org/example-app`, and pin actions by commit SHA:

```yaml
name: identity release

on:
  repository_dispatch:
    types: [auth-manager-release]

permissions: {}

jobs:
  bump:
    if: github.repository == 'example-org/example-app'
    runs-on: ubuntu-24.04
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Verify the announced release
        env:
          GH_TOKEN: ${{ github.token }}
          TAG: ${{ github.event.client_payload.tag }}
          SHA256: ${{ github.event.client_payload.sha256 }}
          COMMIT: ${{ github.event.client_payload.commit }}
        run: |
          set -euo pipefail
          [[ $TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]
          [[ $SHA256 =~ ^[0-9a-f]{64}$ ]]
          [[ $COMMIT =~ ^[0-9a-f]{40}$ ]]
          name="auth-manager-$TAG.tar.gz"
          mkdir "$RUNNER_TEMP/identity" && cd "$RUNNER_TEMP/identity"
          gh release download "$TAG" --repo bherila/auth-manager --pattern "$name" --pattern SHA256SUMS
          sha256sum --check --strict SHA256SUMS
          test "$(sha256sum "$name" | cut -d' ' -f1)" = "$SHA256"
          gh attestation verify "$name" --repo bherila/auth-manager \
            --signer-workflow bherila/auth-manager/.github/workflows/release.yml
          gh release view "$TAG" --repo bherila/auth-manager --json body --jq .body | grep -qF "$COMMIT"

      - name: Open the identity.lock pull request
        env:
          GH_TOKEN: ${{ github.token }}
          TAG: ${{ github.event.client_payload.tag }}
          SHA256: ${{ github.event.client_payload.sha256 }}
          COMMIT: ${{ github.event.client_payload.commit }}
        run: |
          set -euo pipefail
          branch="identity/$TAG"
          if git ls-remote --exit-code --heads origin "$branch" >/dev/null; then
            echo "A pull request branch for $TAG already exists."
            exit 0
          fi
          jq -n --arg tag "$TAG" --arg commit "$COMMIT" --arg sha256 "$SHA256" \
            '{repository: "bherila/auth-manager", tag: $tag, commit: $commit, sha256: $sha256}' >identity.lock
          git config user.name 'github-actions[bot]'
          git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
          git switch -c "$branch"
          git add identity.lock
          git commit -m "Pin identity provider $TAG"
          git push origin "$branch"
          gh pr create --head "$branch" --title "Pin identity provider $TAG" \
            --body "Verified checksum and build provenance for $TAG ($COMMIT)."
```

Two repository settings matter on the consumer side. **Allow GitHub Actions to
create and approve pull requests** must be on for `gh pr create` with the
workflow token. And a pull request opened with the workflow token does not start
the consumer's own `pull_request` workflows; use a GitHub App token, or another
token the consumer controls, if the bump must run CI without a manual push.

The consumer's deploy job then reads `identity.lock`, downloads that exact tag,
checks the asset against the locked `sha256`, verifies the attestation again,
and installs the tree with its own configuration, branding and release marker.
