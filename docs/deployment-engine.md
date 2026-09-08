# Deployment engine contract v1

`scripts/deployment/deploy.py` activates a prebuilt provider release on an already provisioned, isolated Linux/systemd host. It provides the release transaction: archive checks, migration/cache preparation, atomic `current` switching, public health/revision/release verification, fixed queue restart, rollback and persisted status. It does not provision machines, choose targets, approve schema changes, acquire secrets, build source or configure SSH trust. Existing deployment workflows are not changed by this engine.

## Trust and independent pins

A trusted orchestrator must approve and verify **two full Git commit SHAs** before executing checked-out code:

- Application revision: the provider code to build and activate.
- Engine revision: the reviewed deployment implementation used for both launch and rollback.

Use separate verified checkouts even when they come from the same repository. An application rollback must not silently downgrade deployment-engine fixes, and an older application need not contain this script. A SHA supplied to this CLI records provenance; it cannot prove that the caller obtained the script from that commit. The trusted checkout verification and protected upload establish that fact.

Upload the verified script separately from the application archive to:

```text
ROOT/incoming/RELEASE_ID.engine-ENGINE_SHA.py
```

Make this a read-only regular file, for example mode `0400`, readable by the deployment principal. The engine checks its exact canonical per-release path, rejects symlinks and writable copies, and the detached worker executes that same file. Never execute an engine from `current`, the application archive, a moving branch, or a shared filename that another deployment replaces. Operators must not edit or replace this copy while its release is queued or running.

## Server-owned policy and layout

`ROOT` is canonical and ends in `auth-manager-staging` or `auth-manager-prod`. Provision `.identity-instance` containing `ENVIRONMENT HTTPS_ORIGIN`, an `incoming/` directory, `releases/`, and `shared/.env` plus `shared/storage/`. Root/release ancestors must permit traversal by the separate web-server principal. Private runtime files and signing keys keep their provisioned permissions. Existing storage aliases, aliased ancestors and a `current` pointer outside the instance are rejected.

Provision `ROOT/.deployment-policy.json` separately from application artifacts. It must be a regular, non-aliased UTF-8 JSON file of at most 16 KiB, readable by the deployment principal and not group/other writable. Root ownership with a read-only deployment group is appropriate; policy changes belong to the provisioning/approval process, never an application bundle. Unknown/duplicate fields and unsupported versions fail closed.

A synthetic policy using the provider's bundled light/dark defaults:

```json
{
  "contract_version": 1,
  "environment": "staging",
  "url": "https://identity.example.test",
  "database": "auth_manager_staging",
  "database_user": "auth_manager_staging",
  "application_name": "Example Identity",
  "branding": { "enabled": false }
}
```

The requested environment, HTTPS origin and database must exactly match the policy and instance marker. Database names/users retain the `auth_manager_` namespace. The PHP preflight compares the exact database principal, application name/URL/environment and branding settings without printing runtime configuration. It requires MySQL without a URL override, database-backed sessions/cache/queues on the default connection, a host-only session cookie with the dedicated prefix, a configured application key and isolated OAuth signing keys. The engine always controls the fixed `auth-manager-queue.service`; it accepts no arbitrary service names or shell commands.

Default branding is automatic: `branding.enabled=false` requires no custom files and preserves the bundled light/dark stylesheet. Custom branding is an explicit policy choice. Replace the branding object with:

```json
{
  "enabled": true,
  "logo_light": "/branding/logo-light.svg",
  "logo_dark": "/branding/logo-dark.svg",
  "favicon": "/branding/favicon.ico",
  "stylesheet": "/branding/theme.css"
}
```

Custom mode requires every declared asset in the candidate and matching provider configuration. Paths must remain under `/branding/` with approved image/CSS extensions; URL queries, fragments, traversal and remote origins are rejected. See [deployment branding](deployment-branding.md) for runtime settings. Optional custom branding does not replace or remove the bundled default stylesheet.

## Artifact and invocation

A unique release ID is `APPLICATION_SHA-RUN_NUMBER-ATTEMPT_NUMBER`, using a lowercase 40-character SHA and numeric suffixes. Upload the archive to `ROOT/incoming/RELEASE_ID.tar.gz`. It must contain a complete prebuilt application, including production dependencies and frontend assets, but no `.env`, persistent `storage/`, symlinks, hardlinks, devices or path traversal. Include these public marker files:

- `public/deployment-revision.txt`: the exact application SHA.
- `public/deployment-release.txt`: the exact unique release ID, distinguishing repeated builds of the same application revision.

Launch from the verified per-release engine file, passing validated orchestration values as separate arguments:

```sh
python3 "$ROOT/incoming/$RELEASE_ID.engine-$ENGINE_SHA.py" start \
  --root "$ROOT" --environment "$TARGET" --release-id "$RELEASE_ID" \
  --app-sha "$APPLICATION_SHA" --engine-sha "$ENGINE_SHA" \
  --url "$IDENTITY_URL" --database "$IDENTITY_DATABASE"
```

The `worker` subcommand is internal to the detached user-systemd service; orchestration calls `start`. The start command reserves status exclusively, preventing duplicate launches after a lost acknowledgement. The worker has a 900-second runtime limit and a 120-second stop allowance. The provisioned deployment principal needs user-systemd availability, Python 3.10+, PHP, curl and narrowly scoped sudo permissions for the fixed queue unit. An orchestration-level environment approval and backward-compatible-schema decision must precede this command.

## Completion and rollback

Migrations and config/route/view caches complete before switching `current`. Migration failure leaves the old release serving. After switching, `/up`, both public marker values, and queue activation must succeed. A post-switch failure or termination restores the previous pointer, restarts its queue and verifies its public markers. On a failed first deployment the queue is stopped and the new pointer is removed. Schema changes are never rolled back automatically; only reviewed backward-compatible migrations are eligible.

Poll `ROOT/incoming/RELEASE_ID.status.json`, verifying all identifiers against the approved request:

```json
{
  "contract_version": 1,
  "state": "succeeded",
  "revision": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "engine_revision": "cccccccccccccccccccccccccccccccccccccccc",
  "release_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-123-1"
}
```

States are `queued`, `running`, `succeeded` and `failed`. Only the detached worker decides terminal status after an ambiguous launch acknowledgement. Success publication is the last fallible commit step; a publication failure rolls back. Rollback protects itself from repeated SIGTERM, then persists failure. A definitive local spawn failure can immediately publish `failed`. A transport timeout or polling timeout is an **unobserved outcome**, not proof of failure: inspect persisted status and `current` before attempting another release. `failed` requires protected-log inspection, particularly if rollback itself encountered an error; it does not universally prove the old release is healthy.

Status/log files remain private under `incoming/`. Their durability covers process termination and transport loss, not a guarantee against host or filesystem failure. Invalid release paths cannot create status outside the validated instance. Secrets and provisioning policy never belong in the public repository or application archive.

Run synthetic regressions with `python3 -m unittest discover -s tests/deployment`; `composer ci:check` includes them. Unit tests exercise activation ordering, release identity, rollback/signals/status, aliases, policy mismatches, engine identity and default/custom branding. Actual host provisioning, systemd/sudo access and transport behavior still require a staging deployment and a post-switch rollback exercise before adopting a new engine pin.
