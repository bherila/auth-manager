# Restoring the provider database

Restoring the provider's database from a backup rolls back everything that happened after the
backup was taken: people disabled or deleted, grants and group memberships removed, passwords and
second factors reset, and the credential generation (`credential_version`) each of those raised.
Until those changes are made again, a session or token they ended matches the database again, and
a relying application asking about that person is told what was true at backup time.

Two mechanisms make a restore visible, and this runbook makes it safe. It is written for one
operator working alone.

## Recovery epoch

`AUTH_MANAGER_RECOVERY_EPOCH` is a positive integer, default 1. The provider sends it as the
integer `recovery_epoch` in the sign-in identity (`GET /api/oauth/user`) and in every identity
status answer (`POST /api/reconciliation/identity-status`). Both fields are additive:
`contract_version` stays 1 and older consumers ignore them.

Raise it by one after every restore, and never lower it. A consumer records the epoch with the
session it establishes; a later status answer with a higher epoch means the provider's state was
rolled back since, so that session cannot be trusted and must sign in again. (Enforcing this is the
consumer's side, in `bherila/auth-laravel`.)

## High-water guard

The guard notices a restore the operator has not yet declared. Every authentication event appends
to the audit log, so its highest id only grows. On each identity status request the provider
compares that id with a small file holding the highest id it has seen and the epoch it was seen
under, and records any growth.

- If the database is **behind** the file at the same epoch, it was rolled back: identity status
  answers HTTP 503 with `Retry-After: 60` until the operator raises the epoch. Consumers treat that
  as the provider being unavailable, which ends nobody's access wrongly and grants nothing stale.
- Raising the epoch resets the guard: the next request records the current database under the new
  epoch.
- A configured epoch **below** the recorded one (a stale environment file, a configuration
  rollback), or a file that cannot be read or written, also answers 503 and logs why.

| Setting | Default | |
| --- | --- | --- |
| `AUTH_MANAGER_RECOVERY_HIGH_WATER_GUARD` | `true` | `false` turns the guard off. |
| `AUTH_MANAGER_RECOVERY_HIGH_WATER_PATH` | `storage/app/private/auth-manager/recovery-high-water.json` | Absolute path. |

The file is useful only if a restore cannot roll it back with the database. The default lives in
the release's persistent `storage/`, which is not part of a database backup; if the host's own
backup restores `storage/` together with the database, point the path somewhere that backup does
not cover. Deleting the file, or moving the instance to a new host without it, starts a new record
and so protects nothing until the database next moves forward.

The guard costs one indexed `MAX(id)` and one locked read of a few bytes per status request, plus a
small write when the log has grown.

## Runbook

1. **Stop traffic.** `php artisan down`. Maintenance mode stops new requests; let in-flight
   requests and queue jobs finish (`php artisan queue:restart`, then confirm no worker is still
   running a job) before touching the database.
2. **Restore the database** and note the exact time the backup was taken. Everything after that
   time is what has to be made again.
3. **Raise the epoch.** Set `AUTH_MANAGER_RECOVERY_EPOCH` to one more than its current value in the
   instance's environment, then `php artisan config:cache`. This also resets the high-water guard.
4. **Reapply the changes made after the backup**, from the off-box audit copy (below), for the
   window between the backup time and the restore:
   - people disabled or deleted (`directory_user_disabled`, `directory_user_tombstoned`) — disable
     or delete them again;
   - OAuth client grants removed (`directory_client_revoked`), access-group members removed
     (`access_group_member_removed`) and groups' applications removed (`access_group_client_removed`)
     — remove them again;
   - password resets (`directory_password_reset`), second-factor resets and other credential
     changes — reset again, so the credential generation moves past every session issued before;
   - provider-administrator authority removed (`provider_administrator_changed`) — remove it again.

   People created or granted access in that window are simply absent; recreate them only on
   request. A recreated person receives a new subject and is a new account to every application.
5. **Leave maintenance mode.** `php artisan up`. Check that identity status answers 200 for a known
   active subject and carries the new `recovery_epoch`.
6. **Check each consumer.** In every application with a recorded provider-identity cutover, run
   `php artisan bherila-auth:provider-identity-cutover status` and confirm enforcement is still on,
   so the raised epoch and the reapplied changes actually end the sessions they should.

### The off-box audit copy

Step 4 depends on a copy of the authentication audit log that the restore did not roll back.

> **TODO (owner decision):** where the off-box audit copy lives is not decided. The recommendation
> is an hourly append-only export of new `auth_audit_log` rows to storage that the database backup
> does not cover. Until that exists, the window between the last backup and the restore can only be
> reconstructed from application logs and memory, and anything missed stays rolled back.
