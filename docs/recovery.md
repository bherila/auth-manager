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
  answers HTTP 503 with `Retry-After: 60` until the operator raises the epoch. The file records that
  the rollback was seen, so the refusal holds even after new sign-ins carry the restored log past
  the mark again. Consumers treat that as the provider being unavailable, which ends nobody's access
  wrongly and grants nothing stale.
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
   instance's environment, then `php artisan config:cache`. This also resets the high-water guard,
   and lets the off-box audit export continue: until the epoch is raised it refuses to run against
   the restored database.
4. **Reapply the changes made after the backup**, from the off-box audit copy
   ([reading it](#reading-the-export-for-step-4)), for the window between the backup time and the
   restore:
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
   active subject and carries the new `recovery_epoch`, and that
   `php artisan auth-manager:audit-export --status` succeeds once the next hourly run has passed.
6. **Check each consumer.** In every application with a recorded provider-identity cutover, run
   `php artisan bherila-auth:provider-identity-cutover status` and confirm enforcement is still on,
   so the raised epoch and the reapplied changes actually end the sessions they should.

### The off-box audit copy

Step 4 depends on a copy of the authentication audit log that the restore did not roll back. It is
an hourly, append-only export of new audit rows to a dedicated S3 bucket with Object Lock in
compliance mode, ideally in a different AWS account from the database backups.
`php artisan auth-manager:audit-export` writes it; the provider's schedule runs it hourly, without
overlapping, once a destination is configured. Like every scheduled task it does not run while the
instance is in maintenance mode.

#### Where it lives

- **A bucket used for nothing else, with Object Lock in compliance mode** and a default retention
  at least as long as the oldest backup you would ever restore from, plus a margin (a year, if
  unsure). In compliance mode nobody, the account's root user included, can delete an object or
  shorten its retention before it expires, and the bucket cannot be deleted while it holds one.
  That is the point, and it also means a mistaken retention cannot be undone: try the commands
  below on a scratch bucket with a one-day retention first.
- **In a separate AWS account from the database backups.** Whoever can delete or replace the
  backups should not also be able to touch the record of what happened after them, and credentials
  taken from the application host should reach neither.
- **Written by a principal that may only put, get and list**, under the export's prefix. It needs
  `GetObject` because each run reads the newest object back to check that the database still holds
  its last row, and checks that a name is free before writing; it never deletes, and the bucket
  would refuse if it tried. Grant nothing else: no `DeleteObject`, no `PutObjectRetention`, no
  `BypassGovernanceRetention`, no bucket configuration.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AppendAuditObjects",
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject"],
      "Resource": "arn:aws:s3:::<bucket>/audit/*"
    },
    {
      "Sid": "ListAuditObjects",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::<bucket>",
      "Condition": { "StringLike": { "s3:prefix": ["audit", "audit/*"] } }
    }
  ]
}
```

| Setting | Default | |
| --- | --- | --- |
| `AUTH_MANAGER_AUDIT_EXPORT_DISK` | unset | The filesystem disk to write to, normally `audit-export`. Unset, the command refuses and nothing is scheduled. |
| `AUTH_MANAGER_AUDIT_EXPORT_PREFIX` | `audit` | Key prefix inside the bucket. |
| `AUTH_MANAGER_AUDIT_EXPORT_BATCH_SIZE` | `5000` | Most rows in one object, 1 to 50000. A run writes at most 100 objects (`--max-objects`); the next continues. |
| `AUTH_MANAGER_AUDIT_EXPORT_STATE_PATH` | `storage/app/private/auth-manager/audit-export-state.json` | Absolute path of the local fallback record. |
| `AUTH_MANAGER_AUDIT_EXPORT_S3_BUCKET`, `_S3_REGION` | unset | The `audit-export` disk's bucket and region. |
| `AUTH_MANAGER_AUDIT_EXPORT_S3_KEY`, `_S3_SECRET` | unset | The writer's access key. Unset, the AWS SDK's default credential chain is used (an instance role, say). |

The `audit-export` disk uses Laravel's `s3` driver, through the `league/flysystem-aws-s3-v3`
package this repository requires. Object Lock refuses an upload without an integrity checksum; the
AWS SDK for PHP sends one by default on every upload, and the first run against the bucket confirms
it. Embedded in a host application, the disk is one of the host's, and the host must require the
same package.

#### What it writes

Each run writes the rows after the last exported one, oldest first, as gzip-compressed JSON lines
named `audit/<yyyy>/<mm>/<dd>/e<epoch>-<first id>-<last id>.jsonl.gz` (the date is the run's, in
UTC; the epoch is `AUTH_MANAGER_RECOVERY_EPOCH`). It never overwrites a name, and refuses if one is
already taken; it never deletes. A row younger than a minute waits for the next run, so that an id
still inside an uncommitted transaction is not passed over.

Each line holds `id`, `created_at` (as stored: `YYYY-MM-DD HH:MM:SS` in the application's timezone,
UTC by default), `event`, `succeeded`, `auth_method`, `reason`, `user_id`, `acting_user_id`,
`is_suspicious`, `metadata`, and two hashes: `email_sha256`, the SHA-256 of the address trimmed and
lowercased (the normalization the sign-in throttles use), and `session_sha256`, the SHA-256 of the
session id. The address, the session id, the network address and the browser string are never
copied, and metadata keys that could carry a credential (`password`, `secret`, `token`, `code` and
the like) are replaced by `[redacted]`. Objects cannot be changed once written: when a deleted
identity is purged, the provider clears the address from its own audit rows, but the copy keeps the
person's user id and address hash until its retention ends.

#### How it decides where to resume

From the destination, never from the database. The newest object's name gives the last exported id
and epoch, and its last line that row's time and event; a local state file, written after each
object, is used instead when it is further on, or when the destination lists nothing (every object
expired). A state file recorded for another disk or prefix is ignored; delete it to start a fresh
bucket from the first row.

Before exporting, a run checks that the database still holds the last exported row unchanged.

- If it does, the run continues after it.
- If it does not and the epoch is unchanged, the database was restored or rolled back. The run
  refuses, exports nothing and changes nothing, until the epoch is raised (step 3). Without this, rows
  written after the restore, which reuse ids the export has already seen, would be skipped.
- Under a newly raised epoch, the run continues after the newest restored row that is no newer than
  the last exported one: everything the restored database held was exported before, so it is not
  copied again, and every row written since the restore is.
- A configured epoch below the newest exported one is refused.

#### Creating the bucket

In the account that will hold the copy, with placeholders for every name:

```sh
aws s3api create-bucket --bucket <bucket> --region <region> \
  --create-bucket-configuration LocationConstraint=<region> \
  --object-lock-enabled-for-bucket
aws s3api put-object-lock-configuration --bucket <bucket> --object-lock-configuration \
  '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":<days>}}}'
aws s3api put-public-access-block --bucket <bucket> --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-ownership-controls --bucket <bucket> \
  --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'

aws iam create-user --user-name <writer>
aws iam put-user-policy --user-name <writer> --policy-name audit-export-append \
  --policy-document file://audit-export-policy.json
aws iam create-access-key --user-name <writer>
```

In `us-east-1`, leave out `--create-bucket-configuration`. Creating the bucket with Object Lock
turns on versioning, which cannot be turned off. Put the access key only in the instance's
environment (`AUTH_MANAGER_AUDIT_EXPORT_S3_KEY` and `_S3_SECRET`), or grant the policy to a role
the host assumes instead of creating a user. Then set `AUTH_MANAGER_AUDIT_EXPORT_DISK=audit-export`,
`php artisan config:cache`, and run `php artisan auth-manager:audit-export` once by hand to export
the existing log.

#### Reading the export for step 4

The rows step 4 reapplies are those of the epoch before the raise (`e<old epoch>-` objects) with a
`created_at` after the backup time. Copy the days from the backup's date to the restore's into a
private working directory, then filter:

```sh
aws s3 cp s3://<bucket>/audit/<yyyy>/<mm>/ ./audit-window/ --recursive \
  --exclude '*' --include '<dd>/e<old epoch>-*' --include '<dd+1>/e<old epoch>-*'
find ./audit-window -name '*.jsonl.gz' -print0 | xargs -0 gzip -dc \
  | jq -c 'select(.created_at > "<backup time, YYYY-MM-DD HH:MM:SS>")
      | select(.event | IN("directory_user_disabled", "directory_user_tombstoned",
          "directory_client_revoked", "access_group_member_removed", "access_group_client_removed",
          "directory_password_reset", "provider_administrator_changed"))' \
  | sort -u
```

The filter is a starting point: read the whole window for second-factor resets and other changes
too. `user_id` is the person's id in the restored database. Before acting on one, check that the
restored person with that id has the same address hash
(`printf '%s' '<address, trimmed and lowercased>' | sha256sum`): someone created after the backup has
no row in the restored database, and their id may since have been issued to someone else.

The copy ends at the last hourly run before the restore. Changes made after it are not in the copy
and have to be recovered some other way, which is why the export must be kept current.

#### Checking the export is current

`php artisan auth-manager:audit-export --status` writes nothing. It prints the newest object, the
last exported id and epoch, the database's highest id and how many rows wait, and fails if a row
older than two hours has not been exported, if the database no longer holds the last exported row
under the same epoch, or if no destination is configured. Run it from monitoring and alert when it
fails. From the bucket's side, `aws s3 ls s3://<bucket>/audit/<yyyy>/<mm>/<dd>/` lists the day's
objects, and `aws s3api get-object-retention --bucket <bucket> --key <key>` shows each one's lock
mode and retain-until date.
