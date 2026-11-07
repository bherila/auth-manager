# Short-lived synthetic test logins

`auth-manager:test-logins` is a trusted operator command for synthetic browser
tests. It creates a new flagged provider identity with a generated password,
explicit static OAuth client grants and a future expiry. It never converts an
existing person, grants provider administration or provisions an application
account or application role. The marker is separate from development login and
the shared library's test OTP setting; an address alone grants no exemption.

## Configuration and schema

Apply the reviewed provider migration before using the command:
`2026_11_07_000000_add_test_login_lifecycle_to_users_table.php` adds
`is_test_login` (default `false`) and nullable UTC `test_login_expires_at`.
Neither field is mass assignable or included in default user JSON. Existing
identities remain ordinary identities. An embedded host applies provider schema
with its normal, separately reviewed `auth-manager:migrate` deployment step.
Creation remains an explicit operator action after reviewed schema deployment.

| Setting | Default | Meaning |
| --- | --- | --- |
| `AUTH_MANAGER_TEST_LOGIN_MAX_HOURS` | `24` | Maximum requested lifetime measured from now; integer `1`–`168` |
| `AUTH_MANAGER_TEST_LOGIN_DOMAINS` | empty | Comma-separated additional exact ASCII domains, case insensitive; no wildcards, URLs or implicit subdomains |

Reserved addresses on `example.com`, `example.net`, `example.org` and their
subdomains, or domains under `.test`, `.example`, `.invalid` and `.localhost`,
are accepted without extra configuration. Label boundaries matter:
`notexample.com` is not an example domain. Extra configured domains are matched
exactly. Rebuild the configuration cache when changing these settings.

Every create/extend requires an explicit future UTC timestamp in
`YYYY-MM-DDTHH:MM:SSZ` form, within the configured maximum. There is no implicit
expiry. Invalid, missing or expired deadlines deny provider authentication.

## Create and use a login

Use an existing private directory outside the application and all web roots.
Supply its canonical absolute path, without symlink components. `$PRIVATE_DIR`
below is a private operator location; do not create it in this repository.

```sh
php artisan auth-manager:test-logins create \
  --name='Synthetic browser login' \
  --email='browser@example.test' \
  --expires-at='2026-11-08T12:00:00Z' \
  --client='<static-oauth-client-id>' \
  --output="$PRIVATE_DIR/browser-login.json"
```

Choose an expiry in the future when executing the command. Repeat `--client` for
each intended active static authorization-code client. Revoked, dynamic, unknown
and foreign-directory clients are refused. Even on the resource profile, flagged
identities cannot acquire implicit access to dynamically registered clients.

The command reports the new subject on the console. The JSON file contains the
subject, email, generated password, expiry and selected clients. It is created
exclusively with mode `0600`; an existing file or symlink is never overwritten.
The password is 72 cryptographically random ASCII characters and is delivered
only in this file, once. It is never printed or written to authentication audits.
A file-write failure rolls back the new identity, grants and creation audit.
If a database commit is interrupted after file delivery, inspect the private file
and directory state before retrying. Retain credentials only in private temporary
storage and remove them under the test's retention policy; do not put them in CI
logs, artifacts, repositories, tickets or screenshots.

A valid flagged login uses its password without an emailed second factor even
when `AUTH_MANAGER_REQUIRE_CODE_AFTER_PASSWORD=true`. It reports `amr=pwd` and
single-factor assurance. That password-only sign-in cannot satisfy an application's MFA/OTP/passkey
request, and the password exemption supplies no second-factor enrollment proof.
Ordinary identities retain their normal authentication policy. A relying
application may still require its own account approval, permissions or stronger
authentication; this command cannot override those decisions.

## Extend, disable and retire

Use the positive provider subject from the private file, not an email address:

```sh
php artisan auth-manager:test-logins extend '<subject>' \
  --expires-at='2026-11-08T15:00:00Z'
php artisan auth-manager:test-logins disable '<subject>'
php artisan auth-manager:test-logins retire '<subject>'
```

These commands refuse ordinary identities. Extension moves a deadline forward
and does not clear `disabled_at`, whether an administrator, this command or
expiry cleanup disabled the identity. There is no implicit enable operation;
an intentionally disabled identity needs a separately authorized enable through
existing provider administration after its deadline is valid again.

Extending after expiry revokes the old credential generation, sessions, remember
cookies, trusted devices, OAuth credentials and pending sign-in/reset material,
even if the scheduler has not yet marked the account disabled. A new sign-in is
required. Disabling performs the same revocation and is idempotent.

Retirement uses the existing identity lifecycle: it retains the test marker,
creates a subject tombstone and relying-client snapshots, revokes credentials
and soft-deletes the identity. Retention, acknowledgement and eventual purge
follow [identity deletion](identity-deletion.md). The subject is never reassigned.
Repeating retirement before purge returns the same tombstone; a purged subject
has no flagged row for this tool to manage. Retired identities cannot be extended
or enabled. Rolling code or schema back does not restore them. Older code cannot
enforce this marker/deadline; retire all flagged identities before activating an
older release or removing these columns.

## Expiry and scheduled cleanup

Provider password, browser/remember, bearer/refresh and identity-status gates
check the deadline immediately. They do not wait for a scheduler tick. Existing
relying-application sessions follow the application's established provider-status
freshness window (currently up to five minutes); expiry is not a claim of instant
cross-application revocation.

The provider scheduler runs this idempotent cleanup every minute, with overlap
protection:

```sh
php artisan auth-manager:test-logins expire
```

Each invocation disables and revokes residual credentials for at most 100 expired
flagged identities; later ticks handle a larger backlog. It never retires an
identity automatically. Normal identities and already disabled rows are untouched.
An operator still needs the deployment's normal `schedule:run` invocation; an
embedded provider registers the task on its host scheduler in provider context.

Each successful lifecycle transition records the target subject and console
authority with non-secret expiry/client/tombstone metadata. Unchanged disable or
retire requests do not append duplicate lifecycle events.

## Directory transfers

Live flagged identities are refused by selected and portable directory exports,
even when disabled or expired. Retire them first. The legacy importer also
refuses to turn synthetic source identities into ordinary destination people.
Retired rows may be included in a portable directory move because their deleted
state and tombstones remain preserved; they cannot authenticate after import.
The command never clears the marker to bypass those protections.
