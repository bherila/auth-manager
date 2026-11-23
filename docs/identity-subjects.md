# Provider subjects

Relying applications bind their accounts to `(provider, subject)`. A subject must therefore never
be issued to a second person, including after the provider's database is restored from a backup
or copied to another instance.

## What a subject is

Every account has a `users.subject`: 1 to 64 ASCII letters and digits, compared case-sensitively.
It is what leaves the provider, everywhere an application sees an account:

| Edge | Field |
| --- | --- |
| Sign-in identity, `GET /api/oauth/user` | `sub` |
| Identity status, `POST /api/reconciliation/identity-status` | request `subject`, response `subject` |
| Tombstone feed, `GET /api/reconciliation/identity-tombstones` | `data[].subject` (`identity_tombstones.provider_subject`) |
| Delegated access, provider to application | actor assertion `sub`, and every `subject` in a request |
| Invitation roles at acceptance | `subject` in the delegated read and update |
| Application invitations, application to provider | actor assertion `sub` (any valid subject, no longer only digits) |

The row id is internal. OAuth client grants (`oauth_client_grants.subject`), access-group members
(`access_group_members.subject`), sessions, tokens and the audit log keep referring to `users.id`.

An all-digit subject is always the decimal id of the account that holds it (no sign, no leading
zero, at most 9223372036854775807); any other all-digit value is not a subject. Every account created
before subjects had a column of their own is known that way, the migration backfills exactly that
value, and so nothing an application sees changes for an existing account. The rule also means an
id the directory allocates later can never produce a subject somebody already holds.

## How a new account gets one

The account is inserted and its subject issued in one transaction (`User::performInsert()`):

- A subject carried from another instance (a directory archive, an identity copy, a legacy import)
  is kept. It is refused, and nothing is written, if another account holds it or a deleted identity
  held it.
- Otherwise the instance's generator decides (`ProviderSubjects::forNewAccount()`). Without one the
  account takes its own id, as before.
- A subject a tombstone records is never issued again, and a subject never changes once issued.

## Rollout

The migration `2026_11_23_000000_add_subject_to_users_and_identity_tombstones` adds
`users.subject` and `identity_tombstones.provider_subject`, both unique and nullable, and fills
every existing row with its id. They stay nullable in this release because the previous code may
still be serving while it runs and inserts rows without them. A row without one is known by its id,
exactly as before (`User::providerSubject()`, `IdentityTombstone::providerSubject()`). A later
release backfills again and makes both columns NOT NULL. The numeric `identity_tombstones.subject`
(the deleted account's row id, still used to purge it) stays until a later release drops or
renames it; the feed already reads `provider_subject`.

On MySQL and MariaDB both columns are `ascii` with `ascii_bin` collation so that comparison is byte
for byte.

## Copies and archives

- **Directory archive** (`directory:export` / `directory:import`, [portable directory](portable-directory.md)):
  version 3 carries `users.subject` and `identity_tombstones.provider_subject`. Import refuses an
  archive in which a subject is held twice, is held by an account and a deleted identity (other
  than a deleted account awaiting purge and its own tombstone), or is all digits but not its
  holder's id. Version 2 archives still import: each account's subject is its id.
- **Identity copy** (`identity:export` / `identity:import`, [identity copy](identity-copy.md)):
  the document carries each person's id as their subject, so export refuses an account known by
  anything else; use the directory archive for those. Import refuses a subject another account
  holds or a deleted identity held.
- **Legacy import** keeps the legacy id as the subject and skips a record whose subject another
  account holds or a deleted identity held.
