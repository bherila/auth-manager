# Moving a provider directory

`identity:directory-export` and `identity:directory-import` move a complete provider
into a fresh instance, including from an embedded `/auth` provider to a standalone
one. They preserve the subjects relying applications already bind. They do not
merge directories or automatically switch an application's sign-in configuration.
The older selected-person [`identity:export` / `identity:import`](identity-copy.md)
contract stays unchanged.

Install the reviewed provider version containing these commands on both ends and
apply its reviewed migrations first. An embedded host runs its separate
`auth-manager:migrate`; the receipt table belongs to the provider, never the host.
A host still pinned to an earlier source archive must update its package and
matching built assets before these commands become available.

## Archive contents

| Preserved | Excluded |
| --- | --- |
| Users, exact numeric subjects, password hashes, roles, credential generations, disabled and soft-deleted state | Remember tokens, sessions, trusted browsers, password-reset and sign-in codes |
| Compatible passkey IDs, original user IDs/user handles, key bytes, counters, RP IDs and backup eligibility | OAuth authorization/device codes, access tokens and refresh tokens |
| OAuth client IDs, recognized secret hashes, redirect/grant metadata, provider client grants | Source `APP_KEY`, OAuth private signing keys, runtime secrets and private integration keys |
| Application registrations and client mappings | Replay/nonce stores, invitation email-verification codes and audit history |
| Invitation business state, token hashes and delegated-operation IDs | Source cache, queues and imported-directory receipts |
| Tombstones and client acknowledgement records | Automatic configuration changes or source deletion |

The archive also carries source issuer/RP provenance, sign-in assurance settings and
allocation floors above every previously allocated identifier. Tombstoned subjects
remain reserved, including when the user's original row was already purged.
Soft-deleted people stay deleted. Import never associates accounts by email.

Client providers belonging to this directory (`users`, `auth-manager-users` or the
default `null`) are mapped to the destination's own provider. A foreign client
provider or owner model is refused. Current Passport client secrets are one-way
hashes and remain usable with the existing client secret; no source key is needed.
Unknown or encrypted secret representations are refused rather than copied as
unusable ciphertext. Align the target's hasher, or rotate an unsupported client on
the source and update its consumer before making a new archive.

Clients owned by a purged person retain their recognized owner model and historical
owner ID. The ID must be positive and below the reserved source allocation floor.
It is never reassigned to a new person. Keeping those fields also keeps a third-party
client third-party; clearing them would incorrectly make Passport trust it as
first-party. `historical_client_owners` reports these preserved references.

## Protect the material

The format is a versioned JSON envelope with SHA-256 over the exact decoded
payload JSON bytes; those bytes travel in a base64 field. Row values are also
base64 encoded so credential bytes survive exactly.
The checksum detects accidental corruption; it is **not a signature** and does not
authenticate the sender. Import only a trusted operator's snapshot, transferred
over a pinned private channel. Anyone who can replace the payload can replace its
checksum too.

Archives contain password hashes, client-secret hashes, identities, invitations
and credential public keys. Export creates a new file exclusively with mode
`0600`, refuses application/web-root paths, and never prints the archive. It will
not overwrite a file or follow a destination symlink. Import requires a regular
private file with no group/other permissions. Both commands cap the file at
64 MiB; larger directories require a separately reviewed streaming implementation.
Do not put archives in a repository, public object store, CI artifact, ticket or log.
The operator supplies encrypted storage/transport where required and securely
removes retained copies under their retention policy.

## Rehearse and prepare

1. Rehearse on isolated copies with no production keys or real identities in test
   fixtures. Back up the actual source separately using its operator procedure.
2. Prepare the fresh target with the reviewed provider schema, its own `APP_KEY`,
   new OAuth signing keys, working mail, explicit public issuer and origin, and
   its own cookie/cache/queue namespace. Create no target users or clients yet.
3. Set an explicit target `WEBAUTHN_RP_ID`. It must equal the source's effective RP
   ID and every copied credential's recorded RP ID, and be valid at the target
   host. Configure `WEBAUTHN_ALLOWED_ORIGINS` for the target. A credential with no
   recorded RP ID retains `null`; compatibility relies on the archive's source RP
   provenance, never on relabelling it. If the source never configured an RP ID,
   its effective source host is recorded, which often prevents a cross-host move.
4. Match or strengthen source sign-in assurance. In particular, a source requiring
   a code after a password requires `AUTH_MANAGER_REQUIRE_CODE_AFTER_PASSWORD=true`
   on the target; a source forbidding code-only login requires
   `AUTH_MANAGER_ALLOW_CODE_ONLY_SIGN_IN=false`. A source with trusted devices off
   requires `AUTH_MANAGER_ALLOW_TRUSTED_DEVICES=false`. If copied passkeys require
   user verification, set `WEBAUTHN_USER_VERIFICATION=required`. Import refuses a
   weaker target, including `preferred` becoming `discouraged`, during dry run.
   Rebuild the target configuration cache.
5. Freeze source directory/credential/client/invitation mutations before the final
   snapshot and keep it frozen through cutover. A consistent snapshot cannot
   account for subjects or credentials created on the source after export. Keep
   target provisioning closed until import and verification finish.

For a relying application, its local-account bulk importer first stages the
directory inside its embedded provider with explicit local-to-provider bindings. A subsequent full
provider move uses this archive and preserves those subjects. The local bulk
importer and a provider directory move are separate steps; importing this archive
never reads a relying application's users table.

## Export and inspect a dry run

Use an existing private directory outside both applications and their web roots.
`$PRIVATE_DIR` below is a private operator path, not a directory in this repository.

```sh
# On the source (the wrapper enters the provider context when embedded):
php artisan identity:directory-export --output="$PRIVATE_DIR/provider-directory.json"
```

Copy the file to the target with a trusted private channel, preserve mode `0600`,
and run:

```sh
php artisan identity:directory-import --input="$PRIVATE_DIR/provider-directory.json"
```

Dry run is the default and writes no rows, receipts or allocation counters. Output
contains counts only, not identities, hashes, credential bytes or client secrets.
It reports each table's planned count, `passkeys_omitted`, and
`passwords_requiring_reset`. `verification_codes_excluded: 1` and
`runtime_keys_excluded: 1` are exclusion flags, not counts of secret values.

An RP mismatch fails closed. If re-enrollment is planned, explicitly add
`--skip-incompatible-passkeys` to both dry run and apply; incompatible credentials
are omitted and counted, with users and their password hashes retained.

An unknown hash or a hash incompatible with the target's configured algorithm
verification also fails closed. Prefer matching the source's supported hash
configuration. With an explicit recovery plan,
`--reset-incompatible-passwords` replaces those user credentials with unknown
random target-compatible hashes during apply and reports their count. Nobody is
given the random password; affected users need a configured provider password
reset or an administrator-assisted reset. This option never changes client secrets.
Unrecognized source password material is redacted to `null` during export; the
archive carries only the requirement for recovery rather than copying a value
that could be an obsolete hash or even plaintext.
Each replaced credential advances that person's credential generation, so an old
relying-application session cannot keep treating the original generation as
current. Unchanged compatible hashes keep their original generation. Verify an
administrator or enabled recovery method can reset affected accounts before
opening sign-in, especially when code-only sign-in is forbidden.

## Apply, retry and cut over

```sh
php artisan identity:directory-import --input="$PRIVATE_DIR/provider-directory.json" --apply
```

The target must be fresh: no existing directory identities, clients, registrations,
invitations, tombstones or live credentials are adopted. All rows and the import
receipt commit atomically. A fixed receipt primary key prevents concurrent imports
of different snapshots from merging disjoint identities. Another archive is refused.

Identifier floors are raised before row writes because MariaDB/MySQL's
`AUTO_INCREMENT` DDL commits independently. If the later transaction fails, rows
and receipt roll back while floors may already be higher. Correct the underlying
failure and rerun the same archive. The higher floors cannot give a new user an
old subject. There is no partial-row resume state to reconcile.

A completed archive's checksum has a durable receipt. Replaying that exact archive
returns the saved report with `already_imported: 1` and writes nothing, even if
people have since signed in, changed their names or rotated credentials. It is not
a synchronization command. Do not delete the receipt to force a stale reimport.

Before cutover, verify password and any compatible passkey sign-in, granted and
ungranted client behavior, disabled/deleted-account refusal, and a real OAuth
callback resolving to the relying application's existing account. Keep the
application's provider *name* unchanged; update its base URL/issuer to the target.
Preserved client IDs and supported hashes keep existing client credentials usable.
Confirm logout and provider-session revocation against the target.

Runtime trust is independent of the directory: configure target invitation,
delegated-access and reconciliation integration keys explicitly. Do not copy the
source `APP_KEY`. Old OAuth credentials and provider sessions cannot be continued.
Source reconciliation cursors may be rejected and need their normal reset/retry
path. Pending invitation token hashes and business state are retained, but old
email links still name the source origin; resend invitations from the new host.
Email-verification codes and any `APP_KEY`-derived evidence are excluded and must
be issued afresh. Do not claim an old link or code remains valid at a new origin.

Only after consumer verification should the operator retire the old client/runtime
and unfreeze the destination. Keep one authoritative directory. Code rollback does
not reverse imported data or undo identities created after cutover; rehearse a
separate recovery plan and preserve the subject bindings.

## Validation

`DirectoryCopyTest` covers private files, checksums, fresh-only behavior, credential
compatibility, assurance, tombstones, invitation state, atomic failure/retry and
receipt replay. `EmbeddedDirectoryCopyTest` exports an embedded provider and boots
a separate standalone provider with a new key/database, completes a real OAuth
code exchange, and resolves an unchanged consumer binding. The isolated CI-only
`DirectoryCopyMariaDbTest` checks MariaDB allocation floors and portable rows.
Full suites, engine tests and builds run in CI.
