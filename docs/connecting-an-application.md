# Connecting an application

This is the operator runbook for connecting a first-party application to a provider
instance, from choosing the instance through delegated access, verification and rollback.
Work through the sections in order. Every host, key ID and path below is synthetic; keep
real hostnames, paths and deployment identifiers in private configuration, never in this
repository, issues or pull requests.

The examples use:

| Value | Example |
| --- | --- |
| Provider instance | `https://identity.example.test` |
| Application | `https://app.example.test` |
| Registry key | `example-app` |
| Delegated access endpoint | `https://app.example.test/application-access` |
| Integration key ID | `integration-2026-09` |

## 1. Choose an instance

Each provider instance is a complete, separate identity boundary: one directory of people,
one set of provider administrators, one audit trail, one issuer, one
`AUTH_MANAGER_PROFILE`, one branding and one delegated access integration key.

**Shared instance.** One provider serves several first-party applications. Each
application gets its own static OAuth client, and people hold per-client grants, so signing
in to one application never implies access to another. People keep one account and one set
of credentials across the applications.

**Dedicated instance.** One provider per organisation or customer, optionally with a
staging instance alongside it. Nothing is shared between instances: not accounts,
credentials, administrators, clients, registry entries or keys.

Weigh:

- **Blast radius.** A shared instance is a single point of failure and compromise for every
  application behind it. An outage, a malformed configuration value (which stops the whole
  instance loading, see section 5) or a leaked integration key affects all of them. A
  dedicated instance limits each to one organisation.
- **Directories and administrators.** A shared instance has one directory and one group of
  provider administrators, who can see every person and manage every application's grants.
  Use a dedicated instance when an organisation must own its own directory and administrators,
  or must not see another organisation's people.
- **Profile.** `AUTH_MANAGER_PROFILE` is per instance. `bherila` keeps the plain
  authorization-code behaviour; `resource` adds resource-bound OAuth, dynamic client
  registration and introspection for a protected resource server. An instance cannot offer
  both, so an application that needs a different profile needs a different instance. See
  [deployment profiles](deployment-profiles.md).
- **Branding.** Sign-in pages, consent and recovery mail carry one instance-wide brand
  ([deployment branding](deployment-branding.md)). Applications that must present different
  brands at sign-in need dedicated instances.
- **Rate limits and edge rules.** Throttles, firewall and CDN rules apply per host. On a
  shared instance, one application's traffic or an attack on it counts against the sign-in
  limits of all of them, and edge rules cannot differ per application. A dedicated instance
  can be tuned for its own traffic.
- **Staging.** A staging pair (a separate staging instance for a staging application) lets
  you rehearse this runbook, key rotation and contract-version changes without touching
  production people or keys. Never point a staging application at a production instance.

The rest of this runbook is the same for either choice; run it against the chosen instance.

## 2. Register the static OAuth client

Create one confidential authorization-code client per application (and per environment) on
the chosen instance. Do not use a dynamically registered client: the registry and delegated
access accept only static, non-revoked authorization-code clients.

The client secret is shown once. Capture the command output straight into a private file
that only you can read, and never print it to a terminal, log, ticket or chat:

```sh
umask 077
php artisan passport:client \
  --name="Example App" \
  --redirect_uri="https://app.example.test/oauth/callback" \
  --no-interaction > "$PRIVATE_DIR/example-app-oauth-client.txt"
```

`$PRIVATE_DIR` stands for a private directory outside the web root and outside any
repository. Check the file exists and is non-empty (for example `test -s`) without
displaying it, then transfer the client ID and secret into the application's own secret
store. Delete the capture file once the application is configured. The redirect URI must be
the application's exact callback URL.

The application uses these values with its OAuth settings from `bherila/auth-laravel`
(`OAUTH_PROVIDER`, `OAUTH_PROVIDER_URL`, `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`,
`OAUTH_REDIRECT_URI`). Set `OAUTH_PROVIDER` explicitly rather than relying on the package
default.

## 3. Grant people the client

A provider administrator opens `/admin/users`, selects each person who should be able to sign
in to the application, and grants the new client. Grants are coarse: they allow a person to
authorize that client, nothing more. They do not create an account inside the application or
give any application permission.

Grant only the intended people. Check with one granted and one ungranted test account that
only the granted one can complete sign-in.

## 4. Add the registry entry and map the client

A provider administrator opens `/admin/applications` and creates the entry:

- **Key:** lowercase letters, digits and hyphens, starting with a letter, at most 64
  characters (for example `example-app`). It cannot be changed later. The same key is used
  by delegated access on both sides.
- **Name** and **launch URL:** the display name and the exact HTTPS URL people are sent to.
- **Enabled**, and the OAuth client ID(s) from section 2.

Follow the rollout in [the application registry](application-registry.md), including when to
turn on `AUTH_MANAGER_APP_REGISTRY_LAUNCH_ENABLED`. The launch URL is navigation only; it is
never used as the delegated access endpoint.

## 5. Delegated access: the provider

Delegated access lets the provider's `/applications/manage` pages ask the application about
and change a person's access in that application. See
[the delegated access transport](delegated-access-transport.md) and
[application access controls](application-access-ui.md) for the design.

### Generate a dedicated integration key pair

Use a new RS256 key pair for this purpose only. Never reuse, copy or derive it from the
provider's OAuth signing keys.

```sh
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out "$PRIVATE_DIR/delegated-access-integration-2026-09.key"
openssl pkey -in "$PRIVATE_DIR/delegated-access-integration-2026-09.key" -pubout \
  -out "$PRIVATE_DIR/delegated-access-integration-2026-09.pub.pem"
```

The private key stays on the provider instance, outside the web root and every repository,
readable only by the account the provider runs as. The public key is copied to each
connected application. One instance uses one integration key for all of its applications.

### Configure the provider

In the instance's private environment configuration:

```dotenv
AUTH_MANAGER_DELEGATED_ACCESS_ENABLED=false
AUTH_MANAGER_DELEGATED_ACCESS_WRITES_ENABLED=false
AUTH_MANAGER_DELEGATED_ACCESS_ISSUER=https://identity.example.test
AUTH_MANAGER_DELEGATED_ACCESS_KEY_ID=integration-2026-09
AUTH_MANAGER_DELEGATED_ACCESS_PRIVATE_KEY_PATH=/path/to/delegated-access-integration-2026-09.key
AUTH_MANAGER_DELEGATED_ACCESS_APPLICATIONS=example-app|https://app.example.test/application-access|2
```

- `ISSUER` is the provider's root HTTPS URL with no path. The application pins it exactly.
- `KEY_ID` names the key pair; the application maps the same ID to the public key.
- `APPLICATIONS` is a comma-separated list of `key|https://endpoint|contract_version`
  entries, for example
  `example-app|https://app.example.test/application-access|2,other-app|https://other.example.test/application-access|1`.
  Each key must match the registry key format and appear once. Each endpoint must be the
  application's exact HTTPS delegated access URL with no credentials, query or fragment.
  The version is `1` or `2`, as agreed with the application; it is never negotiated. Empty
  or unset means no applications.

Leave `ENABLED` off until the application side (section 6) is deployed, and leave
`WRITES_ENABLED` off until reads are verified (section 7).

**A malformed `AUTH_MANAGER_DELEGATED_ACCESS_APPLICATIONS` value prevents the whole
instance's configuration from loading**, exactly like an unrecognized
`AUTH_MANAGER_PROFILE`. No entry is silently skipped. The error names the entry position and
the rule it breaks, never the value.

### Rebuild the configuration cache

`config:cache` clears the existing cache before it loads the new configuration, so a
malformed value would leave the instance without a working configuration. Check first, into
a scratch cache file, with the new environment in place:

```sh
APP_CONFIG_CACHE="$(mktemp -d)/config-check.php" php artisan config:cache
```

Only if that succeeds, rebuild the real cache and reload the PHP workers the way the
deployment normally does:

```sh
php artisan config:cache
```

### Rotate the integration key

1. Generate a new key pair with a new key ID, for example `integration-2027-03`.
2. Add the new public key to every connected application alongside the old one
   (`DELEGATED_ACCESS_PUBLIC_KEYS=integration-2026-09|/path/old.pub.pem,integration-2027-03|/path/new.pub.pem`)
   and deploy each application.
3. Switch the provider's `KEY_ID` and `PRIVATE_KEY_PATH` to the new pair, check and rebuild
   the configuration cache, and verify (section 7).
4. After a few minutes (assertions live at most 60 seconds), remove the old public key from
   every application, then destroy the old private key.

If the old private key may be compromised, turn the provider's `ENABLED` flag off first,
remove the old public key from every application immediately, and then continue from step 3.

## 6. Delegated access: the application

The application receives delegated calls through the delegated access endpoint in
`bherila/auth-laravel` (in progress in that package, due in its next minor release). The
package README is the reference for the application side; this section lists what the
provider operator must line up with it.

The application is configured with:

```dotenv
DELEGATED_ACCESS_ENABLED=true
DELEGATED_ACCESS_ISSUER=https://identity.example.test
DELEGATED_ACCESS_ENDPOINT=https://app.example.test/application-access
DELEGATED_ACCESS_APPLICATION=example-app
DELEGATED_ACCESS_PUBLIC_KEYS=integration-2026-09|/path/to/delegated-access-integration-2026-09.pub.pem
```

plus `OAUTH_PROVIDER`, set explicitly (section 2).

These must match the provider exactly:

| Application | Provider |
| --- | --- |
| `DELEGATED_ACCESS_ISSUER` | `AUTH_MANAGER_DELEGATED_ACCESS_ISSUER` |
| `DELEGATED_ACCESS_ENDPOINT` | the endpoint in the `APPLICATIONS` entry |
| `DELEGATED_ACCESS_APPLICATION` | the key in the `APPLICATIONS` entry and the registry key |
| a key ID in `DELEGATED_ACCESS_PUBLIC_KEYS` | `AUTH_MANAGER_DELEGATED_ACCESS_KEY_ID` |
| the contract version the application implements | the version in the `APPLICATIONS` entry |

`DELEGATED_ACCESS_PUBLIC_KEYS` is a comma-separated list of `key-id|/path/to/public.pem`
entries; it holds two entries only during rotation.

The application publishes the package's delegated access nonce migration and applies it
through its normal reviewed deployment before enabling the endpoint:

```sh
php artisan vendor:publish --tag=bherila-auth-delegated-access-migrations
```

The application implements the package's adapter, which decides every authorization: who
the actor may see and change, in which workspaces, with which roles, and its own
last-administrator rules. The provider only proves who is asking. A provider administrator is
not an application administrator.

The application's edge (firewall, CDN, bot protection) must let the provider's
server-to-server `POST` reach the endpoint without a browser challenge or redirect. The
provider never follows redirects.

## 7. Verify

1. On the provider, confirm the map loaded as intended:
   `php artisan config:show delegated-access.applications`.
2. Turn on `AUTH_MANAGER_DELEGATED_ACCESS_ENABLED`, check and rebuild the configuration
   cache (section 5).
3. Sign in to the provider as a test account that holds the client grant and is an
   administrator inside the application. Open `/applications/manage`; the application should
   be listed and its accounts readable.
4. Sign in as a granted account that is not an application administrator, and as an
   ungranted account. The first should see only what the application's adapter allows; the
   second should not see the application at all.
5. If a call fails, the page shows a typed outcome. A configuration outcome points at the
   provider values; `unavailable` usually means the endpoint is unreachable or blocked at the
   application's edge; `not_authorized` is the application's (or the grant check's) refusal.
   The application should record a nonce for each accepted call.
6. Only then turn on `AUTH_MANAGER_DELEGATED_ACCESS_WRITES_ENABLED`, rebuild the
   configuration cache, and make one intended change with recent identity confirmation.
   Confirm it in the application itself.

## Rollback

- **Stop changes only:** set `AUTH_MANAGER_DELEGATED_ACCESS_WRITES_ENABLED=false` on the
  provider, check and rebuild the configuration cache.
- **Stop delegated access:** set `AUTH_MANAGER_DELEGATED_ACCESS_ENABLED=false` on the provider,
  or remove the application's entry from `AUTH_MANAGER_DELEGATED_ACCESS_APPLICATIONS`, then
  check and rebuild the configuration cache. On the application, set
  `DELEGATED_ACCESS_ENABLED=false` and rebuild its configuration.
- **A malformed value stopped the instance loading:** restore the previous value and rebuild
  the configuration cache.
- Keep the application's nonce table; do not roll back its migration.
- Registry navigation and sign-in are separate: disable the registry entry or launch flag as
  described in [the application registry](application-registry.md), and revoke client grants
  in `/admin/users` (or revoke the client) when sign-in itself must end.
