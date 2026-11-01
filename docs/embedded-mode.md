# Embedded mode

Embedded mode installs Auth Manager as a Composer package inside another Laravel
application (the *host*). The provider is mounted under a path prefix, `/auth` by
default. It is the same code that runs standalone at `id.<domain>`. Embedded is a
packaging mode, not a fork, and an embedded instance can later move to its own
deployment with its accounts intact (see [Moving to standalone](#moving-to-standalone)).

There is one instance per installation, with no multi-tenancy. The host remains a
relying party. It signs people in through auth-laravel's `RelyingPartyLoginController`
over OAuth (authorization code + S256 PKCE), exactly as it would against a standalone
instance. The two setups differ only in `oauth_client.base_url` and in the issuer:

| | Standalone | Embedded |
| --- | --- | --- |
| Issuer | `https://id.example.test` | `https://app.example.test/auth` |
| `OAUTH_PROVIDER_URL` (host) | `https://id.example.test` | `https://app.example.test/auth` |
| Authorize / token | `/oauth/authorize`, `/oauth/token` | `/auth/oauth/authorize`, `/auth/oauth/token` |
| Identity | `/api/oauth/user` | `/auth/api/oauth/user` |
| End session | `/oauth/end-session` | `/auth/oauth/end-session` |
| RFC 8414 metadata¹ | `/.well-known/oauth-authorization-server` | `/.well-known/oauth-authorization-server/auth` |

¹ Published only by the `resource` profile, in both modes. There is no JWKS endpoint.
Access tokens are validated through `/api/oauth/user` or introspection.

## Package layout and service provider

The repository is the package. `composer.json` is named `bherila/auth-manager`, and
its code lives under `BWH\AuthManager\` (`app/`). Factories and seeders live under
`BWH\AuthManager\Database\…`. Nothing claims the host's `App\` or `Database\` namespaces.

- **Standalone** boots `bootstrap/app.php`, which registers `AppServiceProvider`.
- **Embedded:** the host auto-discovers `BWH\AuthManager\Providers\EmbeddedServiceProvider`
  through `extra.laravel.providers`. That provider registers `AppServiceProvider`
  itself. It then adds the connection, guards, middleware groups, routes and commands
  described below. A standalone checkout never loads it, because Composer doesn't
  discover the root package.

Code that has to know where it is mounted asks `BWH\AuthManager\Support\Mount` for:
- the prefix
- mount-relative path checks
- the web and api middleware groups
- the API guard

Route names are `auth-manager.*` in both modes, so views and controllers are the same
everywhere. The `passport.*` and `bherila-auth.*` names keep their own names, because
vendor views and controllers look them up.

## Configuration

`config/auth-manager-embedded.php` holds the mount settings. A host may publish it
(`vendor:publish --tag=auth-manager-config`) or set the environment variables:

| Key | Env | Default |
| --- | --- | --- |
| `prefix` | `AUTH_MANAGER_EMBEDDED_PREFIX` | `auth` |
| `issuer` | `AUTH_MANAGER_OAUTH_ISSUER` | `APP_URL` + `/` + prefix |
| `name` | `AUTH_MANAGER_EMBEDDED_NAME` | `APP_NAME` |
| `database.connection` | `AUTH_MANAGER_EMBEDDED_DB_CONNECTION` | the host's default connection |
| `database.table_prefix` | `AUTH_MANAGER_EMBEDDED_TABLE_PREFIX` | `auth_manager_` |
| `session.cookie` | `AUTH_MANAGER_EMBEDDED_SESSION_COOKIE` | `auth_manager_session` |
| `session.driver` | `AUTH_MANAGER_EMBEDDED_SESSION_DRIVER` | the host's driver |
| `session.lifetime` | `AUTH_MANAGER_EMBEDDED_SESSION_LIFETIME` | the host's lifetime |
| `well_known` | `AUTH_MANAGER_EMBEDDED_WELL_KNOWN` | `true` |
| `keys_path` | `AUTH_MANAGER_EMBEDDED_KEYS_PATH` | `storage/app/private/auth-manager/oauth` |
| `config` | — | per-file overrides, e.g. `['branding' => […]]` |

The provider's own configuration files are evaluated by the provider rather than
published:
- `auth-manager`
- `branding`
- `delegated-access`
- `application-registry`
- `application-invitations`
- `identity-deletion`
- Auth Manager's copy of `bherila-auth`

Their environment variables mean the same thing as in standalone. Embedded mode
changes these defaults, so nothing defaults to a bherila value:
- The issuer defaults to the mount URL, and its path must equal the prefix.
- There is no theme cookie domain.
- The users model is Auth Manager's own.
- The login URLs are under the prefix.

Branding, the provider's name and its URLs all come from this configuration. Branding
asset paths are root-relative under the prefix (`/auth/branding/…`).

## Routing under the prefix

Every route is inside `Route::prefix($prefix)`. The only exception is the RFC 8414 §3
metadata document at `/.well-known/oauth-authorization-server/<prefix>`. It can't
collide with the host's own `/.well-known/oauth-authorization-server`, and
`well_known=false` drops it. The same document is also served at
`/<prefix>/.well-known/oauth-authorization-server`.

Passport's own routes stay off (`Passport::ignoreRoutes()`), so embedding registers
nothing at `/oauth`. Auth-laravel's passkey and two-factor routes are loaded from the
package under `/<prefix>/api`. The host's own auth-laravel routes are unaffected.
The health route `/up` is standalone-only.

## Isolation

Every embedded route starts with `EnterEmbeddedContext`. It switches the following for
the duration of the request, and restores them afterwards:

- **Database:** the default connection becomes `auth-manager`. That connection is a copy
  of the configured connection with the table prefix appended. Eloquent, the query
  builder, auth-laravel's models and Passport (`passport.connection`) all use it. Auth
  Manager never reads the host's tables, and the host has no models over the prefixed
  ones.
- **Users and guard:**
  - guard `auth-manager` (session) and guard `auth-manager-api` (Passport)
  - provider `auth-manager-users`, which uses Auth Manager's own `User` model

  The context calls `Auth::shouldUse('auth-manager')`, so `auth`, `Auth::user()` and
  Passport's authorization screens resolve the provider's people, never the host's.
- **Session and cookies:** Auth Manager has its own middleware group `auth-manager.web`
  instead of the host's `web` group. Inside it, the session cookie is
  `auth_manager_session`, its path is `/<prefix>`, and it is host-only. The cookie
  jar's default path matches, so remember-me cookies are scoped too. Sessions on the
  database driver live in the prefixed `sessions` table.
- **CSRF:** the group runs its own `ValidateCsrfToken` against Auth Manager's session.
  It doesn't set an `XSRF-TOKEN` cookie, so it never shadows the host's. Pages send
  the token from the `csrf-token` meta tag.
- **Views, mail and assets:** the package's views take precedence inside the context
  only. Mail uses the package's markdown theme. `@vite` resolves the package's manifest
  (see Assets).
- **Errors:** JSON rendering for `/<prefix>/api/*` and delegated-access error pages are
  registered on the host's handler. Both are conditional on the request being inside the
  context. Adding `code` to the host's don't-flash list is the one global change. It
  keeps a refused one-time code out of the session.

Console commands are wrapped the same way when they start (`CommandStarting`):
- `identity:*`, `identities:*` and `auth-manager:*`
- `passport:*`, which owns the `auth-manager` connection and the keys path

Auth Manager's schedule entries are registered on the host's scheduler.

**Host requirements.** The host must not run Passport itself, because Passport's
configuration is process-wide. Host listeners for Laravel auth events (`Login`,
`Logout`, …) receive Auth Manager's events too, and should check `$event->guard`.
The cache store and `APP_KEY` are shared. Rate-limiter keys are namespaced
`auth-manager.*`.

### Same-origin caveat

On a shared origin, script running in a host page can call the provider's endpoints
with the person's provider session. The same applies in reverse. Cookie paths
are not a security boundary between pages on one origin. So an XSS anywhere in the
host can act as the signed-in person at the provider:
- read the account page
- start an authorization
- manage passkeys, after the recent-authentication check

This is accepted for a single-application instance. An installation that needs the
boundary should run the provider on its own origin (standalone).

## Tables

Tables are created on the `auth-manager` connection, so they carry its prefix
(`auth_manager_users`, `auth_manager_oauth_clients`, …). Its migrations repository is
`auth_manager_migrations`. To use a separate database instead, define
`database.connections.auth-manager` in the host, which takes precedence, or point
`database.connection` at another connection and set the prefix to `''`.

## Migrations

The host's `php artisan migrate` doesn't run the provider's migrations. Their names
(`0001_01_01_000000_create_users_table`, …) would collide in the host's repository.
Run them separately:

```sh
php artisan auth-manager:migrate --force
```

This runs `migrate` on the `auth-manager` connection with its own repository, from
`database/migrations/auth-manager` when the host has published them
(`vendor:publish --tag=auth-manager-migrations`), and otherwise from the package. A
host's deploy must call it as a separate step.

## Assets

The Vite build ships in the package at `public/build`. Embedded pages use a separate
`Vite` instance, so the host's own `@vite` is untouched. That instance:
- reads the package manifest and the package `hot` file
- emits URLs under `/<prefix>/build/…`

`GET /<prefix>/build/assets/{file}` serves those files with immutable cache headers.
It only serves hashed files from the package's build directory, and only for an
allowlist of extensions. A host can publish the files instead
(`vendor:publish --tag=auth-manager-assets` copies them to `public/<prefix>/build`), so
the web server serves them directly at the same URLs. The browser code reads its base
path from `<meta name="auth-manager-base">`, so a single build serves either mode.

## Installing in a host

1. `composer require bherila/auth-manager` from the release's source archive, which
   includes `public/build` (see [Packaging](#packaging)).
2. Set `AUTH_MANAGER_EMBEDDED_PREFIX`, if you don't want `auth`, and
   `AUTH_MANAGER_OAUTH_ISSUER=https://app.example.test/auth`. Set the profile
   variables as for standalone.
3. `php artisan auth-manager:migrate --force`, then `php artisan passport:keys`. Keys
   go to `keys_path`.
4. Create people as on a standalone instance, for example with `identity:import`. Then
   grant the first administrator with
   `php artisan auth-manager:user-roles admin@example.test --add=admin`. Provider
   commands run against the provider's tables.
5. Register the host as a static client with `php artisan passport:client`, then grant
   people that client, as in [connecting an application](connecting-an-application.md).
   Both write to the provider's tables.
6. Configure the host's auth-laravel relying party:
   - `OAUTH_PROVIDER_URL=https://app.example.test/auth`
   - `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET` and `OAUTH_REDIRECT_URI`
   - an explicit `OAUTH_PROVIDER`

   Then route its `/login` through `RelyingPartyLoginController`. A host that signs in
   only through the provider sets `bherila-auth.routes.enabled=false`, so it serves no
   auth-laravel routes of its own at the root.
7. Add `auth-manager:migrate --force` to the deploy, before the new code is activated.

## Standalone-only

The following belong to the standalone deployment and are not registered when embedded:
- `bootstrap/app.php`, including trusted proxies and the global middleware stack
- the `/up` health check and its signing-key probe
- the Brevo mailer transport
- the deployment and release workflows
- the theme-cookie defaults

Embedding uses the host's mailer, proxies and scheduler.

## Moving to standalone

The issuer changes from `https://app.example.test/auth` to `https://id.example.test`.
Relying applications keep their `(oauth_provider, oauth_subject)` bindings when the
provider *name* is unchanged. Passkeys survive only if their RP ID is still valid at the
new host, so set `WEBAUTHN_RP_ID` to the registrable domain from the start. Copying the
directory is #105: [copying identities](identity-copy.md) already reads the
`auth-manager` connection, prefix included. Reconciliation secrets derived from
`APP_KEY` need the same key, or new secrets, after the move.

## Packaging

The package stays in this repository, and the app itself is installable. A
`packages/` split would need two release lines for one codebase. Composer installs
need the built assets, which aren't committed. Each release
therefore attaches a Composer source archive, `auth-manager-source-<tag>.zip`, next to
the deploy tarball. It holds the tracked source plus the compiled `public/build`, and no
`vendor/` or `node_modules/`. Its `composer.json` carries `version` set from the tag
(`v1.2.3` installs as `1.2.3`). Its checksum is in `SHA256SUMS-source`, and it has the
same build-provenance attestation as the tarball. Verify it before use:

```sh
gh release download v1.2.3 --repo bherila/auth-manager \
  --pattern 'auth-manager-source-v1.2.3.zip' --pattern SHA256SUMS-source
sha256sum --check SHA256SUMS-source
gh attestation verify auth-manager-source-v1.2.3.zip --repo bherila/auth-manager
```

A host then installs it through a Composer `artifact` repository: put the verified zip
in a directory the host commits or restores in CI, such as `packages/`.

```json
{
    "repositories": [
        { "type": "artifact", "url": "packages/" }
    ]
}
```

```sh
composer require bherila/auth-manager:1.2.3
```

Alternatively, a `package` repository pins one zip by URL without a directory scan. Use
the zip's `shasum` (SHA-1, which Composer verifies) and the exact version:

```json
{
    "repositories": [
        {
            "type": "package",
            "package": {
                "name": "bherila/auth-manager",
                "version": "1.2.3",
                "dist": {
                    "type": "zip",
                    "url": "packages/auth-manager-source-v1.2.3.zip",
                    "shasum": "<sha1 of the zip>"
                },
                "require": { "php": "^8.4" }
            }
        }
    ]
}
```

A `package` repository does not read the archive's own `composer.json`, so it must
repeat the `require` list; prefer `artifact`. Both need the host to bump the pinned file
deliberately, which is the point. Without a release, a host can build the assets in place:

```sh
pnpm --dir vendor/bherila/auth-manager install --frozen-lockfile
pnpm --dir vendor/bherila/auth-manager run build
```
