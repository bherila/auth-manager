# auth-manager

An identity provider with shared account and administrator screens, OAuth 2.0,
passkeys, and optional deployment branding. Each instance owns its identity
directory and registered applications; connected applications retain their own
business data and authorization rules.

## Responsibilities

- Authenticate people: password, passkey (WebAuthn), and second factor.
- Own credential material and the authentication audit trail.
- Issue and refresh OAuth 2.0 tokens for registered first-party clients.
- Record coarse per-client entitlement — whether a subject may obtain a token
  for a given application at all.

Applications resolve their own fine-grained permissions locally. This service
does not model any application's feature vocabulary.

## Directory administration

Active provider administrators can use `/admin/users` to create people, change
provider email addresses and passwords, disable or re-enable sign-in, and manage
coarse OAuth client grants. The resource profile also permits active users to
consent to dynamically registered MCP clients without a per-installation grant;
see [deployment profiles](docs/deployment-profiles.md). They can also delete a provider identity through the
tombstone-and-reconcile lifecycle. Every successful mutation records the target
and the acting provider administrator in the authentication audit log.

Provider state deliberately stops at the OAuth boundary: creating a person or
granting an OAuth client here never creates an account or permissions inside a
connected application.

The relying-application contract for deletion feeds, acknowledgements, and the
30-day provider retention rule is documented in
[`docs/identity-deletion.md`](docs/identity-deletion.md).

## Stack

Laravel 13 on PHP 8.5, with [`bherila/auth-laravel`](https://github.com/bherila/auth-laravel)
providing the shared authentication services and
[`bherila/auth-react`](https://github.com/bherila/auth-react) the browser-side
WebAuthn helpers.

## Local development

```bash
composer setup     # install dependencies, seed .env, build assets
composer dev       # serve the application
composer ci:check  # the checks CI runs
```

## Theme

Theme preference is resolved before first paint by
`resources/views/layouts/theme-init.blade.php`. A deployment may opt into a
shared, non-sensitive `theme` cookie through a validated domain and host
allow-list; `localStorage` remains the fallback. Session cookies stay host-only
unless a deployment explicitly changes `SESSION_DOMAIN`.

## Deployment profiles and resource OAuth

The provider has a legacy identity profile and an opt-in resource-bound OAuth
profile. See [`docs/deployment-profiles.md`](docs/deployment-profiles.md) for
the environment contract, OAuth metadata, dynamic client registration, and
introspection configuration.

## Deployment

One codebase can serve independently operated client instances. The built-in
stylesheet includes light and dark modes and remains the default. Optional logos,
colors and font settings customize that shared UI without maintaining a fork.

An operator's deployment repository owns its CI jobs, environment approvals,
private branding and credentials. It checks out reviewed application and tooling
revisions, builds a release, and deploys to an isolated identity runtime. Reusable
deployment scripts and synthetic tests belong here; client-specific orchestration
and assets stay with the operator.

Start with [the deployment guide](docs/deployment.md), then use the focused
[branding guide](docs/deployment-branding.md) and
[OAuth profile reference](docs/deployment-profiles.md). The repository's existing
automatic deployment jobs serve configured installations; they are not a generic
onboarding mechanism for another client.

The host invokes `php artisan schedule:run` every minute. The application
scheduler runs identity-tombstone retention hourly and prevents overlapping
runs.
