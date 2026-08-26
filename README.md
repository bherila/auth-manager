# auth-manager

Identity provider for the `bherila.net` application family. Runs at
[`id.bherila.net`](https://id.bherila.net) and issues OAuth 2.0 tokens to the
applications that rely on it.

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
coarse OAuth client grants. Every successful mutation records the target and the
acting provider administrator in the authentication audit log.

Provider state deliberately stops at the OAuth boundary: creating a person or
granting an OAuth client here never creates an account or permissions inside a
connected application.

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

Colour scheme is shared across `*.bherila.net` through a `theme` cookie on
`Domain=.bherila.net`, resolved before first paint by
`resources/views/layouts/theme-init.blade.php` so navigating between
applications does not flash. `localStorage` mirrors the value and is the
fallback in local development, where that cookie cannot be set.

## Deployment

Merges to `main` that pass CI deploy automatically. The deploy destination is
hard-coded; runtime configuration and database credentials live on the server
outside the repository and are never committed.
