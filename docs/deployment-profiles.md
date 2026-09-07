# Deployment profiles and resource OAuth

`AUTH_MANAGER_PROFILE` selects one of two validated deployment contracts:

| Profile | OAuth behavior | Scopes |
| --- | --- | --- |
| `bherila` (default) | Preserves the existing authorization-code OAuth behavior. Resource-server helpers are disabled. | `identity:read` |
| `resource` | Enables the authorization server, S256 PKCE, RFC 8707 resource indicators, authorization-server metadata, dynamic client registration, and RFC 7662 introspection. | `mcp:use`, `offers:read` |

An unrecognized profile prevents configuration from loading. Do not use a
profile name as an ad-hoc feature flag.

## Resource profile configuration

The `resource` profile requires deployment-specific, absolute HTTPS URLs. Use
synthetic values when documenting or testing a deployment:

```dotenv
AUTH_MANAGER_PROFILE=resource
AUTH_MANAGER_OAUTH_ISSUER=https://identity.example.test
AUTH_MANAGER_OAUTH_RESOURCE=https://resource.example.test/api/mcp
```

Loopback `http` URLs are accepted only in local and testing environments. The
resource is an exact audience: a client must send the same `resource` value
when requesting authorization, exchanging an authorization code, and refreshing
the token. Both protected-resource scopes require that binding.

The resource profile publishes authorization-server metadata at
`/.well-known/oauth-authorization-server`. It exposes dynamic client
registration at `POST /oauth/register` and token introspection at
`POST /oauth/introspect`. These endpoints are absent from the default profile.

On the `resource` profile, active provider users can authorize dynamically
registered MCP clients (including Codex, ChatGPT, and Claude) without an
administrator granting each newly registered client. Registration does not grant
consent: these public clients still show the explicit authorization screen and
must satisfy PKCE, registered redirects, scope, and resource checks. The resource
application remains responsible for resolving its own account and permissions.

Static OAuth clients still require explicit per-user client grants. The `bherila`
profile retains this requirement for every client, including dynamic clients;
the MCP onboarding policy must not widen the shared provider's other deployment.
Disabled-account and credential-version checks apply throughout code exchange,
access-token validation, introspection, and refresh on both profiles.

Revoking a dynamic client's grant through directory administration revokes its
existing tokens, but does not prohibit an active resource-profile user from
consenting again. Revoke the client itself to prevent any further use of that
registration, or disable the provider account to prevent that user's sign-in.
Static client grant removal continues to block subsequent authorization.

## Introspection credential

Introspection is for the resource server, not browser or public OAuth clients.
Configure exactly one dedicated client ID and a `password_hash()` result:

```dotenv
AUTH_MANAGER_INTROSPECTION_CLIENT_ID=resource-server-example
AUTH_MANAGER_INTROSPECTION_SECRET_HASH='$2y$...password_hash output...'
```

Store the plaintext password only in the resource server's secret store. Never
place it in `.env`, application configuration, source code, issue text, or logs.
The endpoint uses HTTP Basic authentication; invalid credentials receive
`invalid_client`, while invalid, expired, revoked, grant-revoked, or
disabled-account tokens return `{ "active": false }`.

## Theme and session settings

`AUTH_MANAGER_THEME_COOKIE_DOMAIN` and
`AUTH_MANAGER_THEME_ALLOWED_HOSTS` control only the non-sensitive theme cookie.
The domain must be a DNS domain and every allowed host must be within that
domain. For example:

```dotenv
AUTH_MANAGER_THEME_COOKIE_DOMAIN=.example.test
AUTH_MANAGER_THEME_ALLOWED_HOSTS=example.test,admin.example.test
```

`SESSION_DOMAIN`, `APP_NAME`, `APP_URL`, and WebAuthn values remain explicit
deployment settings. In particular, leaving `SESSION_DOMAIN` unset keeps a
session cookie host-only; do not use the theme-cookie configuration to widen
session scope.
