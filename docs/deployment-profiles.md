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

The existing provider access-grant, disabled-account, and credential-version
checks still apply to every authorization code, access token, and refresh token.
Removing a grant or disabling an account makes an existing credential inactive.

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
