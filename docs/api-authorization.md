# API authorization: the provider as authorization server for application APIs

**Status: Proposed.** Nothing here is implemented. This replaces the direction of #68
(retire the `resource` profile): its pieces become the starting point instead.

## Summary

Today an instance signs people in, and an application that exposes an API to agents
(REST or MCP) runs its own OAuth authorization server: Passport, consent pages, dynamic
client registration (DCR), refresh tokens and personal tokens, once per application. This
design moves all of that into the provider, in the style of a hosted identity platform's
"APIs" feature:

- One **instance** is one user directory. It serves many **applications** (sign-in clients,
  already modelled by the [registry](application-registry.md)) and many **APIs** (resource
  servers). Every API has its own audience identifiers and scope catalog. The user list is
  shared by every application and API on the instance.
- Each API gets its own OAuth flow for MCP clients (discovery, DCR, consent, tokens), all
  served by the one instance.
- Relying applications keep exactly two auth paths: **sign-in** (the existing auth-laravel
  `OAuthClient`) and **local validation of provider-issued access tokens** plus scope
  enforcement, both from the shared package. They run no authorization server.

Deployment shape is unchanged: a product gets its own dedicated instance; a shared instance
serves a set of personal applications. One deployment serving several directories is
deferred.

### Decisions at a glance

| # | Question | Recommendation |
| --- | --- | --- |
| 1 | Catalog | A versioned JSON file per instance, assembled from per-application fragments generated in each application's CI, reviewed where the instance's deployment is defined (the operator's repository, or beside the identity deploy workflow when the application owns that pipeline), read at config-cache time by a pinned release. Not secret. No publish API. |
| 2 | Token format | RFC 9068 JWT access tokens (`typ: at+jwt`), RS256, a dedicated per-instance key set with `kid`, JWKS validated locally. Five-minute TTL, rotating refresh tokens with family revocation on reuse. Operations needing a catalog-`sensitive` scope get a current-status check automatically. |
| 3 | Clients | Public DCR clients with PKCE for MCP, static confidential clients by operator command, client credentials deferred. A per-API user-access policy (`granted`, `open` or `application`) keeps the per-user grant posture available and lets an application own eligibility, asked at authorization and at every refresh. |
| 4 | Consent | Provider-side consent per subject × client × API × scopes, shown with the catalog's text; revocable in account settings and by administrators. Outstanding JWTs live out their five minutes unless the API introspects. |
| 5 | Personal tokens | Provider-issued, opaque, per API, bound to a non-connection resource, validated by cached introspection. Connection scopes (`mcp:use`) are refused by the catalog validator, the issuer and the relying guard. No opt-in. |
| 6 | Profiles | Capability derived from the catalog. The `resource` profile becomes a synthesized one-API catalog so its deployment keeps working unchanged; profiles shrink to defaults. |
| 7 | Relying package | auth-laravel `provider-api` guard, JWKS cache, resource/scope/step-up middleware, RFC 9728 metadata naming the provider, RFC 6750/9470 challenges, catalog fragment generator and drift check. |
| 8 | Migration | Dual-accept (local tokens and provider tokens), metadata flip, forced reconnect, then removal of the local server in a later release. |
| 9 | Authentication context | Tokens and the identity response carry `auth_time`, `amr`, `acr`; the provider enforces `prompt=login`, `max_age` and `acr_values`. |

## 1. API registration and the scope catalog

### Model

```
instance
├── applications            (registry keys; sign-in clients mapped to them)
└── apis
    └── <api key>           (belongs to one application key)
        ├── resources       (audience identifiers, each with its own scope ceiling)
        └── scopes          (names, consent text, flags)
```

An API has **several resources**, because RFC 9728 makes every endpoint whose
protected-resource document a client reads its own audience: a REST base, an MCP endpoint,
and an MCP alias are three identifiers. This is the shape auth-laravel's `resources` setting
already uses for in-application servers, and it is why a flat scope list is not enough: the
connection scope must be admissible on MCP resources and refused on REST, and REST-only
scopes must stay off MCP tokens.

### File format (catalog version 1)

```json
{
  "catalog_version": 1,
  "apis": {
    "records": {
      "application": "records",
      "name": "Records",
      "enabled": true,
      "resources": {
        "rest":      { "identifier": "https://records.example.test/api/v1",     "scopes": ["records:read", "records:write"] },
        "mcp":       { "identifier": "https://records.example.test/api/v1/mcp", "scopes": ["mcp:use", "records:read", "records:write"], "requires": ["mcp:use"] },
        "mcp_alias": { "identifier": "https://records.example.test/mcp",        "scopes_from": "mcp" }
      },
      "default_resource": "rest",
      "scopes": {
        "mcp:use":       { "description": "Connect an AI assistant to Records", "connection": true },
        "records:read":  { "description": "Read your records" },
        "records:write": { "description": "Create and change your records", "sensitive": true }
      },
      "policy": {
        "user_access": "granted",
        "dynamic_registration": true,
        "first_party_consent_skip": false,
        "access_token_ttl": "PT5M",
        "refresh_idle": "P30D",
        "refresh_absolute": "P90D",
        "personal_tokens": { "enabled": true, "resource": "rest", "lifetimes": ["P30D", "P90D"] }
      },
      "source": { "fragment_sha256": "…", "generated_from": "records@<commit>" }
    }
  }
}
```

Validation rules, enforced by one validator used at load and by a check command:

- API keys and resource names are registry-style lowercase keys. `application` must be an
  instance registry key (checked when the registry is readable; the file alone is still
  validated structurally).
- Every resource `identifier` is an absolute HTTPS URL by the existing
  `validatedAbsoluteUrl()` rules, canonicalized, and **unique across the whole instance**.
  None may equal the issuer or sit under the issuer's own paths.
- Every scope listed under a resource exists in the API's `scopes`. `requires` lists scopes a
  token for that resource must contain (today's `resource_required_scopes`).
- Scope names are unique within an API and may repeat across APIs: a scope means nothing
  without its audience. `identity:read` and provider-internal scopes (`invitations:admit`)
  are reserved and refused in any API.
- `connection: true` scopes may appear only on resources that also `require` them, and never
  in `personal_tokens` (section 5).
- `sensitive: true` marks a scope whose operations must see current token status (section 2):
  the consent screen calls it out and the relying guard checks status before every operation
  that requires it. It comes from the application's scope declarations through the fragment,
  like the description.
- Descriptions are plain text, at most 200 characters, rendered escaped. They are the consent
  copy, so they come only from reviewed configuration, never from client registration.
- Durations are ISO-8601 with hard ceilings: access tokens at most `PT15M`, refresh absolute
  at most `P365D`, personal tokens at most `P365D`.

### How the catalog reaches the provider

**Recommended: generated fragments, assembled and reviewed as deployment configuration.**

1. Each application's CI runs a package command (section 7) that emits its **fragment**: the
   API's resources and scopes, generated from the same capability registry and resource
   configuration that drive its MCP tools and OpenAPI document. A `--check` mode fails CI
   when the committed fragment differs from what the registry generates, exactly like the
   existing OpenAPI drift checks.
2. The catalog lives **where the instance's deployment is defined**, assembled from fragments
   pinned by digest plus instance-owned `policy` blocks (policy is the instance's decision,
   not the application's). Two sources are valid:
   - *An operator deploys the instance:* the operator's private deployment repository holds
     one catalog per instance.
   - *The relying application owns the instance's deployment pipeline* (its identity deploy
     workflow lives in the application's own repository, which may be public): the
     application's CI-generated fragment and the instance policy are committed beside that
     workflow, and the workflow assembles the catalog for the release it builds.

   Either way the invariants are the same: every change is reviewed (a pull request to the
   repository that defines the deployment), the catalog is pinned to the release (its digest
   recorded with the release, so an activated release has exactly one catalog), and it is read
   when configuration is built. **Catalog content is not secret**: the provider publishes it
   (the per-API catalog document and the consent screen), so a public repository is fine.
   Nothing secret belongs in it; introspection and application-access credentials, signing keys
   and endpoint secrets stay in the instance's secret store and environment.
3. The instance's environment names the file: `AUTH_MANAGER_API_CATALOG=/absolute/path`.
   The release engine places it with the rest of the deployment configuration. It is read
   during `config:cache`, so a running release serves exactly the catalog it was activated
   with; changing it is a configuration rebuild, never a database or host-panel edit.
4. `php artisan auth-manager:apis:check` validates the file and is run by the release before
   activation. At runtime, an invalid catalog disables API authorization only (every API
   request is refused with `temporarily_unavailable`, reported once without the value);
   sign-in keeps working. This mirrors the delegated-access map.

A small catalog may instead be passed inline as `AUTH_MANAGER_API_CATALOG_JSON` for
deployments whose engine cannot place files; the same validator applies.

**Rejected: an authenticated publish API.** It makes consent text and scope ceilings mutable
runtime state writable by an application credential. A compromised application could widen
its own scopes or rewrite consent copy into a phishing prompt without review, the state lives
in the database rather than in the pinned release, and the publish credential is one more
secret and one more endpoint to secure. Generated-plus-reviewed keeps the convenience
(no hand-maintained scope lists) without any of that.

**Rejected: administrator UI editing.** Same runtime-state objection, plus drift from the
application's registry is guaranteed.

### Drift detection

Three independent checks, because each catches a different drift:

| Drift | Detected by |
| --- | --- |
| Application registry changed, fragment not regenerated | Application CI `--check` |
| Fragment regenerated, instance catalog not updated (or the reverse) | The relying package's `verify` command, run after each application deploy and daily: it fetches the provider's public per-API catalog (`GET /.well-known/api-catalog/{api}`, names, descriptions, resources, scopes and `fragment_sha256`; no policy, no secrets) and compares it with what the application generates |
| Catalog validates but the resource is not actually served | `auth-manager:apis:check --live` fetches each resource's RFC 9728 document and requires its `resource` to match and its `authorization_servers` to name this issuer |

A scope the application requires but the provider lacks is an error (operations are
unreachable); a scope the provider offers but the application does not know is a warning
(consent would show something nothing enforces) and should be removed.

## 2. Token format and validation

### Recommendation: JWT access tokens validated locally (RFC 9068)

Opaque tokens with RFC 7662 introspection on every request would put the provider on every
API call's critical path and make a provider outage an outage of every API. Local validation
keeps the property the per-application design was chosen for (no per-request dependency) and
costs only the revocation latency of one access-token lifetime, which the section on disabled
accounts below bounds. Introspection survives for operations that require a `sensitive` scope
and as the validation path for personal tokens.

### Claims

Header: `{"typ": "at+jwt", "alg": "RS256", "kid": "<RFC 7638 thumbprint>"}`.

| Claim | Value |
| --- | --- |
| `iss` | The instance issuer, exactly as in its RFC 8414 metadata |
| `sub` | Provider subject (opaque string; same subject the application binds at sign-in) |
| `aud` | Exactly one resource identifier (a string, not an array) |
| `client_id` | The OAuth client |
| `scope` | Space-delimited scopes, already intersected with the resource's ceiling |
| `iat`, `nbf`, `exp`, `jti` | Standard; `exp - iat` is the API's access-token TTL |
| `auth_time` | When the person last actively authenticated at the provider (section 2.6) |
| `amr` | Methods used for that authentication |
| `acr` | Assurance class satisfied |
| `credential_version` | The subject's credential generation when the grant was issued |

Existing sign-in tokens are left as they are: Passport-format, `aud[0]` = client ID, no
`typ: at+jwt`, used only against the provider's own `/api/oauth/user`. A relying API's
validator therefore rejects them on two independent checks (`typ` and `aud`). Tokens for
APIs are never accepted by the provider's own API routes, which keep Passport's guard.

### Signing keys

- **A dedicated API-token key set per instance**, separate from Passport's sign-in key and
  from delegated-access keys, under the private storage root that deploys never transfer
  (`storage/app/private/oauth/api-keys/`). Only its public halves are published, at
  `/.well-known/jwks.json`, referenced by `jwks_uri` in the authorization-server metadata.
- **RS256, 3072-bit.** It is the RFC 9068 mandatory algorithm, the one Passport and the
  delegated-access assertions already use, and supported by the package's JWT library
  without new dependencies. HS256 is rejected outright (every API would hold a minting
  secret). ES256/EdDSA are acceptable later; the relying validator pins an algorithm
  allowlist per issuer so a change is an explicit configuration step.
- **`kid` is the RFC 7638 thumbprint**, so a key cannot be republished under another
  identity.
- **Rotation** by command, never automatic: `apis:keys:generate` (publish as *next*; not
  signing), `apis:keys:activate` after at least the relying JWKS cache maximum plus margin
  (one hour), `apis:keys:retire` once the previous key has signed nothing for longer than the
  maximum access-token TTL. Scheduled cadence: every six months. **Emergency rotation**
  removes the compromised key from JWKS at once; relying caches stop accepting it within
  their maximum cache age (ten minutes), and the refresh path keeps working, so connectors
  recover silently on their next refresh.

### Relying-side validation and JWKS caching

A token is accepted only if all of these hold: `typ` is `at+jwt`; `alg` is in the pinned
allowlist; `kid` is in the cached JWKS for the configured issuer; the signature verifies;
`iss` equals the configured issuer byte for byte; `aud` equals the identifier of the resource
the route expects (not merely any resource of the application); `exp`/`nbf` hold with at most
60 seconds of leeway; `client_id`, `sub` and `scope` are present.

JWKS cache: honour `Cache-Control` capped at ten minutes; on an unknown `kid`, refetch at most
once per minute; if the provider is unreachable, keep serving the last good key set for up to
24 hours (keys only; tokens still expire). Applications that cannot make outbound calls may
pin the key set in a deployment file instead, as delegated access pins keys, and rotate by
deploying the next key before activation.

### Refresh tokens

- Rotating: every refresh returns a new refresh token and revokes the old one (Passport's
  behaviour, already present).
- **Reuse detection:** presenting an already-rotated refresh token revokes the whole lineage
  (every refresh and access-token row descended from the same authorization), using the
  package's existing credential lineages. The legitimate client then re-authorizes.
- Lifetimes per API: idle window (default 30 days) and absolute lifetime from the original
  authorization (default 90 days). Sign-in clients keep today's one day.
- A refresh is refused, without consuming the token, unless the account is active, its
  `credential_version` matches the one recorded on the lineage, the client is not revoked,
  the consent still covers the scopes, the person still satisfies the API's `user_access`
  policy (for `application`, by asking the application; section 3), and the API is enabled. The refreshed token keeps the original `auth_time`, `amr`
  and `acr`: refreshing is not re-authenticating.

### Disabled accounts and credential generations under local validation

Disable, password change, reset and administrator revocation already increment the credential
generation and revoke OAuth rows. With local validation that takes effect:

1. **Within one access-token lifetime** (five minutes by default) everywhere, because the next
   refresh is refused.
2. **Immediately** for every operation whose required scopes include a catalog-`sensitive`
   scope: the relying guard applies the current-status check automatically (section 7), an
   introspection call cached at most 30 seconds that answers inactive for a revoked lineage,
   revoked consent, changed generation, disabled account or (for `user_access: application`)
   withdrawn eligibility.
3. Applications that already enforce identity status for their web sessions may also compare
   the token's `credential_version` with the generation they recorded for that subject; a
   mismatch is a refusal.

No revocation list is pushed to applications: five minutes, plus status checks on sensitive
operations, is the accepted bound.

### Authentication context: `auth_time`, `amr`, `acr`, `prompt`, `max_age`

So that applications can require a fresh sign-in or a stronger method without writing login
code, the provider records how a session was authenticated and enforces requests for more.

**Recording.** Each successful interactive authentication at the provider updates the session
with `auth_time` and the `amr` values used. The authorization code, the tokens issued from
it, and the refresh lineage carry them unchanged.

| Method | `amr` (RFC 8176) |
| --- | --- |
| Password | `pwd` |
| Emailed sign-in code | `otp` |
| Passkey | `hwk`, plus `user` when the authenticator reported user verification |
| Password then a second factor (roadmap) | `pwd`, the factor's value, `mfa` |

**`acr`.** A small instance vocabulary, ordered:

| `acr` | Satisfied by |
| --- | --- |
| `urn:auth-manager:acr:single` | Any one method |
| `urn:auth-manager:acr:phishing-resistant` | A passkey with user verification |
| `urn:auth-manager:acr:mfa` | Reserved until a second factor exists (appendix) |

**Method sets, not only the ladder.** Some step-ups ask "did this person just prove control of
their email or a passkey?" That is neither multi-factor nor phishing-resistant (an emailed code
is phishable), so no rung of the ladder expresses it, and a ladder rung that did would mislead
every other reader of `acr`. Requirements can therefore name a set of `amr` methods instead.
On the wire a method set is requested through `acr_values` with one method-class value per
method, because `acr_values` is the standard request parameter and the one RFC 9470 challenges
already carry:

| `acr_values` entry | Re-authenticate with |
| --- | --- |
| `urn:auth-manager:amr:pwd` | Password |
| `urn:auth-manager:amr:otp` | Emailed sign-in code |
| `urn:auth-manager:amr:hwk` | Passkey |

Several entries mean any of them (`acr_values` is a preference list). The returned `acr` names
the entry satisfied, and `amr` lists what was actually used.

**Requests the provider enforces** on `/oauth/authorize`, for sign-in and API clients alike:

- `prompt=login`: always re-authenticate before issuing a code.
- `max_age=N`: re-authenticate if the session's `auth_time` is older than N seconds
  (`max_age=0` behaves like `prompt=login`).
- `acr_values`: re-authenticate with a method that satisfies one of the values, offering only
  those methods on the sign-in screen (a request for `amr:otp amr:hwk` shows no password
  form); refuse with `access_denied`/`unmet_authentication_requirements` when the person has no
  such method (for example, no passkey enrolled).
- `prompt=none` remains refused, as today.

Re-authentication during authorization reuses the existing sign-in screens and must reach the
same subject; a different person signing in cancels the flow.

**Where it surfaces.** API access tokens carry the three claims. The identity response
(`GET /api/oauth/user`) adds `auth_time`, `amr` and `acr` from the sign-in token, so a relying
application can store them in its session at login. The authorization-server metadata
advertises `acr_values_supported`, and `prompt_values_supported` lists `login`.

**Enforcement is relying-side.** The provider honouring a request is a convenience; the
relying application decides from the returned `auth_time` and `amr` (section 7), so a provider
that ignored `max_age` or offered another method would still be refused.

**Rejected:** a non-standard `amr_values` request parameter (no client library sends it, and
challenges could not carry it), and applications re-prompting for a password themselves (that is a second login path
to secure), and inferring freshness from token `iat` (refresh resets it without any
authentication).

## 3. Clients

| Kind | Who creates it | Authentication | Use |
| --- | --- | --- | --- |
| Dynamic (MCP) | The client, through `POST /oauth/register` | Public; S256 PKCE required | Agents connecting to an API's MCP resource |
| Static confidential | An operator command | `client_secret_basic`/`_post`, PKCE also required | An application's own sign-in client; trusted server-side integrations |
| Machine-to-machine | Deferred | — | See below |

**Dynamic registration rules** (existing behaviour, tightened):

- Public clients only; a confidential request is registered public and the response says
  `none`, as the package does today.
- Redirect URIs: exact HTTPS URLs, or RFC 8252 loopback (`http://127.0.0.1`, `http://[::1]`,
  any port) for native clients. No wildcards, fragments, user information or private-use
  schemes in v1.
- Abuse limits: per-IP registration throttle (10 per hour), an instance-wide cap on
  registrations that have never completed an authorization (default 500, oldest pruned
  first), pruning of never-used registrations after 24 hours and of unused ones after the
  existing 30-day retention.
- A registration is not consent and is not bound to an API. Every authorization names a
  resource, and consent is per API (section 4).
- Each API can switch DCR off (`dynamic_registration: false`); DCR is available on the
  instance while at least one enabled API allows it.

**Static clients** gain a stored list of APIs and a scope ceiling; authorization outside it is
`invalid_scope` or `invalid_target`. The existing `oauth_client_grants` keep governing
sign-in.

**Per-instance user-access policy** (`policy.user_access`), the posture switch:

- `granted`: a person may authorize any client for the API only if they hold a grant to one
  of the API's application's mapped static clients, the same rule that decides launch
  visibility. This keeps the shared instance's "administrators decide who uses which
  application" posture without per-client grants for dynamic registrations, which cannot
  exist in advance. Recommended default for shared instances.
- `open`: any active person on the instance may authorize. Equivalent to today's `resource`
  profile behaviour. The application can still refuse every call, but the provider will keep
  refreshing a lineage the application no longer honours until its absolute lifetime ends, so
  prefer `application` when the application has its own notion of who may use the API.
- `application`: the provider asks the API's application whether this person may use this API
  with these scopes, before consent is shown and again at every refresh (below). Recommended
  for a dedicated product instance whose application owns roles and memberships.

### Application-owned eligibility (`user_access: application`)

**Question asked.** "May subject S use API A with scopes X?" The application answers with the
subset of X it allows now, or none, with a reason code.

**When.**

- At `/oauth/authorize`, after the person is authenticated and the resource and scope ceiling
  are resolved, and **before** consent is shown. Always asked fresh (no cache): it is
  interactive and rare.
- At every refresh, before a new access token is issued. A positive answer may be cached for
  at most 60 seconds per (subject, API, scope set), so a burst of refreshes is one call; a
  negative answer is never cached.
- By introspection, through the same 60-second cache: for operations requiring a `sensitive`
  scope, and for every personal-token call (personal tokens have no refresh, so this is where
  a demotion reaches them).

An application-side demotion therefore ends the refresh lineage at the next refresh (within
one access-token lifetime), instead of leaving a token family that refreshes for its full
absolute lifetime while every call is refused.

**Outcomes.**

| Answer | At authorize | At refresh |
| --- | --- | --- |
| All requested scopes allowed | Consent (or the existing consent) as usual | New tokens |
| Some allowed, every resource-`requires` scope among them | Consent shows only the allowed scopes and says some were withheld by the application; the token carries the subset | New tokens with the intersection of consented and allowed scopes, recorded on the lineage |
| None allowed, or a `requires` scope (such as the connection scope) withheld | No consent offered (below) | `invalid_grant`; the lineage is revoked and audited (`api_eligibility_revoked`) |
| No usable answer (timeout, error, malformed, bad signature) | "Temporarily unavailable" page; no consent, no code | `temporarily_unavailable`; the refresh token is **not** consumed and the lineage is kept, so a later refresh can succeed |

Narrowing never widens: if the application later allows more, the client gets it only through
a new authorization and consent. Narrowing below a resource's `requires` set is treated as
ineligible rather than issuing a token the resource would refuse.

**When eligibility fails at authorize** the provider shows its own page, not a consent
screen: "Your account does not have access to *API* in *Application*. Ask its administrator."
The reason code (`not_provisioned`, `not_permitted`, `suspended`) selects fixed provider copy;
application-supplied text is never rendered. One button returns to the client with
`error=access_denied`. Nothing is recorded as consent.

**Transport: reuse the signed application-access channel.** The provider already signs
requests to each application with that application's own key (`application-access+jwt`:
exact issuer, audience and method, body hash, nonce, at most 60 seconds), pins its endpoint
in deployment configuration, never follows redirects, bounds the response and fails closed
([delegated access](delegated-access-transport.md)). Eligibility is one more read operation,
`eligibility`, on that channel and endpoint, carrying `subject`, `api`, `resource` and
`scopes` and answered with `{allowed_scopes, reason}`. It is a sessionless path, like
invitation application, because refresh happens without a provider session; the actor is the
provider itself, and the subject is a parameter. It ships as an additive contract revision
that an application opts into by naming it in its delegated-access entry; an API with
`user_access: application` whose application has not opted in fails catalog validation. The
deadline is shorter than writes' (two seconds), because it sits on the token endpoint.

**Rejected: the application pushes an eligible-subjects list.** It needs a new authenticated
write endpoint at the provider (runtime state an application credential can change, which the
catalog design avoids), it is stale by its push interval exactly when it matters (right after
a demotion), per-scope answers multiply its size, and it needs reconciliation after missed
pushes. The pull's apparent cost, a dependency on the application at refresh, is not a real
one: when the application is down its API is down too, and the lineage survives the outage.

**Client credentials: deferred.** No relying API has a named machine caller. When one does,
it gets static clients only, scopes marked `machine: true` that are never offered to people,
tokens with `sub` equal to `client_id` and no `auth_time`/`amr`, and routes that opt in to
client principals explicitly. The provider's own `invitations:admit` client credentials
flow is unaffected.

## 4. Consent and grants

**Record.** A new `api_consents` row per (subject, client, API): consented scopes, first and
last granted, last used, revoked. Passport keeps tokens; the consent row is the durable
decision that tokens descend from.

**Flow.** At `/oauth/authorize` the provider resolves `resource` to one resource of one API
(several resources, or none with no `default_resource`, is `invalid_target`), checks
`user_access` (for `application`, the scopes the application allows become the ceiling, and an
ineligible person sees no consent; section 3), applies the scope ceiling, and shows consent unless an unrevoked consent
already covers every requested scope. The screen shows the API's name, its application, the
client's name, the "registered automatically" warning and redirect host for dynamic clients,
and each scope's catalog description, with `sensitive` and `connection` scopes called out.
Consent is all-or-nothing in v1; deselecting individual scopes is rejected because clients
mishandle partially granted scope sets and the result is support load, not safety. (Narrowing
by application eligibility is different: it is policy, applied before the screen, and the
token response's `scope` reports it.)

`first_party_consent_skip` lets a static first-party client of the API's own application skip
consent (today's `skipsAuthorization` rule, narrowed to its own API). Dynamic clients never
skip.

**Account pages.** `/settings/connections` lists, per API, each connected client with scopes,
dates and last use, and offers **Disconnect**. Disconnecting revokes the consent, every
refresh lineage for that subject × client × API, and the access-token rows, and is audited
(`api_consent_revoked`).

**Administration.** Directory administrators can list and revoke a person's connections, and
revoke a dynamic client instance-wide (all its consents and lineages). An API can be switched
off by `AUTH_MANAGER_APIS_DISABLED=<key>,…` in deployment configuration as a kill switch;
that refuses authorization, refresh and introspection for it at once.

**What revocation does to outstanding JWTs.** Nothing directly: they remain valid until
`exp`, at most the API's access-token TTL, because they are validated locally. Refresh fails
immediately. Operations requiring a `sensitive` scope refuse within the status check's
30-second cache.
The account page says so ("may keep working for up to five minutes").

## 5. Personal API tokens

**Recommendation: the provider issues them, per API, opaque, validated by introspection.**

- Created by the signed-in person at `/settings/api-tokens`, choosing an API, scopes from that
  API's personal-token ceiling, and a lifetime from its list. The secret is shown once,
  `Cache-Control: no-store`, with a recognisable prefix (`amp_`) so secret scanners find
  leaks.
- Bound to the API's `personal_tokens.resource`, which must be a resource that `requires`
  no connection scope.
- **Never a connection scope.** Enforced three times: the catalog validator refuses any
  connection scope in the personal-token ceiling or a personal-token resource that requires
  one; the issuer refuses one at creation; the relying guard refuses an introspection result
  for a personal token that carries one or names an MCP resource. There is no opt-in
  (unlike the package's `personal_token_connection_scopes`, which this design retires).
- Validated by introspection with positive caching of at most 60 seconds, because a long-lived
  token must be revocable promptly and cannot carry a meaningful `exp`. This is the one place a
  provider outage affects API calls, and only for personal-token callers.

**Rejected:**

- *No personal tokens* (the hosted-platform model): REST-only connectors that need a static
  key would have no path.
- *Long-lived JWTs*: unrevocable without a revocation list, which is a second distribution
  system.
- *Application-local tokens*: the application would keep Passport and a token table, which is
  the authorization server this design removes.
- *Client credentials per person*: turns every person into a client operator.

## 6. Profiles

**Recommendation: capability comes from the catalog; profiles become defaults.**

- `oauth_server`, DCR and introspection switch on when the catalog has at least one enabled
  API that needs them, instead of being tied to `AUTH_MANAGER_PROFILE=resource`.
- An instance on the `resource` profile **without** a catalog gets a synthesized one-API
  catalog from `AUTH_MANAGER_OAUTH_RESOURCE`: one resource, scopes `mcp:use` and `offers:read`,
  `user_access: open`, its existing introspection client. Its tokens keep today's format until
  the operator replaces the synthesis with an explicit catalog; the move to RFC 9068 tokens is
  then an ordinary release with a reconnect.
- The `bherila` profile without a catalog is unchanged: sign-in only, per-client grants.
- Once no instance relies on the synthesis, the `resource` profile is removed and profiles
  carry only theme and issuer defaults. That closes the question #68 asked.

**Rejected:** a third profile (profiles would multiply with every combination), and boolean
flags per feature (the catalog already says which APIs need what; flags would let the two
disagree).

## 7. Relying-side package (auth-laravel)

One configuration block names the provider and the application's resources:

```php
'provider_api' => [
    'issuer' => env('OAUTH_PROVIDER_ISSUER'),
    'api' => 'records',
    'resources' => [
        'rest' => 'https://records.example.test/api/v1',
        'mcp' => 'https://records.example.test/api/v1/mcp',
        'mcp_alias' => 'https://records.example.test/mcp',
    ],
    'jwks' => ['cache_store' => null, 'max_age' => 600, 'stale_for' => 86400, 'pinned_file' => null],
    'introspection' => ['client_id' => env('PROVIDER_API_CLIENT_ID'), 'client_secret' => env('PROVIDER_API_CLIENT_SECRET')],
],
```

It provides:

- **`provider-api` guard**: validates per section 2, resolves `sub` to the local account
  through the same explicit provider-and-subject binding as sign-in (never by email), and
  applies the application's `CredentialOwnerPolicy`. An unknown subject is refused (403
  `account_not_provisioned`); API calls never provision accounts. Personal tokens take the introspection path by prefix.
- **`ExpectProviderResource:<name>`**: the route's expected audience (one per route).
- **`RequireScopes:<scope>,…`** and a bridge `Principal` adapter whose `hasScope()` reads the
  token, so the capability registry's `Requirement`s enforce scopes unchanged and permissions
  stay the application's.
- **`RequireRecentAuthentication:<seconds>[,acr=<value>][,amr=<m>|<m>…]`** for both
  principals, for example `RequireRecentAuthentication:300,amr=otp|hwk`. It is satisfied when
  `auth_time` is within the given seconds **and**, if given, `acr` satisfies the rung **and**,
  if given, `amr` intersects the set. For a session it checks the claims captured at sign-in
  and, when unsatisfied, redirects through `OAuthClient` with `max_age` and the matching
  `acr_values` (method-class values for an `amr` set), with `SameSubject` on return; for a
  bearer token it answers 401 `insufficient_user_authentication` with `max_age` and
  `acr_values` (RFC 9470). `OAuthClient` gains `prompt`, `max_age` and `acr_values` and checks
  the returned `auth_time`, `acr` and `amr` itself rather than trusting that the provider
  honoured the request.
- **Automatic current-status checks for sensitive scopes.** The scope declarations the
  fragment is generated from (the capability registry's scope catalog, with descriptions and
  `sensitive`) are also what the guard reads. Before an operation runs, if its `Requirement`
  names any `sensitive` scope, the guard checks the token's current status by introspection
  (30-second cache, fail closed) and refuses an inactive token with 401 `invalid_token`. This
  applies to registry operations on every binding (REST and MCP tools) and to `RequireScopes`
  on routes outside the registry, which reads the same declarations. There is no per-route
  list of sensitive operations to keep in step: marking a scope sensitive in the one
  declaration changes consent copy, the provider catalog (through the fragment) and enforcement
  together, and `--check`/`verify` flag a provider catalog whose `sensitive` flags differ.
- **Protected-resource metadata** (RFC 9728) per resource at its path-inserted well-known URL,
  `authorization_servers: [issuer]`, `scopes_supported` from the registry, `resource` exactly
  the identifier.
- **Challenges**: 401 `invalid_token` with `resource_metadata` for the route's own resource
  (from configuration, never the request host); 403 `insufficient_scope` naming the scopes.
- **Catalog tooling**: `bherila-auth:api-catalog` (emit the fragment from the registry and
  resources; `--check` for CI) and `bherila-auth:api-catalog:verify` (compare with the
  provider's published catalog).
- **Testing**: `AssertsProviderApiContract`, with a fake issuer and key set, covering
  discovery, audience isolation between resources, scope ceilings, challenges and step-up.

The in-application authorization-server preset stays in the package during migration and is
deprecated once no application uses it.

## 8. Migration per relying application

Each application migrates on its own schedule. Its existing connectors hold tokens from its
own server for the same resource URLs.

1. **Prepare.** Upgrade the package, generate the fragment, add the API to the instance
   catalog (policy chosen by the operator), release the provider. Nothing changes for users.
2. **Dual-accept.** Enable the `provider-api` guard alongside the application's Passport
   guard. Routing is by header: `typ: at+jwt` with a `kid` goes to provider validation, anything
   else to Passport; each path verifies only with its own keys, so neither can vouch for the
   other's tokens. Verify with a test connector pointed explicitly at the provider.
3. **Flip discovery.** Protected-resource metadata names the provider. The application's
   `/oauth/register` and `/oauth/authorize` close (new connections go to the provider); its
   token endpoint stays open so existing connectors keep refreshing. Users create new personal
   tokens at the provider; existing local ones keep working.
4. **Reconnect.** After notice, revoke the application's own refresh tokens and connection
   tokens. Connectors get 401, rediscover, register at the provider and ask for consent once.
   Remaining local personal tokens are revoked at the end of an announced window (at most their
   connection cap, 30 days, for any that carry a connection scope).
5. **Remove.** In a later release, remove the local authorization server: routes, consent
   view, DCR pruning schedule, Passport guard on API routes, the preset. Keep Passport's tables
   and keys for one further release, then drop them as a separate schema step.

**Rollback.** Before step 4: point the metadata back at the application, reopen its endpoints;
provider tokens stop being issued and expire within five minutes; people who connected through
the provider reconnect. Between steps 4 and 5 the same, but local connections must be
re-authorized because their refresh tokens were revoked. After step 5: redeploy the prior
release; tables and keys were retained, revoked tokens are not revived. Rollback never restores
revoked credentials.

## 9. Threat model

| Threat | Mitigation |
| --- | --- |
| Token for API A used at API B on the same instance | Single `aud`, compared exactly per route; identifiers unique per instance; scope ceilings per resource |
| REST token used at MCP (or alias) | Each is its own audience; the connection scope is required on MCP resources and admissible nowhere else |
| Token from another instance | Pinned issuer and its own JWKS; keys never shared across instances |
| Sign-in token used as an API token | `typ: at+jwt` required; sign-in tokens' `aud` is a client ID |
| Issuer mix-up at a client | RFC 9207 `iss` on authorization responses (enable `authorization_response_issuer` for API flows); the package's existing named-server defences |
| `alg` confusion, key substitution | Algorithm allowlist; keys only from the configured issuer's JWKS; thumbprint `kid` |
| DCR flooding | Throttles, never-used cap and fast pruning; registration creates no consent |
| Application compromise abusing eligibility | Answers can only deny or narrow within the catalog ceiling and the person's consent; never widen. Signed by the provider, pinned endpoint, no redirects |
| Consent phishing (lookalike client names) | Consent text from the reviewed catalog only; dynamic-client warning with redirect host; `user_access: granted` on shared instances; per-API DCR switch; administrators revoke clients instance-wide |
| Authorization-code interception | S256 PKCE for every client; exact redirect match |
| Refresh-token theft | Rotation with lineage revocation on reuse; idle and absolute limits; generation and consent rechecked on refresh |
| Access-token replay | Five-minute TTL; TLS; no sender-constraining in v1 (DPoP is an open question) |
| Personal token leak | Opaque with scannable prefix, revocable within 60 seconds, never a connection scope |
| Signing-key compromise | Blast radius is one instance: every API on it until rotation completes (≤ ten minutes for relying caches) plus outstanding tokens' remaining life. Dedicated instances per product keep this to one product; a shared instance accepts it for its personal applications. Keys are files outside the release tree, never in the database |
| Catalog tampering | Catalog is reviewed configuration in the pinned release; no runtime write path |
| Provider unavailable | Issued tokens keep validating until `exp`; JWKS served stale for 24 hours; new connections, refreshes, personal tokens and sensitive-operation checks fail closed |

Compared with per-application servers, this concentrates risk in the provider (one key set per
instance instead of one per application) in exchange for one hardened implementation of
consent, DCR, refresh and revocation instead of one per application. Permissions stay where they
were: scopes are coarse ceilings; each application still authorizes every operation and target.

## 10. Implementation plan

Each slice is one PR, true on its own, with tests. Provider slices first; the package follows
behind each provider capability.

### auth-manager

| # | Slice | Depends on |
| --- | --- | --- |
| P1 | Catalog schema, validator, loader, `apis:check`, synthesized `resource`-profile catalog, public per-API catalog document. No behaviour change. | — |
| P2 | Authentication context: record `auth_time`/`amr` at every sign-in method, carry on codes/tokens/lineages, add to the identity response, enforce `prompt=login`, `max_age`, `acr_values` (ladder and method-class values, restricting offered methods), advertise them. | — |
| P3 | API key set, JWKS, `jwks_uri`, key commands (generate, activate, retire). | — |
| P4 | RFC 9068 issuance for catalog APIs: resource→API resolution, per-resource ceilings, per-API TTL, authorization-response `iss`. | P1, P3 |
| P5 | Consent store, consent screen from catalog text, `user_access` policy, first-party skip rule. | P4 |
| P6 | Refresh rules: lineage reuse revocation, idle/absolute limits, refusal checks. | P4 |
| P6a | `user_access: application`: eligibility operation on the application-access channel, authorize-time check and no-consent page, refresh-time check with lineage revocation, scope narrowing. | P5, P6 |
| P7 | Account connections page, administrator views, instance-wide client revocation, API kill switch. | P5 |
| P8 | Per-API introspection credentials and `active` rules for API tokens. | P4 |
| P9 | Personal tokens: issuance page, opaque format, introspection path, connection-scope refusals. | P8 |
| P10 | DCR hardening: redirect rules, caps, pruning. | — |
| P11 | Remove the synthesized catalog and the `resource` profile once unused. | migrations |

### auth-laravel

| # | Slice | Depends on |
| --- | --- | --- |
| L1 | `OAuthClient` `prompt`/`max_age`/`acr_values` with returned-claim checks; session capture of `auth_time`/`amr`/`acr`; `RequireRecentAuthentication` (seconds, `acr=`, `amr=` set) for sessions. | P2 |
| L2 | JWKS cache (stale, refetch, pinned file) and RFC 9068 validator. | P3 |
| L3 | `provider-api` guard with dual-accept, resource and scope middleware, challenges, protected-resource metadata, bridge `Principal` adapter, contract test trait. | L2, P4 |
| L4 | Token step-up challenge (RFC 9470) and automatic current-status checks for operations requiring `sensitive` scopes, driven by the registry's scope declarations. | L3, P8 |
| L5 | Personal-token introspection path with connection-scope refusal. | L3, P9 |
| L6 | Catalog fragment generator, `--check`, `verify`. | P1 |
| L6a | Application side of eligibility: an `eligibility` handler on the access adapter, with a conformance test. | P6a |
| L7 | Deprecate, then remove, the in-application server preset. | all migrations |

P1–P3, P10, L1 and L6 can proceed in parallel. The first relying application pilots once P5,
P6 and L3 are released; sign-in step-up (P2 + L1) is useful on its own and can ship first.

## Open questions for the owner

1. **Refresh lifetimes.** Are 30 days idle and 90 days absolute right for API connections, or
   should connectors re-consent more (or less) often?
2. **Shared-instance eligibility.** Is "holds a grant to the application's sign-in client" the
   right rule for `user_access: granted`, or should API access be a separate grant?
3. **First-party consent skip.** Allow it for an application's own static client on its own
   API, or always show consent?
4. **Personal tokens.** Is an introspection dependency (60-second cache) acceptable for
   personal-token callers? Maximum lifetime: 90 or 365 days?
5. **Machine-to-machine.** Is there a named service caller that would justify client
   credentials for relying APIs now?
6. **Passkey `amr`.** Report synced passkeys as `hwk`, or distinguish device-bound from synced
   (`swk`) where the authenticator data allows?
7. **MCP aliases.** Keep alias resources for new connections, or register only one MCP
   resource per API and keep aliases solely for migration?
8. **Sender-constrained tokens.** Is DPoP worth planning for once major MCP clients support
   it?
9. **Key blast radius on the shared instance.** Accept one key set across its personal
   applications, or give each API its own signing key (more keys to rotate, smaller blast
   radius)?

## Appendix: sign-in layer gaps (out of scope; roadmap)

Found while inventorying what a dedicated product instance needs before its applications can
drop their own login code. None is designed here.

1. **Second factor after a password.** The emailed code is only a primary sign-in method; it
   cannot be required after a password. Needed for `acr:mfa`. The shared relying-side
   package's local-credential login already implements password followed by an emailed code
   (its two-factor challenge service and routes), so the provider should reuse that code
   rather than write the flow afresh.
2. **Forced fresh sign-in.** Covered by section 2 (`auth_time`, `amr`, `acr`, `prompt=login`,
   `max_age`, `acr_values`).
3. **Self-service account lifecycle.** Password reset, registration, email verification and
   email change are administrator-mediated or absent.
4. **New-device and sign-in location alerts, trusted devices.** Not present.
5. **Passkey portability.** Passkeys stay bound to their RP ID, so moving people to another
   instance or domain means re-enrolment (by design; see `AGENTS.md`).
6. **Branding depth.** Branding is logos and CSS. Application-specific onboarding journeys stay
   in the applications.
7. **Per-application branding and mail identity.** An instance serving several applications
   shows one brand on its sign-in pages and sends sign-in codes from one sender, whichever
   application the person came from.
8. **Anonymous or bearer admission.** Invitations are per email address with a per-inviter
   rate limit, so a shareable "join" link or QR code (for example, for an event-style
   application) cannot be expressed with them.
