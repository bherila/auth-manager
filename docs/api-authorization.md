# API authorization: the provider as authorization server for application APIs

**Status: Approved in principle (owner, 2026-10-27), pending independent review.** Nothing
here is implemented. This replaces the direction of #68
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
  "source": { "kind": "operator" },
  "apis": {
    "records": {
      "application": "records",
      "name": "Records",
      "enabled": true,
      "resources": {
        "rest":      { "identifier": "https://records.example.test/api/v1",     "scopes": ["records:read", "records:write"] },
        "mcp":       { "identifier": "https://records.example.test/api/v1/mcp", "scopes": ["mcp:use", "records:read", "records:write"], "requires": ["mcp:use"] },
        "mcp_alias": { "identifier": "https://records.example.test/mcp",        "scopes_from": "mcp", "alias_until": "2027-01-31" }
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
        "first_party_consent_skip": true,
        "access_token_ttl": "PT5M",
        "refresh_idle": "P30D",
        "refresh_absolute": "P90D",
        "personal_tokens": { "enabled": true, "resource": "rest", "lifetimes": ["P30D", "P90D"] }
      },
      "fragment": { "sha256": "…", "generated_from": "records@<commit>" }
    }
  }
}
```

Validation rules. One validator runs in two modes: **release-time** (`apis:check`, run by the
release before activation; every rule) and **runtime load** (structural rules only; never a rule
that depends on the date or on state outside the file). At runtime an invalid API entry
disables that API only, and two entries that conflict (for example over an identifier) disable
both; the rest of the catalog and sign-in keep working. Only a file that cannot be read or
parsed at all disables API authorization for the instance.

- API keys and resource names are registry-style lowercase keys. `application` must be an
  instance registry key (checked when the registry is readable; the file alone is still
  validated structurally).
- Every resource `identifier` is an absolute HTTPS URL by the existing
  `validatedAbsoluteUrl()` rules, canonicalized, and **unique across the whole instance**.
  None may equal the issuer or sit under the issuer's own paths.
- An alias resource (`scopes_from`) exists only for a migration window and must carry
  `alias_until`. The provider never issues tokens for an alias: an authorization naming one is
  refused with `invalid_target`. During the window the application's alias route answers a
  request without a token with a permanent redirect (308, so `POST` survives) to the primary
  endpoint, before any challenge, so new connections discover the primary resource; and it
  accepts tokens for the primary identifier as well as the application's own legacy
  alias-bound tokens (dual-accept, section 8). If a client fetches the alias's
  protected-resource document anyway, it names the alias identifier, because RFC 9728 §3.3
  requires the document's `resource` to match the URL it was reached from. After
  `alias_until` the alias simply stops being accepted; the runtime never refuses a catalog
  for a date. `apis:check` fails a catalog with an expired alias, so the next release removes
  it.
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
  at most `P365D`, personal tokens at most `P90D`.

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
     workflow, and the workflow assembles the catalog for the release it builds. This source is
     valid **only for an instance that serves exactly that one application**: the catalog
     declares `"source": {"kind": "application", "application": "<key>"}`, and the validator
     refuses it if any API belongs to another application. Its policy values are bounded by
     ceilings compiled into the provider release (the duration ceilings above, the allowed
     `user_access` values, the DCR limits), which the catalog cannot raise; the instance
     environment may tighten them further.

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
4. `php artisan auth-manager:apis:check` validates the file in release-time mode and is run
   by the release before activation. At runtime the load rules above apply: a disabled API is
   refused at the authorization endpoint with `temporarily_unavailable` and at the token and
   introspection endpoints with HTTP 503 and `Retry-After`, reported once without the value.
   Sign-in keeps working. This mirrors the delegated-access map.

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
  without new dependencies. **One key set per instance**, shared by its APIs: tokens carry a
  single exact audience, so a per-API key would add rotation work without separating anything
  the audience check does not already separate. HS256 is rejected outright (every API would hold a minting
  secret). ES256/EdDSA are acceptable later; the relying validator pins an algorithm
  allowlist per issuer so a change is an explicit configuration step.
- **`kid` is the RFC 7638 thumbprint**, so a key cannot be republished under another
  identity.
- **Rotation** by command, never automatic: `apis:keys:generate` (publish as *next*; not
  signing), `apis:keys:activate` after at least the relying JWKS cache maximum plus margin
  (one hour), `apis:keys:retire` once the previous key has signed nothing for longer than the
  maximum access-token TTL. Scheduled cadence: every six months. **Emergency rotation**
  removes the compromised key from JWKS at once and activates the next one; the refresh path
  keeps working, so connectors recover silently on their next refresh. A relying application
  that can reach the provider stops accepting the removed key within its cache age (ten
  minutes). One that cannot (an outage, or an attacker blocking it) keeps the last fetched key
  set for the stale window (six hours), so the compromised `kid` is also added to the relying
  deployment's `revoked_kids` denylist, which applies to cached and stale keys alike and
  takes effect with a configuration deploy.

### Relying-side validation and JWKS caching

A token is accepted only if all of these hold: `typ` is `at+jwt` or `application/at+jwt`,
compared case-insensitively (RFC 9068 §4); `alg` is in the pinned
allowlist; `kid` is in the cached JWKS for the configured issuer; the signature verifies;
`iss` equals the configured issuer byte for byte; `aud` equals the identifier of the resource
the route expects (not merely any resource of the application); `exp`/`nbf` hold with at most
60 seconds of leeway; `client_id`, `sub` and `scope` are present.

JWKS cache: honour `Cache-Control` capped at ten minutes; on an unknown `kid`, refetch at most
once per minute; if the provider is unreachable, keep serving the key set from the last
successful fetch, and only that, for up to six hours (keys only; tokens still expire). No key
is ever accepted from a response that failed validation, and a `kid` in the deployment's
`revoked_kids` list is refused whatever the cache holds. Applications that cannot make outbound calls may
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
| Device-bound passkey (authenticator data's backup-eligible flag clear) | `hwk`, plus `user` when the authenticator reported user verification |
| Synced passkey (backup-eligible flag set) | `swk`, plus `user` when the authenticator reported user verification |
| Password then a second factor (roadmap) | `pwd`, the factor's value, `mfa` |

**`acr`.** A small instance vocabulary, ordered:

| `acr` | Satisfied by |
| --- | --- |
| `urn:auth-manager:acr:single` | Any one method |
| `urn:auth-manager:acr:phishing-resistant` | A passkey (synced or device-bound) with user verification |
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
| `urn:auth-manager:amr:hwk` | Device-bound passkey |
| `urn:auth-manager:amr:swk` | Synced passkey |

Several entries mean any of them (`acr_values` is a preference list); "any passkey" is
`amr:hwk amr:swk`. The returned `acr` names
the entry satisfied, and `amr` lists what was actually used.

**Requests the provider enforces** on `/oauth/authorize`, for sign-in and API clients alike:

- `prompt=login`: always re-authenticate before issuing a code.
- `max_age=N`: re-authenticate if the session's `auth_time` is older than N seconds
  (`max_age=0` behaves like `prompt=login`).
- `acr_values`: re-authenticate with a method that satisfies one of the values, offering only
  those methods on the sign-in screen (a request for `amr:otp amr:hwk amr:swk` shows no
  password form); refuse with `access_denied`/`unmet_authentication_requirements` when the person has no
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
- Redirect URIs: exact HTTPS URLs, or RFC 8252 loopback (`http://127.0.0.1`, `http://[::1]`)
  for native clients, matched **without regard to port** as RFC 8252 §7.3 requires. No
  wildcards, fragments, user information or private-use schemes in v1.
- Abuse limits: per-IP registration throttle (10 per hour) and an instance-wide cap on unbound
  registrations (default 500). When the cap is full, unbound registrations older than 15
  minutes are pruned first; if none are, new registrations get 429 with `Retry-After`, so a
  flood cannot evict registrations people are in the middle of using. Per-person limits
  follow below.
- A registration is not consent and is not bound to an API. Every authorization names a
  resource, and consent is per API (section 4).
- **A dynamic client never receives a sign-in token.** An authorization from a dynamic client
  that asks for `identity:read`, or for any scope outside an API, is refused with
  `invalid_scope`; one that names no `resource` is refused with `invalid_target`, unless the
  instance names one `omitted_resource_api` for clients that never send `resource`, in which
  case it binds to that API's `default_resource` and its ceiling. It is never left unbound. This
  holds on every profile, including the per-user-grant one, and has its own tests there.
- Each API can switch DCR off (`dynamic_registration: false`); DCR is available on the
  instance while at least one enabled API allows it.

### User-scoped dynamic registrations

Popular MCP clients register a new client for every person who connects them, so an instance
would otherwise collect many near-identical registrations with the same name, each used by one
person, which nobody can review. A dynamic registration is therefore **owned by the first
person who completes an authorization with it**:

- **Unbound at registration.** `POST /oauth/register` is anonymous, so a new registration has
  no owner. An unbound registration expires 24 hours after registration and is
  garbage-collected hourly, with any codes issued to it.
- **Bound at the first successful code exchange**, not at consent: when a token request
  presents an authorization code *and* a PKCE verifier that matches it, the provider sets the
  owner in the same transaction that consumes the code, with a conditional update that sets
  the owner only while it is still empty and then re-reads it. A different stored owner fails
  the exchange with `invalid_grant`.
- **Only the owner afterwards.** Authorization by anyone else is refused before consent, with a
  provider page saying the connection belongs to another account and the client should
  connect again, and `error=access_denied` to the client.
- **Other people's pending consents are removed.** Consent is recorded when a person approves,
  before the code exchange. When the owner is set, consents other people gave the same
  registration are deleted with their unexchanged codes, so only the owner's remains.
- **Per-person caps:** at most 25 bound dynamic registrations per person per instance. Binding
  a further one is refused with a page linking to the connections list; nothing is revoked
  silently.
- **Fingerprints group; they never merge.** A registration's fingerprint is its `software_id`
  when present, otherwise its normalized `client_name`, plus its sorted redirect URIs (loopback
  ports excluded) and token-endpoint auth method. Hosted clients register one client per server
  they connect, with identical metadata, so one person legitimately owns several registrations
  with one fingerprint (for example one per API). The fingerprint is therefore used only to
  group the connections page, aggregate administrator views, count per-person caps and apply
  the denylist. Binding never deletes, revokes or folds another registration, and consent never
  moves between clients.
- **Clean-up of idle duplicates:** a registration a person owns that has had no live lineage
  for 7 days, while they own another with the same fingerprint that has one, is deleted and
  audited (`dynamic_client_pruned`). Any bound registration with no live lineage for 30 days is
  deleted the same way. Returning an existing `client_id` at registration is rejected:
  anonymous callers would then share one unbound registration, and the first to bind would
  take it from the others.

**Why binding cannot be used to steal tokens.** Binding needs a valid authorization code
delivered to one of the registration's redirect URIs (fixed at registration) and the PKCE
verifier that started that authorization, and every token issued afterwards goes only to its
owner's authorizations. For an HTTPS redirect, someone who learns another person's freshly
registered `client_id` and authorizes with their own account gets a code sent to an endpoint
they do not control, so they cannot exchange it or bind. For a loopback redirect, anyone who
learns the `client_id` can receive a code on their own machine, so they could bind an unbound
registration first. That denies the victim this registration (their client is refused and
registers again) but yields the binder only tokens for their own account, never the
victim's. Binding adds no new consent-phishing path: a malicious registration that a victim
authorizes binds to the victim, exactly as its tokens already would.

**Compatibility risk.** A client that shares one registration across several people (for
example a connector registered once for a whole organization) works for the first person and
is refused for the rest. Verify the major MCP clients register per person before enabling
binding on an instance; until then an API can set `dynamic_registration_binding: none`, which
keeps today's unowned registrations with the instance-wide limits.

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

`first_party_consent_skip` lets the API's own application's first-party static client skip
consent for that API only (today's `skipsAuthorization` rule, narrowed to its own API). No
other client skips, on that API or any other, and dynamic clients never skip.

**Account pages.** `/settings/connections` groups a person's connections by client name, then
API, with scopes, dates and last use, and offers **Disconnect**. Disconnecting revokes the
consent, every refresh lineage for that subject × client × API, and the access-token rows, and
is audited (`api_consent_revoked`). For a dynamic registration the person owns, disconnecting
its last API also deletes the registration, so the client's next refresh gets `invalid_client`
and it registers again if the person reconnects. Access tokens already issued remain valid
until `exp` (at most five minutes); operations requiring a `sensitive` scope refuse within the
status check's cache.

**Administration.** Directory administrators see dynamic registrations as aggregates, not
rows: per fingerprint (`software_id` or client name), the number of bound registrations,
people with live connections, unbound registrations pending expiry, and registrations in the
last day. From an aggregate they can drill into one person's connections, revoke everything
under a fingerprint, or add it to a deployment-configured denylist that refuses its future
registrations. They can also list and revoke a person's connections. An API can be switched
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
  `user_access: open`, its existing introspection client. It keeps today's token format and is
  **excluded from RFC 9068 issuance**, JWKS publication, consent records and the other
  per-API features until the operator replaces it with an explicit catalog; the move to RFC 9068
  tokens is then an ordinary release with a reconnect.
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
    'cache_store' => env('PROVIDER_API_CACHE_STORE', 'redis'),
    'jwks' => ['max_age' => 600, 'stale_for' => 21600, 'pinned_file' => null, 'revoked_kids' => []],
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
  principals, for example `RequireRecentAuthentication:300,amr=otp|hwk|swk`
  (email or any passkey). It is satisfied when
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

### Caches on both sides

Every short-lived authorization cache in this design uses one configurable Laravel cache
store, and that store must be **Redis**. The typical deployment is a per-host Redis reached
over a Unix socket.

| Side | Cache | Lifetime |
| --- | --- | --- |
| Relying | Personal-token introspection results | 60 seconds |
| Relying | Current-status checks for operations requiring a `sensitive` scope | 30 seconds |
| Relying | JWKS (key set from the last successful fetch, also held in process memory) | 10 minutes, served stale up to 6 hours |
| Provider | Application eligibility answers (allow only) | 60 seconds |
| Provider | Short lookups whose source is the provider's own database | Up to 60 seconds |

Pending authorization state and rate limiters are not caches of an authoritative source and
are outside this section; they keep their existing stores.

Rules:

- **An unavailable store is a cache miss, not a deny.** If Redis cannot be read, the check goes
  to its authoritative source and proceeds normally if that source answers: provider
  introspection or the status endpoint for personal tokens and sensitive scopes, the
  application's eligibility callback, the provider's own database for provider-side lookups,
  and the in-process copy and then the provider's JWKS endpoint for keys. A request is denied
  only when the authoritative source itself cannot answer, under the fail-closed rules already
  given for it (an introspection or eligibility timeout, error or malformed answer). A cache
  failure never turns into an allow on its own, because nothing is ever allowed from the cache
  without a stored answer from the source.
- **Writes are best effort.** Storing an answer may fail silently (logged at most once per
  interval, without the key); it never fails the request that produced the answer.
- **Namespaced keys.** Keys are `<prefix>:<sha256(issuer)>:<api>:<kind>:<sha256(subject…)>`,
  so instances and APIs sharing one Redis never read each other's entries. A token is never a
  key or a value; only its hash is used. Values hold the decision and its expiry, nothing
  secret.
- **Eviction is safe.** Losing an entry only causes a recheck, so use an evicting memory policy
  for these keys (a separate Redis database or instance from anything that needs
  no-eviction). Under a no-eviction policy a full store rejects every write, which is harmless
  here but turns every check into an uncached one.
- **An outage moves load to the sources.** While Redis is down every check is uncached: each
  personal-token call and each operation requiring a `sensitive` scope introspects, and each
  refresh under `user_access: application` calls the application. The provider bounds this
  with a rate limit per API introspection credential (and per application for eligibility
  calls), kept in a limiter store that is not the cache store, so the bound holds during the
  outage. Calls beyond it get 429, which the relying side treats as a source that cannot
  answer: sensitive operations and personal-token calls on a busy API are then refused until
  Redis returns, while ordinary JWT-validated calls are unaffected.
- **The `database` and `file` cache stores are not configured for these caches**; the
  configuration checks on both sides refuse them (`array` only in tests). An identical re-put of an existing row
  is reported as a failed write by an engine that counts changed rather than matched rows, and
  that failure mode has caused sign-in outages before.

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
| REST token used at MCP (or alias) | Each is its own audience; the connection scope is required on MCP resources and admissible nowhere else. An alias route accepts its primary MCP identifier only during its window, and the provider never issues for an alias |
| Token from another instance | Pinned issuer and its own JWKS; keys never shared across instances |
| Sign-in token used as an API token | `typ: at+jwt` required; sign-in tokens' `aud` is a client ID |
| Issuer mix-up at a client | RFC 9207 `iss` on authorization responses (enable `authorization_response_issuer` for API flows); the package's existing named-server defences |
| `alg` confusion, key substitution | Algorithm allowlist; keys only from the configured issuer's JWKS; thumbprint `kid` |
| DCR flooding | Throttles, an unbound cap with 24-hour expiry that prunes only entries older than 15 minutes and otherwise answers 429, per-person caps and idle-duplicate clean-up; registration creates no consent |
| Binding someone else's registration | Binding only at a code exchange that presents a code sent to the registration's own redirect URI and its PKCE verifier; conditional set-once owner; owner-only authorization afterwards. A loopback registration can be bound first by someone who learns its `client_id`: denial of that registration only, never token theft |
| A dynamic client obtaining a sign-in token | `identity:read` refused to dynamic clients; no `resource` refused unless one omitted-resource API is configured; never an unbound token |
| Application compromise abusing eligibility | Answers can only deny or narrow within the catalog ceiling and the person's consent; never widen. Signed by the provider, pinned endpoint, no redirects |
| Consent phishing (lookalike client names) | Consent text from the reviewed catalog only; dynamic-client warning with redirect host; `user_access: granted` on shared instances; per-API DCR switch; administrators revoke clients instance-wide |
| Authorization-code interception | S256 PKCE for every client; exact redirect match |
| Refresh-token theft | Rotation with lineage revocation on reuse; idle and absolute limits; generation and consent rechecked on refresh |
| Access-token replay | Five-minute TTL; TLS. DPoP (RFC 9449) is planned and built once major MCP clients support it; the token format reserves `cnf.jkt` and the relying validator will require a proof for tokens that carry it |
| Personal token leak | Opaque with scannable prefix, revocable within 60 seconds, never a connection scope |
| Signing-key compromise | Blast radius is one instance: every API on it. Forged tokens stop being accepted within ten minutes at relying applications that can reach the provider; one that cannot keeps the old key set for up to six hours unless its `revoked_kids` denylist is deployed, which takes effect immediately. Dedicated instances per product keep this to one product; a shared instance accepts it for its personal applications. Keys are files outside the release tree, never in the database |
| Catalog tampering | Catalog is reviewed configuration in the pinned release; no runtime write path |
| Provider unavailable | Issued tokens keep validating until `exp`; JWKS served stale for up to six hours; new connections, refreshes, personal tokens and sensitive-operation checks fail closed |

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
| P1 | Catalog schema, validator (release-time and runtime modes, per-API disablement), loader, `apis:check`, source kinds and policy ceilings, synthesized `resource`-profile catalog kept on the legacy format, public per-API catalog document. No behaviour change. | — |
| P2 | Authentication context: record `auth_time`/`amr` at every sign-in method, carry on codes/tokens/lineages, add to the identity response, enforce `prompt=login`, `max_age`, `acr_values` (ladder and method-class values, restricting offered methods), advertise them. | — |
| P3 | API key set, JWKS, `jwks_uri`, key commands (generate, activate, retire). | — |
| P4 | RFC 9068 issuance for catalog APIs: resource→API resolution, per-resource ceilings, per-API TTL, authorization-response `iss`. | P1, P3 |
| P5 | Consent store, consent screen from catalog text, `user_access` policy, first-party skip rule. | P4 |
| P6 | Refresh rules: lineage reuse revocation, idle/absolute limits, refusal checks. Includes an explicit **lineage cutover** step: refresh tokens issued before lineages are recorded for an API are either assigned a lineage at their next refresh (with the credential generation and authentication context they already carry) or retired, chosen and tested before any lineage-dependent revocation is relied on. | P4 |
| P6a | `user_access: application`: eligibility operation on the application-access channel, authorize-time check and no-consent page, refresh-time check with lineage revocation, scope narrowing. | P5, P6 |
| P7 | Account connections page, administrator views, instance-wide client revocation, API kill switch. | P5 |
| P8 | Per-API introspection credentials and `active` rules for API tokens. | P4 |
| P9 | Personal tokens: issuance page, opaque format, introspection path, connection-scope refusals. | P8 |
| P10 | DCR hardening: redirect rules, caps, pruning. | — |
| P10a | User-scoped registrations: set-once owner at code exchange, removal of non-owner consents, owner-only authorization, per-person caps, fingerprint grouping and idle-duplicate clean-up, grouped connections page, administrator aggregates and denylist; tests that a dynamic client never receives a sign-in token on either profile. | P5, P10 |
| P11 | Remove the synthesized catalog and the `resource` profile once unused. | migrations |

### auth-laravel

| # | Slice | Depends on |
| --- | --- | --- |
| L1 | `OAuthClient` `prompt`/`max_age`/`acr_values` with returned-claim checks; session capture of `auth_time`/`amr`/`acr`; `RequireRecentAuthentication` (seconds, `acr=`, `amr=` set) for sessions. | P2 |
| L2 | JWKS cache (last-fetch-only stale window, refetch, pinned file, `revoked_kids`) and RFC 9068 validator (`typ` in both spellings). | P3 |
| L3 | `provider-api` guard with dual-accept, resource and scope middleware, challenges, protected-resource metadata, bridge `Principal` adapter, contract test trait. | L2, P4 |
| L4 | Token step-up challenge (RFC 9470) and automatic current-status checks for operations requiring `sensitive` scopes, driven by the registry's scope declarations. | L3, P8 |
| L5 | Personal-token introspection path with connection-scope refusal. | L3, P9 |
| L6 | Catalog fragment generator, `--check`, `verify`. | P1 |
| L6a | Application side of eligibility: an `eligibility` handler on the access adapter, with a conformance test. | P6a |
| L7 | Deprecate, then remove, the in-application server preset. | all migrations |

P1–P3, P10, L1 and L6 can proceed in parallel. The first relying application pilots once P5,
P6 and L3 are released; sign-in step-up (P2 + L1) is useful on its own and can ship first.

## Decisions (owner, 2026-10-27)

The questions this proposal left open are decided; the sections above reflect them.

1. **Agent connection refresh:** 30 days idle, 90 days absolute.
2. **Shared-instance eligibility:** holding a grant to the application's sign-in client is
   enough to use its API (`user_access: granted`); there is no separate API grant. Where an API
   uses `user_access: application`, the application's answer governs instead.
3. **First-party consent skip:** an application's own first-party client may skip consent for
   its own API, and only that client.
4. **Personal tokens:** calls may depend on the provider through the short introspection cache;
   the maximum personal-token lifetime is 90 days.
5. **Client credentials:** not now (no named machine caller); deferred as described in section 3.
6. **Passkey `amr`:** synced passkeys are reported as `swk`, device-bound ones as `hwk`.
7. **Unknown subjects:** refused with `account_not_provisioned`; API calls never provision.
8. **MCP aliases:** alias resources exist only during migration windows, never for new
   connections.
9. **DPoP:** planned; built when major MCP clients support it.
10. **Signing keys:** one key set per instance; single-audience tokens make per-API keys mostly
    rotation overhead.

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
