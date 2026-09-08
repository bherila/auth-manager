# Account management and registered applications

Implementation contract for #29, #30, #33, #34 and #35. This record specifies the
target behavior; it is not a claim that every endpoint or consumer is deployed.
The rollout checklist below distinguishes independently shippable foundations
from the remaining integration work.

## Ownership

| Control | Authority | Central UI |
| --- | --- | --- |
| Identity name, email, verified-email state | Provider directory | Provider administrator edits; self-service displays read-only |
| Password, passkeys, recovery, provider disable/delete | Provider | Account/security hub and provider administration |
| Static OAuth client grant | Provider | Coarse permission to authorize a client, not an application role |
| Application administrator, workspace membership, read/write access | Application | Delegated controls backed by application authorization APIs |
| Application approval, invitations, onboarding, legal acceptance | Application | Existing application journeys |
| Notification settings and other domain preferences | Application | Existing application settings |
| Local display alias | Application | Explicit projection or separate nickname, chosen per consumer |

A provider administrator does not acquire application administration. An
application administrator does not acquire provider directory access. A user can
hold either, both, or neither role. Provider account inactivity and application
account inactivity are independent denials; neither side can override the other.

Bindings use the configured issuer/provider namespace and opaque provider
subject. Email is mutable display/contact data, never an automatic account-link
key. A consumer records whether its alias projects the provider name or is an
independent nickname. It defines normalization, maximum length and collision
handling explicitly; it must not silently truncate an identity or overwrite a
user-selected nickname. The provider name limit remains 255 characters.

## Account and recovery scope

The account hub owns password changes and passkey management. Password changes
require the current password, confirmation, an active account rechecked under a
lock, and the existing minimum length. They advance the credential generation,
revoke OAuth credentials and invalidate existing sessions. Passkey ceremonies
retain the existing recent-authentication and WebAuthn checks.

Recovery initially uses the existing emailed sign-in code and administrator
password reset. Self-service email changes, self-deletion and new recovery
factors are not implied by the account hub. A failed or throttled email-code
request must not reveal whether an email belongs to an active account.

Bound consumers link to provider credential controls and reject local credential
mutations. Keep a tested, explicitly designated, unbound local emergency
administrator before restricting local sign-in. Passkey credentials remain at
their original RP ID; migration never copies or rebinds them.

## Instance-local application registry

Each deployment has its own directory, registry, client credentials and keys.
Instances do not discover or merge each other's applications. Examples in this
repository use fictional applications and deployment addresses only.

Provider administrators manage a stable application key, display name, launch
URL, enabled state and explicit static OAuth-client mappings. The key survives
renames. An OAuth client belongs to at most one registered application; an
application may have multiple clients. Revoked or dynamically registered
clients cannot supply trusted integration metadata or become mapped clients.
Dynamic registration and consent remain separate OAuth behavior.

An enabled application appears in a user's launcher only when the user has an
existing grant to an eligible mapped client. Registration does not provision an
application account or grant a domain role. Legacy static-client navigation may
remain behind the default rollout mode until administrators populate and verify
the registry. It must never create trusted API registrations implicitly.

Launch URLs require HTTPS outside explicit local/test exceptions. Reject user
info, fragments, malformed hosts and unsafe schemes. Browser input can select a
registered app key, not an arbitrary return URL. The server resolves that key
against the current user's visible applications. Do not accept protocol-relative
destinations or reflect unvalidated callback parameters.

The delegated API destination and signing-key references are deployment-owned
configuration keyed by registered application. Display-name, redirect-URI and
dynamic-client metadata never select a backchannel destination. An administrator
editing the launcher does not gain an arbitrary server-side URL fetch primitive.
The UI displays integration availability without exposing key material.

## Delegated application access

### Existing capabilities and selected actor proof

The shared OAuth client currently establishes a browser session from an
authorization code and identity response. Its token introspector authenticates
OAuth resource requests. Neither provides a token exchange or an app-audience
credential for an administrator acting from the provider's browser session.
The reconciliation API authenticates confidential clients in the opposite
direction and does not prove a human actor. Reusing its password as a general
administrative bypass is therefore inappropriate.

For this integration, use a short-lived signed actor assertion from the provider
to a configured application endpoint. Use the existing JOSE library, RS256 with
a dedicated integration signing key, and a fixed assertion type
`application-access+jwt`. Do not reuse OAuth signing keys or accept an OAuth
access token in this lane. The consumer pins the trusted issuer, key identifiers
and corresponding public keys through deployment configuration; it never fetches
keys from assertion-supplied URLs.

The assertion binds `iss`, `sub` (the session's actor), `aud` (the exact configured
endpoint), `iat`, `exp`, random `jti`, application key, HTTP method and SHA-256 of
the exact request-body bytes. Lifetime is at most 60 seconds with at most five
seconds of clock skew. Accept only the configured algorithm and assertion type.
Reject invalid, future, expired, cross-app or modified requests. Atomically
consume the issuer/app-scoped nonce until expiry; unavailable replay storage
fails closed. These are application-specific constraints on signed JWTs, using
the validation guidance in [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725)
and claim definitions in [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519).

The provider checks active session, current credential generation, CSRF and
current mapped-client grant before each request. A write also requires recent
credential confirmation within five minutes. Actor subject is taken exclusively
from the authenticated session, never the posted target or browser claims.
Assertions stay server-side and are never written to logs or browser state.

The application independently resolves the actor's issuer/subject binding and
current account status, then applies its existing administration/workspace
policy. A valid signature proves who initiated the request, not permission to
perform it. Every target and workspace is resolved inside that application's
authorized scope, including last-administrator protections. Both read and write
operations enforce this policy. Provider-only administrators receive a denial.

### Versioned request and response

Use a fixed configured HTTPS endpoint with POST JSON operations `capabilities`,
`subjects`, `read` and `update`. Do not follow redirects. Set connection/read
timeouts and cap request/response size. Subject queries use opaque cursors and a
maximum page size of 50; cursors are application- and actor-scoped. There is no
provider-directory browsing fallback for application administrators.

An illustrative update body (signed as exact UTF-8 bytes):

```json
{
  "contract_version": 1,
  "operation": "update",
  "application": "example-app",
  "subject": "subject-example",
  "expected_revision": "revision-example",
  "access": {
    "application_admin": false,
    "workspaces": [{"id": "workspace-example", "permission": "read"}]
  }
}
```

The capabilities response declares the supported controls and allowed values;
it is data, not executable UI or HTML. A read returns `provisioned`, an opaque
`revision`, current access and allowed edits for this actor. An unprovisioned
subject is explicit and read-only; adding a client grant does not create it.
Unsupported fields and permissions are rejected rather than ignored.

An update locks/rechecks current actor authority, target and revision, applies
the complete requested change atomically, and returns canonical state with a
new revision. A stale revision returns 409 and no changes. Unauthorized access
returns 403 or the application's established non-disclosing 404. Invalid input
returns 422. A successful transport response with a malformed contract is an
integration failure, never success.

Do not automatically retry writes. A timeout may follow a committed write: show
an unknown outcome and require a fresh read before resubmission. A fresh signed
read can be retried with a new nonce. Display offline applications as unavailable;
cached responses must not appear to be current authority. Each side records
actor, target, application, operation, outcome and correlation identifier;
application audit entries commit with the authorization change. Do not log
assertions, secrets or unrelated directory/domain data.

## Identity and session lifecycle

The login identity response adds `credential_version`. The shared consumer
client validates and preserves it as the session's immutable login generation.
An authenticated status read must never silently replace that baseline with a
newer generation and thereby extend an old session.

`POST /api/reconciliation/identity-status` accepts one bounded `subject` and
authenticates a static confidential client using the existing client credential
validation. The client needs a current explicit grant to that active subject.
Unknown, ungranted, disabled and deleted subjects all return the same minimal
`{"contract_version":1,"active":false}` response. Revoked, dynamic or invalid
clients are rejected. An active response has this shape:

```json
{
  "contract_version": 1,
  "active": true,
  "subject": "subject-example",
  "credential_version": 7,
  "name": "Example User",
  "email": "user@example.test"
}
```

Responses are non-cacheable by intermediaries. Consumers retain the successful
check time privately in the authenticated session. Protected requests recheck
at least every five minutes; privileged writes require a fresh status check.
Inactive status or a generation mismatch invalidates the bound local session.
Valid responses refresh name/email projections according to the consumer's
explicit alias mapping. Existing local authorization checks still run.

Network failures, invalid credentials and malformed responses do not mean
"active". Once the freshness window expires, return a retryable unavailable
response and refuse protected work until verification succeeds. Preserve the
session for retry during an outage; do not turn an outage into a local login
bypass. Consumers without generation support cannot claim this lifecycle
guarantee and must not enable the cutover flag.

Deletion uses the existing tombstone feed and acknowledgement protocol in
[identity-deletion.md](identity-deletion.md). Acknowledge only after the
application's local transaction commits. Provider purge, application
acknowledgement and browser-session enforcement are distinct signals. The
lifecycle dashboard must not equate one with the others. Domain retention stays
application-owned.

## Delivery and evidence

1. Ship provider profile editing, the account hub and lifecycle visibility as
   independent additive changes. These do not require deleting consumer UI.
2. Populate each instance's registry, verify grant-scoped launch links and enable
   the registry launcher switch. Reuse existing directory/client-grant services
   from #4 and tombstone reconciliation from #5.
3. Ship status responses and shared-client generation/freshness handling. The
   callback/binding extraction in `auth-laravel` #37 remains reusable work; this
   contract does not create a competing account-link mechanism.
4. Implement the signed delegated transport and a synthetic reference adapter.
   Prove algorithm/type/audience/body/nonce failures, provider-admin-only denial,
   app-admin-only visibility, workspace isolation, stale writes, revoked actors,
   timeout ambiguity and offline-state behavior before enabling real writes.
5. Migrate consumers in their own repositories. Inventory branded login helpers,
   invitation/claim/signup contexts, approval gates, intended URLs, device trust,
   scanner-safe email links, reset/session revocation and local emergency access.
   Add provider sign-in to an existing specialized shell until parity is proven.
   Separate identity controls from preferences and domain authorization.
6. Verify each dedicated instance's directory/database, issuer, registry, client
   credentials, RP ID, callback configuration and recovery path independently.
   Missing deployment hostnames and credentials block provisioning, not generic
   implementation. Do not publish private deployment assignments in this repo.

Run consumer parity tests against the current default branch, not an older local
checkout. Capture exact deployed revisions and read back login, lifecycle and
authorization behavior before removing duplicate controls. Keep feature switches
off when prerequisites fail. Rollback restores the previous UI while preserving
subject bindings and continuing to reject unauthorized credential mutations.
