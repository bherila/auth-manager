# Delegated application access transport

This is the disabled-by-default transport foundation for application-owned access management. It adds no browser route or live consumer endpoint. The synthetic reference adapter in `tests/Fixtures/ReferenceAccessAdapter.php` demonstrates the contract; it is not a production authorization model.

`App\Services\DelegatedAccess\DelegatedAccessTransport::send(Request $request, string $applicationKey, array $operation): array` obtains the actor from an active provider session, checks its credential generation, and requires an enabled registry application plus a current grant to a mapped static OAuth client. Provider administration never grants application administration. Browser controllers must enforce CSRF before calling this service.

Operations are `capabilities`, `subjects`, `workspaces`, `read`, and `update`. Discovery accepts `cursor` and `limit` (1–50); read requires `subject`; update requires `subject`, `expected_revision`, and the complete `access` value. The service injects `contract_version: 1` and `application`; callers cannot supply an actor. Subjects are bounded to 191 bytes, revisions to 128, and memberships to 100. Requests are limited to 64 KiB and streamed responses to 256 KiB.

Responses echo version, application, and operation. Read/update must also echo the exact requested subject and return `provisioned`, `revision`, `access`, and `allowed_edits`. Unprovisioned users have null revision/access and no editable controls. Capabilities return `controls.application_admin` and a unique subset of `read`/`write` workspace permissions. Discovery returns `subjects: [{subject,label}]` or `workspaces: [{id,label}]`, plus nullable `next_cursor`. Workspace discovery must include only workspaces the actor may manage.

## Trust and rollout

Configure the deployment-owned `delegated-access.applications` map with stable registry keys and exact HTTPS endpoints. Never derive management endpoints from registry launch URLs, OAuth redirect URIs, dynamic registrations, or browser input. Leave both environment flags off until the consumer adapter and protected browser flow are independently verified.

Use a dedicated integration RS256 key pair, separate from OAuth signing keys. Set the provider issuer, integration key ID, and private-key path; consumers pin issuer, exact endpoint audience, application key, and a local key-ID/public-key map. No key discovery or redirects occur. Rotation can temporarily pin both dedicated public keys before switching the sender key ID.

Assertions use `typ: application-access+jwt`, RS256, exact issuer/audience/application/method, the provider subject as actor, SHA-256 of the exact body, a random nonce, and a lifetime of at most 60 seconds (five seconds clock skew). `ActorAssertionVerifier` returns identity only. Consumers must still recheck current actor eligibility, independently authorize every operation and target, and preserve their own last-administrator and emergency-access rules.

`CacheNonceStore` requires a shared database or Redis cache with atomic add. All adapter instances must share its namespace/storage. Unsupported process-local stores and storage failures reject requests; nonce consumption precedes application authorization. The reference adapter demonstrates actor-scoped pagination, unknown-subject handling, optimistic revisions, deterministic row locking, atomic access/audit writes, and last-administrator protection using synthetic tables created only by tests.

Writes additionally require the trusted actor-bound `RequireRecentPasskeyAuthentication::SESSION_KEY` credential-verification record to be at most 300 seconds old. The browser flow must establish this through verified password/passkey authentication, not by setting arbitrary session metadata. Current provider-session checks do not replace the consumer's own session-generation invalidation and lifecycle integration.

## Failure handling

`DelegatedAccessException` exposes readonly `outcome` and HTTP `status`. Configuration, signing, and integration failures fail closed without logging assertions or credentials. Explicit consumer 403/404/409/422 responses become typed refusals. A write timeout, unexpected status, oversized response, or malformed success is `unknown_outcome`: do not retry or claim success. Re-read canonical state and reconcile before a new intentional write. Transport never retries or follows redirects. A monotonic ten-second deadline spans the HTTP request and every streamed body read; individual reads time out after one second, bounding deadline overshoot. Response streams close on success, refusal, and deadline failure.

Provider identity and application authorization remain separate. Consumer adapters own permission semantics, display-name/alias conversion, account provisioning, and domain models. This foundation does not copy credentials, WebAuthn records, or application tables into the provider.
