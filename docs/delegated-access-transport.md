# Delegated application access transport

This is the disabled-by-default transport foundation for application-owned access management. It adds no browser route or live consumer endpoint. The synthetic reference adapter in `tests/Fixtures/ReferenceAccessAdapter.php` demonstrates the contract; it is not a production authorization model.

`App\Services\DelegatedAccess\DelegatedAccessTransport::send(Request $request, string $applicationKey, array $operation): array` obtains the actor from an active provider session, checks its credential generation, and requires an enabled registry application plus a current grant to a mapped static OAuth client. Provider administration never grants application administration. Browser controllers must enforce CSRF before calling this service.

Operations are `capabilities`, `subjects`, `workspaces`, `read`, `update`, `remove` and `receipt`. Discovery accepts `cursor`, `limit` (1–50) and a search `query`; read requires `subject`; update requires `subject`, `expected_revision`, the complete `access` value and an `operation_id`. The service injects `application` and `contract_version` 3 (see [contract version 3](#contract-version-3)); callers cannot supply an actor. Subjects are bounded to 191 bytes, revisions to 128, and memberships to 100. Requests are limited to 64 KiB and streamed responses to 256 KiB.

Responses echo version, application, and operation. Read, update and remove must also echo the exact requested subject and return `provisioned`, `revision`, `access`, and `allowed_edits` (`application_admin`, `workspaces`, `provision`, `remove`). Unprovisioned users have null revision/access and no editable controls. Capabilities return `controls.application_admin`, `workspace_roles` and `provisioning`. Discovery returns `subjects: [{subject,label}]` or `workspaces: [{id,label}]`, plus nullable `next_cursor`. Workspace discovery must include only workspaces the actor may manage.

## Trust and rollout

Configure the deployment-owned `delegated-access.applications` map with stable registry keys and exact HTTPS endpoints, normally through `AUTH_MANAGER_DELEGATED_ACCESS_APPLICATIONS` (comma-separated `key|https://endpoint|contract_version` entries). The list is validated when used, never while configuration loads. A malformed value disables delegated access only: no entry is partly honoured, every call is refused with `invalid_configuration` before anything is signed or sent, and the problem is reported once per request without the value. Check it with `php artisan auth-manager:delegated-access:check` before rebuilding the configuration cache. The step-by-step operator procedure is [connecting an application](connecting-an-application.md). Never derive management endpoints from registry launch URLs, OAuth redirect URIs, dynamic registrations, or browser input. Leave both environment flags off until the consumer adapter and protected browser flow are independently verified.

Use a dedicated RS256 key pair per application, separate from OAuth signing keys, listed in `AUTH_MANAGER_DELEGATED_ACCESS_KEYS` (`application|key-id|/absolute/private/key/path`). Writes are signed only with the application's own key; the instance-wide key ID and private-key path sign reads of applications without one. Consumers pin issuer, exact endpoint audience, application key, and a local key-ID/public-key map. No key discovery or redirects occur. Rotating one application's key can temporarily pin both of its public keys before switching its sender key ID.

Assertions use `typ: application-access+jwt`, RS256, exact issuer/audience/application/method, the provider subject as actor, SHA-256 of the exact body, a random nonce, and a lifetime of at most 60 seconds (five seconds clock skew). `ActorAssertionVerifier` returns identity only. Consumers must still recheck current actor eligibility, independently authorize every operation and target, and preserve their own last-administrator and emergency-access rules.

`DatabaseNonceStore` requires a durable relational connection and dedicated `bherila_auth_delegated_nonces` table (`key` string primary key, `expires_at` unsigned integer). It rejects in-memory SQLite and active business transactions so accepted nonces cannot roll back with permission writes. All adapter instances must share this store. Ordinary cache flush/eviction must not erase replay history; database failures reject requests. Nonce consumption precedes application authorization. `pruneExpired()` removes expired rows only. Consumer deployment must create the dedicated table before enabling its adapter; this provider PR creates it only in synthetic tests. The reference adapter demonstrates actor-scoped pagination, unknown-subject handling, optimistic revisions, deterministic row locking, atomic access/audit writes, and last-administrator protection using synthetic tables created only by tests.

Writes additionally require the trusted actor-bound `RequireRecentPasskeyAuthentication::SESSION_KEY` credential-verification record to be at most 300 seconds old. The browser flow must establish this through verified password/passkey authentication, not by setting arbitrary session metadata. Current provider-session checks do not replace the consumer's own session-generation invalidation and lifecycle integration.

`sendForInvitation(User $inviter, int $credentialVersion, string $applicationKey, array $operation, ?string $correlation = null): array` is the one path without a session, used only to apply an accepted invitation's access. Every operation on it, reads included, requires the inviter to be active now, at the credential generation recorded when they created or last resent the invitation (a password reset, disable or other credential revocation since then refuses), to hold `access-invite` and `access-manage` for the application, a current grant to it, invitations switched on, and writes enabled with the application's own key. It reads no session, so it does not accept a recent confirmation from one; the invitation required that confirmation when it was created. The caller may supply the update's correlation (the assertion's `jti`) to record it, and update audit rows from this path carry `via: invitation`. It never retries.

## Failure handling

`DelegatedAccessException` exposes readonly `outcome` and HTTP `status`. Configuration, signing, and integration failures fail closed without logging assertions or credentials. Explicit consumer 403/404/409/422 responses become typed refusals. A write timeout, unexpected status, oversized response, or malformed success is uncertain: after one receipt check it is `outcome_still_unknown` unless the receipt settles it (a result that cannot be recorded is `unknown_outcome`); do not retry or claim success. Re-read canonical state and reconcile before a new intentional write. Transport never retries or follows redirects. A monotonic ten-second deadline spans the HTTP request and every streamed body read; individual reads time out after one second, bounding deadline overshoot. Response streams close on success, refusal, and deadline failure.

Provider identity and application authorization remain separate. Consumer adapters own permission semantics, display-name/alias conversion, account provisioning, and domain models. This foundation does not copy credentials, WebAuthn records, or application tables into the provider.

Provider writes append an audit attempt before transmission and a separate result afterward, recording only actor, target, application, operation, outcome, and a server-generated correlation equal to the signed nonce. The reference adapter stores the same correlation after verification. Calls inside an active provider/audit database transaction are rejected before transmission so caller rollback cannot erase the trail. Failed attempt persistence prevents transmission; failed result persistence returns an unknown outcome and leaves the durable attempt for reconciliation. Audit records never contain assertions, keys, or request bodies.

## Contract version 3

The transport speaks delegated access contract version 3 only (`bherila/auth-laravel` 0.22 removed
versions 1 and 2). Each application's entry still names its version,
`delegated-access.applications.<key>.contract_version`, and it must be `3`: an entry naming `1` or
`2`, or a literal entry naming none, makes the map malformed, so every call is refused with
`invalid_configuration` and the problem is reported once with the entry position and the rule.
The transport builds every request and checks every answer with the package's `DelegatedContract`,
the same validator applications use. The version is never negotiated at runtime and never taken
from a response; an answer in another version is `invalid_response`.

- **Roles.** Application-defined workspace roles in `capabilities.controls.workspace_roles` (each
  may carry a `description`), and `{id, role, editable}` memberships.
- **Provisioning.** A `provision` allowed edit, and an `update` whose `expected_revision` is `null`,
  optionally with a `display_name`. Such an update creates an account for an unprovisioned subject.
- **Account-only applications.** An application that advertises `workspace_roles: []` has accounts,
  the application administrator flag and provisioning, and no workspaces. Every access value it
  sends or accepts carries `workspaces: []`.
- **Search.** `subjects` and `workspaces` take an optional `query` (2 to 100 characters, checked with
  `DelegatedContract::validQuery()` before anything is sent). The application matches it within the
  actor's scope, exactly as it lists without one, and binds its cursors to it.
- **Removal.** `remove` takes `subject`, `expected_revision` and `operation_id`. It is a write, with
  every check an update has. The answer must leave the account provisioned with nothing in the
  actor's projection.
- **Metadata.** States and `subjects` entries may carry `provisioned_at`, `first_sign_in_at` and
  `last_seen_at`. Shown, never used to decide anything.
- **Operation ids.** Every `update` and `remove` carries an `operation_id`, chosen by the caller once
  per user action and kept across any resubmission of it (`DelegatedContract::operationId()`), and
  never the assertion's `jti`, which stays new for every request. The application keeps a receipt per
  operation and answers a repeat from it without applying it again.
- **Receipt check.** When a write's answer is uncertain (a 5xx, including the endpoint's
  `operation_in_progress`, a timeout, a transport error, a malformed answer, or one that does not fit
  the capabilities the caller checked it against), the transport asks for that operation's `receipt`
  once, with a new assertion, and never sends the write again. `DelegatedContract::receipt()` checks
  the receipt is about that write. A stored success is returned as the write's answer; a stored
  refusal is raised as that refusal, acted on by its status; anything else (no receipt, a pending
  one, a receipt request that failed) is `outcome_still_unknown`.

The provider checks that every role it sends was advertised (`rolesAreAdvertised()`) before
transmitting; for an account-only application that means it sends no memberships. It checks reads
and write answers against the capabilities (`fitsCapabilities()`), so an account-only application
that reports a membership or offers workspace edits is `invalid_response` on a read and an uncertain
outcome on a write. The provider does not ask an account-only application for its workspaces. The
application still decides every authorization, tenant and last-owner rule.

Audit: write records carry `operation` (`update` or `remove`) and `operation_id`. The receipt check
is its own record, `delegated_access_receipt_check`, with `outcome` `applied`, `refused` (with the
stored `refusal` and `refusal_status`) or `unknown`, the write's `correlation` and `operation_id`.
It is written before the write's result record, which notes `confirmed_by: receipt` when the receipt
settled the write. A receipt check that cannot be recorded leaves the outcome unknown.

**History.** Version 1 (per-workspace `read`/`write`) and version 2 (roles, provisioning,
account-only) were spoken until every application moved to version 3; the provider kept both during
that cutover and dropped them with `bherila/auth-laravel` 0.22.

The delegated access classes (`ActorAssertionVerifier`, `DatabaseNonceStore`, `NonceStore`,
`DelegatedContract`, `DelegatedAccessException`) now come from the package. Only the signing side,
`ActorAssertion`, and the transport stay in this repository.
