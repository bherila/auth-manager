# Account-management acceptance audit

Audited provider baseline: `92661dead` (0.1.4 preparation), with locked
`bherila/auth-laravel` 0.28.6. The normative scope is the approved
[account-management contract](account-management-contract.md), including its
five-minute freshness limit and fresh checks before privileged work. This audit
records repository evidence, not deployment or consumer-cutover approval.

“Provider covered” below means implemented behavior with focused automated
coverage. “Shared/synthetic” identifies reusable consumer machinery or a test
adapter; it does not establish adoption by a separately deployed application.
The new [acceptance test](../tests/Feature/AccountManagementAcceptanceTest.php)
connects the shared status client to the real provider HTTP kernel in process.
Its HTTP bridge is test-only; it is neither a browser journey nor a remote service.

## Provider account/security matrix (#31)

| Requirement | Current evidence | Assessment |
| --- | --- | --- |
| Discoverable account destination, read-only identity and app-owned preferences | `/settings`, [account view](../resources/views/settings/account.blade.php), `AccountSettingsTest::test_account_hub_requires_active_session_and_exposes_only_readonly_profile` | Provider covered. Name/email edits remain administrator-owned; no self-deletion or new factor is implied. |
| Provider profile edits, distinct from app authority | `DirectoryAdminTest` name/email edit, authorization and audit cases; `ApplicationRegistryTest` registration/grant separation | Provider covered. A provider administrator does not gain application administration. |
| Password changes affect only the signed-in subject | `AccountSettingsTest` current password/confirmation/minimum, foreign `user_id`, database recheck, old/new password and CSRF cases | Provider covered. Current password is checked under the account lock; a passkey-only sign-in does not waive it. |
| Credential/session consequences and secret-free audit | `AccountSettingsTest::test_password_change_revokes_credentials_and_sessions_without_touching_another_person`, `DirectoryAdminTest` generation/session tests | Provider covered. Change advances generation, revokes OAuth credentials, removes sessions and pending attempts, and signs out the requester. An independent consumer session needs enforcement of its own baseline. |
| Recovery and second-factor parity | [SelfServicePasswordResetTest](../tests/Feature/SelfServicePasswordResetTest.php), `PasswordSecondFactorTest`, `EmailCodeRateLimitTest`, embedded reset tests | Provider covered with configuration. Reset is off by default; completed reset creates no session and returns through ordinary sign-in/MFA. Unknown, disabled and throttled code/reset requests preserve account privacy. A disabled account may complete an existing reset while remaining unable to sign in; this is intentional. |
| Passkeys, recent proof and RP boundaries | [PasskeyManagementTest](../tests/Feature/PasskeyManagementTest.php), `PasskeyChallengePersistenceTest`, `TrustedDevicesTest` passkey-step-up cases; [portable-directory rules](portable-directory.md) | Existing provider protections retained. Remember restoration alone is insufficient recent proof. The hub links to existing controls and introduces no credential copying/rebinding. RP-compatible transfers remain a separate reviewed operation. |
| Trusted-browser ownership and invalidation | [TrustedDevicesTest](../tests/Feature/TrustedDevicesTest.php), embedded trusted-device tests | Provider covered. Only the owner can list/remove devices; password/reset/disable generations invalidate trust. Removing a device does not itself terminate an already authenticated browser session. Trust skips OTP after a correct password and does not advertise MFA. |
| Safe navigation and consumer links | `AccountSettingsTest` ignores untrusted `return_url`; `ApplicationRegistryTest` grant-scoped launcher and unsafe URL cases | Provider covered for local hub navigation and the separate registered launcher. The hub has no arbitrary external return redirect. A consumer-specific round trip still needs its own verification; do not describe the launcher as that test. |

These are API/server-rendered and existing component/embedded tests. They do not
constitute a new full-browser account-hub usability or accessibility audit.

## Lifecycle and consumer-session matrix (#34)

| Requirement | Current evidence | Assessment |
| --- | --- | --- |
| Pending/acknowledged assignments, deadline and provider purge remain distinct | [IdentityLifecycleTest](../tests/Feature/IdentityLifecycleTest.php), read-only `/admin/identity-lifecycle` and `/api/admin/identity-lifecycle` | Provider covered; active provider administrators only, private/no-store, no profile or credential disclosure. Snapshot labels survive client removal. |
| Real deletion through progress, retention and late acknowledgement | New acceptance test `test_real_retention_purge_and_late_acknowledgement_remain_distinct_in_operator_progress` | Provider covered across endpoints/command: an unavailable assignment remains pending after actual retention purge, remains readable in its feed, and only its late acknowledgement clears pending progress. Repeated acknowledgement retains its timestamp. |
| Bounded feed, replay and independent failing applications | [IdentityDeletionTest](../tests/Feature/IdentityDeletionTest.php) paging/client-bound cursor, idempotence, all-acked purge and retention cases | Provider covered. Consumers must record a page and advance its cursor despite one unprocessed subject; expiry/purge never manufactures an acknowledgement. |
| Minimal current status and immutable login generation | [IdentityStatusTest](../tests/Feature/IdentityStatusTest.php), `OAuthUserController`, new password-rotation acceptance case | Provider covered. Static confidential client plus current grant reveals liveness/generation only; name/email refresh is restricted to the person's bearer-authenticated login response. Old tokens cannot adopt a newer generation. |
| Five-minute ordinary-request bound, fresh privileged checks, fail-closed stale outage | New acceptance password-rotation, disable/delete and outage cases use the actual provider status API plus shared `ProviderSession` | Shared/in-process proof: ordinary work may use its login observation for 299 seconds; at 300 seconds a changed generation expires it. Privileged checks see current disable/delete without waiting. Outage refuses privileged or stale checks, preserves the session for retry and never extends its last successful observation. |
| Actual consumer browser session, API/MCP bearer and recovery during outage | Shared package [ProviderIdentityEnforcementTest](https://github.com/bherila/auth-laravel/blob/c6cfc97777132e9fd6ab6679ab75ba0116d1c5f3/tests/Feature/ProviderIdentityEnforcementTest.php), [ProviderIdentityTokensTest](https://github.com/bherila/auth-laravel/blob/c6cfc97777132e9fd6ab6679ab75ba0116d1c5f3/tests/Feature/ProviderIdentityTokensTest.php) and `ProviderSessionTest` | Shared fixtures already prove middleware/session refusal, unchanged generation, bearer use/renewal refusal, privileged issuance and retryable outage behavior. A real consumer must enable/wire these checks and demonstrate them against its deployed configuration before claiming the guarantee. |
| Local cascade commits before acknowledgement, historical attribution and app outage | Existing provider protocol and shared `IdentityTombstoneClientTest` validate transport; domain policies belong to consumers | Consumer evidence still required. Provider receipt of an acknowledgement cannot prove that a remote local transaction committed, nor can a provider purge prove an application cascade. |

Profile projection refresh happens at sign-in, by issuer/provider plus subject;
status never updates name/email. Consumers must explicitly retain their chosen
nickname/projection policy and local authorization checks. No email-based linking
or outage fallback to ordinary local credentials is approved by this audit.

## Existing delegated evidence is reusable

Do not reopen shipped foundations as missing features. The synthetic
[ReferenceAccessAdapter](../tests/Fixtures/ReferenceAccessAdapter.php) and
`DelegatedAccessTransportTest`, `DelegatedActorAssertionTest`,
`DelegatedAccessTransportV3Test` and application-access UI tests already cover
signed actor proof, application-only/provider-only boundaries, workspace
isolation, revisions, replay rejection, malformed responses, unavailable
applications and ambiguous write outcomes without automatic retries. These are
synthetic application authorization fixtures, not proof of an actual consumer's
lifecycle middleware, cascade or deployed delegated endpoint. Real adapters and
cutover remain application-owned work.

## Recommended tracker reconciliation

- **#31:** close the provider account/security implementation scope using the
  matrix above. Carry each application's link/return, credential-form retirement,
  onboarding, approval, factor and tested local-emergency-access parity into #35.
  The old open profile/recovery decision is resolved by the approved contract;
  it is not a reason to recreate the hub or enable additional shared routes.
- **#34:** mark provider progress/status and reusable shared-client foundations
  complete. Split the remaining separately deployed consumer acceptance into a
  linked #35 checklist or focused child: existing browser and API/MCP credentials
  under disable/reset/delete, the 300-second boundary, fresh privileged writes,
  both outages, local transaction/ack order and historical retention. Close #34
  only when that residual work has an explicit owner and tracker link; do not
  claim instantaneous cross-application session revocation.
- **#29:** replace stale “no hub/profile/lifecycle UI” gaps with the completed
  foundations and this evidence. Keep real delegated adapters and consumer
  cutover open. Shared tests and a green provider CI do not establish that every
  consumer meets the contract or that any deployment has been cut over.

Run only focused tests locally; full provider/embedded suites and builds belong
to required CI on the exact candidate. Record exact consumer/provider revisions
and observed behavior when completing the remaining acceptance, without
publishing deployment addresses, credentials or account inventories here.
