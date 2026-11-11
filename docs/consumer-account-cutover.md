# Consumer account-management cutover

This runbook implements the consuming-application acceptance sequence from
[#35](https://github.com/bherila/auth-manager/issues/35). Use it with the
[approved ownership contract](account-management-contract.md),
[application connection procedure](connecting-an-application.md), and
[provider acceptance matrix](account-management-acceptance.md). Provider tests
and a published release establish reusable behavior; they do not approve a
consumer's configuration or a live account migration.

The reference protocol is delegated-access contract version **3**, implemented
by the provider and `bherila/auth-laravel` 0.28.6. The version-1 JSON example in
the original account-management contract describes the original design, not a
supported transport version. Follow the current shared contract and
[transport guide](delegated-access-transport.md) for requests, receipts and
removal semantics. Do not implement a second transport in the application.

## Inventory before replacing controls

For each consumer, record the exact provider, shared-package and application
revisions, the configured sign-in mode, and the following mapping. Keep private
deployment identifiers and account assignments outside this repository.

| Existing control | Required disposition |
| --- | --- |
| Password, passkeys and recovery | Provider destination; reject old local mutation endpoints for provider-owned accounts. Preserve the provider's actual MFA and recent-authentication rules. |
| Name and email | State which fields project provider identity at sign-in and which are application nicknames. Bind by provider/issuer and subject; never adopt an account by email. |
| Application administrator and memberships | Application-owned policy and storage. A delegated panel may edit only capabilities the adapter advertises. A provider administrator acquires no application role. |
| Approval, age gates, invitations, moderation, preferences and historical records | Retain application ownership. Do not reinterpret provider grants as approval or domain permissions. |
| Local emergency access | An explicitly designated, active, unbound local administrator with independent credentials and the application's existing MFA. Prove it during a synthetic provider outage before retiring ordinary local controls. |
| Browser sessions and API/MCP credentials | Inventory actual credential lanes. Verify each existing lane; mark absent lanes not applicable rather than inventing or claiming coverage for them. |

Do not create, bind or promote an emergency account as a side effect of enabling
provider sign-in. Provisioning credentials and selecting the operator's account
are separate authorized operations. The exception must remain unavailable to
provider-bound accounts, ordinary local users, restored remember cookies and
sessions created before the emergency ceremony. Revoking designation or local
eligibility must end the exception on the next request.

## Rehearse with isolated synthetic identities

Use separate test directories, databases, keys and browser sessions. Never copy
production credentials into a fixture. Include an existing bound person, a new
subject, an unprovisioned subject, a same-email conflict, an ordinary local user,
a provider-only administrator, an application administrator and the designated
unbound emergency administrator.

1. Complete sign-in, account/security navigation, sign-out and the return to
   application-owned settings. Check invitations, approval, intended URLs and
   the application's chosen name/email projection. Verify forbidden local
   password/passkey endpoints on the server, not only hidden forms.
2. Register a passkey at the provider's actual RP. An old application passkey
   does not become a provider credential. A changed RP requires enrollment;
   rollback never relabels a credential or subject.
3. Enable consumer identity-status enforcement only after its configured
   confidential client can call the endpoint for the intended subjects. Keep
   the login credential generation immutable. A status observation must never
   replace an old session's baseline with a newer generation.
4. Change and reset the password, disable the identity, and delete it through
   real provider handlers. Ordinary work may use a successful observation for
   less than 300 seconds; at the boundary it must revalidate. Privileged work
   checks fresh state. Include already authenticated application sessions and
   every actual API/MCP credential lane.
5. Make the provider unavailable before and after freshness expires. Fresh
   privileged and stale ordinary work must fail closed without extending the
   successful observation. Preserve retryable session state; verify retry
   against the same baseline after recovery. Ordinary provider-owned accounts
   never gain local password access. Complete emergency authentication without
   a provider call and verify its own local MFA and eligibility checks.
6. Delete a synthetic identity and run the consumer's real tombstone handler.
   Verify the application transaction and required cascade finish before the
   acknowledgement is sent. Check repeat delivery, a lost acknowledgement,
   independent held/failed subjects, historical attribution and the
   application's retention rules. A provider purge is not an acknowledgement.

Use shared/provider fixtures for protocol failures and actual consumer tests
for its middleware, policies and cascades. Distinguish in-process HTTP handler
tests, browser tests and remote deployment checks in the evidence. A synthetic
outage is preferable to interrupting a live provider.

## Verify delegated application access separately

Follow [connecting an application](connecting-an-application.md#5-delegated-access-the-provider)
for per-application signing keys, trusted endpoints and role assignment. Keep
both the endpoint and provider writes disabled until their prerequisites pass.
Publish the shared nonce and receipt migrations through the consumer's reviewed
schema process and schedule pruning; retain replay data during rollback.

The consumer adapter must use its existing actor, target and last-administrator
policies under locks. Advertise no workspace or provisioning capabilities that
the application does not implement. For an account-only adapter, removal may
strip only the advertised administrator projection while retaining the account,
history and domain access. Disclose that meaning; do not call it account
deletion or promise it prevents ordinary sign-in.

Run the shared adapter conformance assertions plus consumer-specific cases:

- Refuse ordinary, provider-only, disabled and foreign-provider actors.
- Keep subjects case-sensitive and independent of mutable email addresses.
- Bound searches and cursors to the application and actor's current scope.
- Refuse stale revisions and unsupported controls without partial changes.
- Commit the local audit with the access change and preserve protected
  administrators.
- Verify nonce replay, durable operation receipts and ambiguous write outcomes
  through the shared endpoint. Do not automatically retry an uncertain write.
- Show unavailable applications as unavailable; neither cached responses nor
  provider directory data become current application authority.

After reads pass, enable writes for one explicit application, make one
intentional change, and verify canonical state in the application itself. These
activation steps require the instance operator's approved rollout; repository
tests do not turn them on.

## Evidence and rollback

Record exact candidate commits, required CI results, focused test names,
configured feature switches and any interactive checks still outstanding.
Leave a requirement open when it needs deployment or physical interaction that
has not happened. A consumer passing this matrix does not certify other
applications or deployments.

Stop delegated writes first if their behavior is uncertain. Revert navigation
or the endpoint switch independently of identity sign-in. Preserve subject
bindings, replay/receipt records, provider generation checks and local history.
For an identity-mode rollback, restore the reviewed configuration and verify
the corresponding coherent sign-in path; do not enable ordinary local
credentials for provider-owned identities. Do not claim that reverting code
restores deleted people, erased domain records or old credential validity.

Keep emergency access explicitly designated and tested through the rollback.
If it is no longer required, revoke its configuration deliberately rather than
leaving an undocumented permanent bypass.
