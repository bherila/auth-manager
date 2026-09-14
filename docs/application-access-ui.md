# Central application access controls

The application-access pages build on the trusted registry and signed delegated
transport. They remain unavailable until their integration is configured.
Enable registry launch navigation and delegated access only after reviewing
each instance's registered applications and configured API endpoints. Keep
delegated writes disabled until the reference-adapter checks also pass for the
real application.

Active users reach `/applications/manage` from the provider home page. The list
is limited to their granted, enabled registered applications with configured
integrations. A launcher grant permits the provider to ask the application;
the application still decides whether the actor can browse or edit accounts.
Provider administration does not override that decision.

The server-rendered UI offers bounded account and workspace discovery, current
access, supported administrator/membership controls and explicit unprovisioned
states. Each update includes the read revision and displays success only after
a valid canonical application response. Conflicts require a reload. Unknown
outcomes state that a change may already have completed and are never retried
automatically. A failed write redirects to the access page for the selected
account and flashes the outcome, so a browser refresh re-reads rather than
resubmitting the write. An unavailable integration does not render cached
authority.

Writes require recent identity confirmation. The password confirmation endpoint
is CSRF-protected and throttled, and rechecks the locked current account,
credential generation and password. It records the same actor-bound proof as
successful passkey/email-code sign-in. Passwords are neither retained nor
flashed. Passkey/email-code users can sign in again to establish a fresh proof.

The app owns role definitions, storage, target/workspace authorization,
last-administrator safeguards and audit commits. This UI does not provision
application accounts, copy domain data into the provider directory or infer
permissions from a provider role. Consumer rollout and retirement of duplicate
forms remain tracked separately from this provider surface.

## Version 2 applications

For an application configured with `contract_version: 2`:

- **Roles.** Workspace access is edited with the application's own role labels. A membership the
  application reports as not editable is shown read-only, and posted back unchanged. An empty role
  removes a membership. A role the application did not advertise is refused before anything is sent.
- **Directory picker.** When the application advertises provisioning, **Give access to someone new**
  lists people who can sign in to that application through this provider. That means they hold a
  current grant to a static client mapped to it, and their account is active. It searches their
  name and email. Nobody else is listed, so the picker is not a general directory search.
- **Provisioning.** Choosing a person reads their access. When the application reports them
  unprovisioned with `provision` allowed, the page offers **Create account and give access** with
  one workspace and role. Submitting re-checks the grant, the application's offer and the role, then
  sends an `update` with a null revision and the person's name as `display_name`. The application
  creates the account bound to this provider's issuer and the exact subject. Writes need recent
  identity confirmation, as for every other change.
