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
automatically. An unavailable integration does not render cached authority.

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
