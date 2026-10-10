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

## Who may use these pages

Delegated administration is **denied unless granted** by provider roles in `user_role`, scoped per application (`*` means every application):

| Role | Allows |
|---|---|
| `access-view:<app>` | Read the application's access pages. |
| `access-manage:<app>` | Read and change access there (includes view). |
| `access-directory:<app>` | Browse the people who can sign in to the application when choosing whom to provision. It needs `access-manage` as well. |
| `access-invite:<app>` | Invite people by email (see [Invitations](#invitations)). It needs `access-manage` as well. |

These are narrow delegated-administration permissions, not provider administration. A workspace administrator needs only these, and **the application still decides** what each actor may see and change: the provider's role is an extra restriction, never a substitute.

**The directory is separate on purpose.** It lists grant holders across every workspace of the application, which a workspace-scoped administrator must not see. Without `access-directory`, **Give access to someone new** asks for the person's **exact email**. The answer is the same whether or not that person exists, can sign in, or was provisioned, so it can't be used to discover people. The new account then shows up in the account list.

**Writes are switched on per application.** `AUTH_MANAGER_DELEGATED_ACCESS_WRITES_ENABLED` must be on **and** the application must be listed in `AUTH_MANAGER_DELEGATED_ACCESS_WRITES_APPLICATIONS`. Otherwise its pages are read-only, and a change is refused as not authorized.

## Version 2 applications

For an application configured with `contract_version: 2`:

- **Roles.** Workspace access is edited with the application's own role labels. A membership the
  application reports as not editable is shown read-only, and posted back unchanged. An empty role
  removes a membership. A role the application did not advertise is refused before anything is sent.
- **Directory picker** (with `access-directory`). When the application advertises provisioning, **Give access to someone new**
  lists people who can sign in to that application through this provider. That means they hold a
  current grant to a static client mapped to it, and their account is active. It searches their
  name and email. Nobody else is listed, so the picker is not a general directory search.
- **Roles are always chosen.** A new membership's role select starts empty and must be chosen; the
  page never defaults to the first (usually most senior) role an application advertises.
- **Provisioning.** Choosing a person reads their access. When the application reports them
  unprovisioned with `provision` allowed, the page offers **Create account and give access** with
  one workspace and role. Submitting re-checks the grant, the application's offer and the role, then
  sends an `update` with a null revision and the person's name as `display_name`. The application
  creates the account bound to this provider's issuer and the exact subject. Writes need recent
  identity confirmation, as for every other change.
- **Account-only applications.** An application that advertises no workspace roles has no
  workspace section at all. An account shows only the **Application administrator** control,
  editable only where the application's capabilities and its read both allow it (an application
  typically refuses self-demotion and demoting its last administrator). Otherwise it is shown
  read-only. Provisioning asks for no workspace or role. It asks whether the new account is an
  application administrator. That choice starts empty and must be made, and **Yes** is offered only
  when the application lets this actor grant administration. Provisioning by exact email answers
  exactly as it does for a workspace application, whatever the outcome.

## Invitations

Invitations let a manager give someone access to an application by email, whether or not that
person has an account here yet. They are off unless `AUTH_MANAGER_INVITATIONS_ENABLED=true`, and
are offered only for a version 2 application that advertises provisioning and has writes enabled.

**Who may invite.** `access-invite:<app>` together with `access-manage:<app>`, plus everything a
write needs: a current grant to the application and a credential check within the last five
minutes. Revoking needs the two roles only. The pending list on the access page is shown to holders
of `access-invite` or `access-manage` for that application, and lists only its invitations.

**What the inviter chooses.** The email address, and the access to apply: the application
administrator flag (always chosen, never defaulted, offered only when the application lets this
actor grant it) and, for a workspace application, up to three workspaces each with an explicitly
chosen role. Roles must be ones the application advertises.

**What the inviter learns.** Always **Invitation sent.** and the link, shown once. Creating an
invitation never looks the address up, and the email is the same in every case, so neither the
answer nor its timing says whether the address has an account. If the email could not be sent the
page says so, and the link can be shared another way.

**The link.** 32 random bytes, stored only as a SHA-256 hash. It works once, expires after seven
days, and can be revoked. **Send again with a new link** replaces the token, so the old link stops
working, and makes whoever resends it the inviter. Invitations are rate-limited to 20 per inviter per hour and 5 per recipient address per
day, counted the same whether or not the address has an account. Opening a link is limited per IP.

**Accepting.** The page names the application and the invited address.

- If an account has that address (case-insensitively), the person signs in to it and accepts.
  Someone signed in as a different account is refused and offered a sign-out.
- Otherwise they create an account with a name and password; the address is fixed to the invited
  one and counts as verified.
- A disabled or deleted account with that address cannot accept.

Acceptance, in order: the invitation is marked used under a lock, the person is granted the
application's sign-in clients, and then the access is applied.

**Applying the access.** As if the inviter made the change at that moment. The provider re-checks
that the inviter is still active, has had no credential reset or revocation since creating (or last resending) the invitation, still holds `access-invite` and `access-manage` for the
application, and that writes are enabled (the credential check was required when the invitation
was created). It then calls the application as the inviter, without the inviter's session,
through a narrow path that only invitations use. An account the application has not seen is
provisioned with `expected_revision: null`. An existing account keeps everything it has and gains
the invited memberships in workspaces it is not yet in, and administration if the invitation
grants it; nothing is removed or demoted, and nothing is sent when nothing is missing.

If the provider's re-check or the application refuses, the person stays admitted with no access
applied and the pending list shows **Accepted; roles not applied** with the reason. If the
application does not confirm the write, the list shows **Accepted; roles not confirmed**: the
change may have happened, so review the person's current access. It is never retried.

**Audit.** Provider audit rows record invitations created, sent (with whether delivery succeeded),
resent, revoked and accepted, and access applied or not applied with the outcome and the delegated
request id (`correlation`, the actor assertion's `jti`). The transport's own update audit rows carry
`via: invitation`. Rows name the invitation by id rather than the address; purging a person's
identity deletes the invitations sent to them.

**Mail.** `MAIL_MAILER=hybrid` sends through Brevo's API (`MAILER_DSN=brevo+api://KEY@default`)
and fails over to the SMTP settings; `MAIL_MAILER=brevo` uses the API alone. The local default
stays `log`, which delivers nothing.

**Enabling, per instance:**

1. Configure a mailer that delivers, and a `MAIL_FROM_ADDRESS` the mail service accepts.
2. Migrate (`access_invitations`).
3. Set `AUTH_MANAGER_INVITATIONS_ENABLED=true` and rebuild the configuration cache. The
   application must already be on contract version 2, advertise provisioning, and be listed in
   `AUTH_MANAGER_DELEGATED_ACCESS_WRITES_APPLICATIONS`.
4. Grant `access-invite:<app>` to each inviter, who also needs `access-manage:<app>`:
   `php artisan auth-manager:user-roles person@example.test --add=access-invite:example-app`.

