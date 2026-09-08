# Account and security

Signed-in, active people manage their provider credentials at `/settings`. This page shows their name and email as read-only values and links to the existing `/settings/passkeys` page. Provider administrators maintain names and email addresses; application preferences and reports remain in the application that owns them.

## Passwords and recovery

`PUT /settings/password` accepts `current_password`, `password`, and `password_confirmation` for the authenticated subject only. There is no target-user parameter. Every change verifies the current password under a database row lock, rechecks account status, requires a different password of at least 12 characters, and requires matching confirmation. Five attempts per minute are allowed. The endpoint retains the web session and CSRF protections; it does not enable the shared package's password routes.

Successful changes increment the credential version, rotate the remembered-login token, revoke existing OAuth credentials, remove persisted provider sessions, and sign out the requesting browser. A stale provider session is refused on its next request even when the session driver is not the database. Connected applications may retain their own sessions until they next consult the provider. The page confirms success and asks the person to sign in again. The audit event is `self_password_changed`, with the subject and actor set to the same person and no password values in metadata.

Recovery uses the existing emailed sign-in-code flow. A person who has forgotten their password still needs an administrator to reset it; an emailed sign-in code does not waive current-password confirmation. People without access to their account email must contact an administrator. This milestone adds no email editing, account deletion, new MFA, or session-management product.

Email-code requests are limited independently to one per normalized email address per 30 seconds and ten per IP per minute. Limits run before lookup, including for unknown and disabled addresses. Successful request responses always contain an opaque 64-character attempt token; throttled responses always use the same JSON error shape and retry headers. Only eligible accounts receive mail.

## Passkeys and return destinations

The hub reuses the existing passkey page, routes, and recent-authentication protections. Passkeys stay bound to the relying-party domain where they were registered; no credentials are copied or rebound. The UI reminds people to keep email or password access before removing a passkey. Persistent passkey-login behavior remains the separate upstream work tracked in #21.

The hub's current navigation stays local. Arbitrary `return_url` input is ignored. A relying-application registry can later supply configured destinations; consumer-provided external URLs must never become redirects without that validation contract.
