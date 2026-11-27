# Application-owned identity registration

An application that keeps its registration and onboarding can create a new provider identity
for the account it has just committed. This is a separate authority from human-initiated
admission invitations. It is off by default. An operator must list the enabled registry key
in `AUTH_MANAGER_APPLICATION_REGISTRATION`; only that registration's confidential, static
authorization-code clients qualify.

The application's server sends `POST /api/application-identities` over HTTPS with its own
OAuth client id/secret as HTTP Basic credentials, as on the reconciliation endpoints.
Never expose those credentials to a browser. The request is a JSON object with exactly:

| Field | Meaning |
|---|---|
| `external_id` | A durable UUID for the application's committed local account; never reused |
| `name` | The person's name, at most 255 characters |
| `email` | The email address, at most 254 characters |
| `password_hash` | The application's existing password hash, never plaintext |

Hashes must match the provider's configured verifier: bcrypt cost 10–14, or Argon2id with
8–128 MiB, 1–6 iterations and 1–4 threads when its driver is `argon2id`. Name and email are
trimmed, email and UUID are lowercased, and the normalized request must stay the same on retry.
Neither request bodies nor password hashes belong in application logs.

A create returns `201` and `{contract_version: 1, subject: "…", initial_credential_version: 0}`.
An identical retry returns the same body with `200`. The application records the returned
opaque subject against the exact local account that sent this request; email is never a
binding key. Commit the durable UUID before making the request, so a timeout can retry it.

The provider creates only a **new** identity, with the `user` role and an unproven address,
and grants only the calling client. A verified, destination-bound emailed code or ordinary
recovery can prove the address afterwards. No provider administrator or application role is
inferred from registration. An existing or deleted address causes `409`; it never adopts,
changes or grants an existing identity. Linking an existing identity requires the application's
separate, explicit ownership-proof flow. Other fields, including roles, subjects, verification
flags and client ids, are refused.

The operator may deliberately add static confidential client grants at creation through
`AUTH_MANAGER_APPLICATION_REGISTRATION_CLIENT_GRANTS`, a JSON object mapping registry keys to
lists of client ids. Defaults are empty. Missing, revoked, dynamic or public targets refuse
the entire create. Callers cannot choose these grants. A replay never restores a revoked
additional grant, and cannot revive a deleted/disabled identity or the calling client's
revoked grant.

The client/UUID receipt stores an opaque subject and request digest, not the submitted hash.
A changed request or another client cannot claim that receipt. Keep receipts with directory
backups: deleting them is not a way to rerun admission. A per-client creation quota is
independent of identity-status/tombstone budgets; an outer per-IP quota bounds unauthenticated
traffic. Responses are private and uncached.

Publish/apply both the destination-evidence migration from auth-laravel v0.32.1 and the
application-registration receipt migration through the reviewed deployment before enabling
registration. Existing identities and login policy are unchanged while the feature is off.
