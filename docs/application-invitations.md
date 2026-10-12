# Application-requested admission invitations

An application that manages its own sharing (a client portal, for example) can ask this provider to
invite someone who has never signed in. The invitation admits that person to **the calling
application's client only**, with no roles. Whatever the person may do inside the application is
still the application's to decide, usually when they first sign in.

This is a machine endpoint, called by the application's server. It is separate from the invitations
a manager sends from the provider's own access pages
([application access](application-access-ui.md#invitations)), which carry roles and need
`access-invite:<app>`.

It is **off for every application** until an operator enables it (see [Enabling](#enabling)).

## Trust model

- **The application authenticates as itself**: an OAuth 2.0 client credentials access token for its
  own confidential sign-in client, carrying the dedicated scope `invitations:admit`.
- **It names the person asking** in a signed actor assertion (RS256, a key pair the application
  holds, its public half pinned here). The provider checks that this person is an active provider
  account with a current grant to the calling client.
- **The provider relies on the application's own authority check.** No provider permission is
  required of the actor; the application must decide, before calling, that the actor may invite.
- **Admission only, to the calling client only.** The invitation carries no roles, and acceptance
  grants the client that requested it and nothing else: not the application's other clients, not any
  other application. An application can see, resend and revoke only invitations requested through its
  own client.

## Endpoints

All three are `POST`, under the provider's issuer URL (`ISSUER` below: the provider's OAuth issuer,
an `https://` origin with no path).

| Operation | Path |
|---|---|
| Create | `/api/application-invitations` |
| Resend | `/api/application-invitations/{id}/resend` |
| Revoke | `/api/application-invitations/{id}/revoke` |

`{id}` is the integer `id` a create returned.

### Request

Headers:

| Header | Value |
|---|---|
| `Authorization` | `Bearer <access token>`: a client credentials token for the application's client with scope `invitations:admit` (see [Getting a token](#getting-a-token)) |
| `Actor-Assertion` | The signed actor assertion for this exact request (see [Actor assertion](#actor-assertion)) |
| `Content-Type` | `application/json` |
| `Accept` | `application/json` |

Body: a JSON object, sent byte for byte as signed.

| Operation | Body |
|---|---|
| Create | `{"email": "person@example.test"}`: required, a valid address of at most 255 characters. No other member is accepted (there is no way to ask for roles). |
| Resend | `{}` |
| Revoke | `{}` |

### Responses

Create (`201 Created`) and resend (`200 OK`):

```json
{
  "invitation": {
    "id": 42,
    "status": "pending",
    "expires_at": "2026-10-19T12:00:00Z",
    "link": "https://identity.example.test/invitations/<token>",
    "email_sent": true
  }
}
```

- `id`: the provider's invitation id, for resend and revoke.
- `status`: `pending`.
- `expires_at`: UTC, seven days after the create or resend.
- `link`: the acceptance link, a single-use bearer credential. It is returned on **every** create and
  resend so the application's manager can always copy it. Treat it as a secret: show it only to the
  person who asked, never log it, and never return it to automated agents.
- `email_sent`: whether this provider's email to the address was accepted for delivery. The link is
  returned either way.

Revoke (`200 OK`):

```json
{ "invitation": { "id": 42, "status": "revoked" } }
```

Revoking an invitation that is already revoked answers the same.

Every response carries `Cache-Control: no-store`.

### Enumeration resistance

A create never looks the address up. The response, its status and the email are the same whether
or not the address already has a provider account, a grant to the application, or a pending
invitation from the provider's pages. Rate limits are counted the same way. Whether an account
exists is decided only when the link is opened, by its recipient.

### Errors

Errors are JSON, `{"error": "<code>", "message": "<text>"}`, sometimes with more members. Nothing was
changed by a refused request.

| Status | `error` | Meaning |
|---|---|---|
| 401 | `invalid_token` | No valid bearer token, or it is not a client credentials token (it names a person). `WWW-Authenticate: Bearer error="invalid_token"`. |
| 403 | `insufficient_scope` | The token does not carry exactly `invitations:admit` (`*` does not count). |
| 403 | `application_not_enabled` | The calling client is not a confidential sign-in client of an enabled registry entry that is listed for invitations and has a public key configured. |
| 401 | `invalid_actor_assertion` | Missing, malformed, wrongly signed, expired, or not for this client, URL or body. |
| 401 | `replayed_actor_assertion` | This assertion's `jti` was already used. Sign a new one. |
| 403 | `actor_not_eligible` | The actor is not an active provider account with a current grant to the calling client. |
| 422 | `invalid_request` | The body is not a JSON object, has a member it should not, or the address is invalid. `errors` maps each field to messages. |
| 404 | `invitation_not_found` | No invitation with that id was requested through this client. Another client's, another application's and the provider pages' invitations all get this answer. |
| 409 | `invitation_not_pending` | Resend of an invitation that is revoked or accepted. A pending or expired one can be resent. |
| 409 | `invitation_accepted` | Revoke of an invitation already accepted. Remove the person's access in the application instead. |
| 409 | `concurrent_invitation` | Another invitation to the same address was being created at the same moment. Try again. |
| 429 | `rate_limited` | `limit` is `application`, `actor` or `recipient`; `Retry-After` gives seconds. |
| 503 | `mail_unavailable` | The provider's mailer does not deliver (for example `log`), so it sends no invitations. |
| 503 | `invalid_configuration` | The provider's key configuration for this application is malformed or a key is unreadable. |
| 503 | `replay_storage_unavailable` | Used assertion ids could not be recorded. Try again later. |

The route also has a coarse per-address limit of 60 requests a minute, answered by the framework
with `429`.

## Getting a token

Request a client credentials token from the provider's token endpoint with the application's own
client id and secret:

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=<id>&client_secret=<secret>&scope=invitations:admit
```

Tokens live five minutes; reuse one until shortly before `expires_in`. The scope exists only for
client credentials tokens: it is not in the provider's advertised catalog, it is never offered on a
consent screen, and it is dropped from any token issued for a person.

## Actor assertion

A compact JWS, signed RS256 with the application's private key for this provider. Exactly these
members:

Header:

| Member | Value |
|---|---|
| `alg` | `RS256` |
| `typ` | `application-invitation+jwt` (not the delegated access `application-access+jwt`; neither is accepted as the other) |
| `kid` | The key id configured for the application's public key here |

Claims:

| Claim | Value |
|---|---|
| `iss` | The calling client's OAuth client id, the same client as the token |
| `sub` | The actor's provider subject: the `sub` the provider's user endpoint returned for them (a decimal string, no leading zeros) |
| `aud` | The exact URL being called: `ISSUER` + path, for example `https://identity.example.test/api/application-invitations/42/resend` (a string, or an array of that one string) |
| `iat`, `exp` | Integer seconds. `exp` within 60 seconds of `iat`. Five seconds of clock skew are allowed. |
| `jti` | 64 lowercase hex characters, new for every request. Each is accepted once. |
| `method` | `POST` |
| `body_sha256` | Lowercase hex SHA-256 of the exact request body bytes |

Any other header member or claim refuses the request.

## Audit

Provider audit rows for these invitations use the same events as the provider's own invitations
(`access_invitation_created`, `_sent`, `_resent`, `_revoked`, `_accepted`), with `acting_user_id`
the actor, and metadata `via: application`, `oauth_client_id` (the requesting client),
`actor_subject` and `link_returned: true`. A revocation by supersession carries
`reason: superseded`. An acceptance that created an account carries `address_verified`.

Two more events cover the code that proves the address (see [Acceptance](#acceptance)), with
`via: application`, `oauth_client_id` and no actor: `access_invitation_code_sent` (refusals have
`succeeded: false` and a `reason`: `mail_unavailable`, `rate_limited`, `send_limit`, `unavailable`
or `delivery_failed`) and `access_invitation_code_rejected` (`reason`: `missing`, `incorrect`,
`exhausted` or `expired`).

Rows name the invitation by id, never the address, and never hold a code.

## Invitation life

- One pending invitation per application client and address (case-insensitive). A new create for the
  same address revokes the earlier pending one (`superseded`); it never touches an invitation sent
  from the provider's pages or requested through another client.
- Resend issues a new token and a new seven-day expiry; the old link stops working at once.
- Expired invitations need no job: an expired link simply stops working, and can be resent.
- Rate limits, per hour unless stated: `per_application_per_hour` (100) per calling client,
  `per_actor_per_hour` (20) per actor, and 5 per recipient address per day, shared with the
  provider's own invitations. Creates and resends count; revokes do not.

## Acceptance

The recipient opens the link. The provider's acceptance page is the same as for its own
invitations: only the account with the invited address (case-insensitive) can accept, by signing in
to it, or by creating it when no account has that address. A disabled account cannot.

**An existing account** accepts at once, signed in as itself, as for the provider's own invitations.

**Creating an account needs a code sent to the address.** The link was returned to the application,
so whoever opens it may not read the address. Before the page offers to create the account, it asks
the recipient to have a six-digit code emailed to the invited address; the account is created only
when the code is entered with the name and password, and it is then marked email-verified. Holding the
link alone is not enough to create an account.

- Each code is stored only as a keyed hash, bound to the invitation, its current link and its
  address: it works nowhere else, and a resend (a new link) deletes them all.
- Every code sent for the link stays usable until it expires (15 minutes), so asking twice gives two
  working codes. One works once; using it spends the others too.
- Wrong entries count per invitation: five spend every live code, and the recipient sends a new one.
- At most five codes are sent per link and five an hour to one address across every invitation, so
  one link allows at most 25 wrong entries. A send that fails counts against neither limit.
- The email goes out only after its code is stored, never inside a database transaction. A failed send
  deletes its code; codes delivered earlier are untouched.
- A code is sent only when the provider's mailer delivers. If mail is unavailable, no code is sent
  and no account can be created; the page says so.
- Expired codes are pruned hourly by the host's scheduler.

The settings are in `config/application-invitations.php` under `verification`.

Accepting marks the invitation used and grants the requesting client to that account, and nothing
else: no other client, no roles, no provider permissions. The provider makes no call to the
application.

A link stops working when the invitation is revoked, superseded, accepted or expired, and also when
the application is no longer listed for invitations, its registry entry is disabled, or the
requesting client is no longer one of its sign-in clients.

The provider's own access pages neither list nor manage these invitations.

## Enabling

Everything below is off by default. Enable one application at a time, after the application's own
side is deployed with its feature off.

1. Deploy (the migrations add `access_invitations.requesting_client_id`, the
   `invitation_acceptance_codes` table and two `access_invitations.verification_*` counters for
   acceptance codes, and the
   `bherila_auth_delegated_nonces` table, used for assertion ids; all are inert until enabled).
   The provider's mailer must deliver: without it, invitations are refused and no code can be sent.
2. Generate an RS256 key pair for the application, separate from its OAuth and delegated access
   keys. The application keeps the private key in its own secret store. Place the public key on the
   provider host, outside the web root.
3. Set `AUTH_MANAGER_APPLICATION_INVITATION_KEYS` to `<app>|<key-id>|/absolute/path/public.pem`
   (comma-separated entries; one application may list several key ids while it rotates; a key id or
   file may not be shared between entries).
4. Allow the client credentials grant on the application's confidential sign-in client:
   `php artisan auth-manager:application-invitations <app> --allow-client-credentials`. Without an
   option the command only shows readiness. A client with a stored scope ceiling also needs
   `invitations:admit` in it.
5. Add the application's registry key to `AUTH_MANAGER_APPLICATION_INVITATIONS`, rebuild the
   configuration cache, and run the command again: every column should say yes.
6. Check end to end from the application with a test address before telling its managers.

The host's scheduler prunes expired assertion ids and acceptance codes hourly.

**Turn it off** by removing the application from `AUTH_MANAGER_APPLICATION_INVITATIONS` and
rebuilding the configuration cache: requests are refused and outstanding links stop admitting. Also
`--remove-client-credentials` if the client should hold no client credentials grant. Accounts and
grants already created by accepted invitations stay; remove them in `/admin/users` if needed.
