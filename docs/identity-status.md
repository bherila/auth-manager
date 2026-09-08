# Provider identity status contract (version 1)

A registered, confidential authorization-code application can revalidate one previously received provider subject through `POST /api/reconciliation/identity-status`. Authenticate using the application's existing HTTP Basic OAuth client credentials over HTTPS. The application must still have an explicit grant for that subject. Public, revoked, invalid, and dynamically registered clients cannot use this endpoint, including confidential dynamic clients. Resource-profile consent does not substitute for a directory grant.

Send a JSON object with a nonempty string `subject`, at most 255 characters. Treat subjects as opaque, case-sensitive values; do not normalize or interpret them as numbers. This endpoint exposes neither a directory listing nor an arbitrary profile lookup.

For an active account with a current grant, the response is:

```json
{"contract_version":1,"active":true,"subject":"42","credential_version":3}
```

Unknown, disabled, deleted, and ungranted subjects receive the identical successful response:

```json
{"contract_version":1,"active":false}
```

The active response never carries profile data. A client credential plus a caller-chosen subject is not proof about the person: grants are coarse permission to authorize a client, the grant migration backfilled every active subject to every existing client, and subjects are sequential identifiers. Returning `name` or `email` here would let any client operator, or anyone holding one client secret, enumerate the directory. Profile data is released only through the bearer-authenticated `GET /api/oauth/user` response, which is bound to that person's own OAuth login; consumers refresh their name/email projections from that response at sign-in. A status response that unexpectedly includes profile fields must be ignored by consumers, never adopted.

Invalid client authentication is HTTP 401; invalid request shape is HTTP 422. The existing reconciliation throttle allows 60 requests per minute and returns HTTP 429 when exhausted. Responses, including authentication, validation and throttle failures, carry `Cache-Control: private, no-store`. Do not log client credentials or returned statuses.

The existing OAuth user response also includes the authenticated bearer token's integer `credential_version`, allowing a consumer to capture the generation when establishing its own session. Existing callers can ignore the additive field. Disabled identities, revoked tokens, transient cookie sessions, and a token whose generation no longer matches the current account cannot obtain this response. A concurrent reset can never upgrade an old token into a new-generation login.

## Consumer responsibility

This provider addition supplies current evidence; it does not invalidate a consumer's independent browser session by itself. The intended consumer policy is at most five minutes of status freshness and an immediate status check before privileged writes. A consumer must reject an inactive identity, a different subject, a changed generation, or an invalid/failed response when a fresh check is required. Provider outages must not extend the allowed freshness indefinitely. Store the subject and generation established at login, rather than silently adopting a new generation after a reset.

Consumers still own their local historical-attribution and cascade policies. The existing tombstone feed remains the source for deletion work, with acknowledgement only after the local policy commits. Status is not a deletion acknowledgement. Provider disable/reset/delete, local-session refusal within the freshness bound, bearer access, and provider/application outage cases need end-to-end consumer acceptance tests before claiming enforcement.
