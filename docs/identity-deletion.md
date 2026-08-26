# Identity deletion and reconciliation

Provider deletion is a tombstone-and-reconcile protocol, not a transaction
across application databases.

## Provider lifecycle

An administrator deletes a person through the directory. In one provider
transaction, the service:

1. creates a non-PII tombstone for the OAuth subject;
2. snapshots every expected relying application;
3. disables the account, advances its credential generation, and revokes its
   authorization codes, device codes, access tokens, and refresh tokens;
4. invalidates provider sessions and password-reset tokens; and
5. soft-deletes the provider user row.

The person cannot sign in or obtain another token once that transaction commits.
The provider user row remains temporarily so applications can reconcile before
provider-owned data is hard-deleted.

An expected relying application is an active, confidential OAuth
authorization-code client with at least one absolute HTTP(S) redirect URI. The
set is snapshotted when deletion starts. A client registered later could not
have held a projection of that subject through this provider, and is not added
retroactively. Revoking or deleting a client later does not erase its snapshot.

## Reconciliation API

Relying applications authenticate with HTTP Basic using their existing OAuth
client ID and client secret. User bearer tokens and provider browser sessions
do not authorize these endpoints. Responses are JSON and carry
`Cache-Control: private, no-store`.

### Read pending tombstones

```text
GET /api/reconciliation/identity-tombstones?limit=100
Authorization: Basic base64(client_id:client_secret)
```

The default and maximum limit are 100. Results are the oldest unacknowledged
assignments for that client:

```json
{
  "contract_version": 1,
  "data": [
    {
      "id": "648b1f85-9192-4eb2-943d-734c5f5fd817",
      "subject": "42",
      "tombstoned_at": "2026-08-26T12:00:00.000000Z",
      "purge_after": "2026-09-25T12:00:00.000000Z",
      "provider_purged_at": null
    }
  ],
  "has_more": false,
  "next_cursor": null
}
```

The subject is a string because it is the exact OAuth `sub` value applications
already store. The feed contains no name, email address, credentials, grants,
or application-owned data.

When `has_more` is true, `next_cursor` is a non-null opaque string. The client
must pass it unchanged on the next read:

```text
GET /api/reconciliation/identity-tombstones?limit=100&cursor={next_cursor}
```

Advance the cursor after recording every result from the current page, even if
one of those tombstones cannot yet be acknowledged. This prevents one failing
record from hiding later pages. Persisting the cursor makes a process restart
safe; repeating a page is also safe. When `has_more` is false, `next_cursor` is
null and the next polling cycle starts without a cursor. Cursors are bound to
the authenticated reconciliation client and must not be parsed or reused by a
different client. Acknowledged items leave the pending feed.

### Acknowledge a tombstone

```text
PUT /api/reconciliation/identity-tombstones/{id}/acknowledgement
Authorization: Basic base64(client_id:client_secret)
```

An application must commit its own local deletion transaction before sending
the acknowledgement. Acknowledgement means that application's cascade has
completed; it is not a reservation or a delivery receipt. Replaying the same
request is safe and returns the original `acknowledged_at` value. A client
cannot read or acknowledge a tombstone outside its snapshotted assignments.

## Retention and unavailable applications

`identities:purge-tombstones` runs hourly through Laravel's scheduler. It
hard-deletes the provider user row when either:

- every snapshotted application has acknowledged; or
- the 30-day retention window has expired.

The window is configurable with `IDENTITY_TOMBSTONE_RETENTION_DAYS` and never
falls below one day.

An unavailable application therefore cannot block provider deletion forever,
but its absence is not treated as success. At retention expiry the provider
stores the unacknowledged client IDs and names on the tombstone and emits a
structured warning naming them. The minimal tombstone and per-client
assignments remain after provider purge, so a late application still receives
the event and can acknowledge it. A provider purge never fabricates an
application acknowledgement.

The deployment environment must invoke Laravel's `schedule:run` every minute;
the repository owns the hourly job definition and overlap lock.
