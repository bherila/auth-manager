# Default access

**Status: implemented.** This note records the design and the operator procedure.

## The problem

A person reaches an application through a direct grant or through a group they belong to
([access groups](access-groups.md)). Nothing gave a new account access automatically, so every
account needed someone to pick its applications, one person at a time. Nothing let an
administrator say "everyone gets these, except the people I take out".

## Decision

1. **Groups are the main way to give access. Direct grants are exceptions.** Groups already
   expand into the per-person grants that sign-in checks. Removing a group's grant only removes
   access no other group or direct grant still gives, and revokes the person's tokens for that
   application. Directory administration lists a person's Groups before their Applications, and
   describes a direct grant as an exception for that one person. Test logins still use direct
   grants only, because they cannot join groups.
2. **Default access is a group that new accounts join automatically.** It is not a separate list
   of default grants. Any group can be marked `auto_join`, and an instance can have several. A
   default group is an ordinary group otherwise: the same rename, application changes, audit and
   member list.
3. **An override is an opt-out, not a deny rule.** Taking a person out of a default group records
   an opt-out. A later backfill never puts them back, and adding them again clears it. Access
   stays allow-only, so "why can this person sign in here?" always has one answer: a direct
   grant or a group membership. To keep someone away from an application entirely, take them out
   of every group that grants it and remove any direct grant.
4. **Existing accounts join only through an explicit, previewed backfill.** Turning `auto_join` on
   changes nobody who already has an account.

### Alternatives considered

- **A separate list of default applications.** This duplicates what a group already is, needs
  its own audit and UI, and makes "who has this application, and why?" harder to answer.
- **Deny rules or negative grants.** "Everyone except X" can then collide with a grant from
  another group or a direct grant, and the precedence becomes something every reader has to
  learn. An opt-out record gives the same outcome for default groups without that.
- **Joining existing accounts as soon as `auto_join` is turned on.** That is a bulk change to
  many people's access from one checkbox. A previewed operator command makes it deliberate.

## Behaviour

### When a person joins automatically

Every account created live joins each default group, in the same transaction that creates it:

| Path | Code |
| --- | --- |
| An administrator creates the account in Directory administration | `DirectoryAdminService::create` |
| A new person accepts an access invitation | `AccessInvitationService::accept` |
| An application registers a new identity | `ApplicationIdentityRegistrationService::register` |

This happens whether or not the account starts enabled: a disabled account cannot sign in,
and it keeps its memberships if it is enabled later.

These never join automatically:
- test logins;
- accounts brought in by the identity import or directory archive commands, which carry their
  own state;
- existing accounts, until a backfill.

Joining locks each default group row before adding the member. That serializes it with a change
to the group's applications (`addClient` and `removeClient` lock the same row). It then reads the
group's applications, the opt-out and each grant's group sources with locking reads, so it sees
the latest commit even when the creating transaction took its repeatable-read snapshot earlier
(registration checks the address first). A new member therefore always ends up with exactly the
applications the group grants when it commits. `DefaultAccessMariaDbTest` reproduces that
ordering on MariaDB. Each join is audited as
`access_group_member_added`, with `auth_method` `default_access` and `joined_by` naming the path
(`directory_admin`, `invitation`, `application_registration` or `backfill`).

### Opt-outs

Removing a person from a group marked `auto_join` writes a row to `access_group_opt_outs`. The
`access_group_member_removed` audit row records `opted_out_of_default: true`. Adding the person
back deletes the opt-out. A backfill, and automatic joining, skip anyone with an opt-out for that
group. Turning `auto_join` off keeps the existing opt-outs, so they still apply if it is turned
on again.

### Backfill

```sh
php artisan auth-manager:access-group-backfill "<group id or exact name>"
php artisan auth-manager:access-group-backfill "<group id or exact name>" --apply
```

Without `--apply` the command writes nothing. It reports how many people would join, and for
each of the group's applications, how many would gain it (people who already hold it, directly
or through another group, are not counted). It never adds:
- deleted accounts;
- test logins;
- current members;
- anyone opted out.

It runs under the directory lock that every grant change takes, so it never interleaves with an
administrator's change. It is idempotent: a second run finds nobody left to add. It only accepts a
group marked `auto_join`.

## Caution

A default group gives its applications to every new account at once. That includes accounts
created through application registration or invitations, and so possibly accounts people create
for themselves. Put only applications every new account should reach into a default group. A
grant only lets a person sign in: each application still decides what they can do there. Keep
sensitive applications behind ordinary groups or application invitations. The Groups tab asks for
confirmation before a group becomes a default.

## API and UI

- `PUT /api/admin/groups/{group}/auto-join` with `auto_join` (boolean) turns default access on or
  off for a group, audited as `access_group_auto_join_changed`.
- Groups report `auto_join`. `GET /api/admin/users` reports each person's `opted_out_group_ids`.
- Directory administration:
  - **Groups tab:** marks default groups and offers the "New accounts join this group
    automatically" setting.
  - **A person's Groups section:** labels default groups, asks for confirmation before taking
    someone out of one, and shows "Taken out of this default group" for an opt-out.

## Limits

- The [portable directory archive](portable-directory.md) does not carry `auto_join` or opt-outs
  yet. After copying a directory, mark the default groups again. Recreate any opt-outs by taking
  those people out again before running a backfill.
- Membership is per account. There is no rule-based membership, for example by email domain.
