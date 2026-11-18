# Access groups

An access group grants its applications to every member. It is the same coarse permission as a
direct OAuth client grant: it decides who may sign in to an application, never what they can do
there. Roles, workspaces and other application permissions stay with each application.

Provider administrators manage groups in **Directory administration** (`/admin/users`), or through
the JSON API below. Groups are available on every profile; an instance with no groups behaves
exactly as before.

## How a group grants access

Sign-in reads one table, `oauth_client_grants`, whatever the source. A group's applications are
expanded into those per-person rows, and each row's `direct` flag records whether it also stands on
its own:

| Change | Effect on a member's grant for an application |
| --- | --- |
| Join a group that has the application | A grant is added if the person had none (`direct = false`) |
| Leave a group, or the group loses the application, or the group is deleted | The grant is removed only if it is not direct and no other group of theirs has the application |
| Remove a direct grant while a group still has the application | The grant stays, now `direct = false`; access and tokens continue |
| Add a direct grant to group-held access | The same row becomes `direct = true` |

A person keeps an application while a direct grant or any of their groups still grants it. When
the last source goes, the grant is removed and the person's tokens for that application are
revoked in the same transaction, exactly as a direct revocation does. Every change holds the
directory lock that direct grant changes take, so the two never interleave.

Removing a direct grant through **Directory administration** never touches access a group gives:
that is changed from the group. The person's grant list shows which applications come through a
group.

Existing grants were all made directly and are marked `direct = true` by the migration.

## Who can be a member

Any provider account except a test login: test logins are granted applications individually (see
[test logins](test-logins.md)). A deleted person keeps their memberships until their record is
purged but is never granted an application again. A disabled person stays a member; disabling
already stops their sign-in.

Only an active (non-revoked) OAuth client can be added to a group.

## Audit

Every change is recorded in the authentication audit log with the acting administrator:

| Event | Recorded against |
| --- | --- |
| `access_group_created`, `access_group_updated`, `access_group_deleted` | The group (no person) |
| `access_group_client_added`, `access_group_client_removed` | The group, listing the people granted or revoked |
| `access_group_member_added`, `access_group_member_removed` | The person, listing the applications granted or revoked |
| `directory_client_granted`, `directory_client_revoked` | Each person whose access changed because a group gained or lost an application, or was deleted |

Group events carry `access_group_id` and `access_group_name` in their metadata.

## API

All routes require an active provider administrator and use the provider session, like the rest of
`/api/admin`.

| Method and path | Purpose |
| --- | --- |
| `GET /api/admin/groups` | List groups: `id`, `name`, `description`, `member_ids`, `client_ids` |
| `POST /api/admin/groups` | Create: `name` (unique, at most 100 characters), `description` (nullable, at most 500) |
| `PATCH /api/admin/groups/{group}` | Rename or re-describe |
| `DELETE /api/admin/groups/{group}` | Delete; members lose what only this group granted |
| `PUT` / `DELETE /api/admin/groups/{group}/members/{user}` | Add or remove a member |
| `PUT` / `DELETE /api/admin/groups/{group}/clients/{client}` | Add or remove an application |

`GET /api/admin/users` also reports each person's `direct_client_ids` and `group_ids` beside the
effective `client_ids`.

## Directory copies

The [portable directory archive](portable-directory.md) carries groups, memberships, group
applications and each grant's `direct` flag. Archive version 2 adds them; both ends must run a
provider version that supports it.
