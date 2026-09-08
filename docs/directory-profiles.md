# Provider directory profiles

An active provider administrator can edit a person's display name in the directory
or through `PATCH /api/admin/users/{subject}/name` with a non-empty `name` string
of at most 255 characters. The update uses the existing directory row lock and
records `directory_name_changed` with the acting administrator and target. Sending
the unchanged name does not create another change event. A display-name update
does not change roles, credentials, account status, or application grants.

The updated value is returned as `name` by `/api/oauth/user` when the consuming
application next retrieves that subject's identity profile. This is a profile
refresh boundary, not a claim that every application session updates immediately.
Each consumer owns its display-name or alias mapping, including shorter column
limits, normalization and any distinct application nickname. Consumers must not
use a changed name or email to adopt another local account; the identity join is
the configured provider and exact subject.

Provider roles govern this directory. OAuth client grants govern permission to
request credentials. Application roles and workspace memberships remain decisions
of the consuming application; editing the provider profile grants none of them.
