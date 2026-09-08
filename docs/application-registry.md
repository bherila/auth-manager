# Trusted application registry

The provider instance owns an explicit registry, independent of OAuth registration.
An active provider administrator manages `/admin/applications`. Each entry has an
immutable lowercase key, a display name, an absolute HTTPS launch URL and an enabled
flag. URLs exclude credentials, query strings and fragments. This navigation URL is
never used as a backchannel API destination or as proof of application ownership.

Mappings accept only existing, nonrevoked static authorization-code clients in this
instance. The configured shared-package dynamic-registration marker is checked on
both save and launch discovery; invalid marker configuration or a missing marker field fails closed. A client
maps to at most one application, while an application may map several static clients.
Saving a mapping does not change client metadata, first-party status, consent rules,
user grants or application permissions. Registration changes are audited.

`RelyingApplications` preserves the `{key, name, url}` identity-payload contract.
With `AUTH_MANAGER_APP_REGISTRY_LAUNCH_ENABLED=true`, it returns only enabled registry
entries for which the subject holds an existing grant to an eligible mapped client.
Revoked, deleted or dynamically registered clients cannot make an entry visible.
Application keys come from the registry and survive display-name changes.

## Rollout

1. Deploy the additive tables and administration surface. Both deployment profiles
   run framework-only migrations before application rsync; a migration failure stops
   the application update. Table creation is restartable after partial MySQL DDL.
2. Leave `AUTH_MANAGER_APP_REGISTRY_LAUNCH_ENABLED=false` initially. Legacy navigation
   still derives launch origins from static clients with existing grants, but excludes
   dynamic registrations. It never creates registry entries or trusted API endpoints.
3. An administrator registers each intended application, verifies the exact launch
   destination and maps its static OAuth client IDs. No real deployment entries are
   seeded or committed. Verify grant-bearing and ungranted synthetic subjects.
4. Enable the launch flag in the instance's private configuration and rebuild the
   configuration cache. Verify the next identity-profile fetch returns the intended
   entries, including stable keys. Existing consuming sessions may cache older lists
   until their next profile refresh or sign-in.
5. Roll back navigation by disabling the flag and refreshing configuration; retain
   the additive tables. Disabling a registry entry withdraws navigation only: revoke
   OAuth grants or application permissions through their respective owners when access
   itself must end.

The instance registry does not publish application data, provision user projections,
or authorize delegated application writes. A future delegated API integration must
establish its own trusted destination, actor proof and application authorization.
