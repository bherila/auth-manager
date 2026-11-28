<?php

namespace BWH\AuthManager\Services;

use BWH\Auth\Models\AuthAuditLog;
use BWH\Auth\Support\ClientIp;
use BWH\AuthManager\Models\AccessGroup;
use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

/**
 * Groups grant applications to their members, and nothing else: no roles, no application
 * permissions. A group's applications are expanded into the per-person `oauth_client_grants`
 * rows that sign-in already checks, so a change here takes effect exactly as a direct grant
 * or revocation would. A person keeps an application while a direct grant or any of their
 * groups still grants it; when the last one goes, their grant is removed and its tokens are
 * revoked.
 *
 * Every change holds the directory lock that direct grant changes take, so the two never
 * interleave.
 */
class AccessGroupService
{
    public const EVENT_GROUP_CREATED = 'access_group_created';

    public const EVENT_GROUP_UPDATED = 'access_group_updated';

    public const EVENT_GROUP_DELETED = 'access_group_deleted';

    public const EVENT_MEMBER_ADDED = 'access_group_member_added';

    public const EVENT_MEMBER_REMOVED = 'access_group_member_removed';

    public const EVENT_CLIENT_ADDED = 'access_group_client_added';

    public const EVENT_CLIENT_REMOVED = 'access_group_client_removed';

    public const EVENT_AUTO_JOIN_CHANGED = 'access_group_auto_join_changed';

    /** How a person came to join a default group, recorded on the membership audit row. */
    public const JOINED_BY_DIRECTORY_ADMIN = 'directory_admin';

    public const JOINED_BY_INVITATION = 'invitation';

    public const JOINED_BY_APPLICATION_REGISTRATION = 'application_registration';

    public const JOINED_BY_BACKFILL = 'backfill';

    public function __construct(
        private readonly OAuthClientGrantService $grants,
        private readonly ProviderAdministrators $administrators,
        private readonly DirectoryAdminAuditLogger $audit,
    ) {}

    public function create(Request $request, User $actor, string $name, ?string $description): AccessGroup
    {
        return DB::transaction(function () use ($request, $actor, $name, $description): AccessGroup {
            $this->administrators->actor($this->administrators->lockDirectory(), $actor, $request);
            $this->assertNameAvailable($name);
            $group = AccessGroup::query()->create(['name' => $name, 'description' => $description]);
            $this->recordGroup($request, $actor, self::EVENT_GROUP_CREATED, $group);

            return $group;
        }, 3);
    }

    public function update(Request $request, User $actor, AccessGroup $group, string $name, ?string $description): AccessGroup
    {
        return DB::transaction(function () use ($request, $actor, $group, $name, $description): AccessGroup {
            $this->administrators->actor($this->administrators->lockDirectory(), $actor, $request);
            $locked = $this->lockGroup($group);
            if ($locked->name !== $name) {
                $this->assertNameAvailable($name, $locked);
            }
            $previous = ['name' => $locked->name, 'description' => $locked->description];
            $locked->forceFill(['name' => $name, 'description' => $description]);
            if ($locked->isDirty()) {
                $locked->save();
                $this->recordGroup($request, $actor, self::EVENT_GROUP_UPDATED, $locked, ['previous' => $previous]);
            }

            return $locked;
        }, 3);
    }

    /** Delete the group. Members lose each application nothing else still grants them. */
    public function delete(Request $request, User $actor, AccessGroup $group): void
    {
        DB::transaction(function () use ($request, $actor, $group): void {
            $users = $this->administrators->lockDirectory();
            $this->administrators->actor($users, $actor, $request);
            $locked = $this->lockGroup($group);
            $subjects = $this->memberSubjects($locked);
            $clientIds = $this->clientIds($locked);
            // Explicit, not left to the foreign-key cascade, so reconciliation below never
            // sees the group's rows on a connection that does not enforce foreign keys.
            DB::table('access_group_members')->where('access_group_id', $locked->getKey())->delete();
            DB::table('access_group_clients')->where('access_group_id', $locked->getKey())->delete();
            $locked->delete();

            $revoked = [];
            foreach ($subjects as $subject) {
                foreach ($clientIds as $clientId) {
                    if ($this->grants->reconcile($subject, $clientId) === 'revoked') {
                        $revoked[$subject][] = $clientId;
                    }
                }
            }
            foreach ($revoked as $subject => $removed) {
                $this->recordPerson($request, $actor, $users, (string) $subject, DirectoryAdminService::EVENT_CLIENT_REVOKED, $locked, ['oauth_client_ids' => $removed]);
            }
            $this->recordGroup($request, $actor, self::EVENT_GROUP_DELETED, $locked, [
                'member_subjects' => $subjects,
                'oauth_client_ids' => $clientIds,
            ]);
        }, 3);
    }

    public function addMember(Request $request, User $actor, AccessGroup $group, User $target): AccessGroup
    {
        return DB::transaction(function () use ($request, $actor, $group, $target): AccessGroup {
            $users = $this->administrators->lockDirectory();
            $this->administrators->actor($users, $actor, $request);
            $person = $this->administrators->target($users, $target);
            if ($person->isTestLogin()) {
                throw ValidationException::withMessages(['user' => 'Test logins are granted applications individually and cannot join a group.']);
            }
            $locked = $this->lockGroup($group);
            $added = DB::table('access_group_members')->insertOrIgnore([
                'access_group_id' => $locked->getKey(),
                'subject' => $person->getKey(),
                'created_at' => now(),
                'updated_at' => now(),
            ]) === 1;
            // Adding a person back undoes an opt-out, whether or not they were already a member.
            DB::table('access_group_opt_outs')
                ->where('access_group_id', $locked->getKey())
                ->where('subject', $person->getKey())
                ->delete();
            if (! $added) {
                return $locked;
            }

            $granted = [];
            foreach ($this->clientIds($locked) as $clientId) {
                if ($this->grants->reconcile((string) $person->getKey(), $clientId) === 'granted') {
                    $granted[] = $clientId;
                }
            }
            $this->audit->record($request, $actor, $person, self::EVENT_MEMBER_ADDED, [
                'access_group_id' => $locked->getKey(),
                'access_group_name' => $locked->name,
                'granted_oauth_client_ids' => $granted,
            ]);

            return $locked;
        }, 3);
    }

    public function removeMember(Request $request, User $actor, AccessGroup $group, User $target): AccessGroup
    {
        return DB::transaction(function () use ($request, $actor, $group, $target): AccessGroup {
            $users = $this->administrators->lockDirectory();
            $this->administrators->actor($users, $actor, $request);
            $person = $this->administrators->target($users, $target);
            $locked = $this->lockGroup($group);
            $removed = DB::table('access_group_members')
                ->where('access_group_id', $locked->getKey())
                ->where('subject', $person->getKey())
                ->delete() === 1;
            if (! $removed) {
                return $locked;
            }
            // Taking someone out of a default group is a decision about them: a backfill must
            // never put them back. Adding them again clears it.
            if ($locked->auto_join) {
                DB::table('access_group_opt_outs')->insertOrIgnore([
                    'access_group_id' => $locked->getKey(),
                    'subject' => $person->getKey(),
                    'created_at' => now(),
                    'updated_at' => now(),
                ]);
            }

            $revoked = [];
            foreach ($this->clientIds($locked) as $clientId) {
                if ($this->grants->reconcile((string) $person->getKey(), $clientId) === 'revoked') {
                    $revoked[] = $clientId;
                }
            }
            $this->audit->record($request, $actor, $person, self::EVENT_MEMBER_REMOVED, [
                'access_group_id' => $locked->getKey(),
                'access_group_name' => $locked->name,
                'revoked_oauth_client_ids' => $revoked,
                'opted_out_of_default' => (bool) $locked->auto_join,
            ]);

            return $locked;
        }, 3);
    }

    /**
     * Mark a group as default access, or stop. Turning it on adds nobody who already has an
     * account: an operator brings existing people in deliberately with backfill().
     */
    public function setAutoJoin(Request $request, User $actor, AccessGroup $group, bool $autoJoin): AccessGroup
    {
        return DB::transaction(function () use ($request, $actor, $group, $autoJoin): AccessGroup {
            $this->administrators->actor($this->administrators->lockDirectory(), $actor, $request);
            $locked = $this->lockGroup($group);
            if ((bool) $locked->auto_join === $autoJoin) {
                return $locked;
            }
            $locked->forceFill(['auto_join' => $autoJoin])->save();
            $this->recordGroup($request, $actor, self::EVENT_AUTO_JOIN_CHANGED, $locked, ['auto_join' => $autoJoin]);

            return $locked;
        }, 3);
    }

    /**
     * Join a newly created account to every default group, inside the transaction that created
     * it. Locking each default group first serializes this with a change to that group's
     * applications, so the new member holds every application the group grants when the
     * transaction commits. Test logins never join groups.
     *
     * @param  self::JOINED_BY_*  $via
     * @return list<int> the groups joined
     */
    public function joinDefaultGroups(User $person, string $via): array
    {
        if ($person->isTestLogin()) {
            return [];
        }

        return DB::transaction(function () use ($person, $via): array {
            $joined = [];
            foreach (AccessGroup::query()->where('auto_join', true)->orderBy('id')->lockForUpdate()->get() as $group) {
                if ($this->join($group, $person, $via)) {
                    $joined[] = (int) $group->getKey();
                }
            }

            return $joined;
        });
    }

    /**
     * Bring every existing account into a default group, except deleted accounts, test logins,
     * current members and anyone an administrator took out of it. Without $apply nothing is
     * written: the result says how many people would join and how many would gain each
     * application they do not already hold.
     *
     * @return array{people:int, applications:array<string,int>}
     */
    public function backfill(AccessGroup $group, bool $apply): array
    {
        return DB::transaction(function () use ($group, $apply): array {
            $users = $this->administrators->lockDirectory();
            $locked = $this->lockGroup($group);
            if (! $locked->auto_join) {
                throw ValidationException::withMessages(['group' => 'Only a group that new accounts join automatically can be backfilled.']);
            }
            $excluded = DB::table('access_group_members')->where('access_group_id', $locked->getKey())->pluck('subject')
                ->merge(DB::table('access_group_opt_outs')->where('access_group_id', $locked->getKey())->pluck('subject'))
                ->map(static fn (mixed $subject): int => (int) $subject)
                ->flip();
            $eligible = $users->filter(static fn (User $user): bool => ! $user->trashed() && ! $user->isTestLogin()
                && ! $excluded->has((int) $user->getKey()))->values();
            $clientIds = $this->clientIds($locked);
            $held = DB::table('oauth_client_grants')
                ->whereIn('subject', $eligible->map(static fn (User $user): int => (int) $user->getKey())->all())
                ->whereIn('oauth_client_id', $clientIds)
                ->get(['subject', 'oauth_client_id'])
                ->map(static fn (object $grant): string => $grant->subject.'|'.$grant->oauth_client_id)
                ->flip();

            $applications = array_fill_keys($clientIds, 0);
            foreach ($eligible as $user) {
                foreach ($clientIds as $clientId) {
                    if (! $held->has($user->getKey().'|'.$clientId)) {
                        $applications[$clientId]++;
                    }
                }
                if ($apply) {
                    $this->join($locked, $user, self::JOINED_BY_BACKFILL);
                }
            }

            return ['people' => $eligible->count(), 'applications' => $applications];
        }, 3);
    }

    /** Add one person to a default group they have not been taken out of, grant its applications and audit it. */
    private function join(AccessGroup $group, User $person, string $via): bool
    {
        $optedOut = DB::table('access_group_opt_outs')
            ->where('access_group_id', $group->getKey())
            ->where('subject', $person->getKey())
            ->exists();
        if ($optedOut) {
            return false;
        }
        $added = DB::table('access_group_members')->insertOrIgnore([
            'access_group_id' => $group->getKey(),
            'subject' => $person->getKey(),
            'created_at' => now(),
            'updated_at' => now(),
        ]) === 1;
        if (! $added) {
            return false;
        }

        $granted = [];
        foreach ($this->clientIds($group) as $clientId) {
            if ($this->grants->reconcile((string) $person->getKey(), $clientId) === 'granted') {
                $granted[] = $clientId;
            }
        }
        AuthAuditLog::create([
            'user_id' => $person->getKey(),
            'email' => $person->email,
            'event' => self::EVENT_MEMBER_ADDED,
            'auth_method' => 'default_access',
            'succeeded' => true,
            'metadata' => [
                'access_group_id' => $group->getKey(),
                'access_group_name' => $group->name,
                'granted_oauth_client_ids' => $granted,
                'joined_by' => $via,
            ],
        ]);

        return true;
    }

    public function addClient(Request $request, User $actor, AccessGroup $group, PassportClient $client): AccessGroup
    {
        return DB::transaction(function () use ($request, $actor, $group, $client): AccessGroup {
            $users = $this->administrators->lockDirectory();
            $this->administrators->actor($users, $actor, $request);
            $locked = $this->lockGroup($group);
            $active = PassportClient::query()->whereKey($client->getKey())->lockForUpdate()->first();
            if (! $active instanceof PassportClient || $active->revoked) {
                throw ValidationException::withMessages(['client' => 'The selected application is not active.']);
            }
            $clientId = (string) $active->getKey();
            $added = DB::table('access_group_clients')->insertOrIgnore([
                'access_group_id' => $locked->getKey(),
                'oauth_client_id' => $clientId,
                'created_at' => now(),
                'updated_at' => now(),
            ]) === 1;
            if (! $added) {
                return $locked;
            }

            $granted = [];
            foreach ($this->memberSubjects($locked, activeOnly: true) as $subject) {
                if ($this->grants->reconcile($subject, $clientId) === 'granted') {
                    $granted[] = $subject;
                    $this->recordPerson($request, $actor, $users, $subject, DirectoryAdminService::EVENT_CLIENT_GRANTED, $locked, ['oauth_client_id' => $clientId]);
                }
            }
            $this->recordGroup($request, $actor, self::EVENT_CLIENT_ADDED, $locked, [
                'oauth_client_id' => $clientId,
                'granted_subjects' => $granted,
            ]);

            return $locked;
        }, 3);
    }

    public function removeClient(Request $request, User $actor, AccessGroup $group, PassportClient $client): AccessGroup
    {
        return DB::transaction(function () use ($request, $actor, $group, $client): AccessGroup {
            $users = $this->administrators->lockDirectory();
            $this->administrators->actor($users, $actor, $request);
            $locked = $this->lockGroup($group);
            $clientId = (string) $client->getKey();
            $removed = DB::table('access_group_clients')
                ->where('access_group_id', $locked->getKey())
                ->where('oauth_client_id', $clientId)
                ->delete() === 1;
            if (! $removed) {
                return $locked;
            }

            $revoked = [];
            foreach ($this->memberSubjects($locked) as $subject) {
                if ($this->grants->reconcile($subject, $clientId) === 'revoked') {
                    $revoked[] = $subject;
                    $this->recordPerson($request, $actor, $users, $subject, DirectoryAdminService::EVENT_CLIENT_REVOKED, $locked, ['oauth_client_id' => $clientId]);
                }
            }
            $this->recordGroup($request, $actor, self::EVENT_CLIENT_REMOVED, $locked, [
                'oauth_client_id' => $clientId,
                'revoked_subjects' => $revoked,
            ]);

            return $locked;
        }, 3);
    }

    /** @return list<string> */
    public function memberSubjects(AccessGroup $group, bool $activeOnly = false): array
    {
        $query = DB::table('access_group_members')
            ->where('access_group_id', $group->getKey())
            ->orderBy('subject');
        if ($activeOnly) {
            // A deleted person keeps their memberships until purged, but is never granted again.
            $query->whereIn('subject', User::query()->select('id'));
        }

        return $query->pluck('subject')->map(static fn (mixed $subject): string => (string) $subject)->all();
    }

    /** @return list<string> */
    public function clientIds(AccessGroup $group): array
    {
        return DB::table('access_group_clients')
            ->where('access_group_id', $group->getKey())
            ->orderBy('oauth_client_id')
            ->pluck('oauth_client_id')
            ->map(static fn (mixed $id): string => (string) $id)
            ->all();
    }

    private function lockGroup(AccessGroup $group): AccessGroup
    {
        $locked = AccessGroup::query()->whereKey($group->getKey())->lockForUpdate()->first();
        abort_unless($locked instanceof AccessGroup, 404);

        return $locked;
    }

    private function assertNameAvailable(string $name, ?AccessGroup $except = null): void
    {
        $taken = AccessGroup::query()
            ->where('name', $name)
            ->when($except !== null, static fn ($query) => $query->whereKeyNot($except->getKey()))
            ->exists();
        if ($taken) {
            throw ValidationException::withMessages(['name' => 'Another group already has this name.']);
        }
    }

    /**
     * @param  Collection<int, User>  $users
     * @param  array<string, mixed>  $metadata
     */
    private function recordPerson(Request $request, User $actor, Collection $users, string $subject, string $event, AccessGroup $group, array $metadata): void
    {
        $person = $users->first(static fn (User $user): bool => (string) $user->getKey() === $subject);
        if (! $person instanceof User) {
            return;
        }
        $this->audit->record($request, $actor, $person, $event, [
            ...$metadata,
            'access_group_id' => $group->getKey(),
            'access_group_name' => $group->name,
        ]);
    }

    /** @param array<string, mixed> $metadata */
    private function recordGroup(Request $request, User $actor, string $event, AccessGroup $group, array $metadata = []): void
    {
        AuthAuditLog::create([
            'user_id' => null,
            'acting_user_id' => $actor->getKey(),
            'email' => null,
            'event' => $event,
            'auth_method' => 'admin',
            'succeeded' => true,
            'ip_address' => ClientIp::resolve($request),
            'user_agent' => $request->userAgent(),
            'session_id' => $request->hasSession() ? $request->session()->getId() : null,
            'metadata' => [
                'access_group_id' => $group->getKey(),
                'access_group_name' => $group->name,
                ...$metadata,
            ],
        ]);
    }
}
