<?php

namespace BWH\AuthManager\Services;

use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Support\Mount;
use BWH\AuthManager\Support\StaticApplicationClients;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

class OAuthClientGrantService
{
    public function __construct(private readonly OAuthTokenRevocationService $tokens, private readonly StaticApplicationClients $clients) {}

    public function allows(string $subject, string $clientId, bool $lockForUpdate = false): bool
    {
        $user = User::query()->find($subject);
        if ($user?->isTestLogin()) {
            $client = PassportClient::query()->whereKey($clientId);
            if ($lockForUpdate) {
                $client->lockForUpdate();
            }
            $client = $client->first();
            if (! $user->canLogin() || ! $client instanceof PassportClient || ! $this->eligibleTestClient($client)) {
                return false;
            }
        }
        // Public MCP clients are registered before a user signs in. On the
        // resource profile, active users may consent without an administrator
        // pre-granting each installation. UC owns account and shop access.
        if (! $user?->isTestLogin() && config('auth-manager.profile') === 'resource'
            && config('auth-manager.dynamic_client_registration') === true
            && PassportClient::query()->whereKey($clientId)
                ->where('revoked', false)->whereNotNull('dynamically_registered_at')->exists()) {
            return $user?->canLogin() === true;
        }

        $grant = DB::table('oauth_client_grants')
            ->where('subject', $subject)
            ->where('oauth_client_id', $clientId);

        if ($lockForUpdate) {
            $grant->lockForUpdate();
        }

        return $grant->exists();
    }

    /**
     * Record a direct grant. True when the person had no direct grant before, including when
     * they already reached the application through a group.
     */
    public function grant(string $subject, string $clientId): bool
    {
        if (User::query()->find($subject)?->isTestLogin()) {
            $client = PassportClient::query()->find($clientId);
            if (! $client instanceof PassportClient || ! $this->eligibleTestClient($client)) {
                throw ValidationException::withMessages(['client' => 'Test logins require an active static authorization-code client.']);
            }
        }

        $inserted = DB::table('oauth_client_grants')->insertOrIgnore([
            'subject' => $subject,
            'oauth_client_id' => $clientId,
            'direct' => true,
            'created_at' => now(),
            'updated_at' => now(),
        ]) === 1;

        return $inserted || DB::table('oauth_client_grants')
            ->where('subject', $subject)
            ->where('oauth_client_id', $clientId)
            ->where('direct', false)
            ->update(['direct' => true, 'updated_at' => now()]) === 1;
    }

    /**
     * Remove a direct grant through this boundary so its existing tokens are revoked atomically.
     * While a group still grants the application, the person keeps access and their tokens:
     * only the direct grant goes. A grant held only through a group is not changed here.
     */
    public function revoke(string $subject, string $clientId): bool
    {
        return DB::transaction(function () use ($subject, $clientId): bool {
            $grant = DB::table('oauth_client_grants')
                ->where('subject', $subject)
                ->where('oauth_client_id', $clientId)
                ->lockForUpdate()
                ->first();

            if ($grant !== null && ! (bool) $grant->direct) {
                return false;
            }

            if ($grant !== null && $this->grantedByGroup($subject, $clientId)) {
                return DB::table('oauth_client_grants')
                    ->where('subject', $subject)
                    ->where('oauth_client_id', $clientId)
                    ->update(['direct' => false, 'updated_at' => now()]) === 1;
            }

            $removed = DB::table('oauth_client_grants')
                ->where('subject', $subject)
                ->where('oauth_client_id', $clientId)
                ->delete();

            $revokedTokens = $this->tokens->forSubjectAndClient($subject, $clientId);

            return $removed === 1 || $revokedTokens;
        });
    }

    /**
     * Bring the person's grant for one application in line with their direct grant and their
     * groups, after a group's members or applications changed. Adds a group-sourced grant, or
     * removes a grant nothing stands behind any longer and revokes its tokens.
     *
     * @return 'granted'|'revoked'|null
     */
    public function reconcile(string $subject, string $clientId): ?string
    {
        return DB::transaction(function () use ($subject, $clientId): ?string {
            $grant = DB::table('oauth_client_grants')
                ->where('subject', $subject)
                ->where('oauth_client_id', $clientId)
                ->lockForUpdate()
                ->first();
            $byGroup = $this->grantedByGroup($subject, $clientId);

            if ($grant === null) {
                if (! $byGroup) {
                    return null;
                }
                DB::table('oauth_client_grants')->insertOrIgnore([
                    'subject' => $subject,
                    'oauth_client_id' => $clientId,
                    'direct' => false,
                    'created_at' => now(),
                    'updated_at' => now(),
                ]);

                return 'granted';
            }

            if ((bool) $grant->direct || $byGroup) {
                return null;
            }

            DB::table('oauth_client_grants')
                ->where('subject', $subject)
                ->where('oauth_client_id', $clientId)
                ->delete();
            $this->tokens->forSubjectAndClient($subject, $clientId);

            return 'revoked';
        });
    }

    public function grantedByGroup(string $subject, string $clientId): bool
    {
        // A locking read: it sees the latest committed memberships and group applications, not
        // a repeatable-read snapshot the caller's transaction took before it acquired its locks.
        return DB::table('access_group_members')
            ->join('access_group_clients', 'access_group_clients.access_group_id', '=', 'access_group_members.access_group_id')
            ->where('access_group_members.subject', $subject)
            ->where('access_group_clients.oauth_client_id', $clientId)
            ->sharedLock()
            ->exists();
    }

    private function eligibleTestClient(PassportClient $client): bool
    {
        $provider = config('auth.guards.'.Mount::apiGuard().'.provider');

        return $this->clients->eligible($client)
            && ($client->provider === null || (is_string($provider) && $client->provider === $provider));
    }
}
