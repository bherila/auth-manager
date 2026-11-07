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

    public function grant(string $subject, string $clientId): bool
    {
        if (User::query()->find($subject)?->isTestLogin()) {
            $client = PassportClient::query()->find($clientId);
            if (! $client instanceof PassportClient || ! $this->eligibleTestClient($client)) {
                throw ValidationException::withMessages(['client' => 'Test logins require an active static authorization-code client.']);
            }
        }

        return DB::table('oauth_client_grants')->insertOrIgnore([
            'subject' => $subject,
            'oauth_client_id' => $clientId,
            'created_at' => now(),
            'updated_at' => now(),
        ]) === 1;
    }

    /**
     * Remove a grant through this boundary so its existing tokens are revoked atomically.
     */
    public function revoke(string $subject, string $clientId): bool
    {
        return DB::transaction(function () use ($subject, $clientId): bool {
            $removed = DB::table('oauth_client_grants')
                ->where('subject', $subject)
                ->where('oauth_client_id', $clientId)
                ->delete();

            $revokedTokens = $this->tokens->forSubjectAndClient($subject, $clientId);

            return $removed === 1 || $revokedTokens;
        });
    }

    private function eligibleTestClient(PassportClient $client): bool
    {
        $provider = config('auth.guards.'.Mount::apiGuard().'.provider');

        return $this->clients->eligible($client)
            && ($client->provider === null || (is_string($provider) && $client->provider === $provider));
    }
}
