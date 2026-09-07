<?php

namespace App\Services;

use App\Models\PassportClient;
use App\Models\User;
use Illuminate\Support\Facades\DB;

class OAuthClientGrantService
{
    public function __construct(private readonly OAuthTokenRevocationService $tokens) {}

    public function allows(string $subject, string $clientId): bool
    {
        // Public MCP clients are registered before a user signs in. On the
        // resource profile, active users may consent without an administrator
        // pre-granting each installation. UC owns account and shop access.
        if (config('auth-manager.profile') === 'resource'
            && config('auth-manager.dynamic_client_registration') === true
            && PassportClient::query()->whereKey($clientId)
                ->where('revoked', false)->whereNotNull('dynamically_registered_at')->exists()) {
            return User::query()->find($subject)?->canLogin() === true;
        }

        return DB::table('oauth_client_grants')
            ->where('subject', $subject)
            ->where('oauth_client_id', $clientId)
            ->exists();
    }

    public function grant(string $subject, string $clientId): bool
    {
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
}
