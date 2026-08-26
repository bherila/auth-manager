<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

class OAuthClientGrantService
{
    public function __construct(private readonly OAuthTokenRevocationService $tokens) {}

    public function allows(string $subject, string $clientId): bool
    {
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
