<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;

class OAuthClientGrantService
{
    public function allows(string $subject, string $clientId): bool
    {
        return DB::table('oauth_client_grants')
            ->where('subject', $subject)
            ->where('oauth_client_id', $clientId)
            ->exists();
    }

    public function grant(string $subject, string $clientId): void
    {
        DB::table('oauth_client_grants')->insertOrIgnore([
            'subject' => $subject,
            'oauth_client_id' => $clientId,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    /**
     * Remove a grant through this boundary so its existing tokens are revoked atomically.
     */
    public function revoke(string $subject, string $clientId): void
    {
        DB::transaction(function () use ($subject, $clientId): void {
            DB::table('oauth_client_grants')
                ->where('subject', $subject)
                ->where('oauth_client_id', $clientId)
                ->delete();

            $accessTokenIds = DB::table('oauth_access_tokens')
                ->where('user_id', $subject)
                ->where('client_id', $clientId)
                ->pluck('id');

            if ($accessTokenIds->isEmpty()) {
                return;
            }

            DB::table('oauth_refresh_tokens')
                ->whereIn('access_token_id', $accessTokenIds)
                ->update(['revoked' => true]);

            DB::table('oauth_access_tokens')
                ->whereIn('id', $accessTokenIds)
                ->update(['revoked' => true]);
        });
    }
}
