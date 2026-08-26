<?php

namespace App\Services;

use Illuminate\Database\Query\Builder;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;

class OAuthTokenRevocationService
{
    public function forSubject(string $subject): bool
    {
        $authCodes = DB::table('oauth_auth_codes')
            ->where('user_id', $subject)
            ->where('revoked', false)
            ->update(['revoked' => true]);

        return $this->revoke(
            DB::table('oauth_access_tokens')->where('user_id', $subject),
        ) || $authCodes > 0;
    }

    public function forSubjectAndClient(string $subject, string $clientId): bool
    {
        $authCodes = DB::table('oauth_auth_codes')
            ->where('user_id', $subject)
            ->where('client_id', $clientId)
            ->where('revoked', false)
            ->update(['revoked' => true]);

        return $this->revoke(
            DB::table('oauth_access_tokens')
                ->where('user_id', $subject)
                ->where('client_id', $clientId),
        ) || $authCodes > 0;
    }

    private function revoke(Builder $accessTokens): bool
    {
        $changed = false;

        $accessTokens
            ->where('revoked', false)
            ->select('id')
            ->chunkById(500, function (Collection $tokens) use (&$changed): void {
                $ids = $tokens->pluck('id');
                $refreshTokens = DB::table('oauth_refresh_tokens')
                    ->whereIn('access_token_id', $ids)
                    ->where('revoked', false)
                    ->update(['revoked' => true]);
                $updatedAccessTokens = DB::table('oauth_access_tokens')
                    ->whereIn('id', $ids)
                    ->where('revoked', false)
                    ->update(['revoked' => true]);

                $changed = $changed || $refreshTokens > 0 || $updatedAccessTokens > 0;
            }, 'id');

        return $changed;
    }
}
