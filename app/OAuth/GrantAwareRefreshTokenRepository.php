<?php

namespace App\OAuth;

use App\Services\OAuthClientGrantService;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\Bridge\RefreshTokenRepository;

class GrantAwareRefreshTokenRepository extends RefreshTokenRepository
{
    public function __construct(
        Dispatcher $events,
        private readonly OAuthClientGrantService $grants,
    ) {
        parent::__construct($events);
    }

    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        if (parent::isRefreshTokenRevoked($tokenId)) {
            return true;
        }

        $token = DB::table('oauth_refresh_tokens as refresh_tokens')
            ->join('oauth_access_tokens as access_tokens', 'access_tokens.id', '=', 'refresh_tokens.access_token_id')
            ->where('refresh_tokens.id', $tokenId)
            ->select(['access_tokens.user_id', 'access_tokens.client_id'])
            ->first();

        return $token === null || ! $this->grants->allows(
            (string) $token->user_id,
            (string) $token->client_id,
        );
    }
}
