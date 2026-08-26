<?php

namespace App\OAuth;

use App\Services\OAuthClientGrantService;
use App\Services\UserAccountStatusService;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\Bridge\RefreshTokenRepository;

class GrantAwareRefreshTokenRepository extends RefreshTokenRepository
{
    public function __construct(
        Dispatcher $events,
        private readonly OAuthClientGrantService $grants,
        private readonly UserAccountStatusService $accounts,
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

        if ($token === null) {
            return true;
        }

        $subject = (string) $token->user_id;

        return ! $this->accounts->allowsSignIn($subject)
            || ! $this->grants->allows($subject, (string) $token->client_id);
    }
}
