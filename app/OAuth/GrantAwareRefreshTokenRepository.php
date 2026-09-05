<?php

namespace App\OAuth;

use App\Services\OAuthClientGrantService;
use App\Services\OAuthCredentialGenerationContext;
use App\Services\UserAccountStatusService;
use BWH\Auth\OAuth\Server\ResourceRefreshTokenRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\DB;

class GrantAwareRefreshTokenRepository extends ResourceRefreshTokenRepository
{
    public function __construct(
        Dispatcher $events,
        private readonly OAuthClientGrantService $grants,
        private readonly UserAccountStatusService $accounts,
        private readonly OAuthCredentialGenerationContext $credentialGeneration,
    ) {
        parent::__construct($events);
    }

    protected function isApplicationRefreshTokenRevoked(string $tokenId): bool
    {
        $token = DB::table('oauth_refresh_tokens as refresh_tokens')
            ->join('oauth_access_tokens as access_tokens', 'access_tokens.id', '=', 'refresh_tokens.access_token_id')
            ->where('refresh_tokens.id', $tokenId)
            ->select([
                'access_tokens.user_id',
                'access_tokens.client_id',
                'access_tokens.credential_version',
            ])
            ->first();

        if ($token === null) {
            return true;
        }

        $subject = (string) $token->user_id;
        $currentVersion = $this->accounts->credentialVersionIfActive($subject);

        if ($currentVersion === null
            || $currentVersion !== (int) $token->credential_version
            || ! $this->grants->allows($subject, (string) $token->client_id)) {
            return true;
        }

        $this->credentialGeneration->expect($subject, $currentVersion);

        return false;
    }
}
