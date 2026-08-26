<?php

namespace App\OAuth;

use App\Models\User;
use App\Services\OAuthClientGrantService;
use App\Services\UserAccountStatusService;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\Bridge\AccessTokenRepository;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;

class GrantAwareAccessTokenRepository extends AccessTokenRepository
{
    public function __construct(
        Dispatcher $events,
        private readonly OAuthClientGrantService $grants,
        private readonly UserAccountStatusService $accounts,
    ) {
        parent::__construct($events);
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        if (parent::isAccessTokenRevoked($tokenId)) {
            return true;
        }

        $token = Passport::token()->newQuery()->whereKey($tokenId)->first();

        if ($token === null || Passport::client()->newQuery()
            ->whereKey($token->getAttribute('client_id'))
            ->where('revoked', false)
            ->doesntExist()) {
            return true;
        }

        $subject = $token->getAttribute('user_id');

        return $subject !== null && (
            ! $this->accounts->allowsSignIn((string) $subject)
            || ! $this->grants->allows(
                (string) $subject,
                (string) $token->getAttribute('client_id'),
            )
        );
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        $subject = $accessTokenEntity->getUserIdentifier();

        if ($subject === null) {
            parent::persistNewAccessToken($accessTokenEntity);

            return;
        }

        $clientId = $accessTokenEntity->getClient()->getIdentifier();

        DB::transaction(function () use ($accessTokenEntity, $subject, $clientId): void {
            $user = User::query()->whereKey($subject)->lockForUpdate()->first();

            if (! $user instanceof User || ! $user->canLogin()) {
                throw OAuthServerException::accessDenied('The provider account is not active.');
            }

            $grantExists = DB::table('oauth_client_grants')
                ->where('subject', (string) $subject)
                ->where('oauth_client_id', $clientId)
                ->lockForUpdate()
                ->exists();

            if (! $grantExists) {
                throw OAuthServerException::accessDenied('Application access has been removed.');
            }

            parent::persistNewAccessToken($accessTokenEntity);
        });
    }
}
