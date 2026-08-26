<?php

namespace App\OAuth;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\Bridge\AccessTokenRepository;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;

class GrantAwareAccessTokenRepository extends AccessTokenRepository
{
    public function __construct(
        Dispatcher $events,
    ) {
        parent::__construct($events);
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
