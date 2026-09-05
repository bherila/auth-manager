<?php

namespace App\OAuth;

use App\Models\User;
use App\Services\OAuthClientGrantService;
use App\Services\OAuthCredentialGenerationContext;
use App\Services\UserAccountStatusService;
use BWH\Auth\OAuth\Server\ResourceAccessTokenRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;

class GrantAwareAccessTokenRepository extends ResourceAccessTokenRepository
{
    public function __construct(
        Dispatcher $events,
        private readonly OAuthClientGrantService $grants,
        private readonly UserAccountStatusService $accounts,
        private readonly OAuthCredentialGenerationContext $credentialGeneration,
    ) {
        parent::__construct($events);
    }

    protected function isApplicationAccessTokenRevoked(string $tokenId): bool
    {
        $token = Passport::token()->newQuery()->whereKey($tokenId)->first();

        if ($token === null || Passport::client()->newQuery()
            ->whereKey($token->getAttribute('client_id'))
            ->where('revoked', false)
            ->doesntExist()) {
            return true;
        }

        $subject = $token->getAttribute('user_id');

        if ($subject === null) {
            return false;
        }

        $subject = (string) $subject;
        $currentVersion = $this->accounts->credentialVersionIfActive($subject);

        return $currentVersion === null
            || $currentVersion !== (int) $token->getAttribute('credential_version')
            || ! $this->grants->allows($subject, (string) $token->getAttribute('client_id'));
    }

    protected function persistResourceAccessToken(
        AccessTokenEntityInterface $accessTokenEntity,
        ?string $resource,
        bool $hasResourceColumn,
    ): void {
        $this->persistForActiveGrantedSubject(
            $accessTokenEntity,
            function () use ($accessTokenEntity, $resource, $hasResourceColumn): void {
                parent::persistResourceAccessToken($accessTokenEntity, $resource, $hasResourceColumn);
            },
        );
    }

    protected function persistUnboundAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        $this->persistForActiveGrantedSubject(
            $accessTokenEntity,
            function () use ($accessTokenEntity): void {
                parent::persistUnboundAccessToken($accessTokenEntity);
            },
        );
    }

    /** @param callable(): void $persist */
    private function persistForActiveGrantedSubject(AccessTokenEntityInterface $accessTokenEntity, callable $persist): void
    {
        $subject = $accessTokenEntity->getUserIdentifier();

        if ($subject === null) {
            $persist();

            return;
        }

        $clientId = $accessTokenEntity->getClient()->getIdentifier();
        $expectedVersion = $this->credentialGeneration->expectedFor((string) $subject);

        DB::transaction(function () use ($accessTokenEntity, $clientId, $expectedVersion, $persist, $subject): void {
            $user = User::query()->whereKey($subject)->lockForUpdate()->first();

            if (! $user instanceof User
                || ! $user->canLogin()
                || $expectedVersion === null
                || $expectedVersion !== (int) $user->credential_version) {
                throw OAuthServerException::accessDenied('The provider credentials changed during token issuance.');
            }

            $grantExists = DB::table('oauth_client_grants')
                ->where('subject', (string) $subject)
                ->where('oauth_client_id', $clientId)
                ->lockForUpdate()
                ->exists();

            if (! $grantExists) {
                throw OAuthServerException::accessDenied('Application access has been removed.');
            }

            $persist();
            DB::table('oauth_access_tokens')
                ->where('id', $accessTokenEntity->getIdentifier())
                ->update(['credential_version' => $expectedVersion]);
        });
    }
}
