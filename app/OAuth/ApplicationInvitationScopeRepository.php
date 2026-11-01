<?php

namespace BWH\AuthManager\OAuth;

use BWH\AuthManager\Support\ApplicationInvitations;
use Laravel\Passport\Bridge\ScopeRepository;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;

/**
 * Keeps the admission invitation scope to client credentials tokens.
 *
 * It names an application acting as itself, so it is never offered on a consent screen, never
 * issued for a person, and never carried by a refreshed token: anywhere but a client credentials
 * token request it is an unknown scope.
 */
class ApplicationInvitationScopeRepository extends ScopeRepository
{
    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        if ($identifier === ApplicationInvitations::SCOPE && ! $this->clientCredentialsTokenRequest()) {
            return null;
        }

        return parent::getScopeEntityByIdentifier($identifier);
    }

    public function finalizeScopes(array $scopes, string $grantType, ClientEntityInterface $clientEntity, ?string $userIdentifier = null, ?string $authCodeId = null): array
    {
        $finalized = parent::finalizeScopes($scopes, $grantType, $clientEntity, $userIdentifier, $authCodeId);
        if ($grantType === 'client_credentials' && $userIdentifier === null) {
            return $finalized;
        }

        return array_values(array_filter($finalized, static fn (ScopeEntityInterface $scope): bool => $scope->getIdentifier() !== ApplicationInvitations::SCOPE));
    }

    private function clientCredentialsTokenRequest(): bool
    {
        if (! app()->bound('request')) {
            return false;
        }
        $request = request();

        return $request->routeIs('passport.token') && $request->input('grant_type') === 'client_credentials';
    }
}
