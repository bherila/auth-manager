<?php

namespace App\OAuth;

use App\Services\OAuthClientGrantService;
use App\Services\UserAccountStatusService;
use Laravel\Passport\Bridge\AuthCodeRepository;
use Laravel\Passport\Passport;

class GrantAwareAuthCodeRepository extends AuthCodeRepository
{
    public function __construct(
        private readonly OAuthClientGrantService $grants,
        private readonly UserAccountStatusService $accounts,
    ) {}

    public function isAuthCodeRevoked(string $codeId): bool
    {
        if (parent::isAuthCodeRevoked($codeId)) {
            return true;
        }

        $code = Passport::authCode()->newQuery()->whereKey($codeId)->first();

        if ($code === null) {
            return true;
        }

        $subject = (string) $code->getAttribute('user_id');

        return ! $this->accounts->allowsSignIn($subject)
            || ! $this->grants->allows($subject, (string) $code->getAttribute('client_id'));
    }
}
