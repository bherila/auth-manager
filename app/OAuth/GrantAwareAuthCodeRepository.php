<?php

namespace App\OAuth;

use App\Services\OAuthClientGrantService;
use Laravel\Passport\Bridge\AuthCodeRepository;
use Laravel\Passport\Passport;

class GrantAwareAuthCodeRepository extends AuthCodeRepository
{
    public function __construct(private readonly OAuthClientGrantService $grants) {}

    public function isAuthCodeRevoked(string $codeId): bool
    {
        if (parent::isAuthCodeRevoked($codeId)) {
            return true;
        }

        $code = Passport::authCode()->newQuery()->whereKey($codeId)->first();

        return $code === null || ! $this->grants->allows(
            (string) $code->getAttribute('user_id'),
            (string) $code->getAttribute('client_id'),
        );
    }
}
