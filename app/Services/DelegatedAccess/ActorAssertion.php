<?php

namespace App\Services\DelegatedAccess;

use DateTimeImmutable;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Builder;
use SensitiveParameter;
use Throwable;

final class ActorAssertion
{
    public const TYPE = 'application-access+jwt';

    public function issue(string $issuer, string $subject, string $endpoint, string $application, string $body, string $keyId, #[SensitiveParameter] string $privateKey): string
    {
        if ($subject === '' || strlen($subject) > 191 || $keyId === '' || strlen($keyId) > 128) {
            throw new DelegatedAccessException('invalid_signing_configuration');
        }

        try {
            $now = new DateTimeImmutable('@'.time());

            return Builder::new(new JoseEncoder, ChainedFormatter::withUnixTimestampDates())
                ->withHeader('typ', self::TYPE)
                ->withHeader('kid', $keyId)
                ->issuedBy($issuer)->relatedTo($subject)->permittedFor($endpoint)
                ->issuedAt($now)->expiresAt($now->modify('+60 seconds'))
                ->identifiedBy(bin2hex(random_bytes(32)))
                ->withClaim('application', $application)
                ->withClaim('method', 'POST')
                ->withClaim('body_sha256', hash('sha256', $body))
                ->getToken(new Sha256, InMemory::plainText($privateKey))->toString();
        } catch (Throwable) {
            throw new DelegatedAccessException('signing_unavailable');
        }
    }
}
