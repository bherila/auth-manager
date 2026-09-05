<?php

namespace App\OAuth;

use App\Http\Middleware\EnsureCredentialVersion;
use App\Models\User;
use App\Services\OAuthClientGrantService;
use App\Services\OAuthCredentialGenerationContext;
use App\Services\UserAccountStatusService;
use BWH\Auth\OAuth\Server\ResourceAuthCodeRepository;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;

class GrantAwareAuthCodeRepository extends ResourceAuthCodeRepository
{
    public function __construct(
        private readonly OAuthClientGrantService $grants,
        private readonly UserAccountStatusService $accounts,
        private readonly OAuthCredentialGenerationContext $credentialGeneration,
    ) {}

    /**
     * The package has already validated the RFC 8707 binding when this hook is
     * reached. Keep this application policy inside that final protocol.
     *
     * @param  list<string>  $scopeIdentifiers
     */
    protected function persistResourceAuthCode(
        AuthCodeEntityInterface $authCodeEntity,
        ?string $resource,
        bool $hasResourceColumn,
        array $scopeIdentifiers,
    ): void {
        $subject = $authCodeEntity->getUserIdentifier();

        if ($subject === null) {
            throw OAuthServerException::accessDenied('A provider account is required.');
        }

        DB::transaction(function () use ($authCodeEntity, $hasResourceColumn, $resource, $scopeIdentifiers, $subject): void {
            $user = User::query()->whereKey($subject)->lockForUpdate()->first();
            $sessionVersion = request()->hasSession()
                ? request()->session()->get(EnsureCredentialVersion::SESSION_KEY)
                : null;

            if (! $user instanceof User
                || ! $user->canLogin()
                || ! is_int($sessionVersion)
                || $sessionVersion !== (int) $user->credential_version) {
                throw OAuthServerException::accessDenied('The authenticated session is no longer valid.');
            }

            parent::persistResourceAuthCode($authCodeEntity, $resource, $hasResourceColumn, $scopeIdentifiers);
            DB::table('oauth_auth_codes')
                ->where('id', $authCodeEntity->getIdentifier())
                ->update(['credential_version' => $sessionVersion]);
        });
    }

    protected function isApplicationAuthCodeRevoked(string $codeId): bool
    {
        $code = Passport::authCode()->newQuery()->whereKey($codeId)->first();

        if ($code === null) {
            return true;
        }

        $subject = (string) $code->getAttribute('user_id');
        $currentVersion = $this->accounts->credentialVersionIfActive($subject);

        if ($currentVersion === null
            || $currentVersion !== (int) $code->getAttribute('credential_version')
            || ! $this->grants->allows($subject, (string) $code->getAttribute('client_id'))) {
            return true;
        }

        $this->credentialGeneration->expect($subject, $currentVersion);

        return false;
    }
}
