<?php

namespace App\OAuth;

use App\Http\Middleware\EnsureCredentialVersion;
use App\Models\User;
use App\Services\OAuthClientGrantService;
use App\Services\OAuthCredentialGenerationContext;
use App\Services\UserAccountStatusService;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\Bridge\AuthCodeRepository;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;

class GrantAwareAuthCodeRepository extends AuthCodeRepository
{
    public function __construct(
        private readonly OAuthClientGrantService $grants,
        private readonly UserAccountStatusService $accounts,
        private readonly OAuthCredentialGenerationContext $credentialGeneration,
    ) {}

    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
    {
        $subject = $authCodeEntity->getUserIdentifier();

        if ($subject === null) {
            throw OAuthServerException::accessDenied('A provider account is required.');
        }

        DB::transaction(function () use ($authCodeEntity, $subject): void {
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

            parent::persistNewAuthCode($authCodeEntity);
            DB::table('oauth_auth_codes')
                ->where('id', $authCodeEntity->getIdentifier())
                ->update(['credential_version' => $sessionVersion]);
        });
    }

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
