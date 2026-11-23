<?php

namespace BWH\AuthManager\Http\Controllers;

use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\RecoveryHighWater;
use BWH\AuthManager\Support\RelyingApplications;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Laravel\Passport\AccessToken;
use Laravel\Passport\Passport;

class OAuthUserController extends Controller
{
    public function __construct(private readonly RelyingApplications $applications, private readonly RecoveryHighWater $recovery) {}

    public function __invoke(Request $request): JsonResponse
    {
        $authenticated = $request->user();
        $accessToken = $authenticated instanceof User ? $authenticated->token() : null;
        // A cookie/transient session has no immutable OAuth credential generation.
        abort_unless($accessToken instanceof AccessToken, 401);
        $token = Passport::token()->newQuery()->whereKey($accessToken->oauth_access_token_id)
            ->where('user_id', $authenticated->getAuthIdentifier())
            ->where('client_id', $accessToken->oauth_client_id)
            ->where('revoked', false)->first();
        abort_if($token === null || $token->getAttribute('credential_version') === null, 401);
        $generation = (int) $token->getAttribute('credential_version');
        $user = User::query()->find($authenticated->getAuthIdentifier());
        abort_unless($user instanceof User && $user->canLogin() && $generation === (int) $user->credential_version, 401);

        return response()->json([
            // The account's subject column, never its row id (docs/identity-subjects.md).
            'sub' => $user->providerSubject(),
            // Always preserve the authenticated token's generation, never adopt a reset.
            'credential_version' => $generation,
            // Raised by the operator after restoring the database (docs/recovery.md). A consumer
            // records it with the session and treats a later, higher one as a reason to end it.
            'recovery_epoch' => $this->recovery->epoch(),
            'name' => $user->name,
            'email' => $user->email,
            // Present only as true, while the person has proven they receive mail at this
            // address (EmailProof). An unproven address omits it rather than sending false,
            // which consumers refuse by default and which would lock out accounts that never
            // had a way to prove theirs. A consumer that needs proof requires an explicit true.
            ...($user->email_verified_at !== null ? ['email_verified' => true] : []),
            // The applications this person can move between. Sent with the identity rather
            // than from an endpoint of its own so a relying application can cache it in the
            // session it is already establishing, and never has to call back here to render
            // a page. Older clients ignore the key.
            'apps' => $this->applications->forSubject((string) $user->getKey()),
            // How the person authenticated when this token's grant began. Absent when unknown.
            ...$this->authenticationContext($token),
        ])->header('Cache-Control', 'private, no-store');
    }

    /** @return array{auth_time?: int, amr?: list<string>, acr?: string} */
    private function authenticationContext(Model $token): array
    {
        $authTime = $token->getAttribute('auth_time');
        if ($authTime === null) {
            return [];
        }

        $amr = json_decode((string) $token->getAttribute('amr'), true);

        return [
            'auth_time' => (int) $authTime,
            'amr' => is_array($amr) ? array_values(array_filter($amr, 'is_string')) : [],
            'acr' => (string) $token->getAttribute('acr'),
        ];
    }
}
