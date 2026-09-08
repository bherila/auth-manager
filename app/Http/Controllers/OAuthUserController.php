<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Support\RelyingApplications;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Laravel\Passport\AccessToken;
use Laravel\Passport\Passport;

class OAuthUserController extends Controller
{
    public function __construct(private readonly RelyingApplications $applications) {}

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

        $subject = (string) $user->getKey();

        return response()->json([
            'sub' => $subject,
            // Always preserve the authenticated token's generation, never adopt a reset.
            'credential_version' => $generation,
            'name' => $user->name,
            'email' => $user->email,
            // The applications this person can move between. Sent with the identity rather
            // than from an endpoint of its own so a relying application can cache it in the
            // session it is already establishing, and never has to call back here to render
            // a page. Older clients ignore the key.
            'apps' => $this->applications->forSubject($subject),
        ])->header('Cache-Control', 'private, no-store');
    }
}
