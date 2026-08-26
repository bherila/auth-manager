<?php

namespace App\Http\Middleware;

use App\Models\PassportClient;
use App\Services\OAuthClientGrantService;
use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class RequireOAuthClientGrant
{
    public function __construct(private readonly OAuthClientGrantService $grants) {}

    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();
        $clientId = $request->input('client_id');

        if (! $user instanceof Authenticatable || ! is_string($clientId) || $clientId === '') {
            return $next($request);
        }

        $client = PassportClient::query()->whereKey($clientId)->where('revoked', false)->first();

        if (! $client instanceof PassportClient) {
            return $next($request);
        }

        $subject = (string) $user->getAuthIdentifier();

        if ($this->grants->allows($subject, $clientId)) {
            return $next($request);
        }

        return response()->view('oauth.client-access-denied', [
            'clientName' => (string) $client->name,
        ], 403);
    }
}
