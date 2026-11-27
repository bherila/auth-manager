<?php

namespace BWH\AuthManager\Http\Middleware;

use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Support\ApplicationRegistration;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Symfony\Component\HttpFoundation\Response;

final class AuthenticateApplicationRegistration
{
    public function handle(Request $request, Closure $next): Response
    {
        $client = $request->attributes->get(AuthenticateReconciliationClient::CLIENT_ATTRIBUTE);
        if (! $client instanceof PassportClient || (new ApplicationRegistration)->applicationFor($client) === null) {
            return response()->json(['error' => 'application_not_enabled'], 403)->header('Cache-Control', 'private, no-store');
        }
        $key = 'application-registration:client:'.$client->getKey();
        if (RateLimiter::tooManyAttempts($key, 30)) {
            return response()->json(['error' => 'rate_limited'], 429)
                ->header('Retry-After', (string) max(1, RateLimiter::availableIn($key)))
                ->header('Cache-Control', 'private, no-store');
        }
        RateLimiter::hit($key, 60);

        return $next($request);
    }
}
