<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Enrollment and removal change which authenticators can sign in as a person.
 *
 * The shared passkey routes already require an active authenticated user. This
 * app-level guard additionally requires that the current session was created by
 * a credential-verification request recently enough to resist enrollment from a
 * stolen long-lived or remembered session.
 */
final class RequireRecentPasskeyAuthentication
{
    public const SESSION_KEY = 'passkey_management_authenticated_at';

    private const MAX_AGE_SECONDS = 600;

    public function handle(Request $request, Closure $next): Response
    {
        if (! $this->protects($request) || $request->user() === null || $this->hasFreshAuthentication($request)) {
            return $next($request);
        }

        return new JsonResponse([
            'message' => 'Please sign in again before managing passkeys.',
        ], Response::HTTP_FORBIDDEN, [
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
        ]);
    }

    private function protects(Request $request): bool
    {
        if ($request->isMethod('POST')) {
            return $request->is('api/passkeys/register/options')
                || $request->is('api/passkeys/register');
        }

        return $request->isMethod('DELETE') && $request->is('api/passkeys/*');
    }

    private function hasFreshAuthentication(Request $request): bool
    {
        $authenticatedAt = $request->session()->get(self::SESSION_KEY);

        if (! is_int($authenticatedAt) && ! (is_string($authenticatedAt) && ctype_digit($authenticatedAt))) {
            return false;
        }

        $now = now()->getTimestamp();
        $timestamp = (int) $authenticatedAt;

        return $timestamp <= $now && $timestamp >= $now - self::MAX_AGE_SECONDS;
    }
}
