<?php

namespace BWH\AuthManager\Http\Middleware;

use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\AuthenticationContext;
use BWH\AuthManager\Services\TrustedDevices;
use BWH\AuthManager\Support\Mount;
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
        if ($this->protects($request) && $request->user() !== null && ! $this->hasFreshAuthentication($request)) {
            return new JsonResponse([
                'message' => TrustedDevices::enabled()
                    ? 'Managing passkeys needs a sign-in with an emailed code or a passkey. If this browser skips the code, stop trusting it under Account and security, then sign in again.'
                    : 'Please sign in again before managing passkeys.',
            ], Response::HTTP_FORBIDDEN, [
                'Cache-Control' => 'no-store',
                'Pragma' => 'no-cache',
            ]);
        }

        $response = $next($request);

        if ($this->completedJsonCredentialVerification($request, $response)) {
            self::recordCredentialVerification($request);
        }

        return $response;
    }

    private function protects(Request $request): bool
    {
        if ($request->isMethod('POST')) {
            return Mount::is($request, 'api/passkeys/register/options', 'api/passkeys/register');
        }

        return $request->isMethod('DELETE') && Mount::is($request, 'api/passkeys/*');
    }

    public static function recordCredentialVerification(Request $request): void
    {
        $user = $request->user();

        if ($user === null) {
            return;
        }

        $request->session()->put(self::SESSION_KEY, [
            'user_id' => (string) $user->getAuthIdentifier(),
            'authenticated_at' => now()->getTimestamp(),
        ]);
    }

    private function hasFreshAuthentication(Request $request): bool
    {
        $authentication = $request->session()->get(self::SESSION_KEY);
        $user = $request->user();

        if (! is_array($authentication) || $user === null) {
            return false;
        }

        if (TrustedDevices::enabled() && ! $this->presentedMoreThanAPassword($request, $user)) {
            return false;
        }

        $authenticatedUserId = $authentication['user_id'] ?? null;
        $authenticatedAt = $authentication['authenticated_at'] ?? null;

        if ((! is_int($authenticatedAt) && ! (is_string($authenticatedAt) && ctype_digit($authenticatedAt)))
            || ! is_string($authenticatedUserId)
            || ! hash_equals((string) $user->getAuthIdentifier(), $authenticatedUserId)) {
            return false;
        }

        $now = now()->getTimestamp();
        $timestamp = (int) $authenticatedAt;

        return $timestamp <= $now && $timestamp >= $now - self::MAX_AGE_SECONDS;
    }

    /**
     * Where a trusted browser can skip the code, a password is no proof the second factor was
     * ever seen, and a passkey enrolled on it would reach the `mfa` rung. So the session must
     * have presented a code or passkey. A session restored from a remember-me cookie has no
     * recorded context and doesn't qualify, and neither does a password confirmed again later.
     */
    private function presentedMoreThanAPassword(Request $request, mixed $user): bool
    {
        $context = $user instanceof User ? AuthenticationContext::for($request, $user) : null;

        return $context !== null && array_diff($context['amr'], ['pwd']) !== [];
    }

    /**
     * The shared package exposes only these two JSON verification endpoints to
     * this application. A route match alone is not enough: Laravel restores a
     * remembered user before the login controller, which emits Login even when
     * the password submitted later in the request is wrong. Both controllers
     * return this exact JSON success response only after a valid email code or
     * WebAuthn assertion has authenticated the user.
     */
    private function completedJsonCredentialVerification(Request $request, Response $response): bool
    {
        if (! $request->isMethod('POST') || ! $response instanceof JsonResponse || ! $response->isSuccessful()) {
            return false;
        }

        if (! in_array(Mount::relativePath($request), ['api/auth/two-factor/verify', 'api/passkeys/auth'], true)) {
            return false;
        }

        $payload = $response->getData(true);

        return is_array($payload) && ($payload['success'] ?? false) === true && $request->user() !== null;
    }
}
