<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

/**
 * Protects the bherila-auth two-factor login flow used by passwordless email codes.
 *
 * The vendored route set includes a token-only confirm endpoint intended for
 * magic-link login. Passwordless email-code login must expose an `attempt_token`
 * to the browser so the code can be verified, which makes that same confirm
 * endpoint unsafe: a caller with the token could complete login without the
 * emailed code. This middleware blocks confirm submissions while leaving the
 * code-based verify endpoint available.
 *
 * The vendored `TwoFactorController::verify()` also has no failed-attempt cap or
 * rate limit, so this middleware counts failed verifies per `attempt_token` in
 * the cache and short-circuits with HTTP 429 once the cap is reached.
 *
 * The counter is keyed solely by the token (not the IP), so rotating source IPs
 * cannot bypass the cap. The middleware self-scopes to the relevant two-factor
 * URIs and the e-file credential confirmation endpoint, and is a no-op for
 * every other request.
 */
class ThrottleTwoFactorVerify
{
    /**
     * Maximum number of failed verify attempts allowed per `attempt_token`
     * before the token is locked out for the remainder of the code window.
     */
    private const MAX_ATTEMPTS = 5;

    private const CACHE_KEY_PREFIX = '2fa-verify-fail:';

    public function handle(Request $request, Closure $next): Response
    {
        if ($this->isConfirmSubmission($request)) {
            return $this->confirmDisabledResponse($request);
        }

        if (! $this->shouldThrottle($request)) {
            return $next($request);
        }

        $token = (string) $request->input('attempt_token', '');

        if ($token === '') {
            return $next($request);
        }

        $cacheKey = self::CACHE_KEY_PREFIX.$token;

        if ((int) Cache::get($cacheKey, 0) >= self::MAX_ATTEMPTS) {
            return $this->lockedResponse();
        }

        $response = $next($request);

        $status = $response->getStatusCode();

        if ($status === 422) {
            $this->recordFailure($cacheKey);
        } elseif ($status >= 200 && $status < 300) {
            Cache::forget($cacheKey);
        }

        return $response;
    }

    private function isConfirmSubmission(Request $request): bool
    {
        return $request->isMethod('post')
            && Str::is('api/auth/two-factor/confirm/*', $request->path());
    }

    private function shouldThrottle(Request $request): bool
    {
        return $request->is('api/auth/two-factor/verify')
            || $request->is('api/auth/two-factor/resend')
            || $request->is('api/finance/tax-years/*/efile-credentials/confirmation');
    }

    private function recordFailure(string $cacheKey): void
    {
        $ttl = now()->addMinutes((int) config('bherila-auth.two_factor.expires_minutes', 15));

        if (Cache::add($cacheKey, 1, $ttl)) {
            return;
        }

        Cache::increment($cacheKey);
    }

    private function lockedResponse(): Response
    {
        return response()->json([
            'success' => false,
            'message' => 'Too many verification attempts. Please request a new code and try again later.',
        ], 429);
    }

    private function confirmDisabledResponse(Request $request): Response
    {
        if ($request->expectsJson()) {
            return response()->json([
                'success' => false,
                'message' => 'Please enter the verification code from your email to complete login.',
            ], 422);
        }

        return redirect(config('bherila-auth.two_factor.login_url', '/login'))
            ->withErrors(['code' => 'Please enter the verification code from your email to complete login.']);
    }
}
