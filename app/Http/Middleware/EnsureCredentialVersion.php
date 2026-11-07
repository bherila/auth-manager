<?php

namespace BWH\AuthManager\Http\Middleware;

use BWH\AuthManager\Models\User;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class EnsureCredentialVersion
{
    public const SESSION_KEY = 'auth_credential_version';

    public function handle(Request $request, Closure $next): Response
    {
        // Route authentication can select Passport's bearer guard before this
        // web-group middleware runs. Its credential generation belongs to the
        // token, not this browser session, and TokenGuard cannot log out.
        $guard = Auth::guard((string) config('passport.guard', 'web'));
        $user = $guard->user();

        if (! $user instanceof User) {
            return $next($request);
        }

        $current = (int) $user->credential_version;
        $sessionVersion = $request->session()->get(self::SESSION_KEY);

        // Preserve sessions created before this mechanism was deployed only while
        // the account is still at its original generation. Once credentials have
        // changed, an unversioned session is necessarily stale and must fail closed.
        $eligible = ! $user->isTestLogin() || $user->canLogin();
        if ($eligible && $sessionVersion === null && $current === 0) {
            $request->session()->put(self::SESSION_KEY, 0);

            return $next($request);
        }

        if ($eligible && is_int($sessionVersion) && $sessionVersion === $current) {
            return $next($request);
        }

        $guard->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        if ($request->expectsJson()) {
            return new JsonResponse(['message' => 'The authenticated session is no longer valid.'], 401);
        }

        return new RedirectResponse(route('auth-manager.login'));
    }
}
