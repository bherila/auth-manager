<?php

namespace App\Http\Middleware;

use App\Models\User;
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
        $user = $request->user();

        if (! $user instanceof User) {
            return $next($request);
        }

        $current = (int) $user->credential_version;
        $sessionVersion = $request->session()->get(self::SESSION_KEY);

        // Preserve sessions created before this mechanism was deployed only while
        // the account is still at its original generation. Once credentials have
        // changed, an unversioned session is necessarily stale and must fail closed.
        if ($sessionVersion === null && $current === 0) {
            $request->session()->put(self::SESSION_KEY, 0);

            return $next($request);
        }

        if (is_int($sessionVersion) && $sessionVersion === $current) {
            return $next($request);
        }

        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        if ($request->expectsJson()) {
            return new JsonResponse(['message' => 'The authenticated session is no longer valid.'], 401);
        }

        return new RedirectResponse(route('login'));
    }
}
