<?php

namespace BWH\AuthManager\Http\Middleware;

use Closure;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Session\Middleware\AuthenticateSession;

/** Apply Laravel's password-hash session check only to a real browser-session guard. */
final class AuthenticateBrowserSession extends AuthenticateSession
{
    public function handle($request, Closure $next)
    {
        // Some OAuth identity routes use the web middleware stack but authenticate
        // through Passport. TokenGuard has no recaller/session logout methods;
        // token generation and revocation checks protect that separate boundary.
        if (! $this->auth->guard() instanceof StatefulGuard) {
            return $next($request);
        }

        return parent::handle($request, $next);
    }
}
