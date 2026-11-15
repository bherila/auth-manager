<?php

namespace BWH\AuthManager\Http\Middleware;

use Closure;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Session\Middleware\AuthenticateSession;

/** Apply Laravel's password-hash session check only to a real browser-session guard. */
final class AuthenticateBrowserSession extends AuthenticateSession
{
    private ?StatefulGuard $browserGuard = null;

    private ?string $browserGuardName = null;

    public function handle($request, Closure $next)
    {
        // Some OAuth identity routes use the web middleware stack but authenticate
        // through Passport. TokenGuard has no recaller/session logout methods;
        // token generation and revocation checks protect that separate boundary.
        $guard = $this->auth->guard();
        if (! $guard instanceof StatefulGuard) {
            return $next($request);
        }

        $this->browserGuard = $guard;
        $this->browserGuardName = $this->auth->getDefaultDriver();
        // Keep Laravel's before/after checks bound to this browser guard while
        // downstream handlers receive the real request and may select an API principal.
        $browser = clone $request;
        $browser->setUserResolver(static fn () => $guard->user());
        try {
            return parent::handle($browser, static fn () => $next($request));
        } finally {
            $this->browserGuard = null;
            $this->browserGuardName = null;
        }
    }

    protected function guard()
    {
        return $this->browserGuard ?? parent::guard();
    }

    protected function storePasswordHashInSession($request)
    {
        // Laravel also writes the hash after the downstream handler returns. If
        // that handler selected Passport, never copy its principal/hash into the
        // browser session or create a password_hash_api key.
        if ($this->auth->getDefaultDriver() !== $this->browserGuardName
            || $this->auth->guard() !== $this->browserGuard) {
            return;
        }

        parent::storePasswordHashInSession($request);
    }
}
