<?php

namespace BWH\AuthManager\Http\Middleware;

use Illuminate\Auth\Middleware\Authenticate as BaseAuthenticate;
use Illuminate\Http\Request;

/**
 * `auth`, sending a guest to this provider's own sign-in page.
 *
 * Laravel's redirect callback is process-wide; embedded, it belongs to the host and
 * points at the host's login, which would send the person through OAuth back to the
 * host instead of to the provider page they asked for.
 */
final class Authenticate extends BaseAuthenticate
{
    protected function redirectTo(Request $request): string
    {
        return route('auth-manager.login');
    }
}
