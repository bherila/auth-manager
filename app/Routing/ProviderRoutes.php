<?php

namespace BWH\AuthManager\Routing;

use BWH\AuthManager\Support\Mount;
use Illuminate\Support\Facades\Route;

/**
 * The provider's routes, registered the same way at the root of a standalone deployment
 * and inside the embedded prefix group.
 *
 * Application routes are named `auth-manager.*` in both modes, so a host's `login`,
 * `home` or `settings.*` names never collide with them. The OAuth routes keep Passport's
 * `passport.*` names, which Passport and auth-laravel's consent view look up.
 */
final class ProviderRoutes
{
    public static function register(): void
    {
        Route::middleware(Mount::webMiddleware())
            ->name(Mount::ROUTE_NAME_PREFIX)
            ->group(Mount::packagePath('routes/web.php'));
        Route::group([], Mount::packagePath('routes/oauth.php'));
        Route::name(Mount::ROUTE_NAME_PREFIX)->group(Mount::packagePath('routes/reconciliation.php'));
        Route::name(Mount::ROUTE_NAME_PREFIX)->group(Mount::packagePath('routes/application-invitations.php'));
    }
}
