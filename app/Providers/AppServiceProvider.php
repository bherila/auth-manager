<?php

namespace App\Providers;

use App\Models\PassportClient;
use Illuminate\Support\ServiceProvider;
use Laravel\Passport\Passport;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        // Passport's own routes are replaced by routes/oauth.php, which wraps the
        // authorization endpoints in the session and audit middleware this service
        // requires. Registering both would expose an unguarded second path.
        Passport::ignoreRoutes();
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // Keys live under the private storage root, which the deploy excludes from its
        // --delete transfer so they survive every release. Passport's default location is
        // inside the transferred tree and would be wiped on the next deploy.
        Passport::loadKeysFrom(storage_path('app/private/oauth'));

        Passport::useClientModel(PassportClient::class);
        Passport::authorizationView('oauth.authorize');
        Passport::tokensCan([
            'identity:read' => 'Read your account identity',
        ]);
        Passport::tokensExpireIn(now()->addMinutes(5));
        Passport::refreshTokensExpireIn(now()->addDay());
    }
}
