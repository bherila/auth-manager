<?php

namespace App\Providers;

use App\Http\Middleware\EnsureCredentialVersion;
use App\Models\PassportClient;
use App\Models\User;
use App\OAuth\GrantAwareAccessTokenRepository;
use App\OAuth\GrantAwareAuthCodeRepository;
use App\OAuth\GrantAwareRefreshTokenRepository;
use App\Services\OAuthCredentialGenerationContext;
use Illuminate\Auth\Events\Login;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Laravel\Passport\Bridge\AccessTokenRepository;
use Laravel\Passport\Bridge\AuthCodeRepository;
use Laravel\Passport\Bridge\RefreshTokenRepository;
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

        $this->app->bind(AuthCodeRepository::class, GrantAwareAuthCodeRepository::class);
        $this->app->bind(AccessTokenRepository::class, GrantAwareAccessTokenRepository::class);
        $this->app->bind(RefreshTokenRepository::class, GrantAwareRefreshTokenRepository::class);
        $this->app->scoped(OAuthCredentialGenerationContext::class);
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        Event::listen(Login::class, static function (Login $event): void {
            if ($event->user instanceof User && request()->hasSession()) {
                request()->session()->put(
                    EnsureCredentialVersion::SESSION_KEY,
                    (int) $event->user->credential_version,
                );
            }
        });

        // Keys live under the private storage root, which the deploy excludes from its
        // --delete transfer so they survive every release. Passport's default location is
        // inside the transferred tree and would be wiped on the next deploy.
        Passport::loadKeysFrom(storage_path('app/private/oauth'));

        Passport::useClientModel(PassportClient::class);
        Passport::authorizationView('oauth.authorize');
        Passport::tokensCan((array) config('auth-manager.scopes', []));
        Passport::tokensExpireIn(now()->addMinutes(5));
        Passport::refreshTokensExpireIn(now()->addDay());
    }
}
