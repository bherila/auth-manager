<?php

namespace BWH\AuthManager\Providers;

use BWH\Auth\OAuth\Server\ResourceAccessToken;
use BWH\AuthManager\Http\Middleware\EnsureCredentialVersion;
use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\OAuth\ApplicationInvitationScopeRepository;
use BWH\AuthManager\OAuth\GrantAwareAccessTokenRepository;
use BWH\AuthManager\OAuth\GrantAwareAuthCodeRepository;
use BWH\AuthManager\OAuth\GrantAwareRefreshTokenRepository;
use BWH\AuthManager\Services\OAuthCredentialGenerationContext;
use BWH\AuthManager\Support\ApplicationInvitationKeys;
use BWH\AuthManager\Support\ApplicationInvitations;
use BWH\AuthManager\Support\DelegatedAccessApplications;
use BWH\AuthManager\Support\DelegatedAccessKeys;
use BWH\AuthManager\Support\Mount;
use Illuminate\Auth\Events\Login;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Laravel\Passport\Bridge\AccessTokenRepository;
use Laravel\Passport\Bridge\AuthCodeRepository;
use Laravel\Passport\Bridge\RefreshTokenRepository;
use Laravel\Passport\Bridge\ScopeRepository;
use Laravel\Passport\Passport;
use RuntimeException;
use Symfony\Component\Mailer\Bridge\Brevo\Transport\BrevoTransportFactory;
use Symfony\Component\Mailer\Transport\Dsn;
use Symfony\Component\Mailer\Transport\TransportInterface;

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
        $this->app->bind(ScopeRepository::class, ApplicationInvitationScopeRepository::class);
        $this->app->scoped(OAuthCredentialGenerationContext::class);
        // Resolved and, when malformed, reported once per request.
        $this->app->scoped(DelegatedAccessApplications::class);
        $this->app->scoped(DelegatedAccessKeys::class);
        $this->app->scoped(ApplicationInvitationKeys::class);
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        RateLimiter::for('auth-manager.email-code', static function (Request $request): array {
            $blocked = static fn (Request $request, array $headers) => response()->json([
                'success' => false,
                'message' => 'Too many sign-in code requests. Please try again later.',
            ], 429, $headers);
            $input = $request->input('email');
            $email = hash('sha256', mb_strtolower(trim(is_string($input) ? $input : '')));

            // The per-address budget is what an attacker uses to lock a specific person out of
            // recovery, so it allows a few honest retries; Cloudflare's per-IP edge rule and the
            // per-IP budget below (real client IPs via trusted proxies) absorb volume.
            return [
                Limit::perMinute(10)->by('email-code-ip:'.$request->ip())->response($blocked),
                Limit::perMinutes(5, 3)->by('email-code-address:'.$email)->response($blocked),
            ];
        });

        // Brevo's API transport (Symfony bridge), so MAIL_MAILER=brevo or =hybrid works. An unset
        // DSN fails when the mailer is built, `hybrid` included, rather than silently degrading.
        // Standalone only: embedded, the provider sends through the host's mailers.
        if (! Mount::embedded()) {
            $this->app['mail.manager']->extend('brevo', function (array $config): TransportInterface {
                $dsn = (string) $this->app->make('config')->get('services.brevo.dsn');
                if ($dsn === '') {
                    throw new RuntimeException('MAILER_DSN is not set; the brevo mailer cannot be built.');
                }

                return (new BrevoTransportFactory)->create(Dsn::fromString($dsn));
            });
        }

        // Invitation links, per client IP: opening one, accepting one, signing in or out from one.
        RateLimiter::for('auth-manager.invitations', static fn (Request $request): Limit => Limit::perMinute(30)->by('invitations:'.$request->ip()));

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
        // inside the transferred tree and would be wiped on the next deploy. Embedded, they
        // are the provider's own, apart from anything the host keeps there.
        Passport::loadKeysFrom(Mount::embedded()
            ? (string) config('auth-manager-embedded.keys_path')
            : storage_path('app/private/oauth'));
        // auth-laravel does this when the application's own oauth_server flag is on; embedded,
        // that flag is the host's, so the provider sets it from its own profile.
        if (config('auth-manager.oauth_server')) {
            Passport::useAccessTokenEntity(ResourceAccessToken::class);
        }

        Passport::useClientModel(PassportClient::class);
        Passport::authorizationView(config('auth-manager.oauth_server')
            ? 'bherila-auth::oauth.authorize'
            : 'oauth.authorize');
        // The admission invitation scope is Passport's only: it is not in the profile's catalog, so
        // it is never advertised, offered to a person or registered by a dynamic client, and
        // ApplicationInvitationScopeRepository keeps it to client credentials tokens.
        Passport::tokensCan([
            ...(array) config('auth-manager.scopes', []),
            ApplicationInvitations::SCOPE => 'Request admission invitations to this application',
        ]);
        Passport::tokensExpireIn(now()->addMinutes(5));
        Passport::refreshTokensExpireIn(now()->addDay());
    }
}
