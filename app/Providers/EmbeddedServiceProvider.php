<?php

namespace BWH\AuthManager\Providers;

use BWH\Auth\AuthServiceProvider as AuthLaravelServiceProvider;
use BWH\Auth\Http\Controllers\OAuthMetadataController;
use BWH\Auth\Http\Middleware\EnsureOAuthServerEnabled;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use BWH\AuthManager\Console\ProviderSchedule;
use BWH\AuthManager\Embedded\Console\MigrateCommand;
use BWH\AuthManager\Embedded\EmbeddedConfig;
use BWH\AuthManager\Embedded\EmbeddedContext;
use BWH\AuthManager\Http\Controllers\EmbeddedAssetController;
use BWH\AuthManager\Http\Middleware\AddSecurityHeaders;
use BWH\AuthManager\Http\Middleware\ApplicationAccessResponse;
use BWH\AuthManager\Http\Middleware\EnsureCredentialVersion;
use BWH\AuthManager\Http\Middleware\EnterEmbeddedContext;
use BWH\AuthManager\Http\Middleware\PreventEmbeddedRequestForgery;
use BWH\AuthManager\Routing\ProviderRoutes;
use BWH\AuthManager\Support\Mount;
use Illuminate\Console\Events\CommandFinished;
use Illuminate\Console\Events\CommandStarting;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Foundation\CachesConfiguration;
use Illuminate\Contracts\Foundation\CachesRoutes;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Foundation\Exceptions\Handler;
use Illuminate\Foundation\Http\Middleware\TrimStrings;
use Illuminate\Http\Request;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Session\SessionManager;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Str;
use Illuminate\View\Middleware\ShareErrorsFromSession;
use Laravel\Passport\PassportServiceProvider;
use Throwable;

/**
 * Auth Manager embedded in a host application under a path prefix.
 *
 * Discovered by the host through composer.json's extra.laravel.providers; a standalone
 * deployment (the root package) never loads it. See docs/embedded-mode.md.
 */
final class EmbeddedServiceProvider extends ServiceProvider
{
    /** Commands that run inside the embedded context: the provider's own and Passport's. */
    private const PROVIDER_COMMANDS = ['auth-manager:*', 'identity:*', 'identities:*', 'passport:*'];

    /** @var list<bool> whether each started command entered the context */
    private array $commandStack = [];

    public function register(): void
    {
        $this->mergeConfigFrom(Mount::packagePath('config/auth-manager-embedded.php'), 'auth-manager-embedded');
        if (! ($this->app instanceof CachesConfiguration && $this->app->configurationIsCached())) {
            EmbeddedConfig::apply($this->app['config']);
        }

        $this->app->singleton(EmbeddedContext::class);
        // Hard dependencies, registered before the provider's own bindings (which replace some
        // of theirs) whether or not the host's package discovery has reached them yet.
        $this->app->register(AuthLaravelServiceProvider::class);
        $this->app->register(PassportServiceProvider::class);
        $this->app->register(AppServiceProvider::class);
    }

    public function boot(): void
    {
        // The provider's session store, cached by the manager under its own driver name. Its
        // handler is the configured real driver's, built from the context's session settings.
        $this->app->make(SessionManager::class)->extend(EmbeddedContext::SESSION_DRIVER, static fn ($app) => (new SessionManager($app))
            ->driver((string) $app['config']->get('session.embedded_driver', 'file'))
            ->getHandler());

        $this->registerMiddleware();
        $this->registerRoutes();
        $this->registerExceptionRendering();
        $this->registerConsole();

        $this->publishes([
            Mount::packagePath('config/auth-manager-embedded.php') => config_path('auth-manager-embedded.php'),
        ], 'auth-manager-config');
        $this->publishes([
            Mount::packagePath('database/migrations') => database_path('migrations/auth-manager'),
        ], 'auth-manager-migrations');
        $this->publishes([
            Mount::packagePath('public/build') => public_path(Mount::prefix().'/build'),
        ], 'auth-manager-assets');

        // Provider subjects are opaque identifiers, not text fields to normalize.
        TrimStrings::skipWhen(static fn (Request $request): bool => Mount::is($request, 'api/reconciliation/identity-status'));
    }

    private function registerMiddleware(): void
    {
        $router = $this->app['router'];
        $router->middlewareGroup(Mount::EMBEDDED_WEB, [
            EncryptCookies::class,
            AddQueuedCookiesToResponse::class,
            StartSession::class,
            ShareErrorsFromSession::class,
            PreventEmbeddedRequestForgery::class,
            SubstituteBindings::class,
            EnsureCredentialVersion::class,
        ]);
        $router->middlewareGroup(Mount::EMBEDDED_API, [SubstituteBindings::class]);

        // Before the session, the guard and everything else that reads what it switches.
        $kernel = $this->app->make(HttpKernel::class);
        if (method_exists($kernel, 'prependToMiddlewarePriority')) {
            $kernel->prependToMiddlewarePriority(EnterEmbeddedContext::class);
        }
    }

    private function registerRoutes(): void
    {
        if ($this->app instanceof CachesRoutes && $this->app->routesAreCached()) {
            return;
        }

        $prefix = Mount::prefix();
        $authLaravel = (array) config('auth-manager-embedded.overlay.bherila-auth', []);

        Route::prefix($prefix)
            ->middleware([EnterEmbeddedContext::class, AddSecurityHeaders::class])
            ->group(static function () use ($authLaravel): void {
                ProviderRoutes::register();

                // auth-laravel's passkey and two-factor routes, which a standalone deployment
                // gets from auth-laravel's own provider. Their files read the provider's
                // bherila-auth configuration, so it is in place while they load.
                $routes = (array) ($authLaravel['routes'] ?? []);
                $hostConfig = config('bherila-auth');
                config(['bherila-auth' => $authLaravel]);
                try {
                    Route::prefix((string) ($routes['prefix'] ?? 'api'))
                        ->middleware((array) ($routes['middleware'] ?? [Mount::EMBEDDED_WEB]))
                        ->group(static function () use ($routes): void {
                            if (($routes['passkeys'] ?? true) === true) {
                                require EmbeddedConfig::authLaravelPath('routes/passkeys.php');
                            }
                            if (($routes['password_resets'] ?? false) || ($routes['change_password'] ?? false) || ($routes['two_factor'] ?? false)) {
                                require EmbeddedConfig::authLaravelPath('routes/auth.php');
                            }
                        });
                } finally {
                    config(['bherila-auth' => $hostConfig]);
                }

                Route::get('build/assets/{file}', EmbeddedAssetController::class)
                    ->where('file', '[A-Za-z0-9][A-Za-z0-9._-]*')
                    ->name(Mount::ROUTE_NAME_PREFIX.'assets');
            });

        // RFC 8414 section 3: an issuer with a path publishes its metadata at the well-known
        // path followed by that path. Outside the prefix by definition, and unable to collide
        // with the host's own document at the bare well-known path.
        if (config('auth-manager.oauth_server') && config('auth-manager-embedded.well_known', true)) {
            Route::get('/.well-known/oauth-authorization-server/'.$prefix, [OAuthMetadataController::class, 'authorizationServer'])
                ->middleware([EnterEmbeddedContext::class, AddSecurityHeaders::class, EnsureOAuthServerEnabled::class])
                ->name(Mount::ROUTE_NAME_PREFIX.'oauth.metadata.authorization-server');
        }
    }

    private function registerExceptionRendering(): void
    {
        $this->callAfterResolving(ExceptionHandler::class, function (ExceptionHandler $handler): void {
            if (! $handler instanceof Handler) {
                return;
            }

            // One-time codes are credentials: a refused form must not keep one in the session.
            $handler->dontFlash(['code']);

            $handler->renderable(function (Throwable $exception, Request $request) use ($handler) {
                if (! $this->app->make(EmbeddedContext::class)->active()) {
                    return null;
                }

                if ($exception instanceof DelegatedAccessException && Mount::is($request, 'applications/*')) {
                    return ApplicationAccessResponse::failure($exception, $request);
                }

                // As standalone renders api/* as JSON whatever the request accepts.
                if (Mount::is($request, 'api/*') && ! $request->expectsJson()) {
                    $json = $request->duplicate();
                    $json->headers->set('Accept', 'application/json');

                    return $handler->render($json, $exception);
                }

                return null;
            });
        });
    }

    private function registerConsole(): void
    {
        $context = $this->app->make(EmbeddedContext::class);

        $this->callAfterResolving(Schedule::class, static function (Schedule $schedule) use ($context): void {
            ProviderSchedule::define($schedule, static fn ($task) => $context->run($task));
        });

        if (! $this->app->runningInConsole()) {
            return;
        }

        $this->commands([...$this->providerCommands(), MigrateCommand::class]);

        Event::listen(CommandStarting::class, function (CommandStarting $event) use ($context): void {
            $provider = is_string($event->command) && Str::is(self::PROVIDER_COMMANDS, $event->command);
            $this->commandStack[] = $provider;
            if ($provider) {
                $context->enter();
                if ($event->command === 'passport:keys') {
                    File::ensureDirectoryExists((string) config('auth-manager-embedded.keys_path'), 0700);
                }
            }
        });
        Event::listen(CommandFinished::class, function () use ($context): void {
            if (array_pop($this->commandStack) === true) {
                $context->leave();
            }
        });
    }

    /** @return list<class-string> */
    private function providerCommands(): array
    {
        $commands = [];
        foreach (glob(Mount::packagePath('app/Console/Commands/*.php')) ?: [] as $file) {
            $class = 'BWH\\AuthManager\\Console\\Commands\\'.basename($file, '.php');
            if (class_exists($class)) {
                $commands[] = $class;
            }
        }

        return $commands;
    }
}
