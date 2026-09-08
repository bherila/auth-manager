<?php

use App\Http\Middleware\AddSecurityHeaders;
use App\Http\Middleware\EnsureCredentialVersion;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Bootstrap\LoadConfiguration;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/** @return list<string>|string|null */
$resolveTrustedProxies = static function (mixed $setting, array $cloudflare): array|string|null {
    if (! is_string($setting) || trim($setting) === '') {
        return null;
    }
    $setting = trim($setting);
    if ($setting === '*' || $setting === '**') {
        return $setting;
    }
    $proxies = [];
    foreach (explode(',', $setting) as $entry) {
        $entry = trim($entry);
        if ($entry === 'cloudflare') {
            array_push($proxies, ...$cloudflare);
        } elseif ($entry !== '') {
            $proxies[] = $entry;
        }
    }

    return $proxies === [] ? null : array_values(array_unique($proxies));
};

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
        then: function (): void {
            Route::group([], base_path('routes/oauth.php'));
            Route::group([], base_path('routes/reconciliation.php'));
        },
    )
    ->withMiddleware(function (Middleware $middleware) use ($resolveTrustedProxies): void {
        // Rate limits, login throttling and audit rows key on the client IP. Behind
        // Cloudflare that is only correct when Cloudflare's addresses are trusted to
        // forward it; the origin answers direct connections too, so never trust '*'
        // there. Configuration is not loaded yet at this point, hence the hook.
        app()->afterBootstrapping(LoadConfiguration::class, static function () use ($middleware, $resolveTrustedProxies): void {
            $proxies = $resolveTrustedProxies(config('proxies.trusted'), (array) config('proxies.cloudflare', []));
            if ($proxies !== null) {
                $middleware->trustProxies(at: $proxies,
                    headers: Request::HEADER_X_FORWARDED_FOR | Request::HEADER_X_FORWARDED_PROTO | Request::HEADER_X_FORWARDED_PORT);
            }
        });
        $middleware->prepend(AddSecurityHeaders::class);
        // Provider subjects are opaque identifiers, not text fields to normalize.
        $middleware->trimStrings(except: [fn (Request $request): bool => $request->is('api/reconciliation/identity-status')]);
        $middleware->appendToGroup('web', EnsureCredentialVersion::class);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->expectsJson(),
        );
    })->create();
