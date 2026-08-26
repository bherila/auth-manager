<?php

use App\Http\Middleware\EnsureCredentialVersion;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

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
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->appendToGroup('web', EnsureCredentialVersion::class);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->expectsJson(),
        );
    })->create();
