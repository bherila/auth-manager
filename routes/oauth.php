<?php

use App\Http\Controllers\EndSessionController;
use App\Http\Middleware\AuditOAuthAuthorization;
use App\Http\Middleware\EnsureOAuthSessionIsFullyAuthenticated;
use BWH\Auth\Http\Middleware\RequireActiveUser;
use Illuminate\Support\Facades\Route;
use Laravel\Passport\Http\Controllers\AccessTokenController;
use Laravel\Passport\Http\Controllers\ApproveAuthorizationController;
use Laravel\Passport\Http\Controllers\AuthorizationController;
use Laravel\Passport\Http\Controllers\DenyAuthorizationController;

Route::prefix(config('passport.path', 'oauth'))
    ->name('passport.')
    ->group(function (): void {
        Route::post('/token', [AccessTokenController::class, 'issueToken'])
            ->middleware('throttle')
            ->name('token');

        // Relying-party initiated logout. On the `web` middleware so it can reach — and
        // destroy — the session cookie this service owns.
        Route::get('/end-session', EndSessionController::class)
            ->middleware('web')
            ->name('end-session');

        $authorizationMiddleware = [
            'web',
            EnsureOAuthSessionIsFullyAuthenticated::class,
            RequireActiveUser::class,
            AuditOAuthAuthorization::class,
        ];

        Route::get('/authorize', [AuthorizationController::class, 'authorize'])
            ->middleware($authorizationMiddleware)
            ->name('authorizations.authorize');

        Route::middleware($authorizationMiddleware)
            ->group(function (): void {
                Route::post('/authorize', [ApproveAuthorizationController::class, 'approve'])
                    ->name('authorizations.approve');
                Route::delete('/authorize', [DenyAuthorizationController::class, 'deny'])
                    ->name('authorizations.deny');
            });
    });
