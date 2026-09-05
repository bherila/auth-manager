<?php

use App\Http\Controllers\EndSessionController;
use App\Http\Middleware\AuditOAuthAuthorization;
use App\Http\Middleware\EnsureOAuthSessionIsFullyAuthenticated;
use App\Http\Middleware\RequireOAuthClientGrant;
use BWH\Auth\Http\Controllers\OAuthDynamicClientRegistrationController;
use BWH\Auth\Http\Controllers\OAuthMetadataController;
use BWH\Auth\Http\Controllers\OAuthTokenIntrospectionController;
use BWH\Auth\Http\Middleware\EnforceOAuthPkce;
use BWH\Auth\Http\Middleware\EnforceOAuthResourceIndicator;
use BWH\Auth\Http\Middleware\EnsureOAuthServerEnabled;
use BWH\Auth\Http\Middleware\RequireActiveUser;
use Illuminate\Support\Facades\Route;
use Laravel\Passport\Http\Controllers\AccessTokenController;
use Laravel\Passport\Http\Controllers\ApproveAuthorizationController;
use Laravel\Passport\Http\Controllers\AuthorizationController;
use Laravel\Passport\Http\Controllers\DenyAuthorizationController;

Route::prefix(config('passport.path', 'oauth'))
    ->name('passport.')
    ->group(function (): void {
        $oauthServerMiddleware = config('auth-manager.oauth_server')
            ? [
                EnsureOAuthServerEnabled::class,
                EnforceOAuthPkce::class,
                EnforceOAuthResourceIndicator::class,
            ]
            : [];

        Route::post('/token', [AccessTokenController::class, 'issueToken'])
            ->middleware([...$oauthServerMiddleware, 'throttle'])
            ->name('token');

        // Relying-party initiated logout. On the `web` middleware so it can reach — and
        // destroy — the session cookie this service owns.
        Route::get('/end-session', EndSessionController::class)
            ->middleware('web')
            ->name('end-session');

        $authorizationMiddleware = [
            ...$oauthServerMiddleware,
            'web',
            EnsureOAuthSessionIsFullyAuthenticated::class,
            RequireActiveUser::class,
            RequireOAuthClientGrant::class,
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

if (config('auth-manager.oauth_server')) {
    Route::get('/.well-known/oauth-authorization-server', [OAuthMetadataController::class, 'authorizationServer'])
        ->middleware(EnsureOAuthServerEnabled::class)
        ->name('oauth.metadata.authorization-server');
}

if (config('auth-manager.oauth_server') && config('auth-manager.dynamic_client_registration')) {
    Route::post('/oauth/register', OAuthDynamicClientRegistrationController::class)
        ->middleware([EnsureOAuthServerEnabled::class, 'throttle:10,1'])
        ->name('oauth.register');
}

if (config('auth-manager.oauth_server') && config('auth-manager.introspection')) {
    Route::post('/oauth/introspect', OAuthTokenIntrospectionController::class)
        ->middleware([EnsureOAuthServerEnabled::class, 'throttle:300,1'])
        ->name('oauth.introspect');
}
