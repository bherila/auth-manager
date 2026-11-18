<?php

use BWH\AuthManager\Http\Controllers\IdentityReconciliationController;
use BWH\AuthManager\Http\Controllers\IdentityStatusController;
use BWH\AuthManager\Http\Middleware\AuthenticateReconciliationClient;
use BWH\AuthManager\Support\Mount;
use Illuminate\Support\Facades\Route;

// The per-IP budget runs before client authentication and only bounds unauthenticated traffic.
// Each authenticated client then has its own budget per operation, enforced by
// AuthenticateReconciliationClient itself once the client is known (see auth-manager.reconciliation):
// a route `throttle:` would be sorted ahead of authentication and key on the IP instead.
Route::prefix('/api/reconciliation')
    ->middleware([Mount::apiMiddleware(), 'throttle:auth-manager.reconciliation-ip'])
    ->group(function (): void {
        Route::post('/identity-status', IdentityStatusController::class)
            ->middleware(AuthenticateReconciliationClient::class.':status')
            ->name('reconciliation.identity-status');
        Route::get('/identity-tombstones', [IdentityReconciliationController::class, 'index'])
            ->middleware(AuthenticateReconciliationClient::class.':tombstones')
            ->name('reconciliation.identity-tombstones.index');
        Route::put('/identity-tombstones/{tombstone}/acknowledgement', [IdentityReconciliationController::class, 'acknowledge'])
            ->middleware(AuthenticateReconciliationClient::class.':tombstones')
            ->whereUuid('tombstone')
            ->name('reconciliation.identity-tombstones.acknowledge');
    });
