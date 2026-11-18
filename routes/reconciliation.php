<?php

use BWH\AuthManager\Http\Controllers\IdentityReconciliationController;
use BWH\AuthManager\Http\Controllers\IdentityStatusController;
use BWH\AuthManager\Http\Middleware\AuthenticateReconciliationClient;
use BWH\AuthManager\Support\Mount;
use Illuminate\Support\Facades\Route;

// The per-IP budget runs before client authentication and only bounds unauthenticated traffic.
// Each authenticated client then has its own budget per operation (see auth-manager.reconciliation).
Route::prefix('/api/reconciliation')
    ->middleware([Mount::apiMiddleware(), 'throttle:auth-manager.reconciliation-ip', AuthenticateReconciliationClient::class])
    ->group(function (): void {
        Route::post('/identity-status', IdentityStatusController::class)
            ->middleware('throttle:auth-manager.reconciliation-status')
            ->name('reconciliation.identity-status');
        Route::get('/identity-tombstones', [IdentityReconciliationController::class, 'index'])
            ->middleware('throttle:auth-manager.reconciliation-tombstones')
            ->name('reconciliation.identity-tombstones.index');
        Route::put('/identity-tombstones/{tombstone}/acknowledgement', [IdentityReconciliationController::class, 'acknowledge'])
            ->middleware('throttle:auth-manager.reconciliation-tombstones')
            ->whereUuid('tombstone')
            ->name('reconciliation.identity-tombstones.acknowledge');
    });
