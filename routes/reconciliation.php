<?php

use BWH\AuthManager\Http\Controllers\IdentityReconciliationController;
use BWH\AuthManager\Http\Controllers\IdentityStatusController;
use BWH\AuthManager\Http\Middleware\AuthenticateReconciliationClient;
use BWH\AuthManager\Support\Mount;
use Illuminate\Support\Facades\Route;

Route::prefix('/api/reconciliation')
    ->middleware([Mount::apiMiddleware(), 'throttle:60,1', AuthenticateReconciliationClient::class])
    ->group(function (): void {
        Route::post('/identity-status', IdentityStatusController::class)->name('reconciliation.identity-status');
        Route::get('/identity-tombstones', [IdentityReconciliationController::class, 'index'])
            ->name('reconciliation.identity-tombstones.index');
        Route::put('/identity-tombstones/{tombstone}/acknowledgement', [IdentityReconciliationController::class, 'acknowledge'])
            ->whereUuid('tombstone')
            ->name('reconciliation.identity-tombstones.acknowledge');
    });
