<?php

use App\Http\Controllers\IdentityReconciliationController;
use App\Http\Middleware\AuthenticateReconciliationClient;
use Illuminate\Support\Facades\Route;

Route::prefix('/api/reconciliation')
    ->middleware(['api', 'throttle:60,1', AuthenticateReconciliationClient::class])
    ->group(function (): void {
        Route::get('/identity-tombstones', [IdentityReconciliationController::class, 'index'])
            ->name('reconciliation.identity-tombstones.index');
        Route::put('/identity-tombstones/{tombstone}/acknowledgement', [IdentityReconciliationController::class, 'acknowledge'])
            ->whereUuid('tombstone')
            ->name('reconciliation.identity-tombstones.acknowledge');
    });
