<?php

use BWH\AuthManager\Http\Controllers\ApplicationInvitationController;
use BWH\AuthManager\Http\Middleware\AuthenticateApplicationInvitationRequest;
use Illuminate\Support\Facades\Route;

// Admission invitations an application requests for itself; see docs/application-invitations.md.
// Off for every application until it is listed in AUTH_MANAGER_APPLICATION_INVITATIONS.
Route::prefix('/api/application-invitations')
    ->middleware(['api', 'throttle:60,1', AuthenticateApplicationInvitationRequest::class])
    ->group(function (): void {
        Route::post('/', [ApplicationInvitationController::class, 'store'])->name('application-invitations.store');
        Route::post('/{invitation}/resend', [ApplicationInvitationController::class, 'resend'])
            ->whereNumber('invitation')->name('application-invitations.resend');
        Route::post('/{invitation}/revoke', [ApplicationInvitationController::class, 'revoke'])
            ->whereNumber('invitation')->name('application-invitations.revoke');
    });
