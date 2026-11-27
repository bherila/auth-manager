<?php

use BWH\AuthManager\Http\Controllers\TestLoginTicketController;
use BWH\AuthManager\Http\Middleware\AuthenticateReconciliationClient;
use BWH\AuthManager\Support\Mount;
use Illuminate\Support\Facades\Route;

Route::post('/api/test-login-tickets', [TestLoginTicketController::class, 'issue'])
    ->middleware([Mount::apiMiddleware(), 'throttle:auth-manager.registration-ip', AuthenticateReconciliationClient::class])
    ->name('test-logins.issue');

Route::middleware([Mount::webMiddleware(), 'throttle:30,1'])->group(function (): void {
    Route::get('/test-logins/confirm', static function () {
        abort_if(config('auth-manager.test_logins.ticket_clients', []) === [], 404);

        return response()->view('test-login-confirm')->header('Cache-Control', 'private, no-store');
    })->name('test-logins.show');
    Route::post('/test-logins/preview', [TestLoginTicketController::class, 'preview'])->name('test-logins.preview');
    Route::post('/test-logins/confirm', [TestLoginTicketController::class, 'confirm'])->name('test-logins.confirm');
});
