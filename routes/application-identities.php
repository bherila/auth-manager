<?php

use BWH\AuthManager\Http\Controllers\ApplicationIdentityRegistrationController;
use BWH\AuthManager\Http\Middleware\AuthenticateApplicationRegistration;
use BWH\AuthManager\Http\Middleware\AuthenticateReconciliationClient;
use BWH\AuthManager\Support\Mount;
use Illuminate\Support\Facades\Route;

Route::post('/api/application-identities', ApplicationIdentityRegistrationController::class)
    ->middleware([Mount::apiMiddleware(), 'throttle:auth-manager.registration-ip', AuthenticateReconciliationClient::class, AuthenticateApplicationRegistration::class])
    ->name('application-identities.store');
