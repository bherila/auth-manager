<?php

use App\Http\Controllers\DirectoryAdminController;
use App\Http\Controllers\LoginController;
use App\Http\Controllers\OAuthUserController;
use App\Http\Middleware\RequireProviderAdmin;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::get('/login', fn () => view('login'))->name('login');
Route::post('/login', [LoginController::class, 'login']);
Route::post('/login/email-code', [LoginController::class, 'requestEmailCode'])->name('login.email-code');
Route::post('/login/dev', [LoginController::class, 'devLogin'])->name('login.dev');
Route::post('/login/dev-by-id', [LoginController::class, 'devLoginById'])->name('login.dev.by-id');

Route::post('/logout', function (Request $request) {
    Auth::logout();
    $request->session()->invalidate();
    $request->session()->regenerateToken();

    return redirect('/');
})->name('logout');

Route::middleware(['auth', RequireProviderAdmin::class])->group(function (): void {
    Route::view('/admin/users', 'admin.users')->name('admin.users');

    Route::prefix('/api/admin')->group(function (): void {
        Route::get('/users', [DirectoryAdminController::class, 'index']);
        Route::post('/users', [DirectoryAdminController::class, 'store']);
        Route::patch('/users/{user}/email', [DirectoryAdminController::class, 'updateEmail']);
        Route::post('/users/{user}/disable', [DirectoryAdminController::class, 'disable']);
        Route::post('/users/{user}/enable', [DirectoryAdminController::class, 'enable']);
        Route::put('/users/{user}/password', [DirectoryAdminController::class, 'resetPassword']);
        Route::delete('/users/{user}', [DirectoryAdminController::class, 'destroy']);
        Route::put('/users/{user}/clients/{client}', [DirectoryAdminController::class, 'grantClient']);
        Route::delete('/users/{user}/clients/{client}', [DirectoryAdminController::class, 'revokeClient']);
    });
});

// The identity claim relying applications read after exchanging their code.
// Bound to the token's subject, never to a client-supplied identifier.
Route::get('/api/oauth/user', OAuthUserController::class)
    ->middleware('auth:api')
    ->name('oauth.user');
