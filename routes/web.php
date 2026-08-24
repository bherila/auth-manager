<?php

use App\Http\Controllers\LoginController;
use App\Http\Controllers\OAuthUserController;
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

// The identity claim relying applications read after exchanging their code.
// Bound to the token's subject, never to a client-supplied identifier.
Route::get('/api/oauth/user', OAuthUserController::class)
    ->middleware('auth:api')
    ->name('oauth.user');
