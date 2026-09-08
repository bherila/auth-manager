<?php

namespace App\Http\Controllers;

use App\Services\AccountSettingsService;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;

final class AccountSettingsController extends Controller
{
    public function show(Request $request): Response
    {
        return response()->view('settings.account', ['person' => $request->user()])
            ->header('Cache-Control', 'no-store, private');
    }

    public function changePassword(Request $request, AccountSettingsService $settings): JsonResponse
    {
        $data = $request->validate([
            'current_password' => ['required', 'string', 'max:1024'],
            'password' => ['required', 'string', 'min:12', 'max:72', static function (string $attribute, mixed $value, Closure $fail): void {
                if (is_string($value) && strlen($value) > 72) {
                    $fail('The password must use at most 72 UTF-8 bytes.');
                }
            }, 'confirmed', 'different:current_password'],
        ]);
        $settings->changePassword($request, $data['current_password'], $data['password']);
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return response()->json(['success' => true, 'message' => 'Password changed. Sign in again with your new password.'])
            ->header('Cache-Control', 'no-store');
    }
}
