<?php

namespace BWH\AuthManager\Http\Controllers;

use BWH\AuthManager\Models\TrustedDevice;
use BWH\AuthManager\Services\AccountSettingsService;
use BWH\AuthManager\Services\TrustedDevices;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;

final class AccountSettingsController extends Controller
{
    public function show(Request $request, TrustedDevices $trustedDevices): Response
    {
        return response()->view('settings.account', [
            'person' => $request->user(),
            'trustedDevices' => TrustedDevices::enabled()
                ? $trustedDevices->listFor($request->user())->map(static fn (TrustedDevice $device): array => [
                    'device' => $device,
                    'current' => $trustedDevices->isThisBrowser($request, $device),
                ])
                : null,
        ])->header('Cache-Control', 'no-store, private');
    }

    public function revokeTrustedDevice(Request $request, string $device, TrustedDevices $trustedDevices): RedirectResponse
    {
        $trustedDevices->revoke($request, $request->user(), $device);

        return redirect()->route('auth-manager.settings.account')
            ->with('trusted-devices-status', 'That browser will be asked for a code at its next sign-in.');
    }

    public function revokeTrustedDevices(Request $request, TrustedDevices $trustedDevices): RedirectResponse
    {
        $trustedDevices->revokeAll($request, $request->user());

        return redirect()->route('auth-manager.settings.account')
            ->with('trusted-devices-status', 'Every browser will be asked for a code at its next sign-in.');
    }

    public function changePassword(Request $request, AccountSettingsService $settings): JsonResponse
    {
        $data = $request->validate([
            'current_password' => ['required', 'string', 'max:1024'],
            'password' => ['required', 'string', 'min:'.config('auth-manager.password_min_length'), 'max:72', static function (string $attribute, mixed $value, Closure $fail): void {
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
