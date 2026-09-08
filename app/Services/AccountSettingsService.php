<?php

namespace App\Services;

use App\Models\User;
use BWH\Auth\Models\AuthAuditLog;
use BWH\Auth\Support\ClientIp;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

final class AccountSettingsService
{
    public function __construct(private readonly OAuthTokenRevocationService $tokens) {}

    public function changePassword(Request $request, string $currentPassword, string $password): void
    {
        DB::transaction(function () use ($request, $currentPassword, $password): void {
            // Recheck under the same lock as credential rotation: an administrator
            // may have disabled the account or reset its password since middleware.
            $user = User::query()->lockForUpdate()->findOrFail($request->user()->getAuthIdentifier());
            abort_unless($user->canLogin(), 403);
            if (! Hash::check($currentPassword, $user->password)) {
                throw ValidationException::withMessages(['current_password' => 'The current password is incorrect.']);
            }
            $user->forceFill([
                'password' => $password,
                'credential_version' => (int) $user->credential_version + 1,
                'remember_token' => Str::random(60),
            ])->save();
            $this->tokens->forSubject((string) $user->getKey());
            DB::table('sessions')->where('user_id', $user->getKey())->delete();
            AuthAuditLog::create([
                'user_id' => $user->getKey(),
                'acting_user_id' => $user->getKey(),
                'email' => $user->email,
                'event' => 'self_password_changed',
                'auth_method' => 'password',
                'succeeded' => true,
                'ip_address' => ClientIp::resolve($request),
                'user_agent' => $request->userAgent(),
                'session_id' => $request->session()->getId(),
            ]);
        });
    }
}
