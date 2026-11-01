<?php

namespace BWH\AuthManager\Http\Controllers;

use BWH\AuthManager\Http\Middleware\EnsureCredentialVersion;
use BWH\AuthManager\Http\Middleware\RequireRecentPasskeyAuthentication;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\DelegatedAccess\DelegatedAccessTransport;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class ConfirmApplicationAccessController extends Controller
{
    public function __invoke(Request $request, string $application, DelegatedAccessTransport $transport): RedirectResponse
    {
        // Prove current application visibility before confirming an action for it.
        $transport->send($request, $application, ['operation' => 'capabilities']);
        $input = $request->validate(['password' => ['required', 'string', 'max:4096']]);
        DB::transaction(function () use ($request, $input): void {
            $user = User::query()->lockForUpdate()->find($request->user()?->getAuthIdentifier());
            if (! $user instanceof User || ! $user->canLogin()
                || $request->session()->get(EnsureCredentialVersion::SESSION_KEY) !== (int) $user->credential_version
                || ! Hash::check($input['password'], $user->password)) {
                throw ValidationException::withMessages(['password' => 'The password could not be confirmed.']);
            }
            RequireRecentPasskeyAuthentication::recordCredentialVerification($request);
        });

        return redirect()->route('auth-manager.applications.access', ['application' => $application])
            ->with('status', 'Identity confirmed. Select the account to review its current access.');
    }
}
