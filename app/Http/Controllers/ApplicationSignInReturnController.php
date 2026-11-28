<?php

namespace BWH\AuthManager\Http\Controllers;

use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\OAuthClientGrantService;
use BWH\AuthManager\Support\ApplicationSignInReturn;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

final class ApplicationSignInReturnController
{
    public function __invoke(Request $request, ApplicationSignInReturn $returns, OAuthClientGrantService $grants): RedirectResponse
    {
        $clientId = $returns->clientId($request);
        $application = $returns->application($clientId);
        $user = $request->user();
        if ($clientId === null || $application === null || ! $user instanceof User
            || ! $grants->allows((string) $user->getKey(), $clientId)) {
            return redirect()->route('auth-manager.home');
        }

        // The registered launch URL starts a fresh application-owned OAuth flow. Resetting
        // a password itself creates no session, and old state/PKCE is never replayed.
        return redirect()->away($application->launch_url);
    }
}
