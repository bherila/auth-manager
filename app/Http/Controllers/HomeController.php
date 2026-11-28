<?php

namespace BWH\AuthManager\Http\Controllers;

use BWH\AuthManager\Models\User;
use BWH\AuthManager\Support\RelyingApplications;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

final class HomeController
{
    public function __invoke(Request $request, RelyingApplications $applications): View|RedirectResponse
    {
        $user = $request->user();
        $key = config('application-registry.default_application');

        if ($user instanceof User && $user->canLogin() && ! $user->hasRole('admin')
            && config('application-registry.launch_enabled') && is_string($key) && $key !== '') {
            // Reuse launch discovery so the default never supplies a grant or bypasses
            // disabled applications, revoked clients or static-client eligibility.
            foreach ($applications->forSubject((string) $user->getKey()) as $application) {
                if ($application['key'] === $key) {
                    return redirect()->away($application['url']);
                }
            }
        }

        return view('welcome');
    }
}
