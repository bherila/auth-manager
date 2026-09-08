<?php

namespace App\Http\Middleware;

use App\Services\DelegatedAccess\DelegatedAccessException;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class ApplicationAccessResponse
{
    public function handle(Request $request, Closure $next): Response
    {
        try {
            $response = $next($request);
        } catch (DelegatedAccessException $exception) {
            $message = match ($exception->outcome) {
                'unknown_outcome' => 'The application did not confirm the result. The change may have completed. Reload current access before attempting another change.',
                'revision_conflict' => 'Access changed since you opened this form. Reload current access before editing again.',
                'recent_confirmation_required' => 'Confirm your password or sign in again before changing application access.',
                'not_authenticated' => 'Your authenticated session is no longer current. Sign in again.',
                'not_authorized' => 'The application has not authorized this account to manage the requested access.',
                'invalid_request' => 'The application could not accept these access changes. Reload current access and review the supported controls.',
                default => 'Application access is unavailable. Try again later; saved results are not being shown as current.',
            };
            $response = response()->view('applications.access-error', [
                'message' => $message, 'application' => $request->route('application'),
            ], $exception->status);
        }
        $response->headers->set('Cache-Control', 'private, no-store');

        return $response;
    }
}
