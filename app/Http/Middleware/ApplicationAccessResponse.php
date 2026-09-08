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
        $response = $next($request);
        $response->headers->set('Cache-Control', 'private, no-store');

        return $response;
    }

    public static function failure(DelegatedAccessException $exception, Request $request): Response
    {
        $message = match ($exception->outcome) {
            'unknown_outcome' => 'The application did not confirm the result. The change may have completed. Reload current access before attempting another change.',
            'revision_conflict' => 'Access changed since you opened this form. Reload current access before editing again.',
            'recent_confirmation_required' => 'Confirm your password or sign in again before changing application access.',
            'not_authenticated' => 'Your authenticated session is no longer current. Sign in again.',
            'not_authorized' => 'The application has not authorized this account to manage the requested access.',
            'invalid_request' => 'The application could not accept these access changes. Reload current access and review the supported controls.',
            default => 'Application access is unavailable. Try again later; saved results are not being shown as current.',
        };

        // A failed write must land on a GET page. Rendering it at the POST-only update
        // URL invites a refresh, which resubmits the write; when the first outcome is
        // unknown, that second write is exactly the retry the contract forbids.
        if ($request->routeIs('applications.access.update')) {
            $subject = $request->input('subject');

            return redirect()->route('applications.access', array_filter([
                'application' => $request->route('application'),
                'subject' => is_string($subject) && $subject !== '' ? $subject : null,
            ]))->with('access_failure', $message);
        }

        return response()->view('applications.access-error', [
            'message' => $message, 'application' => $request->route('application'),
        ], $exception->status, ['Cache-Control' => 'private, no-store']);
    }
}
