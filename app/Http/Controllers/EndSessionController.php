<?php

namespace App\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;

/**
 * Sign out of the provider, then return to the application that asked.
 *
 * Without this, signing out of a relying application ends only that application's session.
 * The next protected page sends the person back here, this service still recognises them,
 * and they are returned signed in — which reads as a broken sign-out rather than as single
 * sign-on working. Ending the session here is what makes signing out mean something.
 *
 * Reached by a normal top-level navigation, as RP-initiated logout is everywhere: the point
 * is to destroy a cookie this service owns, which only a request carrying that cookie can
 * do. The consequence is that a third party can force a sign-out; that is an annoyance, not
 * a disclosure, and it is the accepted trade in the OpenID Connect design this follows.
 */
class EndSessionController extends Controller
{
    public function __invoke(Request $request): RedirectResponse
    {
        // Resolve the destination *before* logging out. `session()->invalidate()` throws away
        // the request's session, and reading query parameters afterwards is fine, but doing
        // the validation first keeps an invalid destination from ever being a redirect target.
        $destination = $this->validatedDestination(
            clientId: $request->query('client_id'),
            requested: $request->query('post_logout_redirect_uri'),
        );

        if (Auth::check()) {
            Auth::logout();
        }

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->away($destination);
    }

    /**
     * Where to send the person after signing out.
     *
     * An unvalidated `post_logout_redirect_uri` is an open redirect on a domain people are
     * trained to trust with a password, so a destination is only honoured when it shares an
     * origin with a redirect URI the named client already registered. Anything else falls
     * back to this service's own home page rather than failing — a person who has just been
     * signed out should land somewhere, not on an error.
     */
    private function validatedDestination(mixed $clientId, mixed $requested): string
    {
        $fallback = url('/');

        if (! is_string($clientId) || ! is_string($requested) || $requested === '') {
            return $fallback;
        }

        $requestedOrigin = $this->origin($requested);

        if ($requestedOrigin === null) {
            return $fallback;
        }

        $client = DB::table('oauth_clients')->where('id', $clientId)->where('revoked', false)->first();

        if ($client === null) {
            return $fallback;
        }

        $registered = json_decode((string) ($client->redirect_uris ?? ''), true);

        if (! is_array($registered)) {
            return $fallback;
        }

        foreach ($registered as $uri) {
            if (is_string($uri) && $this->origin($uri) === $requestedOrigin) {
                return $requested;
            }
        }

        return $fallback;
    }

    private function origin(string $uri): ?string
    {
        $parts = parse_url($uri);

        if (! isset($parts['scheme'], $parts['host'])) {
            return null;
        }

        return $parts['scheme'].'://'.$parts['host'].(isset($parts['port']) ? ':'.$parts['port'] : '');
    }
}
