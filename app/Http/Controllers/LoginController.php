<?php

namespace App\Http\Controllers;

use App\Models\User;
use BWH\Auth\Concerns\LogsAuthEvents;
use BWH\Auth\Contracts\LoginThrottle;
use BWH\Auth\Services\TwoFactorService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class LoginController extends Controller
{
    use LogsAuthEvents;

    public function login(Request $request, LoginThrottle $throttle): RedirectResponse
    {
        $email = $request->input('email', '');
        $credentials = $request->only('email', 'password');
        $remember = $request->boolean('remember');

        $throttleState = $throttle->inspect($request, null, $email, 'password');
        if (! $throttleState->allowsLogin()) {
            $throttle->recordBlocked($request, null, $email, 'password', $throttleState);
            $seconds = $throttleState->availableInSeconds();

            return back()->withErrors(['email' => "Too many login attempts. Please try again in {$seconds} seconds."]);
        }

        if (Auth::attempt($credentials, $remember)) {
            $user = Auth::user();

            // Check if user has valid role to login
            if (! $user->canLogin()) {
                Auth::logout();
                $request->session()->invalidate();
                $this->auditLoginFailed($request, $user, $email, 'Account disabled', 'password');

                return back()->withErrors(['email' => 'Your account is disabled. Please contact an administrator.']);
            }

            $request->session()->regenerate();
            $this->auditLoginSucceeded($request, $user, 'password');

            return redirect()->intended('/');
        }

        $this->auditLoginFailed($request, null, $email, 'Invalid credentials', 'password');

        return back()->withErrors(['email' => 'Invalid credentials']);
    }

    /**
     * Passwordless login: email the user a one-time sign-in code.
     *
     * Reuses the bherila-auth two-factor challenge as a primary factor. The
     * response shape is identical whether or not the account exists so the
     * endpoint cannot be used to enumerate registered emails; the frontend
     * always advances to the code-entry step and a bogus token simply fails
     * verification with the same generic error.
     */
    public function requestEmailCode(Request $request, TwoFactorService $twoFactor): JsonResponse
    {
        $validated = $request->validate([
            'email' => 'required|email',
        ]);

        $email = $validated['email'];
        $remember = $request->boolean('remember');
        $user = User::where('email', $email)->first();

        if ($user && $user->canLogin()) {
            $attempt = $twoFactor->startChallenge($user, $request, $remember);

            return response()->json(['success' => true, 'attempt_token' => (string) $attempt->getAttribute('token')]);
        }

        $this->auditLoginFailed($request, $user, $email, $user ? 'Account disabled' : 'User not found', 'email_code');

        return response()->json(['success' => true, 'attempt_token' => '']);
    }

    /**
     * Development-only login that allows blank password.
     * Only works on localhost.
     */
    public function devLogin(Request $request)
    {
        // Only allow on localhost
        if (! $this->isLocalDevRequest($request)) {
            abort(403, 'Dev login is only available on localhost');
        }

        $request->validate([
            'email' => 'required|email',
        ]);

        $email = $request->input('email');
        $user = User::where('email', $email)->first();

        if (! $user) {
            $this->auditLoginFailed($request, null, $email, 'User not found', 'dev');

            return back()->withErrors(['email' => 'User not found']);
        }

        // Check if user has valid role to login
        if (! $user->canLogin()) {
            $this->auditLoginFailed($request, $user, $email, 'Account disabled', 'dev');

            return back()->withErrors(['email' => 'Your account is disabled. Please contact an administrator.']);
        }

        Auth::login($user);
        $request->session()->regenerate();

        // Update last login date
        $user->update(['last_login_date' => now()]);
        $this->auditLoginSucceeded($request, $user, 'dev');

        return redirect()->intended('/');
    }

    /**
     * Development-only login by user ID.
     * Only works on localhost.
     */
    public function devLoginById(Request $request): RedirectResponse
    {
        if (! $this->isLocalDevRequest($request)) {
            abort(403, 'Dev login is only available on localhost');
        }

        $request->validate([
            'user_id' => 'required|integer',
        ]);

        $user = User::find($request->input('user_id'));

        if (! $user) {
            return back()->withErrors(['email' => 'User not found']);
        }

        if (! $user->canLogin()) {
            return back()->withErrors(['email' => 'Your account is disabled. Please contact an administrator.']);
        }

        Auth::login($user);
        $request->session()->regenerate();
        $user->update(['last_login_date' => now()]);
        $this->auditLoginSucceeded($request, $user, 'dev');

        return redirect()->intended('/');
    }

    /**
     * Whether this request may use the password-less developer login routes.
     *
     * These routes authenticate as an arbitrary account without a credential, so the gate
     * guarding them is the only thing between a visitor and any user's session. It therefore
     * requires *two independent* conditions to hold, one configured and one observed:
     *
     * 1. The app is running in the `local` environment, and
     * 2. the request actually originates from a loopback address.
     *
     * The previous version returned true if `config('app.url')` merely *contained* the
     * substring `localhost` or `127.0.0.1`, with no check on the request at all. That turned
     * an ordinary configuration mistake — a staging box whose `APP_URL` still pointed at a
     * tunnel, or a copied `.env` — into a remote authentication bypass, and it is why this
     * has been flagged repeatedly by security scanning. `APP_ENV` alone is not sufficient
     * either: it is a single value, and a single value can be wrong.
     *
     * The IP check is not itself a security boundary (`REMOTE_ADDR` can be influenced by a
     * misconfigured proxy), which is exactly why it is required *in addition to* the
     * environment check rather than instead of it.
     */
    private function isLocalDevRequest(Request $request): bool
    {
        if (config('app.env') !== 'local') {
            return false;
        }

        return in_array($request->ip(), ['127.0.0.1', '::1'], true);
    }
}
