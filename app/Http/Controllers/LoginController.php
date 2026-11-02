<?php

namespace BWH\AuthManager\Http\Controllers;

use BWH\Auth\Concerns\LogsAuthEvents;
use BWH\Auth\Contracts\LoginThrottle;
use BWH\Auth\Models\TwoFactorAttempt;
use BWH\Auth\Services\TwoFactorService;
use BWH\AuthManager\Http\Middleware\RequireRecentPasskeyAuthentication;
use BWH\AuthManager\Models\User;
use Illuminate\Contracts\View\View;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Str;

class LoginController extends Controller
{
    use LogsAuthEvents;

    private const PASSWORD_CHALLENGE_SESSION_KEY = 'auth_manager_password_challenge';

    /** Codes one address can be sent through the password flow in the window below. */
    private const PASSWORD_CHALLENGE_MAIL_LIMIT = 5;

    private const PASSWORD_CHALLENGE_MAIL_WINDOW_SECONDS = 300;

    public function show(Request $request): View
    {
        $attempt = $this->livePasswordChallenge($request);

        return view('login', [
            'passwordChallenge' => $attempt === null ? null : [
                'attempt_token' => (string) $attempt->getAttribute('token'),
                'email' => (string) $request->session()->get(self::PASSWORD_CHALLENGE_SESSION_KEY.'.email'),
            ],
        ]);
    }

    public function login(Request $request, LoginThrottle $throttle, TwoFactorService $twoFactor): RedirectResponse
    {
        $email = $request->input('email', '');
        $credentials = $request->only('email', 'password');
        $remember = $request->boolean('remember');

        $throttleState = $throttle->inspect($request, null, $email, 'password');
        if (! $throttleState->allowsLogin()) {
            $throttle->recordBlocked($request, null, $email, 'password', $throttleState);
            $seconds = $throttleState->availableInSeconds();

            return back()
                ->withErrors(['email' => "Too many sign-in attempts. Please try again in {$seconds} seconds."])
                ->withInput($request->only('email', 'remember'));
        }

        if (config('auth-manager.sign_in.code_after_password')) {
            return $this->startPasswordChallenge($request, $credentials, $remember, $twoFactor);
        }

        if (Auth::attempt($credentials, $remember)) {
            $user = Auth::user();

            // Check if user has valid role to login
            if (! $user->canLogin()) {
                Auth::logout();
                $request->session()->invalidate();
                $this->auditLoginFailed($request, $user, $email, 'Account disabled', 'password');

                return back()
                    ->withErrors(['email' => 'Your account is disabled. Please contact an administrator.'])
                    ->withInput($request->only('email', 'remember'));
            }

            $request->session()->regenerate();
            RequireRecentPasskeyAuthentication::recordCredentialVerification($request);
            $this->auditLoginSucceeded($request, $user, 'password');

            return redirect()->intended(route('auth-manager.home'));
        }

        return $this->invalidCredentials($request);
    }

    /**
     * Sends a new code for the challenge this session's password opened. The package's resend
     * endpoint would work too, but the session has to follow the new token so a reload keeps it.
     */
    public function resendPasswordChallenge(Request $request, TwoFactorService $twoFactor): JsonResponse
    {
        $attempt = $this->livePasswordChallenge($request);
        $user = $attempt?->getRelationValue('user');

        if (! $attempt instanceof TwoFactorAttempt || ! $user instanceof User || ! $user->canLogin()) {
            $this->clearPasswordChallenge($request);

            return response()->json(['success' => false, 'message' => 'That sign-in expired. Start again.'], 422);
        }

        if (! $this->mayMailPasswordChallenge($user)) {
            return response()->json(['success' => false, 'message' => 'Too many sign-in code requests. Please try again later.'], 429);
        }

        $attempt->update(['is_used' => true]);
        $remember = (bool) $request->session()->get((string) config('bherila-auth.two_factor.session_remember_key'), false);
        $next = $twoFactor->startChallenge($user, $request, $remember);
        $request->session()->put(self::PASSWORD_CHALLENGE_SESSION_KEY.'.token', (string) $next->getAttribute('token'));

        return response()->json(['success' => true, 'attempt_token' => (string) $next->getAttribute('token')]);
    }

    public function cancelPasswordChallenge(Request $request): JsonResponse|RedirectResponse
    {
        $this->livePasswordChallenge($request)?->update(['is_used' => true]);
        $this->clearPasswordChallenge($request);

        return $request->expectsJson()
            ? response()->json(['success' => true])
            : redirect()->route('auth-manager.login');
    }

    /** @param array<string, mixed> $credentials */
    private function startPasswordChallenge(Request $request, array $credentials, bool $remember, TwoFactorService $twoFactor): RedirectResponse
    {
        $email = (string) $request->input('email', '');

        // validate(), not attempt(): nothing is signed in until the code is verified.
        if (! Auth::validate($credentials)) {
            return $this->invalidCredentials($request);
        }

        $user = Auth::getLastAttempted();
        if (! $user instanceof User || ! $user->canLogin()) {
            $this->auditLoginFailed($request, $user, $email, 'Account disabled', 'password');

            return back()
                ->withErrors(['email' => 'Your account is disabled. Please contact an administrator.'])
                ->withInput($request->only('email', 'remember'));
        }

        if (! $this->mayMailPasswordChallenge($user)) {
            return back()
                ->withErrors(['email' => 'Too many sign-in code requests. Please try again later.'])
                ->withInput($request->only('email', 'remember'));
        }

        if (config('hashing.rehash_on_login', true)) {
            Auth::getProvider()->rehashPasswordIfRequired($user, $credentials);
        }

        $request->session()->regenerate();
        $attempt = $twoFactor->startChallenge($user, $request, $remember);
        $request->session()->put(self::PASSWORD_CHALLENGE_SESSION_KEY, [
            'token' => (string) $attempt->getAttribute('token'),
            'email' => (string) $user->getAttribute('email'),
        ]);

        return redirect()->route('auth-manager.login');
    }

    private function livePasswordChallenge(Request $request): ?TwoFactorAttempt
    {
        $token = $request->session()->get(self::PASSWORD_CHALLENGE_SESSION_KEY.'.token');
        if (! is_string($token) || $token === '') {
            return null;
        }

        // A verified code clears the package's pending key, which ends the challenge here too.
        $attempt = $request->session()->has((string) config('bherila-auth.two_factor.session_user_key'))
            ? TwoFactorAttempt::where('token', $token)->first()
            : null;

        if ($attempt === null || ! $attempt->isValid()) {
            $this->clearPasswordChallenge($request);

            return null;
        }

        return $attempt;
    }

    private function clearPasswordChallenge(Request $request): void
    {
        $request->session()->forget([
            self::PASSWORD_CHALLENGE_SESSION_KEY,
            (string) config('bherila-auth.two_factor.session_user_key'),
            (string) config('bherila-auth.two_factor.session_remember_key'),
        ]);
    }

    /** Only someone holding the password gets here, so this can't reveal whether an account exists. */
    private function mayMailPasswordChallenge(User $user): bool
    {
        $key = 'password-challenge-mail:'.$user->getKey();
        if (RateLimiter::tooManyAttempts($key, self::PASSWORD_CHALLENGE_MAIL_LIMIT)) {
            return false;
        }
        RateLimiter::hit($key, self::PASSWORD_CHALLENGE_MAIL_WINDOW_SECONDS);

        return true;
    }

    private function invalidCredentials(Request $request): RedirectResponse
    {
        $this->auditLoginFailed($request, null, (string) $request->input('email', ''), 'Invalid credentials', 'password');
        $message = config('auth-manager.sign_in.code_only')
            ? "That email and password don't match. Try again, or email yourself a sign-in code."
            : "That email and password don't match. Try again.";

        // Only the email and remember flag are flashed back; the password never is.
        return back()
            ->withErrors(['email' => $message])
            ->withInput($request->only('email', 'remember'));
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
        // Before any lookup, so the answer is the same for every address.
        abort_unless(config('auth-manager.sign_in.code_only'), 404);

        $validated = $request->validate([
            'email' => 'required|email|max:254',
        ]);

        $email = trim($validated['email']);
        $remember = $request->boolean('remember');
        $user = User::where('email', $email)->first();

        if ($user && $user->canLogin()) {
            $attempt = $twoFactor->startChallenge($user, $request, $remember);

            return response()->json(['success' => true, 'attempt_token' => (string) $attempt->getAttribute('token')]);
        }

        $this->auditLoginFailed($request, $user, $email, $user ? 'Account disabled' : 'User not found', 'email_code');

        return response()->json(['success' => true, 'attempt_token' => Str::random(64)]);
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

        return redirect()->intended(route('auth-manager.home'));
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

        return redirect()->intended(route('auth-manager.home'));
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
