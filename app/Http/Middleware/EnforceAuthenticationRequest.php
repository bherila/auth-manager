<?php

namespace BWH\AuthManager\Http\Middleware;

use BWH\Auth\Models\PasskeyCredential;
use BWH\Auth\OAuth\AuthenticationRequirement;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\AuthenticationContext;
use Closure;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Laravel\Passport\Passport;
use Symfony\Component\HttpFoundation\Response;

/**
 * Honours `prompt=login`, `max_age` and `acr_values` on the authorization endpoint.
 *
 * The person keeps their session while re-authenticating, so a link carrying `prompt=login`
 * can't sign anyone out. It must reach the same subject, and a different person signing in
 * cancels the flow. Relying applications check what comes back themselves, so this is a
 * convenience rather than their enforcement.
 */
final class EnforceAuthenticationRequest
{
    public const string SESSION_KEY = 'auth_manager_reauthentication';

    public function handle(Request $request, Closure $next): Response
    {
        $prompts = array_filter(explode(' ', (string) $request->query('prompt', '')));
        $pendingKey = (string) config('bherila-auth.two_factor.session_user_key', 'bherila_auth_2fa_user_id');

        // Refused or held by EnsureOAuthSessionIsFullyAuthenticated, which runs next.
        if (! $request->isMethod('GET') || in_array('none', $prompts, true) || $request->session()->has($pendingKey)) {
            return $next($request);
        }

        $maxAge = $request->query('max_age');
        if ($maxAge !== null && (! is_string($maxAge) || ! ctype_digit($maxAge))) {
            return $this->refuse($request, 'invalid_request', 'max_age must be a number of seconds.');
        }

        $values = array_values(array_filter(explode(' ', (string) $request->query('acr_values', ''))));
        $supported = self::supportedValues();
        foreach ($values as $value) {
            if (! in_array($value, $supported, true)) {
                return $this->refuse($request, 'invalid_request', 'Unsupported acr_values.');
            }
        }

        $requirement = new AuthenticationRequirement(in_array('login', $prompts, true), $maxAge === null ? null : (int) $maxAge, $values);
        if ($requirement->isEmpty()) {
            $request->session()->forget(self::SESSION_KEY);

            return $next($request);
        }

        $fingerprint = hash('sha256', (string) $request->getQueryString());
        $pending = $request->session()->get(self::SESSION_KEY);
        $pending = is_array($pending) && ($pending['fingerprint'] ?? null) === $fingerprint ? $pending : null;
        $user = $request->user();

        if ($pending !== null && $pending['subject'] !== null && (! $user instanceof User || (string) $user->getKey() !== $pending['subject'])) {
            if ($user === null) {
                return $this->requestAuthentication($request, $requirement, $fingerprint, $pending);
            }

            // Someone else signed in. Their session must not continue this flow.
            Auth::logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();

            return $this->refuse($request, 'access_denied', 'A different person signed in.');
        }

        if ($user instanceof User) {
            $context = AuthenticationContext::for($request, $user);
            $forced = $requirement->forceLogin || $requirement->maxAge === 0;
            $fresh = $context !== null && (! $forced || ($pending !== null && $context['auth_time'] >= $pending['requested_at']));

            if ($fresh && $requirement->satisfiedBy($context['auth_time'], $context['amr'], $context['acr'], now()->getTimestamp(), $pending['requested_at'] ?? null)) {
                $request->session()->forget(self::SESSION_KEY);
                // Passport would otherwise sign them out and ask a second time.
                if ($requirement->forceLogin) {
                    $request->session()->put('promptedForLogin', true);
                }

                return $next($request);
            }

            // They authenticated for this request, and it still didn't meet it. Asking again would loop.
            if ($pending !== null && $context !== null && $context['auth_time'] >= $pending['requested_at']) {
                $request->session()->forget(self::SESSION_KEY);

                return $this->refuse($request, 'unmet_authentication_requirements', 'The sign-in did not meet the requirement.');
            }

            if (! self::hasMethodFor($user, $values)) {
                return $this->refuse($request, 'unmet_authentication_requirements', 'This account has no sign-in method that meets the requirement.');
            }
        }

        return $this->requestAuthentication($request, $requirement, $fingerprint, $pending);
    }

    /** The `acr_values` this instance can satisfy. @return list<string> */
    public static function supportedValues(): array
    {
        $codes = (bool) config('auth-manager.sign_in.code_only') || (bool) config('auth-manager.sign_in.code_after_password');

        return array_values(array_filter([
            AuthenticationRequirement::ACR_SINGLE,
            AuthenticationRequirement::ACR_PHISHING_RESISTANT,
            // A verified passkey satisfies it even where no code follows the password.
            AuthenticationRequirement::ACR_MFA,
            config('auth-manager.sign_in.code_after_password') ? null : AuthenticationRequirement::AMR_PREFIX.'pwd',
            $codes ? AuthenticationRequirement::AMR_PREFIX.'otp' : null,
            AuthenticationRequirement::AMR_PREFIX.'hwk',
            AuthenticationRequirement::AMR_PREFIX.'swk',
        ]));
    }

    /**
     * Which sign-in methods the screen may offer for these values, or null for all of them.
     *
     * @param  list<string>  $values
     * @return list<'password'|'code'|'passkey'>|null
     */
    public static function offeredMethods(array $values): ?array
    {
        if ($values === [] || in_array(AuthenticationRequirement::ACR_SINGLE, $values, true)) {
            return null;
        }

        $methods = [];
        foreach ($values as $value) {
            $methods = [...$methods, ...match ($value) {
                AuthenticationRequirement::AMR_PREFIX.'pwd' => ['password'],
                AuthenticationRequirement::ACR_MFA => config('auth-manager.sign_in.code_after_password') ? ['password', 'passkey'] : ['passkey'],
                AuthenticationRequirement::AMR_PREFIX.'otp' => config('auth-manager.sign_in.code_after_password') ? ['password'] : ['code'],
                default => ['passkey'],
            }];
        }

        return array_values(array_unique($methods));
    }

    /** @param  list<string>  $values */
    private static function hasMethodFor(User $user, array $values): bool
    {
        $methods = self::offeredMethods($values);
        if ($methods === null || array_intersect($methods, ['password', 'code']) !== []) {
            return true;
        }

        $passkeys = PasskeyCredential::query()->where('user_id', $user->getKey());
        $classes = array_diff($values, [AuthenticationRequirement::ACR_PHISHING_RESISTANT, AuthenticationRequirement::ACR_MFA]);
        if (count($classes) !== count($values) || $classes === []) {
            return $passkeys->exists();
        }

        // A passkey enrolled before the flag was recorded could be either class.
        return $passkeys->where(static function ($query) use ($classes): void {
            $query->whereNull('backup_eligible');
            if (in_array(AuthenticationRequirement::AMR_PREFIX.'hwk', $classes, true)) {
                $query->orWhere('backup_eligible', false);
            }
            if (in_array(AuthenticationRequirement::AMR_PREFIX.'swk', $classes, true)) {
                $query->orWhere('backup_eligible', true);
            }
        })->exists();
    }

    /** @param  array<string, mixed>|null  $pending */
    private function requestAuthentication(Request $request, AuthenticationRequirement $requirement, string $fingerprint, ?array $pending): RedirectResponse
    {
        $user = $request->user();
        $request->session()->put(self::SESSION_KEY, [
            'fingerprint' => $fingerprint,
            'requested_at' => $pending['requested_at'] ?? now()->getTimestamp(),
            'subject' => $pending['subject'] ?? ($user instanceof User ? (string) $user->getKey() : null),
            'methods' => self::offeredMethods($requirement->acrValues),
        ]);
        $request->session()->put('url.intended', $request->fullUrl());

        return redirect()->route('auth-manager.login');
    }

    /** Back to the client when its redirect URI is registered, and otherwise a plain error. */
    private function refuse(Request $request, string $error, string $description): Response
    {
        $client = Passport::client()->newQuery()->find((string) $request->query('client_id'));
        $uri = $request->query('redirect_uri');
        $registered = $client === null ? [] : (array) $client->getAttribute('redirect_uris');

        abort_unless(is_string($uri) && in_array($uri, $registered, true), 400, $description);

        return redirect()->away($uri.(str_contains($uri, '?') ? '&' : '?').http_build_query(array_filter([
            'error' => $error,
            'error_description' => $description,
            'state' => is_string($request->query('state')) ? $request->query('state') : null,
        ])));
    }
}
