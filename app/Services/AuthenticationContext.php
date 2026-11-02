<?php

namespace BWH\AuthManager\Services;

use BWH\Auth\Models\PasskeyCredential;
use BWH\Auth\OAuth\AuthenticationRequirement;
use BWH\AuthManager\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

/**
 * How the person in this session last presented a credential.
 *
 * Only a verified password, emailed code or passkey assertion sets it. Restoring a session
 * from a remember-me cookie starts one with no values, and that satisfies no `max_age` or
 * `acr_values` request, so those always force a real re-authentication.
 */
final class AuthenticationContext
{
    public const string SESSION_KEY = 'auth_manager_authentication';

    /** @param  list<string>  $amr */
    public static function record(Request $request, User $user, array $amr, string $acr): void
    {
        $request->session()->put(self::SESSION_KEY, [
            'user_id' => (string) $user->getKey(),
            'auth_time' => now()->getTimestamp(),
            'amr' => $amr,
            'acr' => $acr,
            // Seconds can't tell two presentations apart, so a re-authentication compares this.
            'presentation' => Str::random(32),
        ]);
    }

    public static function recordPasskey(Request $request, User $user, PasskeyCredential $credential, bool $userVerified): void
    {
        self::record(
            $request,
            $user,
            // Device-bound is the authenticator's own unverified claim, so it's informational.
            [$credential->backup_eligible === false ? 'hwk' : 'swk'],
            // Only a passkey with user verification reaches this rung.
            $userVerified ? AuthenticationRequirement::ACR_PHISHING_RESISTANT : AuthenticationRequirement::ACR_SINGLE,
        );
    }

    /** @return array{auth_time: int, amr: list<string>, acr: string, presentation: string|null}|null */
    public static function for(Request $request, User $user): ?array
    {
        $context = $request->hasSession() ? $request->session()->get(self::SESSION_KEY) : null;

        if (! is_array($context)
            || ($context['user_id'] ?? null) !== (string) $user->getKey()
            || ! is_int($context['auth_time'] ?? null)
            || ! is_array($context['amr'] ?? null)
            || ! is_string($context['acr'] ?? null)) {
            return null;
        }

        return [
            'auth_time' => $context['auth_time'],
            'amr' => array_values($context['amr']),
            'acr' => $context['acr'],
            'presentation' => is_string($context['presentation'] ?? null) ? $context['presentation'] : null,
        ];
    }
}
