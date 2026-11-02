<?php

namespace BWH\AuthManager\Services;

use BWH\Auth\Contracts\LocalCredentialPolicy;
use BWH\Auth\Models\AuthAuditLog;
use BWH\Auth\Support\ClientIp;
use BWH\AuthManager\Http\Middleware\EnforceAuthenticationRequest;
use BWH\AuthManager\Models\TrustedDevice;
use BWH\AuthManager\Models\User;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Cookie as ResponseCookie;

/**
 * Lets a person skip the emailed code on a browser they already confirmed with one.
 *
 * Off by default, and only meaningful where a code follows the password. A sign-in that skips
 * the code presented a password and nothing else, so it reports `pwd` and the `single` rung, and
 * a request for anything stronger still asks for the code.
 */
final class TrustedDevices
{
    /** `__Host-` makes the browser refuse it unless it is Secure, host-only and on the root path. */
    public const string COOKIE = '__Host-auth_manager_trusted_device';

    public static function enabled(): bool
    {
        return (bool) config('auth-manager.sign_in.trusted_devices')
            && (bool) config('auth-manager.sign_in.code_after_password');
    }

    /** The trusted browser that lets this password sign-in skip the code, if there is one. */
    public function standingInFor(Request $request, User $user): ?TrustedDevice
    {
        if (! self::enabled() || ! $this->passwordAloneMeetsPendingRequest($request)) {
            return null;
        }

        // Finishing a code challenge makes this same check, and skipping one must not lose it.
        if (! app(LocalCredentialPolicy::class)->mayUseLocalCredentials($user, $request)) {
            return null;
        }

        $hash = $this->presentedHash($request);

        return $hash === null ? null : TrustedDevice::activeFor($user)->where('token_hash', $hash)->first();
    }

    /** Remember this browser. Call only once this request has verified both password and code. */
    public function trust(Request $request, User $user): void
    {
        // Confirming a browser again replaces its row, so the list holds one entry for it.
        $this->rowForThisBrowser($request, $user)?->delete();

        $token = Str::random(64);
        $expires = now()->addDays((int) config('auth-manager.sign_in.trusted_device_days'));

        TrustedDevice::query()->create([
            'user_id' => $user->getKey(),
            'token_hash' => self::hash($token),
            'credential_version' => (int) $user->credential_version,
            'user_agent' => mb_substr((string) $request->userAgent(), 0, 512),
            'expires_at' => $expires,
        ]);
        Cookie::queue($this->cookie($token, $expires->getTimestamp()));
        $this->audit($request, $user, 'trusted_device_added');
    }

    /** @return Collection<int, TrustedDevice> */
    public function listFor(User $user): Collection
    {
        return TrustedDevice::activeFor($user)->latest('id')->get();
    }

    public function isThisBrowser(Request $request, TrustedDevice $device): bool
    {
        $hash = $this->presentedHash($request);

        return $hash !== null && hash_equals((string) $device->token_hash, $hash);
    }

    /** Stop trusting one of this person's browsers. An id that isn't theirs is a 404. */
    public function revoke(Request $request, User $user, string $id): void
    {
        $device = TrustedDevice::query()->where('user_id', $user->getKey())->findOrFail($id);

        if ($this->isThisBrowser($request, $device)) {
            $this->forgetCookie();
        }

        $device->delete();
        $this->audit($request, $user, 'trusted_device_revoked');
    }

    public function revokeAll(Request $request, User $user): void
    {
        TrustedDevice::query()->where('user_id', $user->getKey())->delete();
        $this->forgetCookie();
        $this->audit($request, $user, 'trusted_devices_revoked_all');
    }

    private function rowForThisBrowser(Request $request, User $user): ?TrustedDevice
    {
        $hash = $this->presentedHash($request);

        return $hash === null ? null : TrustedDevice::query()
            ->where('user_id', $user->getKey())
            ->where('token_hash', $hash)
            ->first();
    }

    /**
     * An application waiting on this sign-in may have asked for more than a password. `methods`
     * is null when it named no method, or accepts any, and otherwise lists what the login page may
     * offer. Skipping the code there would only have the request refused once the sign-in misses it.
     */
    private function passwordAloneMeetsPendingRequest(Request $request): bool
    {
        $pending = $request->session()->get(EnforceAuthenticationRequest::SESSION_KEY);

        return ! is_array($pending) || ($pending['methods'] ?? null) === null;
    }

    private function presentedHash(Request $request): ?string
    {
        $token = $request->cookie(self::COOKIE);

        return is_string($token) && $token !== '' ? self::hash($token) : null;
    }

    /** The token is 64 random characters, so an unkeyed hash can't be reversed from a stolen row. */
    private static function hash(string $token): string
    {
        return hash('sha256', $token);
    }

    private function forgetCookie(): void
    {
        Cookie::queue($this->cookie('', 1));
    }

    /**
     * Built directly: Cookie::make() fills in the session's cookie domain, and a Domain attribute
     * would make the browser reject a `__Host-` cookie.
     */
    private function cookie(string $value, int $expires): ResponseCookie
    {
        return new ResponseCookie(
            self::COOKIE,
            $value,
            $expires,
            '/',
            null,
            true,
            true,
            false,
            ResponseCookie::SAMESITE_STRICT,
        );
    }

    private function audit(Request $request, User $user, string $event): void
    {
        AuthAuditLog::create([
            'user_id' => $user->getKey(),
            'acting_user_id' => $user->getKey(),
            'email' => $user->email,
            'event' => $event,
            'auth_method' => null,
            'succeeded' => true,
            'ip_address' => ClientIp::resolve($request),
            'user_agent' => $request->userAgent(),
            'session_id' => $request->session()->getId(),
        ]);
    }
}
