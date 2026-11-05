<?php

namespace BWH\AuthManager\Services;

use BWH\AuthManager\Http\Middleware\EnsureCredentialVersion;
use BWH\AuthManager\Http\Middleware\RequireRecentPasskeyAuthentication;
use BWH\AuthManager\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

/** Shared lock order and recovery invariant for HTTP and operator role mutations. */
final class ProviderAdministrators
{
    public const CONFIRMATION_KEY = 'provider_administration_confirmation';

    public function __construct(private readonly OAuthTokenRevocationService $tokens) {}

    /** @return Collection<int, User> */
    public function lockDirectory(): Collection
    {
        // Locking reads see the latest committed roles under MariaDB repeatable-read.
        // Every operation that can remove an administrator follows this order.
        return User::withTrashed()->orderBy('id')->lockForUpdate()->get();
    }

    /** @param Collection<int, User> $users */
    public function target(Collection $users, User $target): User
    {
        $locked = $users->first(static fn (User $user): bool => $user->getKey() === $target->getKey());
        abort_unless($locked instanceof User && ! $locked->trashed(), 404);

        return $locked;
    }

    /** @param Collection<int, User> $users */
    public function actor(Collection $users, User $actor, Request $request, bool $recent = false): User
    {
        $locked = $users->first(static fn (User $user): bool => $user->getKey() === $actor->getKey());
        abort_unless($locked instanceof User && $locked->canLogin() && $locked->hasRole('admin'), 403, 'Active provider-administrator authority is required.');
        abort_unless((int) $actor->credential_version === (int) $locked->credential_version, 409, 'Your provider authority changed. Reload and sign in again.');
        if ($request->hasSession()) {
            $version = $request->session()->get(EnsureCredentialVersion::SESSION_KEY);
            abort_unless($version === (int) $locked->credential_version, 409, 'Your session changed. Reload and sign in again.');
        }
        if ($recent) {
            $confirmed = $request->hasSession() ? $request->session()->get(self::CONFIRMATION_KEY) : null;
            $signedIn = $request->hasSession() ? $request->session()->get(RequireRecentPasskeyAuthentication::SESSION_KEY) : null;
            $now = now()->getTimestamp();
            $fresh = static fn (mixed $proof): bool => is_array($proof) && ($proof['user_id'] ?? null) === (string) $locked->id
                && is_int($proof['authenticated_at'] ?? null) && $proof['authenticated_at'] <= $now && $proof['authenticated_at'] >= $now - 300;
            abort_unless(($fresh($confirmed) && ($confirmed['credential_version'] ?? null) === (int) $locked->credential_version)
                || $fresh($signedIn), 403, 'Confirm your password or sign in again before changing provider-administrator authority.');
        }

        return $locked;
    }

    /** @param Collection<int, User> $users */
    public function preserveRecoveryAdministrator(Collection $users, User $target, string $action): void
    {
        if ($target->canLogin() && $target->hasRole('admin')
            && $users->filter(static fn (User $user): bool => $user->canLogin() && $user->hasRole('admin'))->count() <= 1) {
            throw ValidationException::withMessages(['user' => "The last active provider administrator cannot be {$action}."]);
        }
    }

    public function revision(User $user): string
    {
        return hash('sha256', json_encode([
            (string) $user->getKey(), $user->roleNames(), $user->disabled_at?->toISOString(),
            $user->deleted_at?->toISOString(), (int) $user->credential_version,
        ], JSON_THROW_ON_ERROR));
    }

    public function expectRevision(User $user, ?string $expected): void
    {
        abort_unless($expected === null || hash_equals($this->revision($user), $expected), 409, 'This directory account changed. Reload its current state before trying again.');
    }

    /** Call while the target row is locked, after applying its new role list. */
    public function invalidateAuthority(User $user): void
    {
        $user->forceFill(['credential_version' => (int) $user->credential_version + 1, 'remember_token' => null])->save();
        $this->tokens->forSubject((string) $user->getKey());
        DB::table('sessions')->where('user_id', $user->getKey())->delete();
        DB::table('trusted_devices')->where('user_id', $user->getKey())->delete();
        DB::table(config('bherila-auth.two_factor.table', 'auth_two_factor_attempts'))->where('user_id', $user->getKey())->delete();
        DB::table('password_reset_tokens')->where('email', $user->email)->delete();
    }
}
