<?php

namespace BWH\AuthManager\Services;

use BWH\Auth\Models\AuthAuditLog;
use BWH\AuthManager\Models\IdentityTombstone;
use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Support\Mount;
use BWH\AuthManager\Support\StaticApplicationClients;
use BWH\AuthManager\Support\TestLoginAddresses;
use Carbon\CarbonImmutable;
use Closure;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

/** Trusted-console lifecycle; never adopts a person or grants a provider role. */
final class TestLoginService
{
    public function __construct(
        private readonly ProviderAdministrators $administrators,
        private readonly OAuthClientGrantService $grants,
        private readonly StaticApplicationClients $clients,
        private readonly IdentityRetirement $retirement,
    ) {}

    public static function parseExpiry(string $value): CarbonImmutable
    {
        try {
            $expiry = CarbonImmutable::createFromFormat('!Y-m-d\TH:i:s\Z', $value, 'UTC');
            if ($expiry !== false && $expiry->format('Y-m-d\TH:i:s\Z') === $value) {
                return $expiry;
            }
        } catch (\Throwable) {
            // Parser errors may contain the supplied input; report only the expected format.
        }

        throw ValidationException::withMessages(['expires_at' => 'Supply an explicit UTC expiry such as 2026-11-08T12:00:00Z.']);
    }

    /**
     * The delivery callback must finish writing credentials to a private file or throw.
     * It runs before commit, so failed delivery cannot leave an active unmanaged login.
     *
     * @param  list<string>  $clientIds
     * @param  Closure(User, string): void  $deliverCredentials
     */
    public function create(string $name, string $email, CarbonImmutable $expiry, array $clientIds, Closure $deliverCredentials): User
    {
        $name = trim($name);
        $email = strtolower(trim($email));
        if ($name === '' || mb_strlen($name) > 255) {
            throw ValidationException::withMessages(['name' => 'Supply a synthetic display name of at most 255 characters.']);
        }
        if (! TestLoginAddresses::allows($email)) {
            throw ValidationException::withMessages(['email' => 'Use a reserved test address or an exact configured test-login domain.']);
        }
        $expiry = $this->futureExpiry($expiry);
        $clientIds = array_values(array_unique($clientIds));
        if ($clientIds === [] || count(array_filter($clientIds, static fn ($id): bool => is_string($id) && $id !== '')) !== count($clientIds)) {
            throw ValidationException::withMessages(['clients' => 'Explicitly select at least one active static authorization-code client.']);
        }
        sort($clientIds);

        return DB::transaction(function () use ($name, $email, $expiry, $clientIds, $deliverCredentials): User {
            $this->administrators->lockDirectory();
            $expiry = $this->futureExpiry($expiry);
            if (User::withTrashed()->whereRaw('lower(email) = ?', [$email])->exists()) {
                throw ValidationException::withMessages(['email' => 'An identity already uses that address; test provisioning never adopts existing identities.']);
            }
            foreach ($clientIds as $id) {
                $client = PassportClient::query()->lockForUpdate()->find($id);
                if (! $client instanceof PassportClient || ! $this->clients->eligible($client)
                    || ! in_array($client->provider, [null, config('auth.guards.'.Mount::apiGuard().'.provider')], true)) {
                    throw ValidationException::withMessages(['clients' => 'Select only active static authorization-code clients from this provider directory.']);
                }
            }
            // 54 random bytes produce 72 ASCII characters: high entropy within bcrypt's limit.
            $password = rtrim(strtr(base64_encode(random_bytes(54)), '+/', '-_'), '=');
            $user = new User;
            $user->forceFill([
                'name' => $name, 'email' => $email, 'password' => $password,
                'user_role' => 'user', 'is_test_login' => true, 'test_login_expires_at' => $expiry,
            ])->save();
            foreach ($clientIds as $id) {
                $this->grants->grant((string) $user->getKey(), $id);
            }
            $this->audit($user, 'test_login_created', ['expires_at' => $expiry->toIso8601String(), 'oauth_client_ids' => $clientIds]);
            $deliverCredentials($user, $password);

            return $user;
        }); // Never retry credential delivery automatically.
    }

    public function extend(int $subject, CarbonImmutable $expiry): User
    {
        $expiry = $this->futureExpiry($expiry);

        return DB::transaction(function () use ($subject, $expiry): User {
            $user = $this->locked($this->administrators->lockDirectory(), $subject);
            $this->assertNotRetired($user);
            $expiry = $this->futureExpiry($expiry);
            $previous = $user->test_login_expires_at;
            $expired = $user->testLoginHasExpired();
            if ($previous?->equalTo($expiry)) {
                return $user;
            }
            if ($previous !== null && $expiry->lessThan($previous)) {
                throw ValidationException::withMessages(['expires_at' => 'An extension must move the existing expiry forward.']);
            }
            $user->test_login_expires_at = $expiry;
            if ($expired) {
                // Extending after expiry must not revive old cookies/tokens while
                // the scheduler has not yet marked the account disabled.
                $this->administrators->invalidateAuthority($user);
            } else {
                $user->save();
            }
            $this->audit($user, 'test_login_extended', [
                'previous_expires_at' => $previous?->toIso8601String(),
                'expires_at' => $expiry->toIso8601String(), 'expired_credentials_revoked' => $expired,
            ]);

            return $user;
        }, 3);
    }

    public function disable(int $subject): User
    {
        return DB::transaction(function () use ($subject): User {
            $user = $this->locked($this->administrators->lockDirectory(), $subject);
            $this->assertNotRetired($user);
            $this->disableLocked($user, 'test_login_disabled');

            return $user;
        }, 3);
    }

    public function retire(int $subject): IdentityTombstone
    {
        return DB::transaction(function () use ($subject): IdentityTombstone {
            $user = $this->locked($this->administrators->lockDirectory(), $subject);
            if ($user->trashed()) {
                $existing = IdentityTombstone::query()->where('subject', $subject)->first();
                if ($existing instanceof IdentityTombstone) {
                    return $existing->load('clients');
                }
                throw ValidationException::withMessages(['subject' => 'This retired identity has no lifecycle tombstone; investigate it before continuing.']);
            }
            $tombstone = $this->retirement->retire($user);
            $this->audit($user, 'test_login_retired', ['identity_tombstone_id' => $tombstone->public_id, 'purge_after' => $tombstone->purge_after->toIso8601String()]);

            return $tombstone;
        }, 3);
    }

    /** Disable a bounded batch; the model enforces expiry even if this is delayed. */
    public function expire(): int
    {
        $subjects = User::query()->where('is_test_login', true)->whereNull('disabled_at')
            ->where(static fn ($query) => $query->whereNull('test_login_expires_at')->orWhere('test_login_expires_at', '<=', now('UTC')))
            ->orderBy('id')->limit(100)->pluck('id');
        $disabled = 0;
        foreach ($subjects as $subject) {
            $disabled += DB::transaction(function () use ($subject): int {
                $user = $this->administrators->lockDirectory()->first(static fn (User $user): bool => (int) $user->getKey() === (int) $subject);
                if (! $user instanceof User || $user->trashed() || ! $user->isTestLogin() || ! $user->testLoginHasExpired()) {
                    return 0;
                }

                return $this->disableLocked($user, 'test_login_expired') ? 1 : 0;
            }, 3);
        }

        return $disabled;
    }

    private function futureExpiry(CarbonImmutable $expiry): CarbonImmutable
    {
        $hours = filter_var(config('auth-manager.test_logins.max_lifetime_hours', 24), FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 168]]);
        $expiry = $expiry->utc();
        if ($hours === false || $expiry->lessThanOrEqualTo(now('UTC')) || $expiry->greaterThan(now('UTC')->addHours($hours))) {
            throw ValidationException::withMessages(['expires_at' => 'Expiry must be in the future and within the configured test-login lifetime limit.']);
        }

        return $expiry;
    }

    /** @param Collection<int, User> $users */
    private function locked(Collection $users, int $subject): User
    {
        $user = $users->first(static fn (User $user): bool => (int) $user->getKey() === $subject);
        if (! $user instanceof User || ! $user->isTestLogin()) {
            throw ValidationException::withMessages(['subject' => 'Select a flagged test-login subject; ordinary identities are never managed by this command.']);
        }

        return $user;
    }

    private function assertNotRetired(User $user): void
    {
        if ($user->trashed()) {
            throw ValidationException::withMessages(['subject' => 'Retired test logins cannot be extended or disabled again.']);
        }
    }

    private function disableLocked(User $user, string $event): bool
    {
        if ($user->disabled_at !== null) {
            return false;
        }
        $user->disabled_at = now('UTC');
        $this->administrators->invalidateAuthority($user);
        $this->audit($user, $event, ['expires_at' => $user->test_login_expires_at?->toIso8601String()]);

        return true;
    }

    /** @param array<string, mixed> $metadata */
    private function audit(User $user, string $event, array $metadata): void
    {
        AuthAuditLog::create([
            'user_id' => $user->getKey(), 'acting_user_id' => null, 'event' => $event,
            'auth_method' => 'console', 'succeeded' => true, 'metadata' => $metadata,
        ]);
    }
}
