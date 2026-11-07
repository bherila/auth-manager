<?php

namespace BWH\AuthManager\Models;

use BWH\AuthManager\Database\Factories\UserFactory;
use BWH\AuthManager\Support\TestLoginAddresses;
use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Attributes\UseFactory;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Validation\ValidationException;
use InvalidArgumentException;
use Laravel\Passport\Contracts\OAuthenticatable;
use Laravel\Passport\HasApiTokens;

#[Fillable(['name', 'email', 'password', 'user_role', 'disabled_at', 'last_login_date'])]
#[Hidden(['password', 'remember_token', 'is_test_login', 'test_login_expires_at'])]
#[UseFactory(UserFactory::class)]
class User extends Authenticatable implements OAuthenticatable
{
    /** @use HasFactory<UserFactory> */
    use HasApiTokens, HasFactory, Notifiable, SoftDeletes;

    protected static function booted(): void
    {
        static::saving(static function (User $user): void {
            if ($user->exists && $user->isDirty('is_test_login')) {
                throw ValidationException::withMessages(['user' => 'Existing identities cannot be converted to or from test logins.']);
            }
            if ($user->isTestLogin() && $user->hasRole('admin')
                && (! $user->exists || $user->isDirty('user_role') || $user->isDirty('is_test_login'))) {
                throw ValidationException::withMessages(['user' => 'Test logins cannot hold provider-administrator authority.']);
            }
            if ($user->isTestLogin() && $user->isDirty('email') && ! TestLoginAddresses::allows((string) $user->email)) {
                throw ValidationException::withMessages(['email' => 'Test logins must keep an allowed synthetic email address.']);
            }
        });

        // Reset tokens are found by address alone, so an outstanding link must not outlive the
        // address it was sent to, or it would work on whoever is given that address next.
        static::updated(static function (User $user): void {
            if ($user->wasChanged('email')) {
                $user->getConnection()->table('password_reset_tokens')
                    ->whereIn('email', [$user->getOriginal('email'), $user->email])
                    ->delete();
            }
        });
    }

    /**
     * Where auth-laravel's passkey and two-factor sign-ins return the person: the page they
     * asked for, or this provider's home, which is below the prefix when embedded.
     */
    public function getLoginRedirectUrl(): string
    {
        $intended = session()->pull('url.intended');

        return is_string($intended) && $intended !== '' ? $intended : route('auth-manager.home', absolute: false);
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'last_login_date' => 'datetime',
            'disabled_at' => 'datetime',
            'credential_version' => 'integer',
            'is_test_login' => 'boolean',
            'test_login_expires_at' => 'immutable_datetime',
            'password' => 'hashed',
        ];
    }

    /**
     * Whether the account holds the named role.
     *
     * Roles are a comma-separated list in `user_role` and are always lowercase.
     */
    public function hasRole(string $role): bool
    {
        return in_array(strtolower($role), $this->roleNames(), true);
    }

    /**
     * @return list<string>
     */
    public function roleNames(): array
    {
        $raw = (string) ($this->attributes['user_role'] ?? '');

        return array_values(array_unique(array_filter(array_map(
            static fn (string $value): string => strtolower(trim($value)),
            explode(',', $raw),
        ))));
    }

    /**
     * Whether the account may authenticate at all.
     *
     * This is the account-status gate, not an authorization decision: it answers
     * "is this account enabled", and nothing about what the account may reach in
     * any particular application. Relying applications resolve their own
     * permissions; this service deliberately does not model their vocabulary.
     */
    public function canLogin(): bool
    {
        return ($this->attributes['deleted_at'] ?? null) === null
            && ($this->attributes['disabled_at'] ?? null) === null
            && ($this->hasRole('user') || $this->hasRole('admin'))
            && (! $this->isTestLogin() || (! $this->hasRole('admin') && ! $this->testLoginHasExpired()
                && TestLoginAddresses::allows((string) $this->email)));
    }

    public function isTestLogin(): bool
    {
        return (bool) $this->getAttribute('is_test_login');
    }

    /** The provider's deadline remains UTC even inside a host with another timezone. */
    protected function testLoginExpiresAt(): Attribute
    {
        return Attribute::make(
            get: static fn (mixed $value): ?CarbonImmutable => $value === null ? null : CarbonImmutable::parse($value, 'UTC')->utc(),
            set: static fn (mixed $value): ?string => $value === null ? null : CarbonImmutable::parse($value, 'UTC')->utc()->format('Y-m-d H:i:s'),
        );
    }

    /** A flagged identity without a valid future deadline always fails closed. */
    public function testLoginHasExpired(): bool
    {
        if (! $this->isTestLogin()) {
            return false;
        }
        try {
            $expiry = $this->getAttribute('test_login_expires_at');
        } catch (InvalidArgumentException) {
            return true;
        }

        return ! $expiry instanceof CarbonInterface || $expiry->lessThanOrEqualTo(now());
    }
}
