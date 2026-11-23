<?php

namespace BWH\AuthManager\Models;

use BWH\AuthManager\Database\Factories\UserFactory;
use BWH\AuthManager\Support\ProviderSubjects;
use BWH\AuthManager\Support\TestLoginAddresses;
use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Attributes\UseFactory;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Validation\ValidationException;
use InvalidArgumentException;
use Laravel\Passport\Contracts\OAuthenticatable;
use Laravel\Passport\HasApiTokens;
use RuntimeException;

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
            // Applications are bound to the subject; changing it would hand one person's
            // bindings to whoever is given the old value, or detach them all.
            if ($user->exists && $user->isDirty('subject') && $user->getOriginal('subject') !== null) {
                throw new RuntimeException('A provider subject never changes once issued.');
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
     * The subject relying applications know this account by. Never the row id: a restore or a
     * copy can reissue an id, and an opaque subject cannot be guessed from one. An account the
     * previous release created while the column was being added has none yet and is still known
     * by its id, exactly as before.
     */
    public function providerSubject(): string
    {
        $subject = $this->attributes['subject'] ?? null;

        return is_string($subject) && $subject !== '' ? $subject : (string) $this->getKey();
    }

    /**
     * Accounts holding exactly this subject. Callers compare providerSubject() afterwards, so a
     * database's collation or numeric coercion can never stand in for an exact match.
     *
     * @param  Builder<User>  $query
     */
    public function scopeWhereProviderSubject(Builder $query, string $subject): void
    {
        if (! ProviderSubjects::valid($subject)) {
            $query->whereRaw('1 = 0');

            return;
        }
        $query->where(fn (Builder $inner) => $inner->where('subject', $subject)
            ->when(ProviderSubjects::canonicalId($subject), fn (Builder $legacy) => $legacy
                ->orWhere(fn (Builder $unassigned) => $unassigned->whereNull('subject')->whereKey((int) $subject))));
    }

    /**
     * Insert the account and issue its subject in one transaction, so no account is ever left
     * known by anything but the subject it was issued, and a refused subject leaves no row.
     *
     * A subject carried from another instance (set with forceFill) is kept; otherwise the
     * instance's generator decides (ProviderSubjects::forNewAccount()), and without one the
     * account takes its own id. Either way a subject a deleted identity held is refused, as is an
     * all-digit subject other than the account's own id.
     *
     * @param  Builder<User>  $query
     */
    protected function performInsert(Builder $query): bool
    {
        return $this->getConnection()->transaction(function () use ($query): bool {
            if (($this->attributes['subject'] ?? null) === '') {
                $this->attributes['subject'] = null;
            }
            $this->attributes['subject'] ??= app(ProviderSubjects::class)->forNewAccount();
            $subject = $this->attributes['subject'] ?? null;
            if ($subject !== null && (! ProviderSubjects::valid($subject) || app(ProviderSubjects::class)->retired($subject, $this->getConnection()))) {
                throw new RuntimeException('That provider subject cannot be issued.');
            }

            if (! parent::performInsert($query)) {
                return false;
            }

            $own = (string) $this->getKey();
            if ($subject === null) {
                if (app(ProviderSubjects::class)->retired($own, $this->getConnection())) {
                    throw new RuntimeException('This account\'s id was issued to a deleted identity; it cannot be a subject again.');
                }
                $this->newQueryWithoutScopes()->toBase()->where($this->getKeyName(), $this->getKey())->update(['subject' => $own]);
                $this->attributes['subject'] = $own;
            } elseif (ProviderSubjects::numeric($subject) && $subject !== $own) {
                throw new RuntimeException('An all-digit provider subject must be the account\'s own id.');
            }

            return true;
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
