<?php

namespace App\Models;

use Database\Factories\UserFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Passport\Contracts\OAuthenticatable;
use Laravel\Passport\HasApiTokens;

#[Fillable(['name', 'email', 'password', 'user_role', 'disabled_at', 'last_login_date'])]
#[Hidden(['password', 'remember_token'])]
class User extends Authenticatable implements OAuthenticatable
{
    /** @use HasFactory<UserFactory> */
    use HasApiTokens, HasFactory, Notifiable, SoftDeletes;

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
            && ($this->hasRole('user') || $this->hasRole('admin'));
    }
}
