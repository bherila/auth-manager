<?php

namespace App\Models;

use Database\Factories\UserFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Passport\Contracts\OAuthenticatable;
use Laravel\Passport\HasApiTokens;

#[Fillable(['name', 'email', 'password', 'user_role', 'last_login_date'])]
#[Hidden(['password', 'remember_token'])]
class User extends Authenticatable implements OAuthenticatable
{
    /** @use HasFactory<UserFactory> */
    use HasApiTokens, HasFactory, Notifiable;

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
        $raw = (string) ($this->attributes['user_role'] ?? '');

        $roles = array_filter(array_map(
            static fn (string $value): string => strtolower(trim($value)),
            explode(',', $raw),
        ));

        return in_array(strtolower($role), $roles, true);
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
        return $this->hasRole('user') || $this->hasRole('admin');
    }
}
