<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * An invitation to one application, for one email address, with the access to apply on acceptance.
 *
 * The token is never stored: {@see hashToken()} is what `token_hash` holds. Status is derived, so an
 * expired invitation needs no job to mark it.
 *
 * @property array{application_admin: bool, workspaces: list<array{id: string, role: string}>} $access
 */
class AccessInvitation extends Model
{
    public const STATUS_PENDING = 'pending';

    public const STATUS_EXPIRED = 'expired';

    public const STATUS_REVOKED = 'revoked';

    public const STATUS_ACCEPTED = 'accepted';

    public const ROLES_APPLIED = 'applied';

    public const ROLES_NOT_APPLIED = 'not_applied';

    /** The application did not confirm a write that was sent: it may or may not have happened. */
    public const ROLES_UNKNOWN = 'unknown';

    protected $guarded = ['id'];

    protected $hidden = ['token_hash'];

    protected function casts(): array
    {
        return [
            'access' => 'array',
            'expires_at' => 'datetime',
            'last_sent_at' => 'datetime',
            'revoked_at' => 'datetime',
            'accepted_at' => 'datetime',
            'roles_checked_at' => 'datetime',
            'send_count' => 'integer',
        ];
    }

    public static function hashToken(string $token): string
    {
        return hash('sha256', $token);
    }

    public static function normalizeEmail(string $email): string
    {
        return mb_strtolower(trim($email));
    }

    public function status(): string
    {
        return match (true) {
            $this->accepted_at !== null => self::STATUS_ACCEPTED,
            $this->revoked_at !== null => self::STATUS_REVOKED,
            $this->expires_at->isPast() => self::STATUS_EXPIRED,
            default => self::STATUS_PENDING,
        };
    }

    public function isPending(): bool
    {
        return $this->status() === self::STATUS_PENDING;
    }

    /** @return BelongsTo<User, $this> */
    public function inviter(): BelongsTo
    {
        return $this->belongsTo(User::class, 'inviter_id')->withTrashed();
    }
}
