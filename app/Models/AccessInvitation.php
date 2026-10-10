<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Builder;
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
            'inviter_credential_version' => 'integer',
            'link_handed_over' => 'boolean',
        ];
    }

    public static function hashToken(string $token): string
    {
        return hash('sha256', $token);
    }

    /** The unique key a pending invitation holds for its application and normalized address. */
    public static function pendingKey(string $application, string $emailNormalized): string
    {
        return hash('sha256', $application."\0".$emailNormalized);
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

    /**
     * Which invitations an actor may see, revoke or resend, by the application's own scope: one that
     * reports this actor as an application administrator (actor-scoped `controls.application_admin`)
     * sees them all; anyone else, such as a workspace-scoped administrator, only those they sent or
     * last resent. The provider cannot tell which workspaces another manager may see, so it never
     * shows someone else's recipients or stored roles to them.
     *
     * @param  Builder<AccessInvitation>  $query
     */
    public function scopeVisibleTo(Builder $query, User $actor, array $capabilities): void
    {
        if (! self::applicationWide($capabilities)) {
            $query->where('inviter_id', $actor->getKey());
        }
    }

    public function isVisibleTo(User $actor, array $capabilities): bool
    {
        return self::applicationWide($capabilities) || $this->inviter_id === $actor->getKey();
    }

    private static function applicationWide(array $capabilities): bool
    {
        return ($capabilities['controls']['application_admin'] ?? false) === true;
    }

    /** @return BelongsTo<User, $this> */
    public function inviter(): BelongsTo
    {
        return $this->belongsTo(User::class, 'inviter_id')->withTrashed();
    }
}
