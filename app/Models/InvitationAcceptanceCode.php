<?php

namespace BWH\AuthManager\Models;

use BWH\AuthManager\Services\Invitations\InvitationAddressVerification;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * One code emailed to an invited address before an application's own invitation creates an account.
 * Only its keyed hash is kept ({@see InvitationAddressVerification}).
 */
class InvitationAcceptanceCode extends Model
{
    public const UPDATED_AT = null;

    protected $guarded = ['id'];

    protected $hidden = ['code_hash'];

    protected function casts(): array
    {
        return [
            'expires_at' => 'datetime',
            'consumed_at' => 'datetime',
        ];
    }

    public static function addressHash(string $emailNormalized): string
    {
        return hash('sha256', $emailNormalized);
    }

    /** Remove codes past their expiry, used or not: nothing can use them, and they hold nothing else. */
    public static function pruneExpired(): int
    {
        return self::query()->where('expires_at', '<=', now())->delete();
    }

    /** @return BelongsTo<AccessInvitation, $this> */
    public function invitation(): BelongsTo
    {
        return $this->belongsTo(AccessInvitation::class, 'access_invitation_id');
    }
}
