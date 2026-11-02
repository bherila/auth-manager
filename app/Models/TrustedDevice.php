<?php

namespace BWH\AuthManager\Models;

use BWH\AuthManager\Services\TrustedDevices;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Query\Builder as QueryBuilder;

/**
 * A browser a person confirmed with an emailed code. Only the hash of its token is kept
 * ({@see TrustedDevices}).
 */
class TrustedDevice extends Model
{
    protected $guarded = ['id'];

    protected $hidden = ['token_hash'];

    protected function casts(): array
    {
        return [
            'credential_version' => 'integer',
            'last_used_at' => 'datetime',
            'expires_at' => 'datetime',
        ];
    }

    /**
     * The rows that still count for this person. A row from an earlier credential version never
     * does, so every present and future place that advances the version revokes these.
     *
     * @return Builder<self>
     */
    public static function activeFor(User $user): Builder
    {
        return self::query()
            ->where('user_id', $user->getKey())
            ->where('credential_version', (int) $user->credential_version)
            ->where('expires_at', '>', now());
    }

    /** Remove rows nothing can use. With the setting off, none can be used. */
    public static function pruneUnusable(): int
    {
        if (! TrustedDevices::enabled()) {
            return self::query()->delete();
        }

        return self::query()
            ->where(static function (Builder $rows): void {
                $rows->where('expires_at', '<=', now())
                    ->orWhereNotExists(static function (QueryBuilder $users): void {
                        $users->selectRaw('1')
                            ->from('users')
                            ->whereColumn('users.id', 'trusted_devices.user_id')
                            ->whereColumn('users.credential_version', 'trusted_devices.credential_version');
                    });
            })
            ->delete();
    }

    /** A name a person can recognize. The browser supplies the string, so it is only a hint. */
    public function label(): string
    {
        $agent = (string) $this->user_agent;

        $browser = match (true) {
            str_contains($agent, 'Edg/') => 'Edge',
            str_contains($agent, 'OPR/') => 'Opera',
            str_contains($agent, 'Firefox/') => 'Firefox',
            str_contains($agent, 'Chrome/'), str_contains($agent, 'CriOS/') => 'Chrome',
            str_contains($agent, 'Safari/') => 'Safari',
            default => null,
        };
        $system = match (true) {
            str_contains($agent, 'iPhone'), str_contains($agent, 'iPad') => 'iOS',
            str_contains($agent, 'Android') => 'Android',
            str_contains($agent, 'Mac OS X') => 'macOS',
            str_contains($agent, 'Windows') => 'Windows',
            str_contains($agent, 'CrOS') => 'ChromeOS',
            str_contains($agent, 'Linux') => 'Linux',
            default => null,
        };

        return match (true) {
            $browser !== null && $system !== null => "{$browser} on {$system}",
            $browser !== null => $browser,
            $system !== null => "A browser on {$system}",
            default => 'Unknown browser',
        };
    }

    /** @return BelongsTo<User, $this> */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
