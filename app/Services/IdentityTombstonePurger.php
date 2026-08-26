<?php

namespace App\Services;

use App\Models\IdentityTombstone;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

class IdentityTombstonePurger
{
    public const REASON_ALL_ACKNOWLEDGED = 'all_acknowledged';

    public const REASON_RETENTION_EXPIRED = 'retention_expired';

    public function __construct(private readonly OAuthTokenRevocationService $tokens) {}

    /**
     * @return array{purged: int, waiting: int, expired_with_unacknowledged: int}
     */
    public function purgeEligible(): array
    {
        $summary = [
            'purged' => 0,
            'waiting' => 0,
            'expired_with_unacknowledged' => 0,
        ];

        IdentityTombstone::query()
            ->whereNull('provider_purged_at')
            ->orderBy('id')
            ->select('id')
            ->chunkById(100, function ($tombstones) use (&$summary): void {
                foreach ($tombstones as $candidate) {
                    $result = $this->purgeOne((int) $candidate->getKey());
                    $summary[$result]++;
                }
            });

        return $summary;
    }

    /**
     * @return 'purged'|'waiting'|'expired_with_unacknowledged'
     */
    private function purgeOne(int $tombstoneId): string
    {
        $warning = null;

        $result = DB::transaction(function () use ($tombstoneId, &$warning): string {
            $tombstone = IdentityTombstone::query()
                ->with('clients')
                ->whereKey($tombstoneId)
                ->lockForUpdate()
                ->first();

            if (! $tombstone instanceof IdentityTombstone || $tombstone->provider_purged_at !== null) {
                return 'waiting';
            }

            $unacknowledged = $tombstone->clients
                ->whereNull('acknowledged_at')
                ->map(static fn ($assignment): array => [
                    'id' => (string) $assignment->oauth_client_id,
                    'name' => (string) $assignment->oauth_client_name,
                ])
                ->values()
                ->all();
            $allAcknowledged = $unacknowledged === [];
            $retentionExpired = now()->greaterThanOrEqualTo($tombstone->purge_after);

            if (! $allAcknowledged && ! $retentionExpired) {
                return 'waiting';
            }

            $subject = (string) $tombstone->subject;
            $user = User::withTrashed()->whereKey($subject)->lockForUpdate()->first();

            if ($user instanceof User) {
                $this->tokens->purgeSubjectCredentials($subject);
                DB::table('sessions')->where('user_id', $subject)->delete();
                DB::table('password_reset_tokens')->where('email', $user->email)->delete();
                DB::table(config('bherila-auth.audit.table', 'auth_audit_log'))
                    ->where('user_id', $subject)
                    ->update(['email' => null]);
                $user->forceDelete();
            }

            $reason = $allAcknowledged
                ? self::REASON_ALL_ACKNOWLEDGED
                : self::REASON_RETENTION_EXPIRED;
            $tombstone->forceFill([
                'provider_purged_at' => now(),
                'purge_reason' => $reason,
                'unacknowledged_clients' => $unacknowledged,
            ])->save();

            if (! $allAcknowledged) {
                $warning = [
                    'identity_tombstone_id' => $tombstone->public_id,
                    'unacknowledged_applications' => $unacknowledged,
                ];

                return 'expired_with_unacknowledged';
            }

            return 'purged';
        });

        if (is_array($warning)) {
            Log::warning(
                'Provider identity purged after its retention window with unacknowledged relying applications.',
                $warning,
            );
        }

        return $result;
    }
}
