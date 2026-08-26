<?php

namespace App\Services;

use App\Models\IdentityTombstone;
use App\Models\IdentityTombstoneClient;
use App\Models\PassportClient;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\DB;

class IdentityReconciliationService
{
    /**
     * @return array{items: Collection<int, IdentityTombstoneClient>, has_more: bool}
     */
    public function pendingFor(PassportClient $client, int $limit): array
    {
        $items = IdentityTombstoneClient::query()
            ->with('tombstone')
            ->where('oauth_client_id', (string) $client->getKey())
            ->whereNull('acknowledged_at')
            ->orderBy('id')
            ->limit($limit + 1)
            ->get();

        $hasMore = $items->count() > $limit;

        return [
            'items' => $items->take($limit)->values(),
            'has_more' => $hasMore,
        ];
    }

    public function acknowledge(PassportClient $client, string $publicId): IdentityTombstoneClient
    {
        return DB::transaction(function () use ($client, $publicId): IdentityTombstoneClient {
            $tombstone = IdentityTombstone::query()->where('public_id', $publicId)->firstOrFail();
            $assignment = IdentityTombstoneClient::query()
                ->where('identity_tombstone_id', $tombstone->getKey())
                ->where('oauth_client_id', (string) $client->getKey())
                ->lockForUpdate()
                ->firstOrFail();

            if ($assignment->acknowledged_at === null) {
                $assignment->forceFill(['acknowledged_at' => now()])->save();
            }

            return $assignment;
        });
    }
}
