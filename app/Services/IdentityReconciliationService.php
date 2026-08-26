<?php

namespace App\Services;

use App\Models\IdentityTombstone;
use App\Models\IdentityTombstoneClient;
use App\Models\PassportClient;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

class IdentityReconciliationService
{
    /**
     * @return array{items: Collection<int, IdentityTombstoneClient>, has_more: bool, next_cursor: ?string}
     */
    public function pendingFor(PassportClient $client, int $limit, ?string $cursor = null): array
    {
        $afterId = $cursor === null ? null : $this->decodeCursor($client, $cursor);
        $items = IdentityTombstoneClient::query()
            ->with('tombstone')
            ->where('oauth_client_id', (string) $client->getKey())
            ->whereNull('acknowledged_at')
            ->when($afterId !== null, fn ($query) => $query->where('id', '>', $afterId))
            ->orderBy('id')
            ->limit($limit + 1)
            ->get();

        $hasMore = $items->count() > $limit;
        $page = $items->take($limit)->values();

        return [
            'items' => $page,
            'has_more' => $hasMore,
            'next_cursor' => $hasMore
                ? $this->encodeCursor($client, (int) $page->last()->getKey())
                : null,
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

    private function encodeCursor(PassportClient $client, int $assignmentId): string
    {
        $payload = $assignmentId.'.'.hash_hmac(
            'sha256',
            (string) $client->getKey().':'.$assignmentId,
            (string) config('app.key'),
        );

        return rtrim(strtr(base64_encode($payload), '+/', '-_'), '=');
    }

    private function decodeCursor(PassportClient $client, string $cursor): int
    {
        $decoded = base64_decode(strtr($cursor, '-_', '+/'), true);

        if (! is_string($decoded)
            || preg_match('/^([1-9][0-9]*)\.([a-f0-9]{64})$/', $decoded, $matches) !== 1
            || (string) (int) $matches[1] !== $matches[1]
            || ! hash_equals(
                hash_hmac('sha256', (string) $client->getKey().':'.$matches[1], (string) config('app.key')),
                $matches[2],
            )) {
            throw ValidationException::withMessages([
                'cursor' => ['The cursor is invalid.'],
            ]);
        }

        return (int) $matches[1];
    }
}
