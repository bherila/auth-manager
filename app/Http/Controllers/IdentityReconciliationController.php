<?php

namespace App\Http\Controllers;

use App\Http\Middleware\AuthenticateReconciliationClient;
use App\Models\IdentityTombstone;
use App\Models\IdentityTombstoneClient;
use App\Models\PassportClient;
use App\Services\IdentityReconciliationService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class IdentityReconciliationController extends Controller
{
    public function __construct(private readonly IdentityReconciliationService $reconciliation) {}

    public function index(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'limit' => ['sometimes', 'integer', 'min:1', 'max:100'],
        ]);
        $result = $this->reconciliation->pendingFor(
            $this->client($request),
            (int) ($validated['limit'] ?? 100),
        );

        return response()->json([
            'contract_version' => 1,
            'data' => $result['items']
                ->map(fn (IdentityTombstoneClient $assignment): array => $this->tombstonePayload(
                    $assignment->tombstone,
                ))
                ->all(),
            'has_more' => $result['has_more'],
        ]);
    }

    public function acknowledge(Request $request, string $tombstone): JsonResponse
    {
        $assignment = $this->reconciliation->acknowledge($this->client($request), $tombstone);

        return response()->json([
            'contract_version' => 1,
            'acknowledgement' => [
                'tombstone_id' => $tombstone,
                'acknowledged_at' => $assignment->acknowledged_at?->toISOString(),
            ],
        ]);
    }

    private function client(Request $request): PassportClient
    {
        $client = $request->attributes->get(AuthenticateReconciliationClient::CLIENT_ATTRIBUTE);

        abort_unless($client instanceof PassportClient, 401);

        return $client;
    }

    /**
     * @return array{
     *     id:string,
     *     subject:string,
     *     tombstoned_at:string,
     *     purge_after:string,
     *     provider_purged_at:?string
     * }
     */
    private function tombstonePayload(IdentityTombstone $tombstone): array
    {
        return [
            'id' => $tombstone->public_id,
            'subject' => (string) $tombstone->subject,
            'tombstoned_at' => $tombstone->tombstoned_at->toISOString(),
            'purge_after' => $tombstone->purge_after->toISOString(),
            'provider_purged_at' => $tombstone->provider_purged_at?->toISOString(),
        ];
    }
}
