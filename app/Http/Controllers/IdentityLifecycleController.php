<?php

namespace App\Http\Controllers;

use App\Models\IdentityTombstone;
use App\Models\IdentityTombstoneClient;
use Illuminate\Contracts\Pagination\Paginator;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

class IdentityLifecycleController extends Controller
{
    public function page(Request $request): Response
    {
        return response()->view('admin.identity-lifecycle', [
            'tombstones' => $this->progress($request),
        ])->header('Cache-Control', 'private, no-store');
    }

    public function index(Request $request): JsonResponse
    {
        $page = $this->progress($request);

        return response()->json([
            'data' => $page->items(),
            'page' => $page->currentPage(),
            'has_more' => $page->hasMorePages(),
        ])->header('Cache-Control', 'private, no-store');
    }

    private function progress(Request $request): Paginator
    {
        $validated = $request->validate(['page' => ['sometimes', 'integer', 'min:1']]);

        return IdentityTombstone::query()
            ->with(['clients' => fn ($query) => $query->orderBy('id')])
            ->orderByDesc('id')
            ->simplePaginate(25, ['*'], 'page', (int) ($validated['page'] ?? 1))
            ->through(function (IdentityTombstone $tombstone): array {
                $applications = $tombstone->clients->map(fn (IdentityTombstoneClient $client): array => [
                    'id' => $client->oauth_client_id,
                    'name' => $client->oauth_client_name,
                    'acknowledged_at' => $client->acknowledged_at?->toISOString(),
                    'status' => $client->acknowledged_at === null ? 'pending' : 'acknowledged',
                ])->all();

                return [
                    'id' => $tombstone->public_id,
                    'subject' => (string) $tombstone->subject,
                    'tombstoned_at' => $tombstone->tombstoned_at->toISOString(),
                    'purge_after' => $tombstone->purge_after->toISOString(),
                    'provider_purged_at' => $tombstone->provider_purged_at?->toISOString(),
                    'retention_expired' => $tombstone->purge_after->isPast(),
                    'pending_count' => $tombstone->clients->whereNull('acknowledged_at')->count(),
                    'applications' => $applications,
                ];
            });
    }
}
