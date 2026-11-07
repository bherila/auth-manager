<?php

namespace BWH\AuthManager\Services;

use BWH\AuthManager\Models\IdentityTombstone;
use BWH\AuthManager\Models\IdentityTombstoneClient;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Support\ReconciliationClientRegistry;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use LogicException;

/** Shared retirement writes; callers own authorization, ordered locks and auditing. */
final class IdentityRetirement
{
    public function __construct(
        private readonly ProviderAdministrators $administrators,
        private readonly ReconciliationClientRegistry $clients,
    ) {}

    /** Call inside a transaction with the target held under the directory lock. */
    public function retire(User $locked): IdentityTombstone
    {
        if (DB::transactionLevel() < 1) {
            throw new LogicException('Identity retirement requires a locked directory transaction.');
        }
        $now = now();
        $tombstone = IdentityTombstone::query()->create([
            'public_id' => (string) Str::uuid(),
            'subject' => (int) $locked->getKey(),
            'tombstoned_at' => $now,
            'purge_after' => $now->copy()->addDays(max(1, (int) config('identity-deletion.retention_days', 30))),
        ]);
        foreach ($this->clients->all() as $client) {
            IdentityTombstoneClient::query()->create([
                'identity_tombstone_id' => $tombstone->getKey(),
                'oauth_client_id' => (string) $client->getKey(),
                'oauth_client_name' => (string) $client->name,
            ]);
        }
        $locked->disabled_at ??= $now;
        $this->administrators->invalidateAuthority($locked);
        $locked->delete();

        return $tombstone->load('clients');
    }
}
