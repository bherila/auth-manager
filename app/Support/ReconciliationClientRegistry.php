<?php

namespace App\Support;

use App\Models\PassportClient;
use Illuminate\Database\Eloquent\Collection;

/**
 * OAuth clients that participate in provider identity deletion.
 *
 * A participant is an active, confidential authorization-code client with at
 * least one absolute HTTP(S) redirect URI. That is both a registered relying
 * application and a client able to authenticate to the reconciliation API.
 */
class ReconciliationClientRegistry
{
    /**
     * @return Collection<int, PassportClient>
     */
    public function all(): Collection
    {
        return PassportClient::query()
            ->where('revoked', false)
            ->whereNotNull('secret')
            ->orderBy('name')
            ->orderBy('id')
            ->get()
            ->filter(fn (PassportClient $client): bool => $this->isParticipant($client))
            ->values();
    }

    public function isParticipant(PassportClient $client): bool
    {
        if ($client->revoked || ! $client->confidential() || ! $client->hasGrantType('authorization_code')) {
            return false;
        }

        foreach ($client->redirect_uris as $uri) {
            if (! is_string($uri)) {
                continue;
            }

            $parts = parse_url($uri);

            if (isset($parts['scheme'], $parts['host'])
                && in_array(strtolower($parts['scheme']), ['http', 'https'], true)) {
                return true;
            }
        }

        return false;
    }
}
