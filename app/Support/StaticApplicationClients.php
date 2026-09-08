<?php

namespace App\Support;

use App\Models\PassportClient;

class StaticApplicationClients
{
    public function eligible(PassportClient $client): bool
    {
        // Use the same marker as the shared ResourceClient. Its helper is private;
        // firstParty() alone cannot distinguish a static third-party client from DCR.
        $column = config('bherila-auth.oauth_server.dynamic_clients.registered_at_column', 'dynamically_registered_at');

        return ! $client->revoked
            && is_string($column)
            && $column !== ''
            && array_key_exists($column, $client->getAttributes())
            && $client->getAttribute($column) === null
            && is_array($client->grant_types)
            && in_array('authorization_code', $client->grant_types, true);
    }
}
