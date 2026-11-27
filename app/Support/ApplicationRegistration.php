<?php

namespace BWH\AuthManager\Support;

use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Models\RegisteredApplication;

/** Explicit authority to create new identities, separate from admission invitations. */
final class ApplicationRegistration
{
    public function applicationFor(PassportClient $client): ?RegisteredApplication
    {
        if (! $client->confidential() || ! (new StaticApplicationClients)->eligible($client)) {
            return null;
        }
        $application = RegisteredApplication::query()->where('enabled', true)
            ->whereHas('clients', fn ($query) => $query->whereKey($client->getKey()))->first();
        $allowed = config('auth-manager.application_registration.applications', []);

        return $application instanceof RegisteredApplication && is_array($allowed)
            && in_array($application->key, $allowed, true) ? $application : null;
    }
}
