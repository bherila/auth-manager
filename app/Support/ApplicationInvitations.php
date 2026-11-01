<?php

namespace BWH\AuthManager\Support;

use BWH\AuthManager\Models\AccessInvitation;
use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Models\RegisteredApplication;

/**
 * Which applications may request admission invitations for themselves, and through which client.
 *
 * Off for every application by default: an operator lists its registry key in
 * `AUTH_MANAGER_APPLICATION_INVITATIONS`. The calling client must be one of the registration's own
 * confidential, statically registered sign-in clients, and the registration must be enabled. An
 * invitation it requests admits to that client alone, and only while all of this still holds.
 */
final class ApplicationInvitations
{
    /** The client credentials scope the endpoint requires. Never granted to a person's token. */
    public const SCOPE = 'invitations:admit';

    public function __construct(private readonly StaticApplicationClients $clients = new StaticApplicationClients) {}

    public function anyEnabled(): bool
    {
        return $this->listed() !== [];
    }

    /** Switched on for this registry key; says nothing about its registration or clients. */
    public function listedFor(string $application): bool
    {
        return in_array($application, $this->listed(), true);
    }

    /** The enabled, listed registration this client may request admission invitations for, or null. */
    public function applicationFor(PassportClient $client): ?RegisteredApplication
    {
        if (! $client->confidential() || ! $this->clients->eligible($client)) {
            return null;
        }
        // A client belongs to at most one registration (`registered_application_clients` is unique on it).
        $registration = RegisteredApplication::query()
            ->where('enabled', true)
            ->whereHas('clients', fn ($query) => $query->whereKey($client->getKey()))
            ->first();

        return $registration instanceof RegisteredApplication && $this->listedFor($registration->key) ? $registration : null;
    }

    /**
     * The one client an application-requested invitation admits to, while that client may still
     * request invitations for the invitation's application; null otherwise.
     */
    public function admittingClient(AccessInvitation $invitation): ?string
    {
        $clientId = $invitation->requesting_client_id;
        if (! is_string($clientId) || $clientId === '') {
            return null;
        }
        $client = PassportClient::query()->find($clientId);

        return $client instanceof PassportClient && $this->applicationFor($client)?->key === $invitation->application
            ? (string) $client->getKey()
            : null;
    }

    /** @return list<string> */
    private function listed(): array
    {
        $listed = config('application-invitations.applications', []);

        return is_array($listed) ? array_values(array_filter($listed, 'is_string')) : [];
    }
}
