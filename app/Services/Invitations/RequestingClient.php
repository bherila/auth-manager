<?php

namespace App\Services\Invitations;

/**
 * The application client an invitation is requested through, with the actor's provider subject as
 * its signed assertion named it. Set only on the application-requested path.
 */
final readonly class RequestingClient
{
    public function __construct(public string $clientId) {}
}
