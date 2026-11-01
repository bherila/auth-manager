<?php

namespace BWH\AuthManager\Services\Invitations;

use RuntimeException;

/**
 * The code entered to create an account from an application's invitation was not accepted. No account
 * was created; the attempt itself was recorded. `reason` is `missing`, `expired`, `incorrect` or
 * `exhausted`.
 */
final class InvitationCodeRejected extends RuntimeException
{
    public function __construct(public readonly string $reason)
    {
        parent::__construct('Invitation code rejected: '.$reason.'.');
    }
}
