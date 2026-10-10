<?php

namespace App\Services\Invitations;

use RuntimeException;

/** An invitation that cannot be accepted as asked; nothing was changed. */
final class InvitationUnavailable extends RuntimeException
{
    public function __construct(public readonly string $reason)
    {
        parent::__construct('Invitation unavailable: '.$reason.'.');
    }
}
