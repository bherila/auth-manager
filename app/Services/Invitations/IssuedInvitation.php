<?php

namespace App\Services\Invitations;

use App\Models\AccessInvitation;

/** An invitation just created or resent: the link is shown to the inviter this once. */
final readonly class IssuedInvitation
{
    public function __construct(
        public AccessInvitation $invitation,
        #[\SensitiveParameter] public string $link,
        public bool $sent,
    ) {}
}
