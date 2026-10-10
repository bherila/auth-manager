<?php

namespace App\Services\Invitations;

use App\Models\AccessInvitation;
use App\Models\User;
use BWH\Auth\Models\AuthAuditLog;
use BWH\Auth\Support\ClientIp;
use Illuminate\Http\Request;

/**
 * Provider audit rows for invitations.
 *
 * Rows name the invitation by id, never the recipient's address: the invitation row holds that, and
 * goes when the recipient's identity is purged. `user_id` is the person who accepted, once there is
 * one, so a purge clears that row's email as it does for every other audit row.
 */
final class InvitationAudit
{
    public const CREATED = 'access_invitation_created';

    public const SENT = 'access_invitation_sent';

    public const RESENT = 'access_invitation_resent';

    public const REVOKED = 'access_invitation_revoked';

    public const ACCEPTED = 'access_invitation_accepted';

    public const ROLES_APPLIED = 'access_invitation_roles_applied';

    public const ROLES_NOT_APPLIED = 'access_invitation_roles_not_applied';

    /**
     * @param  array<string, mixed>  $metadata
     */
    public function record(string $event, AccessInvitation $invitation, ?Request $request, ?User $actor, ?User $person = null, bool $succeeded = true, array $metadata = []): void
    {
        AuthAuditLog::create([
            'user_id' => $person?->getKey(),
            'acting_user_id' => $actor?->getKey(),
            'email' => $person?->email,
            'event' => $event,
            'auth_method' => 'invitation',
            'succeeded' => $succeeded,
            'ip_address' => $request !== null ? ClientIp::resolve($request) : null,
            'user_agent' => $request?->userAgent(),
            'session_id' => $request !== null && $request->hasSession() ? $request->session()->getId() : null,
            'metadata' => ['invitation_id' => $invitation->getKey(), 'application' => $invitation->application, ...$metadata],
        ]);
    }
}
