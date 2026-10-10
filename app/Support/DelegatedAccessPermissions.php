<?php

namespace App\Support;

use App\Models\User;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;

/**
 * Who may use delegated administration here, per application and operation.
 *
 * A provider-side restriction in addition to each application's own
 * authorization, never a substitute for it: the application still decides what
 * the actor may see and change. Denied unless granted, through roles in
 * `user_role` (`*` stands for every application):
 *
 * - `access-view:<application>`: read the application's access pages;
 * - `access-manage:<application>`: read and change access there (includes view);
 * - `access-directory:<application>`: browse the people who can sign in to the
 *   application when choosing whom to provision. Kept separate because it
 *   discloses grant holders across every workspace, which a workspace-scoped
 *   administrator must not see; without it, people are named by exact email.
 * - `access-invite:<application>`: invite someone by email to the application,
 *   with access the invitation applies when they accept. Inviting also needs
 *   `access-manage` for the application, because acceptance applies the roles
 *   as the inviter. Kept separate because an invitation can create a provider
 *   account, which managing existing access never does.
 *
 * These are narrow delegated-administration permissions, not provider
 * administration: a workspace administrator needs no other provider role.
 */
class DelegatedAccessPermissions
{
    public function canView(User $user, string $application): bool
    {
        return $this->canManage($user, $application) || $this->holds($user, 'access-view', $application);
    }

    public function canManage(User $user, string $application): bool
    {
        return $this->holds($user, 'access-manage', $application);
    }

    public function canBrowseDirectory(User $user, string $application): bool
    {
        return $this->canManage($user, $application) && $this->holds($user, 'access-directory', $application);
    }

    /**
     * May invite people to this application: `access-invite` and `access-manage` for it.
     *
     * Whether invitations are switched on is {@see invitationsEnabled()}; whether the actor can
     * write right now (a current grant, writes enabled, a recent confirmation) is the transport's.
     */
    public function canInvite(User $user, string $application): bool
    {
        return $this->canManage($user, $application) && $this->holds($user, 'access-invite', $application);
    }

    /** May see this application's invitations: `access-invite` or `access-manage` for it. */
    public function canSeeInvitations(User $user, string $application): bool
    {
        return $this->canManage($user, $application) || $this->holds($user, 'access-invite', $application);
    }

    public function invitationsEnabled(): bool
    {
        return (bool) config('delegated-access.invitations.enabled', false);
    }

    /**
     * Writes for this application are switched on here, not only globally, and it is signed with
     * its own key. This provider then never signs its writes with a key another application
     * holds; the application must also stop trusting the instance-wide public key, or a holder of
     * that private key can still mint writes it accepts.
     */
    public function writesEnabled(string $application): bool
    {
        $applications = config('delegated-access.writes_applications', []);
        if (! (bool) config('delegated-access.writes_enabled', false)
            || ! is_array($applications) || ! in_array($application, $applications, true)) {
            return false;
        }

        try {
            return app(DelegatedAccessKeys::class)->own($application) !== null;
        } catch (DelegatedAccessException) {
            return false;
        }
    }

    private function holds(User $user, string $permission, string $application): bool
    {
        return $user->hasRole("{$permission}:{$application}") || $user->hasRole("{$permission}:*");
    }
}
