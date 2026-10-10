<?php

namespace App\Services\Invitations;

use App\Models\AccessInvitation;
use App\Models\User;
use App\Services\DelegatedAccess\DelegatedAccessTransport;
use App\Support\DelegatedAccessPermissions;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedContract;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Apply an accepted invitation's access in the application, as the inviter, once.
 *
 * As if the inviter made the change now: this provider first re-checks that the inviter is active,
 * still holds `access-invite` and `access-manage` for the application and that writes are enabled
 * (not a recent confirmation, which was required when the invitation was created). Then the
 * application decides, through the transport's non-interactive path. An account it has not seen is
 * provisioned (`expected_revision: null`). An existing one keeps what it has, and gains the invited
 * memberships it lacks and the administrator flag if the invitation grants it; nothing is removed or
 * demoted.
 *
 * Any refusal leaves the person admitted with no roles applied, and the invitation records it for
 * managers. An unconfirmed write is recorded as unknown and is never retried; on a version 3
 * application the transport first asks for its receipt once, so a write the application did apply,
 * or did refuse, is recorded as that.
 */
final class InvitationRoles
{
    public function __construct(
        private readonly DelegatedAccessTransport $transport,
        private readonly DelegatedAccessPermissions $permissions,
        private readonly InvitationAudit $audit,
        private readonly DelegatedContract $contract = new DelegatedContract,
    ) {}

    public function apply(AccessInvitation $invitation, User $person): string
    {
        $correlation = null;
        try {
            [$status, $outcome, $correlation] = $this->attempt($invitation, $person, $correlation);
        } catch (DelegatedAccessException $refusal) {
            $status = DelegatedAccessTransport::unconfirmed($refusal) ? AccessInvitation::ROLES_UNKNOWN : AccessInvitation::ROLES_NOT_APPLIED;
            $outcome = $refusal->outcome;
        } catch (Throwable $failure) {
            Log::warning('Applying an invitation\'s access failed unexpectedly.', ['invitation_id' => $invitation->getKey(), 'exception' => $failure::class]);
            // A write may have been sent before the failure; only one that was not is "not applied".
            $status = $correlation === null ? AccessInvitation::ROLES_NOT_APPLIED : AccessInvitation::ROLES_UNKNOWN;
            $outcome = 'unavailable';
        }

        $invitation->forceFill([
            'roles_status' => $status, 'roles_outcome' => $outcome,
            'roles_request_id' => $correlation, 'roles_checked_at' => now(),
        ])->save();
        $inviter = $invitation->inviter_id !== null ? User::withTrashed()->find($invitation->inviter_id) : null;
        $this->audit->record(
            $status === AccessInvitation::ROLES_APPLIED ? InvitationAudit::ROLES_APPLIED : InvitationAudit::ROLES_NOT_APPLIED,
            $invitation, null, $inviter, $person, $status === AccessInvitation::ROLES_APPLIED,
            ['status' => $status, 'outcome' => $outcome, 'correlation' => $correlation,
                ...($invitation->roles_operation_id === null ? [] : ['operation_id' => $invitation->roles_operation_id])],
        );

        return $status;
    }

    /**
     * @param-out string|null $correlation set just before the update is handed to the transport
     *
     * @return array{0: string, 1: string, 2: string|null}
     *
     * @throws DelegatedAccessException
     */
    private function attempt(AccessInvitation $invitation, User $person, ?string &$correlation): array
    {
        $application = $invitation->application;
        $notApplied = fn (string $outcome): array => [AccessInvitation::ROLES_NOT_APPLIED, $outcome, null];

        $inviter = $invitation->inviter_id !== null ? User::query()->find($invitation->inviter_id) : null;
        $recorded = $invitation->inviter_credential_version;
        // A credential reset or revocation since the invitation was created voids its roles.
        if (! $inviter instanceof User || ! $inviter->canLogin() || ! is_int($recorded) || (int) $inviter->credential_version !== $recorded
            || ! $this->permissions->invitationsEnabled()
            || ! $this->permissions->canInvite($inviter, $application) || ! $this->permissions->writesEnabled($application)) {
            return $notApplied('inviter_not_authorized');
        }
        $version = DelegatedAccessTransport::contractVersion($application);
        if ($version < DelegatedContract::VERSION_2) {
            return $notApplied('provisioning_unavailable');
        }

        $access = $this->invitedAccess($invitation->access);
        $capabilities = $this->transport->sendForInvitation($inviter, $recorded, $application, ['operation' => 'capabilities']);
        if ($access === null || ! $this->contract->rolesAreAdvertised($capabilities, $access)
            || ($access['application_admin'] && ($capabilities['controls']['application_admin'] ?? false) !== true)) {
            return $notApplied('roles_not_offered');
        }

        $subject = (string) $person->getKey();
        $state = $this->transport->sendForInvitation($inviter, $recorded, $application, ['operation' => 'read', 'subject' => $subject]);
        if (! $this->contract->fitsCapabilities($capabilities, $state)) {
            return $notApplied('invalid_response');
        }

        if (! $state['provisioned']) {
            if (($capabilities['controls']['provisioning'] ?? false) !== true || $state['allowed_edits']['provision'] !== true) {
                return $notApplied('provisioning_unavailable');
            }
            $update = ['operation' => 'update', 'subject' => $subject, 'expected_revision' => null, 'access' => $access];
            $name = trim((string) $person->name);
            if ($name !== '') {
                $update['display_name'] = mb_strcut($name, 0, 255, 'UTF-8');
            }
        } else {
            $merged = $this->merged($state['access'], $access);
            if ($merged === null) {
                return [AccessInvitation::ROLES_APPLIED, 'nothing_to_add', null];
            }
            if (count($merged['workspaces']) > 100) {
                return $notApplied('invalid_request');
            }
            $update = ['operation' => 'update', 'subject' => $subject, 'expected_revision' => $state['revision'], 'access' => $merged];
        }

        if ($version >= DelegatedContract::VERSION_3) {
            $update['operation_id'] = $this->operationId($invitation);
        }
        $correlation = bin2hex(random_bytes(32));
        // An answer that does not fit the capabilities is an unknown outcome from the transport.
        $this->transport->sendForInvitation($inviter, $recorded, $application, $update, $correlation, $capabilities);

        return [AccessInvitation::ROLES_APPLIED, 'applied', $correlation];
    }

    /**
     * The invitation's one `operation_id` for its acceptance-time write: stored before the write is
     * sent, and reused by any later attempt for the same invitation, so the application answers a
     * repeat from its receipt rather than applying it again. Only the first writer stores one.
     */
    private function operationId(AccessInvitation $invitation): string
    {
        if (! DelegatedContract::validOperationId($invitation->roles_operation_id)) {
            AccessInvitation::query()->whereKey($invitation->getKey())->whereNull('roles_operation_id')
                ->update(['roles_operation_id' => DelegatedContract::operationId()]);
            $invitation->refresh();
        }
        if (! DelegatedContract::validOperationId($invitation->roles_operation_id)) {
            throw new DelegatedAccessException('invalid_request', 422);
        }

        return $invitation->roles_operation_id;
    }

    /**
     * What an existing account should have: everything it has now, as the application reported it
     * (so memberships this inviter cannot edit are echoed unchanged), plus each invited membership in
     * a workspace it is not in yet, and the administrator flag if either has it. Null when that is
     * what it already has.
     *
     * @param  array{application_admin: bool, workspaces: list<array{id: string, role: string, editable: bool}>}  $current
     * @param  array{application_admin: bool, workspaces: list<array{id: string, role: string}>}  $invited
     * @return array{application_admin: bool, workspaces: list<array{id: string, role: string}>}|null
     */
    private function merged(array $current, array $invited): ?array
    {
        $workspaces = array_map(fn (array $membership): array => ['id' => $membership['id'], 'role' => $membership['role']], $current['workspaces']);
        $present = array_column($workspaces, 'id');
        $changed = false;
        foreach ($invited['workspaces'] as $membership) {
            if (! in_array($membership['id'], $present, true)) {
                $workspaces[] = ['id' => $membership['id'], 'role' => $membership['role']];
                $present[] = $membership['id'];
                $changed = true;
            }
        }
        $admin = $current['application_admin'] || $invited['application_admin'];

        return $changed || $admin !== $current['application_admin']
            ? ['application_admin' => $admin, 'workspaces' => $workspaces]
            : null;
    }

    /**
     * The stored access, re-shaped strictly; null if it is not what an invitation stores.
     *
     * @return array{application_admin: bool, workspaces: list<array{id: string, role: string}>}|null
     */
    private function invitedAccess(mixed $access): ?array
    {
        if (! is_array($access) || ! is_bool($access['application_admin'] ?? null) || ! is_array($access['workspaces'] ?? null)) {
            return null;
        }
        $workspaces = [];
        foreach ($access['workspaces'] as $membership) {
            if (! is_array($membership) || ! is_string($membership['id'] ?? null) || ! is_string($membership['role'] ?? null)) {
                return null;
            }
            $workspaces[] = ['id' => $membership['id'], 'role' => $membership['role']];
        }

        return ['application_admin' => $access['application_admin'], 'workspaces' => $workspaces];
    }
}
