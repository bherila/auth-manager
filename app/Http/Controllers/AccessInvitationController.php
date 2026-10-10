<?php

namespace App\Http\Controllers;

use App\Models\AccessInvitation;
use App\Models\RegisteredApplication;
use App\Services\DelegatedAccess\DelegatedAccessTransport;
use App\Services\Invitations\AccessInvitationService;
use App\Services\Invitations\IssuedInvitation;
use App\Support\DelegatedAccessPermissions;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedContract;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Validation\ValidationException;

/**
 * Invite someone by email to an application, from its access page; resend or revoke an invitation.
 *
 * Inviting and resending need `access-invite` and `access-manage` for the application and everything
 * a write needs (a current grant, writes enabled for it, a recent confirmation). Revoking needs the
 * permissions only: it removes access that was never used. The access an invitation carries is
 * chosen explicitly from what the application advertises, and only an application that advertises
 * provisioning can be offered at all, since acceptance may have to create the account there.
 */
class AccessInvitationController extends Controller
{
    public const SENT_NOTICE = 'Invitation sent.';

    public const MAIL_UNCONFIGURED = 'Email is not configured to deliver on this provider, so invitations cannot be sent. An operator must configure a mailer first.';

    public function __construct(
        private readonly DelegatedAccessTransport $transport,
        private readonly DelegatedAccessPermissions $permissions,
        private readonly AccessInvitationService $invitations,
    ) {}

    public function store(Request $request, string $application): RedirectResponse
    {
        $this->authorizeInvite($request, $application);
        $back = route('applications.access', ['application' => $application]);
        $capabilities = $this->transport->send($request, $application, ['operation' => 'capabilities']);
        if (($capabilities['controls']['provisioning'] ?? false) !== true) {
            throw ValidationException::withMessages(['invitation' => 'The application does not accept new accounts from this provider, so it cannot be offered in an invitation.'])->redirectTo($back);
        }
        $contract = new DelegatedContract;
        $accountOnly = $contract->accountOnly($capabilities);
        $offersAdmin = ($capabilities['controls']['application_admin'] ?? false) === true;

        $input = $request->validate([
            'email' => ['required', 'string', 'email', 'max:255'],
            // Always a choice, never a default: an empty select fails `required`.
            'application_admin' => [$accountOnly || $offersAdmin ? 'required' : 'prohibited', 'boolean'],
            'workspaces' => [$accountOnly ? 'prohibited' : 'sometimes', 'array', 'max:10'],
            'workspaces.*.id' => ['nullable', 'string', 'max:191'],
            'workspaces.*.role' => ['nullable', 'string', 'max:64'],
        ]);

        $workspaces = [];
        foreach ($input['workspaces'] ?? [] as $row) {
            $id = (string) ($row['id'] ?? '');
            $role = (string) ($row['role'] ?? '');
            if ($id === '' && $role === '') {
                continue;
            }
            if ($id === '' || $role === '') {
                throw ValidationException::withMessages(['workspaces' => 'Choose both a workspace and a role for each membership.'])->redirectTo($back);
            }
            if (in_array($id, array_column($workspaces, 'id'), true)) {
                throw ValidationException::withMessages(['workspaces' => 'Choose each workspace once.'])->redirectTo($back);
            }
            $workspaces[] = ['id' => $id, 'role' => $role];
        }
        $access = ['application_admin' => (bool) ($input['application_admin'] ?? false), 'workspaces' => $workspaces];
        if (! $accountOnly && $workspaces === [] && ! $access['application_admin']) {
            throw ValidationException::withMessages(['workspaces' => 'Choose at least one workspace and role, or application administration.'])->redirectTo($back);
        }
        if ($access['application_admin'] && ! $offersAdmin) {
            throw ValidationException::withMessages(['application_admin' => 'The application does not let you give application administration.'])->redirectTo($back);
        }
        if (! $contract->rolesAreAdvertised($capabilities, $access)) {
            throw ValidationException::withMessages(['workspaces' => 'Choose roles the application offers.'])->redirectTo($back);
        }

        $registration = RegisteredApplication::query()->where('key', $application)->where('enabled', true)->firstOrFail();

        return $this->issued($back, $this->invitations->create($request, $request->user(), $registration, $input['email'], $access));
    }

    public function resend(Request $request, string $application, AccessInvitation $invitation): RedirectResponse
    {
        abort_unless($invitation->application === $application, 404);
        $this->authorizeInvite($request, $application);
        // A new link must still be one the application would accept now: provisioning and every
        // stored role still advertised, checked before the token is replaced.
        $back = route('applications.access', ['application' => $application]);
        $capabilities = $this->transport->send($request, $application, ['operation' => 'capabilities']);
        abort_unless($invitation->isVisibleTo($request->user(), $capabilities), 404);
        if (($capabilities['controls']['provisioning'] ?? false) !== true) {
            throw ValidationException::withMessages(['invitation' => 'The application no longer accepts new accounts from this provider, so this invitation cannot be sent again. Revoke it instead.'])->redirectTo($back);
        }
        $access = is_array($invitation->access) ? $invitation->access : [];
        if (! (new DelegatedContract)->rolesAreAdvertised($capabilities, $access)
            || (($access['application_admin'] ?? false) === true && ($capabilities['controls']['application_admin'] ?? false) !== true)) {
            throw ValidationException::withMessages(['invitation' => 'The application no longer offers the access this invitation gives, so it cannot be sent again. Revoke it and send a new one.'])->redirectTo($back);
        }
        $registration = RegisteredApplication::query()->where('key', $application)->where('enabled', true)->firstOrFail();

        return $this->issued(route('applications.access', ['application' => $application]),
            $this->invitations->resend($request, $request->user(), $invitation, $registration));
    }

    public function revoke(Request $request, string $application, AccessInvitation $invitation): RedirectResponse
    {
        abort_unless($this->permissions->invitationsEnabled() && $invitation->application === $application, 404);
        if (! $this->permissions->canInvite($request->user(), $application)) {
            throw new DelegatedAccessException('not_authorized', 403);
        }
        // The application's scope for this actor decides whose invitations they may revoke.
        $capabilities = $this->transport->send($request, $application, ['operation' => 'capabilities']);
        abort_unless($invitation->isVisibleTo($request->user(), $capabilities), 404);
        $this->invitations->revoke($request, $request->user(), $invitation);

        return redirect()->route('applications.access', ['application' => $application])
            ->with('invitation_notice', 'Invitation revoked. Its link no longer works.');
    }

    /**
     * Everything inviting needs that does not depend on whom: the switch, contract version 2 or 3, the
     * permissions, and the transport's own write checks.
     *
     * @throws DelegatedAccessException
     */
    private function authorizeInvite(Request $request, string $application): void
    {
        abort_unless($this->permissions->invitationsEnabled(), 404);
        abort_unless(DelegatedAccessTransport::contractVersion($application) >= DelegatedContract::VERSION_2, 404);
        if (! $this->permissions->canInvite($request->user(), $application)) {
            throw new DelegatedAccessException('not_authorized', 403);
        }
        $this->transport->authorizeWrite($request, $application);
        if (! AccessInvitationService::mailDelivers()) {
            throw ValidationException::withMessages(['invitation' => self::MAIL_UNCONFIGURED])
                ->redirectTo(route('applications.access', ['application' => $application]));
        }
    }

    /**
     * The same answer for every address. The link goes only to the invited address, so only its
     * reader can accept; it is shown to the inviter, this once, only when the email failed.
     */
    private function issued(string $back, IssuedInvitation $issued): RedirectResponse
    {
        return redirect()->to($back)->with([
            'invitation_notice' => self::SENT_NOTICE,
            'invitation_mail_failed' => ! $issued->sent,
            // Encrypted: the session payload may be stored as plain text, and the link is a bearer token.
            ...($issued->sent ? [] : ['invitation_link' => Crypt::encryptString($issued->link)]),
        ]);
    }
}
