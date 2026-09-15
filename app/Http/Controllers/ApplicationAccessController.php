<?php

namespace App\Http\Controllers;

use App\Models\RegisteredApplication;
use App\Services\DelegatedAccess\DelegatedAccessTransport;
use App\Support\ApplicationGrantHolders;
use App\Support\DelegatedAccessApplications;
use App\Support\RelyingApplications;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedContract;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;

class ApplicationAccessController extends Controller
{
    public function __construct(
        private readonly DelegatedAccessTransport $transport,
        private readonly ApplicationGrantHolders $grantHolders,
    ) {}

    public function directory(Request $request, RelyingApplications $applications, DelegatedAccessApplications $delegated): View
    {
        abort_unless(config('delegated-access.enabled') && config('application-registry.launch_enabled'), 404);

        // A malformed application map lists nothing: the page's existing no-integrations state.
        return view('applications.manage', ['applications' => $delegated->malformed() ? [] : array_values(array_filter(
            $applications->forSubject((string) $request->user()->getAuthIdentifier()),
            fn (array $application): bool => $delegated->find($application['key']) !== null,
        ))]);
    }

    public function index(Request $request, string $application): View
    {
        $input = $this->browseInput($request);
        $subject = $input['subject'] ?? null;
        $state = $subject !== null && $subject !== '' ? $this->transport->send($request, $application,
            ['operation' => 'read', 'subject' => $subject]) : null;

        return $this->page($request, $application, $subject, $state,
            $input['subject_cursor'] ?? null, $input['workspace_cursor'] ?? null,
            $request->session()->get('access_updated') === true,
            (string) ($input['directory_search'] ?? ''), (int) ($input['directory_page'] ?? 1));
    }

    public function browse(Request $request, string $application): RedirectResponse
    {
        return redirect()->route('applications.access', ['application' => $application, ...$this->browseInput($request)]);
    }

    private function browseInput(Request $request): array
    {
        return $request->validate([
            'subject_cursor' => ['nullable', 'string', 'max:512'],
            'workspace_cursor' => ['nullable', 'string', 'max:512'],
            'subject' => ['nullable', 'string', 'max:191'],
            'directory_search' => ['nullable', 'string', 'max:100'],
            'directory_page' => ['nullable', 'integer', 'min:1', 'max:1000'],
        ]);
    }

    public function update(Request $request, string $application): RedirectResponse
    {
        if (DelegatedAccessTransport::contractVersion($application) === DelegatedContract::VERSION_2) {
            return $this->updateWithRoles($request, $application);
        }

        $input = $request->validate([
            'subject' => ['required', 'string', 'max:191'],
            'expected_revision' => ['required', 'string', 'max:128'],
            'application_admin' => ['required', 'boolean'],
            'workspaces' => ['sometimes', 'array', 'max:100'],
            'workspaces.*.id' => ['required', 'string', 'max:191', 'distinct:strict'],
            'workspaces.*.permission' => ['required', 'in:read,write,none'],
            'new_workspace' => ['nullable', 'string', 'max:191'],
            'new_permission' => ['nullable', 'in:read,write'],
        ]);
        $workspaces = array_values(array_filter($input['workspaces'] ?? [],
            fn (array $workspace): bool => $workspace['permission'] !== 'none'));
        if (isset($input['new_workspace']) && $input['new_workspace'] !== '') {
            $workspaces[] = ['id' => $input['new_workspace'], 'permission' => $input['new_permission'] ?? 'read'];
        }
        if (count($workspaces) > 100) {
            throw ValidationException::withMessages(['new_workspace' => 'Remove a workspace membership before adding another.'])
                ->redirectTo(route('applications.access', ['application' => $application, 'subject' => $input['subject']]));
        }
        $this->transport->send($request, $application, [
            'operation' => 'update',
            'subject' => $input['subject'],
            'expected_revision' => $input['expected_revision'],
            'access' => ['application_admin' => (bool) $input['application_admin'], 'workspaces' => $workspaces],
        ]);

        // Only a validated canonical update response can produce the success notice.
        return redirect()->route('applications.access', ['application' => $application, 'subject' => $input['subject']])
            ->with('access_updated', true);
    }

    /**
     * Contract version 2: memberships name one of the application's own roles.
     *
     * A membership the application reported as not editable is posted back as it was, from a hidden
     * field; the application refuses an update that changes one. An empty role removes a membership.
     */
    private function updateWithRoles(Request $request, string $application): RedirectResponse
    {
        $input = $request->validate([
            'subject' => ['required', 'string', 'max:191'],
            'expected_revision' => ['required', 'string', 'max:128'],
            'application_admin' => ['required', 'boolean'],
            'workspaces' => ['sometimes', 'array', 'max:100'],
            'workspaces.*.id' => ['required', 'string', 'max:191', 'distinct:strict'],
            'workspaces.*.role' => ['nullable', 'string', 'max:64'],
            'new_workspace' => ['nullable', 'string', 'max:191'],
            'new_role' => ['nullable', 'string', 'max:64', 'required_with:new_workspace'],
        ]);
        $back = route('applications.access', ['application' => $application, 'subject' => $input['subject']]);

        $workspaces = [];
        foreach ($input['workspaces'] ?? [] as $workspace) {
            if (is_string($workspace['role'] ?? null) && $workspace['role'] !== '') {
                $workspaces[] = ['id' => $workspace['id'], 'role' => $workspace['role']];
            }
        }
        if (isset($input['new_workspace']) && $input['new_workspace'] !== '') {
            $workspaces[] = ['id' => $input['new_workspace'], 'role' => (string) $input['new_role']];
        }
        if (count($workspaces) > 100) {
            throw ValidationException::withMessages(['new_workspace' => 'Remove a workspace membership before adding another.'])
                ->redirectTo($back);
        }

        $access = ['application_admin' => (bool) $input['application_admin'], 'workspaces' => $workspaces];
        $this->assertRolesAdvertised($request, $application, $input['subject'], $access, $back);

        $this->transport->send($request, $application, [
            'operation' => 'update',
            'subject' => $input['subject'],
            'expected_revision' => $input['expected_revision'],
            'access' => $access,
        ]);

        return redirect()->to($back)->with('access_updated', true);
    }

    /**
     * Give a grant holder an account in the application, with one workspace membership.
     *
     * Contract version 2 only. The person must hold a current grant to the application, the
     * application must still advertise provisioning and still report this subject unprovisioned with
     * provisioning allowed, and the role must be one it advertises. The application then creates the
     * account bound to this provider's issuer and the exact subject, and decides everything else.
     */
    public function provision(Request $request, string $application): RedirectResponse
    {
        abort_unless(DelegatedAccessTransport::contractVersion($application) === DelegatedContract::VERSION_2, 404);

        $input = $request->validate([
            'subject' => ['required', 'string', 'max:191'],
            'new_workspace' => ['required', 'string', 'max:191'],
            'new_role' => ['required', 'string', 'max:64'],
        ]);
        $back = route('applications.access', ['application' => $application, 'subject' => $input['subject']]);

        $registration = RegisteredApplication::query()->where('key', $application)->where('enabled', true)->firstOrFail();

        // The application authorizes the actor first. Only then is the target looked up, so somebody
        // the application does not let manage access learns nothing about who holds a grant.
        $capabilities = $this->transport->send($request, $application, ['operation' => 'capabilities']);

        $person = $this->grantHolders->person($registration, $input['subject']);
        if ($person === null) {
            throw ValidationException::withMessages(['subject' => 'Choose someone who can sign in to this application.'])
                ->redirectTo($back);
        }

        $state = $this->transport->send($request, $application, ['operation' => 'read', 'subject' => $input['subject']]);
        if (($capabilities['controls']['provisioning'] ?? false) !== true || $state['provisioned'] || ! $state['allowed_edits']['provision']) {
            return redirect()->to($back)
                ->with('access_failure', 'The application does not offer to create this account now. Review its current access.');
        }

        $access = ['application_admin' => false, 'workspaces' => [['id' => $input['new_workspace'], 'role' => $input['new_role']]]];
        if (! (new DelegatedContract)->rolesAreAdvertised($capabilities, $access)) {
            throw ValidationException::withMessages(['new_role' => 'Choose a role the application offers.'])->redirectTo($back);
        }

        $update = ['operation' => 'update', 'subject' => $input['subject'], 'expected_revision' => null, 'access' => $access];
        $name = trim((string) $person->name);
        if ($name !== '') {
            // Contact data for the new account, bounded in bytes as the contract bounds it.
            $update['display_name'] = mb_strcut($name, 0, 255, 'UTF-8');
        }
        $this->transport->send($request, $application, $update);

        return redirect()->to($back)->with('access_updated', true);
    }

    /**
     * Every membership this update adds or changes names a role the application advertises.
     *
     * A membership kept exactly as the application reports it is not checked: it may hold a role the
     * application has since retired, posted back unchanged from a hidden field, and that must not
     * block saving anything else. The application still refuses an update that changes one.
     */
    private function assertRolesAdvertised(Request $request, string $application, string $subject, array $access, string $back): void
    {
        $capabilities = $this->transport->send($request, $application, ['operation' => 'capabilities']);
        $current = $this->transport->send($request, $application, ['operation' => 'read', 'subject' => $subject]);

        $kept = [];
        foreach ($current['access']['workspaces'] ?? [] as $membership) {
            $kept[$membership['id']."\0".$membership['role']] = true;
        }
        $changed = [...$access, 'workspaces' => array_values(array_filter($access['workspaces'],
            fn (array $membership): bool => ! isset($kept[$membership['id']."\0".$membership['role']])))];

        if (! (new DelegatedContract)->rolesAreAdvertised($capabilities, $changed)) {
            throw ValidationException::withMessages(['workspaces' => 'Choose roles the application offers.'])->redirectTo($back);
        }
    }

    private function page(Request $request, string $application, ?string $subject = null,
        ?array $state = null, ?string $subjectCursor = null, ?string $workspaceCursor = null,
        bool $saved = false, string $directorySearch = '', int $directoryPage = 1): View
    {
        $version = DelegatedAccessTransport::contractVersion($application);
        $capabilities = $this->transport->send($request, $application, ['operation' => 'capabilities']);
        $subjects = $this->transport->send($request, $application,
            array_filter(['operation' => 'subjects', 'limit' => 50, 'cursor' => $subjectCursor], fn ($value) => $value !== null));
        $workspaces = $this->transport->send($request, $application,
            array_filter(['operation' => 'workspaces', 'limit' => 50, 'cursor' => $workspaceCursor], fn ($value) => $value !== null));
        $registration = RegisteredApplication::query()->where('key', $application)->firstOrFail();

        // Listed only once the application has answered capabilities for this actor and advertised
        // provisioning: the picker is part of managing access there, not a directory of its own.
        $directory = $version === DelegatedContract::VERSION_2 && ($capabilities['controls']['provisioning'] ?? false) === true
            ? $this->grantHolders->search($registration, $directorySearch, $directoryPage)
            : null;

        return view('applications.access', [
            'application' => $registration, 'version' => $version,
            'capabilities' => $capabilities, 'subjects' => $subjects, 'workspaces' => $workspaces,
            'subject' => $subject, 'state' => $state, 'saved' => $saved,
            'directory' => $directory, 'directorySearch' => $directorySearch,
        ]);
    }
}
