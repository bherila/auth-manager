<?php

namespace App\Http\Controllers;

use App\Models\RegisteredApplication;
use App\Models\User;
use App\Services\DelegatedAccess\DelegatedAccessTransport;
use App\Support\ApplicationGrantHolders;
use App\Support\DelegatedAccessApplications;
use App\Support\DelegatedAccessPermissions;
use App\Support\RelyingApplications;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedContract;
use Closure;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;

class ApplicationAccessController extends Controller
{
    /** One reply for every exact-email provisioning outcome, so it reveals nobody. */
    public const EMAIL_PROVISION_NOTICE = 'If that person can sign in to this application and has no account there yet, their account now exists with the access you chose. Find them in the account list to confirm.';

    public function __construct(
        private readonly DelegatedAccessTransport $transport,
        private readonly ApplicationGrantHolders $grantHolders,
        private readonly DelegatedAccessPermissions $permissions,
    ) {}

    public function directory(Request $request, RelyingApplications $applications, DelegatedAccessApplications $delegated): View
    {
        abort_unless(config('delegated-access.enabled') && config('application-registry.launch_enabled'), 404);

        // A malformed application map lists nothing: the page's existing no-integrations state.
        return view('applications.manage', ['applications' => $delegated->malformed() ? [] : array_values(array_filter(
            $applications->forSubject((string) $request->user()->getAuthIdentifier()),
            fn (array $application): bool => $delegated->find($application['key']) !== null
                && $this->permissions->canView($request->user(), $application['key']),
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
        $capabilities = $this->assertRolesAdvertised($request, $application, $input['subject'], $access, $back);

        $answer = $this->transport->send($request, $application, [
            'operation' => 'update',
            'subject' => $input['subject'],
            'expected_revision' => $input['expected_revision'],
            'access' => $access,
        ]);
        // The write was sent; an answer that does not fit what the application advertised cannot
        // confirm it, so it is reported as an unknown outcome rather than as success.
        if (! (new DelegatedContract)->fitsCapabilities($capabilities, $answer)) {
            throw new DelegatedAccessException('unknown_outcome');
        }

        return redirect()->to($back)->with('access_updated', true);
    }

    /**
     * Give a grant holder an account in the application: with one workspace membership, or for an
     * account-only application, with the application administrator flag the actor chose.
     *
     * Contract version 2 only. The person must hold a current grant to the application, the
     * application must still advertise provisioning and still report this subject unprovisioned with
     * provisioning allowed, and the role must be one it advertises. The application then creates the
     * account bound to this provider's issuer and the exact subject, and decides everything else.
     *
     * The form says which it is by what it posts: a workspace and role, or `application_admin` and
     * neither. That is checked against the application's capabilities before anybody is looked up.
     */
    public function provision(Request $request, string $application): RedirectResponse
    {
        abort_unless(DelegatedAccessTransport::contractVersion($application) === DelegatedContract::VERSION_2, 404);

        // Directory holders pick a subject; every other administrator names a
        // person by exact email and gets the same answer whatever the outcome.
        $byEmail = ! $this->permissions->canBrowseDirectory($request->user(), $application);
        // Only the account-only form posts application_admin, and it never defaults it: an empty
        // choice fails `required`. The workspace form validates exactly as it always has.
        $accountOnly = $request->exists('application_admin');
        $input = $request->validate([
            'subject' => [$byEmail ? 'prohibited' : 'required', 'string', 'max:191'],
            'email' => [$byEmail ? 'required' : 'prohibited', 'string', 'email', 'max:255'],
            ...($accountOnly ? [
                'application_admin' => ['required', 'boolean'],
                'new_workspace' => ['prohibited'],
                'new_role' => ['prohibited'],
            ] : [
                'new_workspace' => ['required', 'string', 'max:191'],
                'new_role' => ['required', 'string', 'max:64'],
            ]),
        ]);
        $back = $byEmail
            ? route('applications.access', ['application' => $application])
            : route('applications.access', ['application' => $application, 'subject' => $input['subject']]);
        $quietly = fn (): RedirectResponse => redirect()->to($back)->with('access_notice', self::EMAIL_PROVISION_NOTICE);

        $registration = RegisteredApplication::query()->where('key', $application)->where('enabled', true)->firstOrFail();

        // Everything that does not depend on the target is decided before it is looked up: this
        // provider's write checks, the application's authorization of the actor, and the role. What
        // an actor learns from a refusal here is the same whoever they named.
        $this->transport->authorizeWrite($request, $application);
        $capabilities = $this->transport->send($request, $application, ['operation' => 'capabilities']);
        $access = $this->provisionAccess(new DelegatedContract, $capabilities, $input, $accountOnly, $back);

        $person = $byEmail
            ? $this->grantHolders->personByEmail($registration, $input['email'])
            : $this->grantHolders->person($registration, $input['subject']);
        if ($person === null) {
            if ($byEmail) {
                return $quietly();
            }
            throw ValidationException::withMessages(['subject' => 'Choose someone who can sign in to this application.'])
                ->redirectTo($back);
        }

        try {
            return $this->provisionPerson($request, $application, $person, $capabilities, $access, $byEmail, $back, $quietly);
        } catch (DelegatedAccessException $refusal) {
            // A refusal from here on is about this person: whether they exist there, what the
            // application lets this actor do to them, whether the write went through. The transport
            // has audited it; the actor named somebody by email and is told only what anybody is.
            if ($byEmail) {
                return $quietly();
            }

            throw $refusal;
        }
    }

    /**
     * The access a provisioning request asks for, checked against the application's capabilities.
     *
     * Workspace applications get one membership with an advertised role and no administration, as
     * always. Account-only applications get no memberships and the administrator flag as chosen, and
     * administration only where the capabilities offer it to this actor. None of this depends on the
     * person named, so every refusal here is the same whoever it is.
     *
     * @return array{application_admin: bool, workspaces: list<array{id: string, role: string}>}
     */
    private function provisionAccess(DelegatedContract $contract, array $capabilities, array $input, bool $accountOnly, string $back): array
    {
        if ($contract->accountOnly($capabilities) !== $accountOnly) {
            throw ValidationException::withMessages($accountOnly
                ? ['new_workspace' => 'Choose a workspace and a role.']
                : ['application_admin' => 'Choose whether the new account is an application administrator.'])->redirectTo($back);
        }

        $access = $accountOnly
            ? ['application_admin' => (bool) $input['application_admin'], 'workspaces' => []]
            : ['application_admin' => false, 'workspaces' => [['id' => $input['new_workspace'], 'role' => $input['new_role']]]];
        if ($access['application_admin'] && ($capabilities['controls']['application_admin'] ?? false) !== true) {
            throw ValidationException::withMessages(['application_admin' => 'The application does not let you create an application administrator.'])->redirectTo($back);
        }
        if (! $contract->rolesAreAdvertised($capabilities, $access)) {
            throw ValidationException::withMessages(['new_role' => 'Choose a role the application offers.'])->redirectTo($back);
        }

        return $access;
    }

    /**
     * @throws DelegatedAccessException
     */
    private function provisionPerson(Request $request, string $application, User $person, array $capabilities, array $access, bool $byEmail, string $back, Closure $quietly): RedirectResponse
    {
        $subject = (string) $person->getKey();

        $state = $this->transport->send($request, $application, ['operation' => 'read', 'subject' => $subject]);
        if (($capabilities['controls']['provisioning'] ?? false) !== true || $state['provisioned'] || ! $state['allowed_edits']['provision']) {
            if ($byEmail) {
                return $quietly();
            }

            return redirect()->to($back)
                ->with('access_failure', 'The application does not offer to create this account now. Review its current access.');
        }

        $update = ['operation' => 'update', 'subject' => $subject, 'expected_revision' => null, 'access' => $access];
        $name = trim((string) $person->name);
        if ($name !== '') {
            // Contact data for the new account, bounded in bytes as the contract bounds it.
            $update['display_name'] = mb_strcut($name, 0, 255, 'UTF-8');
        }
        $answer = $this->transport->send($request, $application, $update);
        if (! (new DelegatedContract)->fitsCapabilities($capabilities, $answer)) {
            // Caught by provision(): the uniform notice by email, an unknown outcome otherwise.
            throw new DelegatedAccessException('unknown_outcome');
        }

        return $byEmail ? $quietly() : redirect()->to($back)->with('access_updated', true);
    }

    /**
     * Every membership this update adds or changes names a role the application advertises.
     *
     * A membership kept exactly as the application reports it is not checked: it may hold a role the
     * application has since retired, posted back unchanged from a hidden field, and that must not
     * block saving anything else. The application still refuses an update that changes one.
     *
     * @return array<string, mixed> the capabilities it checked against, for checking the update's answer
     */
    private function assertRolesAdvertised(Request $request, string $application, string $subject, array $access, string $back): array
    {
        $contract = new DelegatedContract;
        $capabilities = $this->transport->send($request, $application, ['operation' => 'capabilities']);
        $current = $this->transport->send($request, $application, ['operation' => 'read', 'subject' => $subject]);
        if (! $contract->fitsCapabilities($capabilities, $current)) {
            throw new DelegatedAccessException('invalid_response');
        }
        // An account-only application has no workspaces, so there is no membership to keep or send.
        if ($contract->accountOnly($capabilities) && $access['workspaces'] !== []) {
            throw ValidationException::withMessages(['workspaces' => 'This application has no workspaces.'])->redirectTo($back);
        }

        $kept = [];
        foreach ($current['access']['workspaces'] ?? [] as $membership) {
            $kept[$membership['id']."\0".$membership['role']] = true;
        }
        $changed = [...$access, 'workspaces' => array_values(array_filter($access['workspaces'],
            fn (array $membership): bool => ! isset($kept[$membership['id']."\0".$membership['role']])))];

        if (! $contract->rolesAreAdvertised($capabilities, $changed)) {
            throw ValidationException::withMessages(['workspaces' => 'Choose roles the application offers.'])->redirectTo($back);
        }

        return $capabilities;
    }

    private function page(Request $request, string $application, ?string $subject = null,
        ?array $state = null, ?string $subjectCursor = null, ?string $workspaceCursor = null,
        bool $saved = false, string $directorySearch = '', int $directoryPage = 1): View
    {
        $version = DelegatedAccessTransport::contractVersion($application);
        $contract = new DelegatedContract;
        $capabilities = $this->transport->send($request, $application, ['operation' => 'capabilities']);
        // An account-only application has no workspaces to list, so it is not asked for them. Anything
        // it reports that only a workspace application could is refused rather than rendered.
        $accountOnly = $version === DelegatedContract::VERSION_2 && $contract->accountOnly($capabilities);
        if ($state !== null && $version === DelegatedContract::VERSION_2 && ! $contract->fitsCapabilities($capabilities, $state)) {
            throw new DelegatedAccessException('invalid_response');
        }
        $subjects = $this->transport->send($request, $application,
            array_filter(['operation' => 'subjects', 'limit' => 50, 'cursor' => $subjectCursor], fn ($value) => $value !== null));
        $workspaces = $accountOnly ? ['workspaces' => [], 'next_cursor' => null] : $this->transport->send($request, $application,
            array_filter(['operation' => 'workspaces', 'limit' => 50, 'cursor' => $workspaceCursor], fn ($value) => $value !== null));
        $registration = RegisteredApplication::query()->where('key', $application)->firstOrFail();

        // The picker discloses grant holders across every workspace, so it needs the separate
        // directory permission as well as the application answering capabilities and advertising
        // provisioning. Without it, a manager names a person by exact email instead.
        $provisioning = $version === DelegatedContract::VERSION_2 && ($capabilities['controls']['provisioning'] ?? false) === true;
        $actor = $request->user();
        $directory = $provisioning && $this->permissions->canBrowseDirectory($actor, $application)
            ? $this->grantHolders->search($registration, $directorySearch, $directoryPage)
            : null;
        $writes = $this->permissions->canManage($actor, $application) && $this->permissions->writesEnabled($application);

        return view('applications.access', [
            'application' => $registration, 'version' => $version, 'accountOnly' => $accountOnly,
            'capabilities' => $capabilities, 'subjects' => $subjects, 'workspaces' => $workspaces,
            'subject' => $subject, 'state' => $state, 'saved' => $saved,
            'directory' => $directory, 'directorySearch' => $directorySearch,
            'writes' => $writes, 'provisionByEmail' => $provisioning && $writes && $directory === null,
        ]);
    }
}
