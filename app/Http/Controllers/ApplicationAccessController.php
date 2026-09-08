<?php

namespace App\Http\Controllers;

use App\Models\RegisteredApplication;
use App\Services\DelegatedAccess\DelegatedAccessTransport;
use App\Support\RelyingApplications;
use Illuminate\Contracts\View\View;
use Illuminate\Http\Request;

class ApplicationAccessController extends Controller
{
    public function __construct(private readonly DelegatedAccessTransport $transport) {}

    public function directory(Request $request, RelyingApplications $applications): View
    {
        abort_unless(config('delegated-access.enabled') && config('application-registry.launch_enabled'), 404);

        return view('applications.manage', ['applications' => array_values(array_filter(
            $applications->forSubject((string) $request->user()->getAuthIdentifier()),
            fn (array $application): bool => is_string(config('delegated-access.applications.'.$application['key'].'.endpoint')),
        ))]);
    }

    public function index(Request $request, string $application): View
    {
        return $this->page($request, $application);
    }

    public function browse(Request $request, string $application): View
    {
        $input = $request->validate([
            'subject_cursor' => ['nullable', 'string', 'max:512'],
            'workspace_cursor' => ['nullable', 'string', 'max:512'],
            'subject' => ['nullable', 'string', 'max:191'],
        ]);
        $subject = $input['subject'] ?? null;
        $state = $subject !== null && $subject !== '' ? $this->transport->send($request, $application,
            ['operation' => 'read', 'subject' => $subject]) : null;

        return $this->page($request, $application, $subject, $state,
            $input['subject_cursor'] ?? null, $input['workspace_cursor'] ?? null);
    }

    public function update(Request $request, string $application): View
    {
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
        $state = $this->transport->send($request, $application, [
            'operation' => 'update',
            'subject' => $input['subject'],
            'expected_revision' => $input['expected_revision'],
            'access' => ['application_admin' => (bool) $input['application_admin'], 'workspaces' => $workspaces],
        ]);

        // Only a validated canonical update response can produce the success notice.
        return $this->page($request, $application, $input['subject'], $state, saved: true);
    }

    private function page(Request $request, string $application, ?string $subject = null,
        ?array $state = null, ?string $subjectCursor = null, ?string $workspaceCursor = null,
        bool $saved = false): View
    {
        $capabilities = $this->transport->send($request, $application, ['operation' => 'capabilities']);
        $subjects = $this->transport->send($request, $application,
            array_filter(['operation' => 'subjects', 'limit' => 50, 'cursor' => $subjectCursor], fn ($value) => $value !== null));
        $workspaces = $this->transport->send($request, $application,
            array_filter(['operation' => 'workspaces', 'limit' => 50, 'cursor' => $workspaceCursor], fn ($value) => $value !== null));

        return view('applications.access', [
            'application' => RegisteredApplication::query()->where('key', $application)->firstOrFail(),
            'capabilities' => $capabilities, 'subjects' => $subjects, 'workspaces' => $workspaces,
            'subject' => $subject, 'state' => $state, 'saved' => $saved,
        ]);
    }
}
