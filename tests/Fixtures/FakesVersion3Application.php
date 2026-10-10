<?php

namespace Tests\Fixtures;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Support\Facades\Http;

/**
 * A synthetic application on delegated access contract version 3, answering through `Http::fake()`.
 *
 * Every answer is a valid version 3 message for `example-app` unless a test changes the properties
 * below. It searches its listings the way the contract asks (a case-insensitive substring of the
 * label, within one fixed scope) and pages them two at a time with a cursor bound to the search.
 * Writes can be made to fail uncertainly, and `receipt` answers whatever `$v3Receipt` holds.
 */
trait FakesVersion3Application
{
    /** @var list<array{id: string, role: string, editable: bool}> */
    private array $v3Memberships = [
        ['id' => 'workspace-a', 'role' => 'owner', 'editable' => true],
        ['id' => 'workspace-b', 'role' => 'sender', 'editable' => true],
    ];

    private bool $v3Provisioned = true;

    private bool $v3ProvisionAllowed = true;

    private bool $v3Provisioning = true;

    private bool $v3RemoveAllowed = true;

    /** @var array<string, string|null> state metadata for a read, as the application reports it */
    private array $v3StateMetadata = [];

    /** @var list<array<string, mixed>> */
    private array $v3Subjects = [
        ['subject' => 'subject-example', 'label' => 'Example Account'],
        ['subject' => 'subject-other', 'label' => 'Other Person'],
        ['subject' => 'subject-third', 'label' => 'Third Example'],
    ];

    /** @var list<array{id: string, label: string}> */
    private array $v3Workspaces = [
        ['id' => 'workspace-a', 'label' => 'Workspace A'],
        ['id' => 'workspace-b', 'label' => 'Workspace B'],
        ['id' => 'workspace-c', 'label' => 'Workspace C'],
    ];

    /** @var list<array<string, string>> */
    private array $v3Roles = [
        ['id' => 'owner', 'label' => 'Owner'],
        ['id' => 'admin', 'label' => 'Administrator'],
        ['id' => 'sender', 'label' => 'Sender', 'description' => 'Sends documents for signature.'],
        ['id' => 'auditor', 'label' => 'Auditor'],
    ];

    /** How writes fail: null answers them, `server_error` with a 500, `in_progress` a 503, `timeout` throws. */
    private ?string $v3WriteFailure = null;

    /** A write refused outright with this `[status, error]`. */
    private ?array $v3WriteRefusal = null;

    /**
     * What `receipt` answers: null for unknown, `['status' => int, 'response' => array]` for a stored
     * outcome (a 200 response's envelope is added here), or `fail` for a 500.
     */
    private array|string|null $v3Receipt = null;

    /** @var list<string> every operation the application was sent, in order, including any that timed out */
    private array $v3Sent = [];

    private function fakeVersion3Application(): void
    {
        $this->v3Sent = [];
        Http::fake(function (ClientRequest $request) {
            $operation = $request['operation'];
            $this->v3Sent[] = $operation;
            if (in_array($operation, ['update', 'remove'], true)) {
                if ($this->v3WriteFailure === 'timeout') {
                    throw new ConnectionException('synthetic timeout');
                }
                if ($this->v3WriteFailure !== null) {
                    return Http::response($this->v3WriteFailure === 'in_progress' ? ['error' => 'operation_in_progress'] : ['error' => 'server_error'],
                        $this->v3WriteFailure === 'in_progress' ? 503 : 500);
                }
                if ($this->v3WriteRefusal !== null) {
                    return Http::response(['error' => $this->v3WriteRefusal[1]], $this->v3WriteRefusal[0]);
                }
            }
            if ($operation === 'receipt' && $this->v3Receipt === 'fail') {
                return Http::response(['error' => 'server_error'], 500);
            }

            return Http::response($this->v3Envelope($operation, $this->v3Answer($request)));
        });
    }

    /** @return array<string, mixed> */
    private function v3Answer(ClientRequest $request): array
    {
        return match ($request['operation']) {
            'capabilities' => ['controls' => ['application_admin' => false, 'workspace_roles' => $this->v3Roles, 'provisioning' => $this->v3Provisioning]],
            'subjects' => $this->v3Page($request, $this->v3Subjects, 'subjects'),
            'workspaces' => $this->v3Page($request, $this->v3Workspaces, 'workspaces'),
            'update' => $this->v3UpdatedState($request['subject'], $request['access']['workspaces']),
            'remove' => $this->v3UpdatedState($request['subject'], []),
            'receipt' => $this->v3Receipt === null
                ? ['operation_id' => $request['operation_id'], 'status' => 'unknown']
                : ['operation_id' => $request['operation_id'], 'status' => 'known', 'response_status' => $this->v3Receipt['status'],
                    'response' => $this->v3Receipt['status'] === 200 ? $this->v3Envelope($this->v3Receipt['response']['operation'], $this->v3Receipt['response']) : $this->v3Receipt['response']],
            default => $this->v3ReadState($request['subject']),
        };
    }

    /** @return array<string, mixed> */
    private function v3Envelope(string $operation, array $fields): array
    {
        return ['contract_version' => 3, 'application' => 'example-app', 'operation' => $operation, ...$fields];
    }

    /**
     * Two entries a page; the cursor is bound to the search, as the contract requires.
     *
     * @param  list<array<string, mixed>>  $entries
     * @return array<string, mixed>
     */
    private function v3Page(ClientRequest $request, array $entries, string $operation): array
    {
        $query = $request['query'] ?? null;
        if (is_string($query)) {
            $entries = array_values(array_filter($entries, fn (array $entry): bool => mb_stripos($entry['label'], $query) !== false));
        }
        $offset = 0;
        if (isset($request['cursor'])) {
            [$boundQuery, $offset] = explode('|', $request['cursor'], 2) + [1 => '0'];
            if ($boundQuery !== 'q:'.($query ?? '')) {
                return [$operation => [], 'next_cursor' => null];
            }
            $offset = (int) $offset;
        }

        return [
            $operation => array_slice($entries, $offset, 2),
            'next_cursor' => count($entries) > $offset + 2 ? 'q:'.($query ?? '').'|'.($offset + 2) : null,
        ];
    }

    /** @return array<string, mixed> */
    private function v3ReadState(string $subject): array
    {
        if (! $this->v3Provisioned) {
            return ['subject' => $subject, 'provisioned' => false, 'revision' => null, 'access' => null,
                'allowed_edits' => ['application_admin' => false, 'workspaces' => false, 'provision' => $this->v3ProvisionAllowed, 'remove' => false]];
        }

        return ['subject' => $subject, 'provisioned' => true, 'revision' => 'revision-example',
            'access' => ['application_admin' => false, 'workspaces' => $this->v3Memberships],
            'allowed_edits' => ['application_admin' => false, 'workspaces' => true, 'provision' => false, 'remove' => $this->v3RemoveAllowed],
            ...$this->v3StateMetadata];
    }

    /** @return array<string, mixed> */
    private function v3UpdatedState(string $subject, array $workspaces): array
    {
        return ['subject' => $subject, 'provisioned' => true, 'revision' => $workspaces === [] ? 'revision-removed' : 'revision-after',
            'access' => ['application_admin' => false, 'workspaces' => array_map(
                fn (array $membership): array => ['id' => $membership['id'], 'role' => $membership['role'], 'editable' => true], $workspaces)],
            'allowed_edits' => ['application_admin' => false, 'workspaces' => true, 'provision' => false, 'remove' => true]];
    }
}
