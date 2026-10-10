<?php

namespace Tests\Feature;

use App\Http\Middleware\EnsureCredentialVersion;
use App\Http\Middleware\RequireRecentPasskeyAuthentication;
use App\Models\PassportClient;
use App\Models\RegisteredApplication;
use App\Models\User;
use App\Services\DelegatedAccess\DelegatedAccessTransport;
use BWH\Auth\Models\AuthAuditLog;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedContract;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Foundation\Testing\RefreshDatabaseState;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Tests\Fixtures\FakesVersion3Application;
use Tests\TestCase;

/**
 * The transport talking contract version 3: what it sends for each operation, what it accepts back,
 * and the receipt check after an uncertain write. `DelegatedAccessTransportTest` covers the rest of
 * the transport against the reference adapter.
 */
class DelegatedAccessTransportV3Test extends TestCase
{
    use DatabaseMigrations;
    use FakesVersion3Application;

    public function runDatabaseMigrations(): void
    {
        // Transport writes require independently committed audit records.
        $this->refreshTestDatabase();
        $this->beforeApplicationDestroyed(function (): void {
            RefreshDatabaseState::$migrated = false;
        });
    }

    private string $keyPath;

    private User $actor;

    private Request $request;

    private string $operationId;

    protected function setUp(): void
    {
        parent::setUp();
        $key = openssl_pkey_new(['private_key_bits' => 2048]);
        openssl_pkey_export($key, $private);
        $this->keyPath = tempnam(sys_get_temp_dir(), 'synthetic-transport-v3-');
        file_put_contents($this->keyPath, $private);
        chmod($this->keyPath, 0600);
        config(['delegated-access' => [
            'enabled' => true, 'writes_enabled' => true, 'writes_applications' => ['example-app'],
            'issuer' => 'https://identity.example.test', 'key_id' => null, 'private_key_path' => null,
            'keys_environment' => 'example-app|integration-v1|'.$this->keyPath,
            'applications' => ['example-app' => ['endpoint' => 'https://app.example.test/access', 'contract_version' => 3]],
        ]]);
        $this->actor = User::factory()->create(['user_role' => 'user,access-manage:example-app']);
        $client = PassportClient::create(['id' => (string) Str::uuid(), 'name' => 'Example Client', 'secret' => 'synthetic-secret', 'grant_types' => ['authorization_code'], 'redirect_uris' => ['https://app.example.test/callback'], 'revoked' => false]);
        RegisteredApplication::create(['key' => 'example-app', 'name' => 'Example Application', 'launch_url' => 'https://app.example.test', 'enabled' => true])
            ->clients()->attach($client->id);
        DB::table('oauth_client_grants')->insert(['oauth_client_id' => $client->id, 'subject' => $this->actor->id, 'created_at' => now(), 'updated_at' => now()]);
        $this->request = Request::create('/synthetic-delegated-ui', 'POST');
        $this->request->setUserResolver(fn (): User => $this->actor);
        $this->request->setLaravelSession(app('session.store'));
        $this->request->session()->put(EnsureCredentialVersion::SESSION_KEY, 0);
        RequireRecentPasskeyAuthentication::recordCredentialVerification($this->request);
        $this->operationId = DelegatedContract::operationId();
        Http::preventStrayRequests();
        $this->fakeVersion3Application();
    }

    protected function tearDown(): void
    {
        @unlink($this->keyPath);
        parent::tearDown();
    }

    public function test_each_operation_is_sent_in_version_3_with_exactly_its_fields(): void
    {
        $transport = app(DelegatedAccessTransport::class);
        $transport->send($this->request, 'example-app', ['operation' => 'capabilities']);
        $transport->send($this->request, 'example-app', ['operation' => 'subjects', 'limit' => 50, 'query' => 'Example']);
        $transport->send($this->request, 'example-app', ['operation' => 'workspaces', 'limit' => 50, 'query' => 'work', 'cursor' => 'q:work|2']);
        $transport->send($this->request, 'example-app', ['operation' => 'read', 'subject' => 'subject-example']);
        $transport->send($this->request, 'example-app', $this->update());
        $transport->send($this->request, 'example-app', $this->remove());

        $sent = array_map(fn (array $pair): array => json_decode($pair[0]->body(), true), Http::recorded()->all());
        $envelope = ['contract_version' => 3, 'application' => 'example-app'];
        $this->assertSame([
            [...$envelope, 'operation' => 'capabilities'],
            [...$envelope, 'operation' => 'subjects', 'limit' => 50, 'query' => 'Example'],
            [...$envelope, 'operation' => 'workspaces', 'limit' => 50, 'query' => 'work', 'cursor' => 'q:work|2'],
            [...$envelope, 'operation' => 'read', 'subject' => 'subject-example'],
            [...$envelope, ...$this->update()],
            [...$envelope, ...$this->remove()],
        ], $sent);
    }

    public function test_a_request_the_contract_refuses_is_never_sent(): void
    {
        $transport = app(DelegatedAccessTransport::class);
        $update = $this->update();
        unset($update['operation_id']);
        foreach ([
            'update without an operation id' => $update,
            'remove without an operation id' => ['operation' => 'remove', 'subject' => 'subject-example', 'expected_revision' => 'revision-example'],
            'malformed operation id' => [...$this->remove(), 'operation_id' => 'short'],
            'remove without a revision' => ['operation' => 'remove', 'subject' => 'subject-example', 'operation_id' => $this->operationId],
            'one-character query' => ['operation' => 'subjects', 'query' => 'x'],
            'over-long query' => ['operation' => 'workspaces', 'query' => str_repeat('x', 101)],
            'query with a control character' => ['operation' => 'subjects', 'query' => "ab\ncd"],
        ] as $case => $operation) {
            $this->refused(fn () => $transport->send($this->request, 'example-app', $operation), 'invalid_request', 422, $case);
        }
        Http::assertNothingSent();
        $this->assertSame(0, AuthAuditLog::query()->count());
    }

    public function test_answers_are_held_to_version_3_per_operation(): void
    {
        $transport = app(DelegatedAccessTransport::class);
        $version2State = ['subject' => 'subject-example', 'provisioned' => true, 'revision' => 'revision-example',
            'access' => ['application_admin' => false, 'workspaces' => []],
            'allowed_edits' => ['application_admin' => false, 'workspaces' => true, 'provision' => false]];
        $cases = [
            // A version 2 state: no allowed_edits.remove.
            ['read', ['operation' => 'read', 'subject' => 'subject-example'], $version2State, 'invalid_response'],
            // A malformed answer to a write is uncertain: the receipt is asked for, and has none here.
            ['update', $this->update(), $version2State, DelegatedAccessTransport::STILL_UNKNOWN],
            // A removal that leaves a membership behind is not a removal.
            ['remove', $this->remove(), [...$version2State, 'access' => ['application_admin' => false, 'workspaces' => [['id' => 'workspace-a', 'role' => 'owner', 'editable' => true]]],
                'allowed_edits' => [...$version2State['allowed_edits'], 'remove' => true]], DelegatedAccessTransport::STILL_UNKNOWN],
            // Metadata that is not a timestamp.
            ['subjects', ['operation' => 'subjects'], ['subjects' => [['subject' => 'subject-example', 'label' => 'Example', 'last_seen_at' => 'yesterday']], 'next_cursor' => null], 'invalid_response'],
            // A role description that is empty.
            ['capabilities', ['operation' => 'capabilities'], ['controls' => ['application_admin' => false, 'workspace_roles' => [['id' => 'owner', 'label' => 'Owner', 'description' => '']], 'provisioning' => false]], 'invalid_response'],
        ];
        foreach ($cases as [$name, $operation, $answer, $outcome]) {
            Http::swap(new Factory);
            Http::fake(fn (ClientRequest $request) => Http::response($request['operation'] === 'receipt'
                ? $this->v3Envelope('receipt', ['operation_id' => $request['operation_id'], 'status' => 'unknown'])
                : $this->v3Envelope($name, $answer)));
            $this->refused(fn () => $transport->send($this->request, 'example-app', $operation), $outcome, 503, $name);
        }
        // And a version 2 envelope is not a version 3 answer.
        Http::swap(new Factory);
        Http::fake(fn () => Http::response(['contract_version' => 2, 'application' => 'example-app', 'operation' => 'capabilities',
            'controls' => ['application_admin' => false, 'workspace_roles' => [], 'provisioning' => false]]));
        $this->refused(fn () => $transport->send($this->request, 'example-app', ['operation' => 'capabilities']), 'invalid_response', 503);
    }

    public function test_writes_are_audited_with_their_operation_and_operation_id(): void
    {
        $transport = app(DelegatedAccessTransport::class);
        $transport->send($this->request, 'example-app', $this->update());
        $removal = $this->remove();
        $transport->send($this->request, 'example-app', $removal);

        $records = AuthAuditLog::query()->orderBy('id')->get();
        $this->assertSame(['delegated_access_update_attempt', 'delegated_access_update_result', 'delegated_access_update_attempt', 'delegated_access_update_result'], $records->pluck('event')->all());
        $this->assertSame(['update', 'update', 'remove', 'remove'], $records->map(fn ($row) => $row->metadata['operation'])->all());
        $this->assertSame(['attempt', 'succeeded', 'attempt', 'succeeded'], $records->map(fn ($row) => $row->metadata['outcome'])->all());
        $this->assertSame(array_fill(0, 4, $this->operationId), $records->map(fn ($row) => $row->metadata['operation_id'])->all());
        $this->assertSame(['actor', 'application', 'target', 'operation', 'outcome', 'correlation', 'operation_id'], array_keys($records[0]->metadata));
    }

    public function test_a_removal_is_a_write_and_needs_everything_a_write_needs(): void
    {
        $transport = app(DelegatedAccessTransport::class);
        $this->request->session()->forget(RequireRecentPasskeyAuthentication::SESSION_KEY);
        $this->refused(fn () => $transport->send($this->request, 'example-app', $this->remove()), 'recent_confirmation_required', 403);
        RequireRecentPasskeyAuthentication::recordCredentialVerification($this->request);
        config(['delegated-access.writes_applications' => []]);
        $this->refused(fn () => $transport->send($this->request, 'example-app', $this->remove()), 'not_authorized', 403);
        config(['delegated-access.writes_applications' => ['example-app']]);
        $this->actor->update(['user_role' => 'user,access-view:example-app']);
        $this->refused(fn () => $transport->send($this->request, 'example-app', $this->remove()), 'not_authorized', 403);
        Http::assertNothingSent();
    }

    public function test_an_uncertain_write_is_settled_by_one_receipt_when_the_application_applied_it(): void
    {
        foreach (['server_error', 'in_progress', 'timeout'] as $failure) {
            $this->resetFake();
            $this->v3WriteFailure = $failure;
            $this->v3Receipt = ['status' => 200, 'response' => ['operation' => 'remove', ...$this->v3UpdatedState('subject-example', [])]];

            $state = app(DelegatedAccessTransport::class)->send($this->request, 'example-app', $this->remove());

            $this->assertSame('revision-removed', $state['revision'], $failure);
            $this->assertSame(['remove', 'receipt'], $this->sentOperations(), $failure);
            $receipt = Http::recorded(fn (ClientRequest $request) => $request['operation'] === 'receipt')->first()[0];
            $this->assertSame(['contract_version' => 3, 'application' => 'example-app', 'operation' => 'receipt', 'operation_id' => $this->operationId], $receipt->data());
            if ($failure !== 'timeout') {
                $this->assertNotSame($this->jti(Http::recorded()->first()[0]), $this->jti($receipt), 'A new assertion for the receipt.');
            }
            $this->assertSame([
                ['delegated_access_update_attempt', 'attempt', false],
                ['delegated_access_receipt_check', 'applied', true],
                ['delegated_access_update_result', 'succeeded', true],
            ], $this->audits(), $failure);
            $this->assertSame('receipt', AuthAuditLog::query()->where('event', 'delegated_access_update_result')->first()->metadata['confirmed_by']);
        }
    }

    public function test_an_uncertain_write_the_application_refused_is_reported_as_that_refusal(): void
    {
        $this->v3WriteFailure = 'server_error';
        $this->v3Receipt = ['status' => 409, 'response' => ['error' => 'revision_conflict']];

        $this->refused(fn () => app(DelegatedAccessTransport::class)->send($this->request, 'example-app', $this->update()), 'revision_conflict', 409);

        $this->assertSame(['update', 'receipt'], $this->sentOperations());
        $this->assertSame([
            ['delegated_access_update_attempt', 'attempt', false],
            ['delegated_access_receipt_check', 'refused', true],
            ['delegated_access_update_result', 'revision_conflict', false],
        ], $this->audits());
        $check = AuthAuditLog::query()->where('event', 'delegated_access_receipt_check')->first()->metadata;
        $this->assertSame(['revision_conflict', 409, $this->operationId], [$check['refusal'], $check['refusal_status'], $check['operation_id']]);
        // Settled by the receipt, not by an immediate answer: the result record says so (Codex review on #77).
        $this->assertSame('receipt', AuthAuditLog::query()->where('event', 'delegated_access_update_result')->first()->metadata['confirmed_by'] ?? null);
    }

    public function test_an_uncertain_write_without_a_usable_receipt_stays_unknown_and_is_never_sent_again(): void
    {
        $cases = [
            'no receipt' => null,
            'receipt request failed' => 'fail',
            // A stored success for some other write cannot vouch for this one.
            'receipt for another subject' => ['status' => 200, 'response' => ['operation' => 'update', ...$this->v3UpdatedState('subject-other', [['id' => 'workspace-a', 'role' => 'owner']])]],
            'receipt for another operation' => ['status' => 200, 'response' => ['operation' => 'remove', ...$this->v3UpdatedState('subject-example', [])]],
        ];
        foreach ($cases as $case => $receipt) {
            $this->resetFake();
            $this->v3WriteFailure = 'server_error';
            $this->v3Receipt = $receipt;

            $this->refused(fn () => app(DelegatedAccessTransport::class)->send($this->request, 'example-app', $this->update()), DelegatedAccessTransport::STILL_UNKNOWN, 503, $case);

            $this->assertSame(['update', 'receipt'], $this->sentOperations(), $case);
            $this->assertSame([
                ['delegated_access_update_attempt', 'attempt', false],
                ['delegated_access_receipt_check', 'unknown', false],
                ['delegated_access_update_result', DelegatedAccessTransport::STILL_UNKNOWN, false],
            ], $this->audits(), $case);
            $this->assertArrayNotHasKey('confirmed_by', AuthAuditLog::query()->where('event', 'delegated_access_update_result')->first()->metadata, $case);
        }
    }

    public function test_a_definite_refusal_is_not_followed_by_a_receipt_check(): void
    {
        $this->v3WriteRefusal = [403, 'protected_membership'];

        $this->refused(fn () => app(DelegatedAccessTransport::class)->send($this->request, 'example-app', $this->remove()), 'not_authorized', 403);

        $this->assertSame(['remove'], $this->sentOperations());
    }

    public function test_a_receipt_check_that_cannot_be_audited_leaves_the_outcome_unknown(): void
    {
        $this->v3WriteFailure = 'server_error';
        $this->v3Receipt = ['status' => 200, 'response' => ['operation' => 'remove', ...$this->v3UpdatedState('subject-example', [])]];
        AuthAuditLog::creating(function (AuthAuditLog $record): void {
            if ($record->event === 'delegated_access_receipt_check') {
                throw new \RuntimeException('synthetic audit failure');
            }
        });

        $this->refused(fn () => app(DelegatedAccessTransport::class)->send($this->request, 'example-app', $this->remove()), DelegatedAccessTransport::STILL_UNKNOWN, 503);
        $this->assertSame(['remove', 'receipt'], $this->sentOperations());
    }

    private function resetFake(): void
    {
        Http::swap(new Factory);
        Http::preventStrayRequests();
        $this->fakeVersion3Application();
        AuthAuditLog::query()->delete();
    }

    /** @return list<string> */
    private function sentOperations(): array
    {
        return $this->v3Sent;
    }

    /** @return list<array{0: string, 1: string, 2: bool}> */
    private function audits(): array
    {
        return AuthAuditLog::query()->orderBy('id')->get()
            ->map(fn (AuthAuditLog $row): array => [$row->event, $row->metadata['outcome'], (bool) $row->succeeded])->all();
    }

    private function jti(ClientRequest $request): string
    {
        $payload = explode('.', substr($request->header('Authorization')[0], strlen('Bearer ')))[1];

        return json_decode(base64_decode(strtr($payload, '-_', '+/')), true)['jti'];
    }

    /** @return array<string, mixed> */
    private function update(): array
    {
        return ['operation' => 'update', 'subject' => 'subject-example', 'expected_revision' => 'revision-example',
            'access' => ['application_admin' => false, 'workspaces' => [['id' => 'workspace-a', 'role' => 'owner']]], 'operation_id' => $this->operationId];
    }

    /** @return array<string, mixed> */
    private function remove(): array
    {
        return ['operation' => 'remove', 'subject' => 'subject-example', 'expected_revision' => 'revision-example', 'operation_id' => $this->operationId];
    }

    private function refused(callable $action, string $outcome, int $status, string $case = ''): void
    {
        try {
            $action();
            $this->fail("Expected delegated refusal {$outcome}. {$case}");
        } catch (DelegatedAccessException $exception) {
            $this->assertSame($outcome, $exception->outcome, $case);
            $this->assertSame($status, $exception->status, $case);
        }
    }
}
