<?php

namespace Tests\Feature;

use App\Http\Middleware\EnsureCredentialVersion;
use App\Http\Middleware\RequireRecentPasskeyAuthentication;
use App\Models\PassportClient;
use App\Models\RegisteredApplication;
use App\Models\User;
use App\Services\DelegatedAccess\ActorAssertionVerifier;
use App\Services\DelegatedAccess\CacheNonceStore;
use App\Services\DelegatedAccess\DelegatedAccessException;
use App\Services\DelegatedAccess\DelegatedAccessTransport;
use App\Services\DelegatedAccess\TransportClock;
use BWH\Auth\Models\AuthAuditLog;
use GuzzleHttp\Psr7\FnStream;
use GuzzleHttp\Psr7\Utils;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Tests\Fixtures\ReferenceAccessAdapter;
use Tests\TestCase;

class DelegatedAccessTransportTest extends TestCase
{
    use RefreshDatabase;

    private string $keyPath;

    private string $publicKey;

    private User $actor;

    private PassportClient $client;

    private Request $request;

    protected function setUp(): void
    {
        parent::setUp();
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $private);
        $this->publicKey = openssl_pkey_get_details($key)['key'];
        $this->keyPath = tempnam(sys_get_temp_dir(), 'synthetic-integration-');
        file_put_contents($this->keyPath, $private);
        chmod($this->keyPath, 0600);
        config(['delegated-access' => [
            'enabled' => true, 'writes_enabled' => true,
            'issuer' => 'https://identity.example.test', 'key_id' => 'integration-v1', 'private_key_path' => $this->keyPath,
            'applications' => ['example-app' => ['endpoint' => 'https://app.example.test/access']],
        ]]);
        $this->actor = User::factory()->create(['user_role' => 'user']);
        $this->client = PassportClient::create(['id' => (string) Str::uuid(), 'name' => 'Example Client', 'secret' => 'synthetic-secret', 'grant_types' => ['authorization_code'], 'redirect_uris' => ['https://app.example.test/callback'], 'revoked' => false]);
        $application = RegisteredApplication::create(['key' => 'example-app', 'name' => 'Example Application', 'launch_url' => 'https://app.example.test', 'enabled' => true]);
        $application->clients()->attach($this->client->id);
        DB::table('oauth_client_grants')->insert(['oauth_client_id' => $this->client->id, 'subject' => $this->actor->id, 'created_at' => now(), 'updated_at' => now()]);
        $this->request = Request::create('/synthetic-delegated-ui', 'POST');
        $this->request->setUserResolver(fn (): User => $this->actor);
        $this->request->setLaravelSession(app('session.store'));
        $this->request->session()->put(EnsureCredentialVersion::SESSION_KEY, 0);
        RequireRecentPasskeyAuthentication::recordCredentialVerification($this->request);
        Schema::create('reference_access_accounts', function ($table): void {
            $table->string('subject')->primary();
            $table->boolean('active');
            $table->boolean('application_admin');
            $table->text('managed_workspaces');
            $table->text('workspaces');
            $table->string('revision');
        });
        Schema::create('reference_access_audit', function ($table): void {
            $table->string('correlation');
            $table->id();
            $table->string('actor');
            $table->string('target');
            $table->string('application');
            $table->string('revision');
        });
        $this->account((string) $this->actor->id, false, ['workspace-a']);
        $this->account('target-a', false, [], [['id' => 'workspace-a', 'permission' => 'read']]);
        $this->account('target-b', false, [], [['id' => 'workspace-b', 'permission' => 'read']]);
        $this->fakeAdapter();
    }

    protected function tearDown(): void
    {
        @unlink($this->keyPath);
        parent::tearDown();
    }

    public function test_app_scoped_actor_can_discover_read_update_and_audit_without_provider_admin(): void
    {
        $transport = app(DelegatedAccessTransport::class);
        $workspaces = $transport->send($this->request, 'example-app', ['operation' => 'workspaces']);
        $this->assertSame([['id' => 'workspace-a', 'label' => 'workspace-a']], $workspaces['workspaces']);
        $subjects = $transport->send($this->request, 'example-app', ['operation' => 'subjects', 'limit' => 1]);
        $this->assertCount(1, $subjects['subjects']);
        $this->assertNotNull($subjects['next_cursor']);
        $read = $transport->send($this->request, 'example-app', ['operation' => 'read', 'subject' => 'target-a']);
        $this->assertFalse($read['allowed_edits']['application_admin']);
        $update = $this->update($read['revision']);
        $saved = $transport->send($this->request, 'example-app', $update);
        $this->assertNotSame($read['revision'], $saved['revision']);
        $this->assertSame('write', $saved['access']['workspaces'][0]['permission']);
        $this->assertDatabaseHas('reference_access_audit', ['actor' => (string) $this->actor->id, 'target' => 'target-a', 'revision' => $saved['revision']]);
        $this->refused(fn () => $transport->send($this->request, 'example-app', $update), 'revision_conflict', 409);
        $this->assertDatabaseCount('reference_access_audit', 1);
        $providerRecords = AuthAuditLog::where('event', 'like', 'delegated_access_update_%')->orderBy('id')->get();
        $this->assertSame(['attempt', 'succeeded', 'attempt', 'revision_conflict'], $providerRecords->map(fn ($row) => $row->metadata['outcome'])->all());
        $this->assertSame(DB::table('reference_access_audit')->value('correlation'), $providerRecords[0]->metadata['correlation']);
        $this->assertSame($providerRecords[0]->metadata['correlation'], $providerRecords[1]->metadata['correlation']);
        $this->assertNotSame($providerRecords[0]->metadata['correlation'], $providerRecords[2]->metadata['correlation']);
        $this->assertSame(['application', 'target', 'operation', 'outcome', 'correlation'], array_keys($providerRecords[0]->metadata));
        $this->assertSame($this->actor->id, $providerRecords[0]->acting_user_id);
        $unprovisioned = $transport->send($this->request, 'example-app', ['operation' => 'read', 'subject' => 'unknown-subject']);
        $this->assertFalse($unprovisioned['provisioned']);
        $this->assertNull($unprovisioned['revision']);
    }

    public function test_consumer_rejects_cross_workspace_and_provider_only_authority_and_bound_cursors(): void
    {
        $transport = app(DelegatedAccessTransport::class);
        $this->refused(fn () => $transport->send($this->request, 'example-app', ['operation' => 'read', 'subject' => 'target-b']), 'not_authorized', 404);
        $bad = $this->update('revision-initial');
        $bad['access']['workspaces'][0]['id'] = 'workspace-b';
        $this->refused(fn () => $transport->send($this->request, 'example-app', $bad), 'not_authorized', 403);
        $this->assertDatabaseCount('reference_access_audit', 0);
        $page = $transport->send($this->request, 'example-app', ['operation' => 'subjects', 'limit' => 1]);
        $this->refused(fn () => $transport->send($this->request, 'example-app', ['operation' => 'workspaces', 'cursor' => $page['next_cursor']]), 'invalid_request', 422);
        $this->actor->update(['user_role' => 'admin']);
        DB::table('reference_access_accounts')->where('subject', $this->actor->id)->update(['managed_workspaces' => '[]']);
        $this->refused(fn () => $transport->send($this->request, 'example-app', ['operation' => 'capabilities']), 'not_authorized', 403);
    }

    public function test_consumer_rechecks_actor_activity_and_preserves_last_administrator(): void
    {
        $transport = app(DelegatedAccessTransport::class);
        DB::table('reference_access_accounts')->where('subject', $this->actor->id)->update(['active' => false]);
        $this->refused(fn () => $transport->send($this->request, 'example-app', ['operation' => 'read', 'subject' => 'target-a']), 'not_authorized', 403);
        DB::table('reference_access_accounts')->where('subject', $this->actor->id)->update(['active' => true, 'application_admin' => true]);
        $demote = $this->update('revision-initial');
        $demote['subject'] = (string) $this->actor->id;
        $this->refused(fn () => $transport->send($this->request, 'example-app', $demote), 'invalid_request', 422);
        $this->assertDatabaseCount('reference_access_audit', 0);
    }

    public function test_provider_requires_fresh_session_current_grant_and_recent_actor_bound_confirmation(): void
    {
        Http::swap(new Factory);
        Http::fake();
        $transport = app(DelegatedAccessTransport::class);
        $this->request->session()->put(RequireRecentPasskeyAuthentication::SESSION_KEY, ['user_id' => 'someone-else', 'authenticated_at' => time()]);
        $this->refused(fn () => $transport->send($this->request, 'example-app', $this->update('revision-initial')), 'recent_confirmation_required', 403);
        $this->request->session()->put(RequireRecentPasskeyAuthentication::SESSION_KEY, ['user_id' => (string) $this->actor->id, 'authenticated_at' => time() - 301]);
        $this->refused(fn () => $transport->send($this->request, 'example-app', $this->update('revision-initial')), 'recent_confirmation_required', 403);
        $this->actor->forceFill(['credential_version' => 1])->save();
        $this->refused(fn () => $transport->send($this->request, 'example-app', ['operation' => 'read', 'subject' => 'target-a']), 'not_authenticated', 401);
        $this->request->session()->put(EnsureCredentialVersion::SESSION_KEY, 1);
        $this->client->update(['revoked' => true]);
        $this->refused(fn () => $transport->send($this->request, 'example-app', ['operation' => 'capabilities']), 'not_authorized', 403);
        Http::assertNothingSent();
    }

    public function test_timeouts_and_malformed_success_never_retry_or_claim_a_write_succeeded(): void
    {
        $transport = app(DelegatedAccessTransport::class);
        Http::swap(new Factory);
        Http::fake(fn () => throw new ConnectionException('synthetic timeout'));
        $this->refused(fn () => $transport->send($this->request, 'example-app', $this->update('revision-initial')), 'unknown_outcome', 503);
        Http::swap(new Factory);
        Http::fake(['*' => Http::response(['success' => true], 200)]);
        $this->refused(fn () => $transport->send($this->request, 'example-app', $this->update('revision-initial')), 'unknown_outcome', 503);
        Http::assertSentCount(1);
        Http::swap(new Factory);
        Http::fake(['*' => Http::response('', 302, ['Location' => 'https://untrusted.example.test'])]);
        $this->refused(fn () => $transport->send($this->request, 'example-app', ['operation' => 'capabilities']), 'unavailable', 503);
        Http::assertSentCount(1);
        Http::swap(new Factory);
        Http::fake(['*' => Http::response(str_repeat('x', 262145), 200)]);
        $this->refused(fn () => $transport->send($this->request, 'example-app', ['operation' => 'capabilities']), 'invalid_response', 503);
    }

    public function test_capability_subsets_are_supported_and_state_must_echo_the_requested_subject(): void
    {
        $transport = app(DelegatedAccessTransport::class);
        foreach ([[], ['read'], ['write'], ['read', 'write']] as $permissions) {
            Http::swap(new Factory);
            Http::fake(['*' => Http::response(['contract_version' => 1, 'application' => 'example-app', 'operation' => 'capabilities',
                'controls' => ['application_admin' => false, 'workspace_permissions' => $permissions]], 200)]);
            $this->assertSame($permissions, $transport->send($this->request, 'example-app', ['operation' => 'capabilities'])['controls']['workspace_permissions']);
        }
        foreach (['read', 'update'] as $operation) {
            Http::swap(new Factory);
            Http::fake(['*' => Http::response(['contract_version' => 1, 'application' => 'example-app', 'operation' => $operation,
                'subject' => 'wrong-subject', 'provisioned' => false, 'revision' => null, 'access' => null,
                'allowed_edits' => ['application_admin' => false, 'workspaces' => false]], 200)]);
            $input = $operation === 'update' ? $this->update('revision-initial') : ['operation' => 'read', 'subject' => 'target-a'];
            $this->refused(fn () => $transport->send($this->request, 'example-app', $input), $operation === 'update' ? 'unknown_outcome' : 'invalid_response', 503);
        }
    }

    public function test_disabled_and_invalid_requests_fail_before_transport(): void
    {
        Http::swap(new Factory);
        Http::fake();
        $transport = app(DelegatedAccessTransport::class);
        foreach ([['operation' => 'capabilities', 'actor' => 'another-subject'], ['operation' => 'subjects', 'limit' => 51],
            ['operation' => 'read', 'subject' => str_repeat('x', 192)]] as $input) {
            $this->refused(fn () => $transport->send($this->request, 'example-app', $input), 'invalid_request', 422);
        }
        config(['delegated-access.enabled' => false]);
        $this->refused(fn () => $transport->send($this->request, 'example-app', ['operation' => 'capabilities']), 'integration_disabled', 503);
        Http::assertNothingSent();
    }

    public function test_slow_response_cannot_extend_absolute_deadline_and_is_closed(): void
    {
        foreach (['read', 'update'] as $operation) {
            $clock = new class extends TransportClock
            {
                public float $elapsed = 0;

                public function now(): float
                {
                    return $this->elapsed;
                }
            };
            $this->app->instance(TransportClock::class, $clock);
            $closed = false;
            $body = Utils::streamFor(json_encode(['contract_version' => 1, 'application' => 'example-app', 'operation' => $operation,
                'subject' => 'target-a', 'provisioned' => false, 'revision' => null, 'access' => null,
                'allowed_edits' => ['application_admin' => false, 'workspaces' => false]], JSON_THROW_ON_ERROR));
            $stream = FnStream::decorate($body, [
                'read' => function (int $length) use ($body, $clock): string {
                    $clock->elapsed = 11;

                    return $body->read($length);
                },
                'close' => function () use (&$closed, $body): void {
                    $closed = true;
                    $body->close();
                },
            ]);
            Http::swap(new Factory);
            Http::fake(fn () => Http::response($stream));
            $input = $operation === 'update' ? $this->update('revision-initial') : ['operation' => 'read', 'subject' => 'target-a'];
            $this->refused(fn () => app(DelegatedAccessTransport::class)->send($this->request, 'example-app', $input),
                $operation === 'update' ? 'unknown_outcome' : 'invalid_response', 503);
            $this->assertTrue($closed);
        }
    }

    public function test_provider_issuer_trailing_slash_uses_canonical_signed_value(): void
    {
        config(['delegated-access.issuer' => 'https://identity.example.test/']);
        $this->fakeAdapter();
        $result = app(DelegatedAccessTransport::class)->send($this->request, 'example-app', ['operation' => 'capabilities']);
        $this->assertSame('capabilities', $result['operation']);
    }

    public function test_provider_audit_failure_blocks_transmission_or_preserves_unknown_outcome(): void
    {
        $this->fakeAdapter();
        $phase = 'attempt';
        Event::listen('eloquent.creating: '.AuthAuditLog::class, function (AuthAuditLog $record) use (&$phase): void {
            if ($record->event === 'delegated_access_update_'.$phase) {
                throw new \RuntimeException('synthetic audit failure');
            }
        });
        $transport = app(DelegatedAccessTransport::class);
        $this->refused(fn () => $transport->send($this->request, 'example-app', $this->update('revision-initial')), 'audit_unavailable', 503);
        Http::assertNothingSent();
        $this->assertDatabaseCount('reference_access_audit', 0);
        $phase = 'result';
        $this->refused(fn () => $transport->send($this->request, 'example-app', $this->update('revision-initial')), 'unknown_outcome', 503);
        $this->assertDatabaseCount('reference_access_audit', 1);
        $this->assertDatabaseHas('auth_audit_log', ['event' => 'delegated_access_update_attempt', 'acting_user_id' => $this->actor->id]);
        $this->assertDatabaseMissing('auth_audit_log', ['event' => 'delegated_access_update_result']);
    }

    private function fakeAdapter(): void
    {
        $adapter = new ReferenceAccessAdapter(new ActorAssertionVerifier('https://identity.example.test', 'https://app.example.test/access', 'example-app', ['integration-v1' => $this->publicKey], new CacheNonceStore(Cache::store('database'))));
        Http::swap(new Factory);
        Http::fake(function (ClientRequest $request) use ($adapter) {
            $token = substr($request->header('Authorization')[0], 7);
            $result = $adapter->handle($token, $request->method(), $request->body());

            return Http::response($result['body'], $result['status']);
        });
    }

    private function account(string $subject, bool $admin, array $managed = [], array $workspaces = []): void
    {
        DB::table('reference_access_accounts')->insert(['subject' => $subject, 'active' => true, 'application_admin' => $admin, 'managed_workspaces' => json_encode($managed), 'workspaces' => json_encode($workspaces), 'revision' => 'revision-initial']);
    }

    private function update(string $revision): array
    {
        return ['operation' => 'update', 'subject' => 'target-a', 'expected_revision' => $revision, 'access' => ['application_admin' => false, 'workspaces' => [['id' => 'workspace-a', 'permission' => 'write']]]];
    }

    private function refused(callable $action, string $outcome, int $status): void
    {
        try {
            $action();
            $this->fail('Expected delegated refusal.');
        } catch (DelegatedAccessException $exception) {
            $this->assertSame($outcome, $exception->outcome);
            $this->assertSame($status, $exception->status);
        }
    }
}
