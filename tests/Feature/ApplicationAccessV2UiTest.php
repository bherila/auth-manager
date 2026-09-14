<?php

namespace Tests\Feature;

use App\Http\Middleware\EnsureCredentialVersion;
use App\Models\PassportClient;
use App\Models\RegisteredApplication;
use App\Models\User;
use App\Services\DelegatedAccess\DelegatedAccessTransport;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Foundation\Testing\RefreshDatabaseState;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Tests\TestCase;

/**
 * The application-access page for an application on delegated access contract version 2 (#56).
 *
 * Version 2 applications advertise their own workspace roles, say per membership whether it can be
 * edited here, and may accept provisioning of a grant holder they have not seen. Version 1
 * applications keep `ApplicationAccessUiTest`, unchanged.
 */
class ApplicationAccessV2UiTest extends TestCase
{
    use DatabaseMigrations;

    public function runDatabaseMigrations(): void
    {
        // Real transport writes require independently committed audit records.
        $this->refreshTestDatabase();
        $this->beforeApplicationDestroyed(function (): void {
            RefreshDatabaseState::$migrated = false;
        });
    }

    private string $keyPath;

    private User $actor;

    private PassportClient $client;

    private bool $provisioned = true;

    private bool $provisionAllowed = true;

    private bool $provisioning = true;

    private array $memberships = [
        ['id' => 'workspace-a', 'role' => 'owner', 'editable' => false],
        ['id' => 'workspace-b', 'role' => 'sender', 'editable' => true],
    ];

    protected function setUp(): void
    {
        parent::setUp();
        $this->withoutVite();
        $key = openssl_pkey_new(['private_key_bits' => 2048]);
        openssl_pkey_export($key, $private);
        $this->keyPath = tempnam(sys_get_temp_dir(), 'synthetic-access-v2-');
        file_put_contents($this->keyPath, $private);
        chmod($this->keyPath, 0600);
        config(['application-registry.launch_enabled' => true, 'delegated-access' => [
            'enabled' => true, 'writes_enabled' => true, 'issuer' => 'https://identity.example.test',
            'key_id' => 'example-v1', 'private_key_path' => $this->keyPath,
            'applications' => ['example-app' => ['endpoint' => 'https://app.example.test/access', 'contract_version' => 2]],
        ]]);
        $this->actor = User::factory()->create(['name' => 'Example Actor', 'user_role' => 'user', 'password' => Hash::make('current-password-example')]);
        $this->client = PassportClient::create(['id' => (string) Str::uuid(), 'name' => 'Example Client',
            'secret' => 'example-secret', 'grant_types' => ['authorization_code'],
            'redirect_uris' => ['https://app.example.test/callback'], 'revoked' => false]);
        $application = RegisteredApplication::create(['key' => 'example-app', 'name' => 'Example Application',
            'launch_url' => 'https://app.example.test', 'enabled' => true]);
        $application->clients()->attach($this->client->id);
        $this->grant($this->actor);
        Http::preventStrayRequests();
        $this->fakeApplication();
        $this->actingAs($this->actor)->withSession([EnsureCredentialVersion::SESSION_KEY => 0]);
    }

    protected function tearDown(): void
    {
        @unlink($this->keyPath);
        parent::tearDown();
    }

    public function test_roles_come_from_the_application_and_a_non_editable_membership_is_read_only(): void
    {
        $this->browse(['subject' => 'subject-example'])->assertOk()
            ->assertSee('Workspace A')
            ->assertSee('Owner (not editable here)')
            ->assertSee('<input type="hidden" name="workspaces[0][role]" value="owner">', false)
            ->assertSee('name="workspaces[1][role]"', false)
            ->assertSee('<option value="auditor">Auditor</option>', false)
            ->assertDontSee('Read and write');

        Http::assertSent(fn ($request) => $request['contract_version'] === 2);
    }

    public function test_an_update_names_roles_and_echoes_the_non_editable_membership(): void
    {
        $this->confirm();
        $this->post('/applications/example-app/access/update', [
            'subject' => 'subject-example', 'expected_revision' => 'revision-example', 'application_admin' => '0',
            'workspaces' => [['id' => 'workspace-a', 'role' => 'owner'], ['id' => 'workspace-b', 'role' => 'auditor']],
        ])->assertRedirect()->assertSessionHas('access_updated', true);

        Http::assertSent(fn ($request) => $request['operation'] === 'update'
            && $request['contract_version'] === 2
            && $request['access'] === ['application_admin' => false, 'workspaces' => [
                ['id' => 'workspace-a', 'role' => 'owner'], ['id' => 'workspace-b', 'role' => 'auditor'],
            ]]);
    }

    public function test_an_empty_role_removes_a_membership_and_a_new_one_names_its_role(): void
    {
        $this->confirm();
        $this->post('/applications/example-app/access/update', [
            'subject' => 'subject-example', 'expected_revision' => 'revision-example', 'application_admin' => '0',
            'workspaces' => [['id' => 'workspace-a', 'role' => 'owner'], ['id' => 'workspace-b', 'role' => '']],
            'new_workspace' => 'workspace-c', 'new_role' => 'admin',
        ])->assertRedirect()->assertSessionHas('access_updated', true);

        Http::assertSent(fn ($request) => $request['operation'] === 'update'
            && $request['access']['workspaces'] === [['id' => 'workspace-a', 'role' => 'owner'], ['id' => 'workspace-c', 'role' => 'admin']]);
    }

    public function test_a_role_the_application_does_not_offer_is_refused_before_anything_is_sent(): void
    {
        $this->confirm();
        $this->post('/applications/example-app/access/update', [
            'subject' => 'subject-example', 'expected_revision' => 'revision-example', 'application_admin' => '0',
            'workspaces' => [['id' => 'workspace-b', 'role' => 'emperor']],
        ])->assertRedirect()->assertSessionHasErrors('workspaces');

        $this->assertCount(0, Http::recorded(fn ($request) => $request['operation'] === 'update'));
    }

    public function test_the_directory_lists_only_people_who_can_sign_in_to_the_application(): void
    {
        $holder = User::factory()->create(['name' => 'Example Holder', 'email' => 'holder@example.test', 'user_role' => 'user']);
        $this->grant($holder);
        $disabled = User::factory()->create(['name' => 'Example Disabled', 'user_role' => 'user', 'disabled_at' => now()]);
        $this->grant($disabled);
        User::factory()->create(['name' => 'Example Stranger', 'user_role' => 'user']);

        $this->get('/applications/example-app/access')->assertOk()
            ->assertSee('Give access to someone new')
            ->assertSee('Example Holder (holder@example.test)')
            ->assertDontSee('Example Stranger')
            ->assertDontSee('Example Disabled');

        $this->browse(['directory_search' => 'Holder'])->assertOk()
            ->assertSee('Example Holder')
            ->assertDontSee('Example Actor (');
    }

    public function test_the_directory_is_absent_when_the_application_does_not_offer_provisioning(): void
    {
        $this->provisioning = false;

        $this->get('/applications/example-app/access')->assertOk()->assertDontSee('Give access to someone new');
    }

    public function test_provisioning_sends_a_null_revision_with_the_role_and_display_name(): void
    {
        $holder = User::factory()->create(['name' => 'Example Holder', 'user_role' => 'user']);
        $this->grant($holder);
        $this->provisioned = false;

        $this->browse(['subject' => (string) $holder->id])->assertOk()->assertSee('Create account and give access');

        $this->confirm();
        $this->post('/applications/example-app/access/provision', [
            'subject' => (string) $holder->id, 'new_workspace' => 'workspace-a', 'new_role' => 'sender',
        ])->assertRedirect()->assertSessionHas('access_updated', true);

        Http::assertSent(fn ($request) => $request['operation'] === 'update'
            && $request['contract_version'] === 2
            && $request['subject'] === (string) $holder->id
            && array_key_exists('expected_revision', $request->data()) && $request['expected_revision'] === null
            && $request['display_name'] === 'Example Holder'
            && $request['access'] === ['application_admin' => false, 'workspaces' => [['id' => 'workspace-a', 'role' => 'sender']]]);
    }

    public function test_provisioning_refuses_someone_who_cannot_sign_in_to_the_application(): void
    {
        $stranger = User::factory()->create(['name' => 'Example Stranger', 'user_role' => 'user']);
        $this->provisioned = false;

        $this->confirm();
        $this->post('/applications/example-app/access/provision', [
            'subject' => (string) $stranger->id, 'new_workspace' => 'workspace-a', 'new_role' => 'sender',
        ])->assertRedirect()->assertSessionHasErrors('subject');

        $this->assertCount(0, Http::recorded(fn ($request) => $request['operation'] === 'update'));
    }

    public function test_provisioning_refuses_an_account_the_application_no_longer_offers_to_create(): void
    {
        $holder = User::factory()->create(['name' => 'Example Holder', 'user_role' => 'user']);
        $this->grant($holder);
        $this->provisioned = true;

        $this->confirm();
        $this->post('/applications/example-app/access/provision', [
            'subject' => (string) $holder->id, 'new_workspace' => 'workspace-a', 'new_role' => 'sender',
        ])->assertRedirect()->assertSessionHas('access_failure');

        $this->assertCount(0, Http::recorded(fn ($request) => $request['operation'] === 'update'));
    }

    public function test_a_version_one_answer_from_a_version_two_application_is_refused(): void
    {
        Http::swap(new Factory);
        Http::fake(['*' => Http::response(['contract_version' => 1, 'application' => 'example-app', 'operation' => 'capabilities',
            'controls' => ['application_admin' => false, 'workspace_permissions' => ['read', 'write']]], 200)]);

        $request = Request::create('/synthetic-delegated-ui', 'POST');
        $request->setUserResolver(fn (): User => $this->actor);
        $request->setLaravelSession(app('session.store'));
        $request->session()->put(EnsureCredentialVersion::SESSION_KEY, 0);

        try {
            app(DelegatedAccessTransport::class)->send($request, 'example-app', ['operation' => 'capabilities']);
            $this->fail('A version 1 answer was accepted from an application configured for version 2.');
        } catch (DelegatedAccessException $exception) {
            $this->assertSame('invalid_response', $exception->outcome);
        }
    }

    private function fakeApplication(): void
    {
        Http::fake(function ($request) {
            $operation = $request['operation'];
            $data = match ($operation) {
                'capabilities' => ['controls' => ['application_admin' => false, 'workspace_roles' => [
                    ['id' => 'owner', 'label' => 'Owner'], ['id' => 'admin', 'label' => 'Administrator'],
                    ['id' => 'sender', 'label' => 'Sender'], ['id' => 'auditor', 'label' => 'Auditor'],
                ], 'provisioning' => $this->provisioning]],
                'subjects' => ['subjects' => [['subject' => 'subject-example', 'label' => 'Example Account']], 'next_cursor' => null],
                'workspaces' => ['workspaces' => [
                    ['id' => 'workspace-a', 'label' => 'Workspace A'], ['id' => 'workspace-b', 'label' => 'Workspace B'],
                    ['id' => 'workspace-c', 'label' => 'Workspace C'],
                ], 'next_cursor' => null],
                'update' => ['subject' => $request['subject'], 'provisioned' => true, 'revision' => 'revision-after',
                    'access' => ['application_admin' => false, 'workspaces' => array_map(
                        fn (array $membership): array => [...$membership, 'editable' => true], $request['access']['workspaces'])],
                    'allowed_edits' => ['application_admin' => false, 'workspaces' => true, 'provision' => false]],
                default => ['subject' => $request['subject'], 'provisioned' => $this->provisioned,
                    'revision' => $this->provisioned ? 'revision-example' : null,
                    'access' => $this->provisioned ? ['application_admin' => false, 'workspaces' => $this->memberships] : null,
                    'allowed_edits' => ['application_admin' => false, 'workspaces' => $this->provisioned,
                        'provision' => ! $this->provisioned && $this->provisionAllowed]],
            };

            return Http::response(['contract_version' => 2, 'application' => 'example-app', 'operation' => $operation, ...$data]);
        });
    }

    private function grant(User $user): void
    {
        DB::table('oauth_client_grants')->insert(['oauth_client_id' => $this->client->id, 'subject' => $user->id,
            'created_at' => now(), 'updated_at' => now()]);
    }

    private function confirm(): void
    {
        $this->post('/applications/example-app/access/confirm', ['password' => 'current-password-example'])
            ->assertRedirect('/applications/example-app/access');
    }

    private function browse(array $input): TestResponse
    {
        $response = $this->post('/applications/example-app/access/browse', $input)->assertRedirect();

        return $this->get($response->headers->get('Location'));
    }
}
