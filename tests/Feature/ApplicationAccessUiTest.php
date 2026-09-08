<?php

namespace Tests\Feature;

use App\Http\Middleware\EnsureCredentialVersion;
use App\Http\Middleware\RequireRecentPasskeyAuthentication;
use App\Models\PassportClient;
use App\Models\RegisteredApplication;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Tests\TestCase;

class ApplicationAccessUiTest extends TestCase
{
    use RefreshDatabase;

    private string $keyPath;

    private User $actor;

    private int $remoteStatus = 200;

    private int $updateStatus = 200;

    private bool $provisioned = true;

    private bool $editable = true;

    protected function setUp(): void
    {
        parent::setUp();
        $this->withoutVite();
        $key = openssl_pkey_new(['private_key_bits' => 2048]);
        openssl_pkey_export($key, $private);
        $this->keyPath = tempnam(sys_get_temp_dir(), 'synthetic-access-ui-');
        file_put_contents($this->keyPath, $private);
        chmod($this->keyPath, 0600);
        config(['application-registry.launch_enabled' => true, 'delegated-access' => [
            'enabled' => true, 'writes_enabled' => true, 'issuer' => 'https://identity.example.test',
            'key_id' => 'example-v1', 'private_key_path' => $this->keyPath,
            'applications' => ['example-app' => ['endpoint' => 'https://app.example.test/access']],
        ]]);
        $this->actor = User::factory()->create(['user_role' => 'user', 'password' => Hash::make('current-password-example')]);
        $client = PassportClient::create(['id' => (string) Str::uuid(), 'name' => 'Example Client',
            'secret' => 'example-secret', 'grant_types' => ['authorization_code'],
            'redirect_uris' => ['https://app.example.test/callback'], 'revoked' => false]);
        $application = RegisteredApplication::create(['key' => 'example-app', 'name' => 'Example Application',
            'launch_url' => 'https://app.example.test', 'enabled' => true]);
        $application->clients()->attach($client->id);
        DB::table('oauth_client_grants')->insert(['oauth_client_id' => $client->id, 'subject' => $this->actor->id,
            'created_at' => now(), 'updated_at' => now()]);
        Http::preventStrayRequests();
        Http::fake(function ($request) {
            $operation = $request['operation'];
            if ($this->remoteStatus !== 200 || ($operation === 'update' && $this->updateStatus !== 200)) {
                return Http::response([], $this->remoteStatus !== 200 ? $this->remoteStatus : $this->updateStatus);
            }
            $data = match ($operation) {
                'capabilities' => ['controls' => ['application_admin' => true, 'workspace_permissions' => ['read', 'write']]],
                'subjects' => ['subjects' => [['subject' => 'subject-example', 'label' => '<script>Example</script>']], 'next_cursor' => 'next-subjects'],
                'workspaces' => ['workspaces' => [['id' => 'workspace-new', 'label' => 'Example Workspace']], 'next_cursor' => 'next-workspaces'],
                default => ['subject' => $request['subject'], 'provisioned' => $this->provisioned,
                    'revision' => $this->provisioned ? 'revision-example' : null,
                    'access' => $this->provisioned ? ['application_admin' => false,
                        'workspaces' => [['id' => 'workspace-current', 'permission' => 'read']]] : null,
                    'allowed_edits' => ['application_admin' => $this->provisioned && $this->editable,
                        'workspaces' => $this->provisioned && $this->editable]],
            };

            return Http::response(['contract_version' => 1, 'application' => 'example-app', 'operation' => $operation, ...$data]);
        });
        $this->actingAs($this->actor)->withSession([EnsureCredentialVersion::SESSION_KEY => 0]);
    }

    protected function tearDown(): void
    {
        @unlink($this->keyPath);
        parent::tearDown();
    }

    public function test_application_admin_ui_does_not_require_provider_admin_and_escapes_labels(): void
    {
        $this->get('/applications/manage')->assertOk()->assertSee('Example Application');
        $this->get('/applications/example-app/access')->assertOk()->assertHeader('Cache-Control', 'no-store, private')
            ->assertSee('&lt;script&gt;Example&lt;/script&gt;', false)->assertDontSee('<script>Example</script>', false);
        $this->post('/applications/example-app/access/browse', ['subject' => 'subject-example'])
            ->assertOk()->assertSee('Current access')->assertSee('workspace-current')->assertSee('Save access');
    }

    public function test_provider_admin_does_not_bypass_application_denial(): void
    {
        $this->actor->update(['user_role' => 'admin']);
        $this->remoteStatus = 403;
        $this->get('/applications/example-app/access')->assertForbidden()
            ->assertSee('has not authorized')->assertDontSee('Save access');
    }

    public function test_unprovisioned_and_readonly_states_offer_no_mutation_controls(): void
    {
        $this->provisioned = false;
        $this->post('/applications/example-app/access/browse', ['subject' => 'subject-example'])
            ->assertOk()->assertSee('not been provisioned')->assertDontSee('Save access');
        $this->provisioned = true;
        $this->editable = false;
        $this->post('/applications/example-app/access/browse', ['subject' => 'subject-example'])
            ->assertOk()->assertSee('read-only')->assertDontSee('Save access');
    }

    public function test_update_requires_confirmation_and_sends_revision_and_selected_memberships(): void
    {
        $this->post('/applications/example-app/access/update', $this->update())->assertForbidden()
            ->assertSee('Confirm your password');
        Http::assertNothingSent();
        $this->confirm();
        $this->post('/applications/example-app/access/update', $this->update())
            ->assertOk()->assertSee('application confirmed the access update');
        Http::assertSent(fn ($request) => $request['operation'] === 'update'
            && $request['expected_revision'] === 'revision-example'
            && $request['subject'] === 'subject-example'
            && $request['access'] === ['application_admin' => false,
                'workspaces' => [['id' => 'workspace-new', 'permission' => 'write']]]);
    }

    public function test_conflict_and_unknown_outcomes_do_not_show_success_or_retry_writes(): void
    {
        $this->confirm();
        $this->updateStatus = 409;
        $this->post('/applications/example-app/access/update', $this->update())
            ->assertConflict()->assertSee('Access changed')->assertDontSee('confirmed the access update');
        $this->updateStatus = 503;
        $this->post('/applications/example-app/access/update', $this->update())
            ->assertStatus(503)->assertSee('change may have completed')->assertDontSee('confirmed the access update');
        $this->assertCount(2, Http::recorded(fn ($request) => $request['operation'] === 'update'));
    }

    public function test_confirmation_requires_current_password_and_does_not_flash_it(): void
    {
        $this->from('/applications/example-app/access')
            ->post('/applications/example-app/access/confirm', ['password' => 'wrong-password'])
            ->assertRedirect()->assertSessionHasErrors('password')->assertSessionMissing('_old_input.password')
            ->assertSessionMissing(RequireRecentPasskeyAuthentication::SESSION_KEY);
        $this->confirm();
        $this->assertSame((string) $this->actor->id, session(RequireRecentPasskeyAuthentication::SESSION_KEY.'.user_id'));
    }

    public function test_confirmation_and_access_update_are_csrf_protected(): void
    {
        $this->app['env'] = 'production';
        $this->post('/applications/example-app/access/confirm', ['password' => 'current-password-example'])->assertStatus(419);
        $this->post('/applications/example-app/access/update', $this->update())->assertStatus(419);
        Http::assertNothingSent();
    }

    public function test_confirmation_rechecks_current_database_credentials(): void
    {
        User::whereKey($this->actor->id)->update(['password' => Hash::make('replacement-password-example')]);
        $this->post('/applications/example-app/access/confirm', ['password' => 'current-password-example'])
            ->assertSessionHasErrors('password')->assertSessionMissing(RequireRecentPasskeyAuthentication::SESSION_KEY);
    }

    public function test_browse_cursors_are_forwarded_and_disabled_registry_has_no_management_directory(): void
    {
        $this->post('/applications/example-app/access/browse', ['subject_cursor' => 'next-subjects', 'workspace_cursor' => 'next-workspaces'])
            ->assertOk();
        Http::assertSent(fn ($request) => $request['operation'] === 'subjects' && $request['cursor'] === 'next-subjects');
        Http::assertSent(fn ($request) => $request['operation'] === 'workspaces' && $request['cursor'] === 'next-workspaces');
        config(['application-registry.launch_enabled' => false]);
        $this->get('/applications/manage')->assertNotFound();
    }

    private function confirm(): void
    {
        $this->post('/applications/example-app/access/confirm', ['password' => 'current-password-example'])
            ->assertRedirect('/applications/example-app/access');
    }

    private function update(): array
    {
        return ['subject' => 'subject-example', 'expected_revision' => 'revision-example', 'application_admin' => '0',
            'workspaces' => [['id' => 'workspace-current', 'permission' => 'none']],
            'new_workspace' => 'workspace-new', 'new_permission' => 'write'];
    }
}
