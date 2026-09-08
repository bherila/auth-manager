<?php

namespace Tests\Feature;

use App\Http\Middleware\EnsureCredentialVersion;
use App\Http\Middleware\RequireRecentPasskeyAuthentication;
use App\Models\PassportClient;
use App\Models\RegisteredApplication;
use App\Models\User;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Foundation\Testing\RefreshDatabaseState;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Tests\TestCase;

class ApplicationAccessUiTest extends TestCase
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

    private int $remoteStatus = 200;

    private int $updateStatus = 200;

    private bool $provisioned = true;

    private bool $editable = true;

    private array $memberships = [['id' => 'workspace-current', 'permission' => 'read']];

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
                        'workspaces' => $this->memberships] : null,
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
        $this->browse(['subject' => 'subject-example'])
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
        $this->browse(['subject' => 'subject-example'])
            ->assertOk()->assertSee('not been provisioned')->assertDontSee('Save access');
        $this->provisioned = true;
        $this->editable = false;
        $this->browse(['subject' => 'subject-example'])
            ->assertOk()->assertSee('read-only')->assertDontSee('Save access');
    }

    public function test_update_requires_confirmation_and_sends_revision_and_selected_memberships(): void
    {
        $unconfirmed = $this->post('/applications/example-app/access/update', $this->update())->assertRedirect();
        $this->assertSame('/applications/example-app/access?subject=subject-example', parse_url($unconfirmed->headers->get('Location'), PHP_URL_PATH).'?'.parse_url($unconfirmed->headers->get('Location'), PHP_URL_QUERY));
        $this->get($unconfirmed->headers->get('Location'))->assertOk()->assertSee('Confirm your password')->assertDontSee('confirmed the access update');
        $this->assertCount(0, Http::recorded(fn ($request) => $request['operation'] === 'update'));
        $this->confirm();
        $saved = $this->post('/applications/example-app/access/update', $this->update())->assertRedirect();
        $this->get($saved->headers->get('Location'))->assertOk()->assertSee('application confirmed the access update');
        Http::assertSent(fn ($request) => $request['operation'] === 'update'
            && $request['expected_revision'] === 'revision-example'
            && $request['subject'] === 'subject-example'
            && $request['access'] === ['application_admin' => false,
                'workspaces' => [['id' => 'workspace-new', 'permission' => 'write']]]);
    }

    public function test_conflict_and_unknown_outcomes_land_on_a_get_page_without_success_or_retried_writes(): void
    {
        $this->confirm();
        $this->updateStatus = 409;
        $conflict = $this->post('/applications/example-app/access/update', $this->update())->assertRedirect();
        $this->assertStringEndsWith('/applications/example-app/access?subject=subject-example', $conflict->headers->get('Location'));
        $this->get($conflict->headers->get('Location'))->assertOk()->assertSee('Access changed')
            ->assertSee('Current access')->assertDontSee('confirmed the access update');
        $this->updateStatus = 503;
        $unknown = $this->post('/applications/example-app/access/update', $this->update())->assertRedirect();
        $page = $this->get($unknown->headers->get('Location'))->assertOk()->assertSee('change may have completed')
            ->assertDontSee('confirmed the access update')->assertHeader('Cache-Control', 'no-store, private');
        // The failure notice is a one-time flash, so a refresh of the GET page shows neither the
        // stale notice nor a success, and never resubmits the write.
        $this->get($unknown->headers->get('Location'))->assertOk()->assertDontSee('change may have completed');
        $this->assertCount(2, Http::recorded(fn ($request) => $request['operation'] === 'update'));
        // Read failures on the GET page itself still render the error page directly: refreshing a GET is harmless.
        $this->remoteStatus = 503;
        $this->get('/applications/example-app/access')->assertStatus(503)->assertSee('unavailable');
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
        $this->browse(['subject_cursor' => 'next-subjects', 'workspace_cursor' => 'next-workspaces'])
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

    public function test_browse_then_password_typo_returns_to_a_get_page_with_errors(): void
    {
        $this->withCookie(config('session.cookie'), session()->getId());
        $selection = $this->post('/applications/example-app/access/browse', ['subject' => 'subject-example'])->assertRedirect();
        $url = $selection->headers->get('Location');
        $this->get($url)->assertOk()->assertSee('Current access');
        $failure = $this->from($url)->post('/applications/example-app/access/confirm', ['password' => 'wrong-password'])
            ->assertRedirect($url)->assertSessionHasErrors('password');
        $this->get($failure->headers->get('Location'))->assertOk()->assertSee('The password could not be confirmed.');
    }

    public function test_membership_limit_hides_add_and_rejects_combined_overflow_before_transport(): void
    {
        $this->memberships = array_map(fn (int $index): array => ['id' => 'workspace-'.$index, 'permission' => 'read'], range(1, 100));
        $this->browse(['subject' => 'subject-example'])->assertOk()
            ->assertDontSee('name="new_workspace"', false)->assertSee('Remove and save a workspace membership');
        $this->confirm();
        $this->post('/applications/example-app/access/update', [...$this->update(), 'workspaces' => $this->memberships])
            ->assertRedirect()->assertSessionHasErrors('new_workspace');
        $this->assertCount(0, Http::recorded(fn ($request) => $request['operation'] === 'update'));
        $replacement = $this->memberships;
        $replacement[0]['permission'] = 'none';
        $this->post('/applications/example-app/access/update', [...$this->update(), 'workspaces' => $replacement])
            ->assertRedirect()->assertSessionHas('access_updated', true);
        Http::assertSent(fn ($request) => $request['operation'] === 'update' && count($request['access']['workspaces']) === 100);
    }

    private function browse(array $input): TestResponse
    {
        $response = $this->post('/applications/example-app/access/browse', $input)->assertRedirect();

        return $this->get($response->headers->get('Location'));
    }

    private function update(): array
    {
        return ['subject' => 'subject-example', 'expected_revision' => 'revision-example', 'application_admin' => '0',
            'workspaces' => [['id' => 'workspace-current', 'permission' => 'none']],
            'new_workspace' => 'workspace-new', 'new_permission' => 'write'];
    }
}
