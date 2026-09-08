<?php

namespace Tests\Feature;

use App\Models\PassportClient;
use App\Models\RegisteredApplication;
use App\Models\User;
use App\Support\RelyingApplications;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Tests\TestCase;

class ApplicationRegistryTest extends TestCase
{
    use RefreshDatabase;

    public function test_only_active_provider_admins_can_read_or_change_the_registry(): void
    {
        $this->get('/admin/applications')->assertRedirect('/login');
        $this->postJson('/api/admin/applications', $this->payload())->assertUnauthorized();
        foreach ([['user_role' => 'user'], ['user_role' => 'admin', 'disabled_at' => now()]] as $attributes) {
            $this->actingAs(User::factory()->create($attributes))->get('/admin/applications')->assertForbidden();
            $this->postJson('/api/admin/applications', $this->payload())->assertForbidden();
        }
        $this->assertDatabaseCount('registered_applications', 0);
    }

    public function test_admin_registration_is_explicit_audited_and_does_not_modify_oauth_authorization(): void
    {
        $this->withoutVite();
        $admin = User::factory()->create(['user_role' => 'admin']);
        $client = $this->client();
        $original = $client->refresh()->getAttributes();
        $this->actingAs($admin)->postJson('/api/admin/applications', $this->payload([$client->id]))
            ->assertCreated()->assertJsonPath('application.key', 'example-app')
            ->assertJsonPath('application.client_ids.0', $client->id);
        $this->assertSame($original, $client->fresh()->getAttributes());
        $this->assertDatabaseCount('oauth_client_grants', 0);
        $this->assertDatabaseHas('auth_audit_log', [
            'event' => 'application_registered', 'acting_user_id' => $admin->id, 'succeeded' => true,
        ]);
        $this->get('/admin/applications')->assertOk()
            ->assertHeader('Cache-Control', 'no-store, private')
            ->assertSee('example-app')->assertSee('Example Application');
    }

    public function test_invalid_client_mappings_fail_atomically_including_dynamic_clients_with_grants(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $static = $this->client();
        $dynamic = $this->client(['dynamically_registered_at' => now()]);
        $this->grant($admin, $dynamic);
        $badClients = [
            $dynamic->id,
            $this->client(['revoked' => true])->id,
            $this->client(['grant_types' => ['client_credentials']])->id,
            (string) Str::uuid(),
        ];
        foreach ($badClients as $bad) {
            $this->actingAs($admin)->postJson('/api/admin/applications', $this->payload([$static->id, $bad]))
                ->assertUnprocessable()->assertJsonValidationErrors('client_ids');
        }
        $this->assertDatabaseCount('registered_applications', 0);
        $this->assertDatabaseCount('registered_application_clients', 0);
        $this->assertDatabaseMissing('auth_audit_log', ['event' => 'application_registered']);
    }

    public function test_registry_launches_require_enabled_entries_and_current_subject_grants(): void
    {
        config(['application-registry.launch_enabled' => true]);
        $admin = User::factory()->create(['user_role' => 'admin']);
        $reader = User::factory()->create();
        $client = $this->client();
        $this->actingAs($admin)->postJson('/api/admin/applications', $this->payload([$client->id]))->assertCreated();
        $registry = new RelyingApplications;
        $this->assertSame([], $registry->forSubject((string) $admin->id));
        $this->grant($reader, $client);
        $expected = [['key' => 'example-app', 'name' => 'Example Application', 'url' => 'https://launch.example.test/start']];
        $this->assertSame($expected, $registry->forSubject((string) $reader->id));
        $application = RegisteredApplication::firstOrFail();
        $application->update(['enabled' => false]);
        $this->assertSame([], $registry->forSubject((string) $reader->id));
        $application->update(['enabled' => true]);
        $client->update(['revoked' => true]);
        $this->assertSame([], $registry->forSubject((string) $reader->id));
        $client->update(['revoked' => false, 'dynamically_registered_at' => now()]);
        $this->assertSame([], $registry->forSubject((string) $reader->id));
        $client->update(['dynamically_registered_at' => null]);
        DB::table('oauth_client_grants')->where('subject', $reader->id)->delete();
        $this->assertSame([], $registry->forSubject((string) $reader->id));
    }

    public function test_legacy_navigation_remains_static_only_without_populating_the_registry(): void
    {
        config(['application-registry.launch_enabled' => false]);
        $user = User::factory()->create();
        $static = $this->client();
        $this->grant($user, $static);
        $this->grant($user, $this->client(['dynamically_registered_at' => now()]));
        $this->grant($user, $this->client(['revoked' => true]));
        $this->assertSame([
            ['key' => 'example-client', 'name' => 'Example Client', 'url' => 'https://static.example.test'],
        ], (new RelyingApplications)->forSubject((string) $user->id));
        $this->assertDatabaseCount('registered_applications', 0);
        config(['bherila-auth.oauth_server.dynamic_clients.registered_at_column' => 'missing_marker']);
        $this->assertSame([], (new RelyingApplications)->forSubject((string) $user->id));
    }

    public function test_keys_are_immutable_and_clients_cannot_be_reassigned_silently(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $client = $this->client();
        $this->actingAs($admin)->postJson('/api/admin/applications', $this->payload([$client->id]))->assertCreated();
        $application = RegisteredApplication::firstOrFail();
        $update = $this->payload([$client->id]);
        $this->putJson('/api/admin/applications/'.$application->id, $update)->assertUnprocessable();
        unset($update['key']);
        $update['name'] = 'Renamed Application';
        $this->putJson('/api/admin/applications/'.$application->id, $update)->assertOk()
            ->assertJsonPath('application.key', 'example-app')->assertJsonPath('application.name', 'Renamed Application');
        $second = $this->payload([$client->id]);
        $second['key'] = 'another-app';
        $this->postJson('/api/admin/applications', $second)->assertUnprocessable();
        $this->assertDatabaseCount('registered_applications', 1);
        $this->assertDatabaseHas('registered_application_clients', ['registered_application_id' => $application->id, 'oauth_client_id' => $client->id]);
    }

    public function test_registry_rejects_untrusted_urls_and_invalid_keys(): void
    {
        $this->actingAs(User::factory()->create(['user_role' => 'admin']));
        foreach (['http://app.example.test', 'https://user:secret@app.example.test', 'https://app.example.test?token=x', 'https://app.example.test#fragment', 'javascript:alert(1)'] as $url) {
            $payload = $this->payload();
            $payload['launch_url'] = $url;
            $this->postJson('/api/admin/applications', $payload)->assertUnprocessable()->assertJsonValidationErrors('launch_url');
        }
        $payload = $this->payload();
        $payload['key'] = 'Not Stable!';
        $this->postJson('/api/admin/applications', $payload)->assertUnprocessable()->assertJsonValidationErrors('key');
        $this->assertDatabaseCount('registered_applications', 0);
    }

    public function test_html_forms_can_register_an_unmapped_disabled_application(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $payload = $this->payload();
        unset($payload['client_ids']);
        $payload['enabled'] = '0';
        $this->actingAs($admin)->post('/api/admin/applications', $payload)->assertRedirect('/admin/applications');
        $this->assertDatabaseHas('registered_applications', ['key' => 'example-app', 'enabled' => false]);
        $this->assertDatabaseCount('registered_application_clients', 0);
    }

    public function test_registry_schema_relationships_and_launch_reads_use_the_passport_connection(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $client = $this->client();
        $this->grant($admin, $client);
        Schema::drop('registered_application_clients');
        Schema::drop('registered_applications');
        $schema = DB::selectOne("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'oauth_clients'")->sql;
        config(['database.connections.registry_passport' => [
            'driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '', 'foreign_key_constraints' => true,
        ], 'passport.connection' => 'registry_passport', 'application-registry.launch_enabled' => true]);
        try {
            DB::connection('registry_passport')->statement($schema);
            DB::connection('registry_passport')->table('oauth_clients')->insert($client->getAttributes());
            $migration = require database_path('migrations/2026_09_08_010000_create_registered_applications.php');
            $this->assertSame('registry_passport', $migration->getConnection());
            $migration->up();
            $migration->up();
            $this->actingAs($admin)->postJson('/api/admin/applications', $this->payload([$client->id]))->assertCreated();
            $this->postJson('/api/admin/applications', $this->payload([]))->assertUnprocessable()->assertJsonValidationErrors('key');
            $application = RegisteredApplication::with('clients')->firstOrFail();
            $this->assertSame([$client->id], $application->clients->modelKeys());
            $this->assertFalse(Schema::connection('sqlite')->hasTable('registered_applications'));
            $this->assertSame(1, DB::connection('sqlite')->table('auth_audit_log')->where('event', 'application_registered')->count());
            $this->assertCount(1, app(RelyingApplications::class)->forSubject((string) $admin->id));
            $this->putJson('/api/admin/applications/'.$application->id, [...$this->payload([]), 'key' => null])->assertOk();
            $this->assertSame([], $application->fresh()->clients->modelKeys());
        } finally {
            config(['passport.connection' => null]);
            DB::purge('registry_passport');
        }
    }

    private function payload(array $clients = []): array
    {
        return ['key' => 'example-app', 'name' => 'Example Application', 'launch_url' => 'https://launch.example.test/start', 'enabled' => true, 'client_ids' => $clients];
    }

    private function client(array $attributes = []): PassportClient
    {
        return PassportClient::create([
            'id' => (string) Str::uuid(), 'name' => 'Example Client', 'secret' => 'synthetic-secret',
            'redirect_uris' => ['https://static.example.test/oauth/callback'],
            'grant_types' => ['authorization_code'], 'revoked' => false,
            ...$attributes,
        ]);
    }

    private function grant(User $user, PassportClient $client): void
    {
        DB::table('oauth_client_grants')->insert(['subject' => $user->id, 'oauth_client_id' => $client->id, 'created_at' => now(), 'updated_at' => now()]);
    }
}
