<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Tests\TestCase;

class ImportLegacyIdentitiesTest extends TestCase
{
    use RefreshDatabase;

    private function configureLegacySource(): void
    {
        config([
            'database.connections.legacy_identity' => [
                'driver' => 'sqlite',
                'database' => __DIR__.'/../../storage/framework/testing/legacy.sqlite',
                'prefix' => '',
            ],
        ]);

        $path = config('database.connections.legacy_identity.database');
        @mkdir(dirname($path), 0777, true);
        file_put_contents($path, '');
        DB::purge('legacy_identity');

        Schema::connection('legacy_identity')->create('users', function ($table): void {
            $table->id();
            $table->string('name');
            $table->string('email');
            $table->timestamp('email_verified_at')->nullable();
            $table->string('password');
            $table->string('user_role')->default('user');
            $table->string('remember_token')->nullable();
            $table->dateTime('last_login_date')->nullable();
            $table->timestamps();
        });

        Schema::connection('legacy_identity')->create('webauthn_credentials', function ($table): void {
            $table->id();
            $table->unsignedBigInteger('user_id');
            $table->string('credential_id', 1024);
            $table->string('credential_id_hash')->nullable();
            $table->text('public_key');
            $table->unsignedBigInteger('counter')->default(0);
            $table->string('aaguid')->nullable();
            $table->string('name')->default('Passkey');
            $table->text('transports')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();
        });
    }

    private function seedLegacyUser(
        int $id,
        string $email = 'person@example.com',
        string $role = 'user',
    ): void {
        DB::connection('legacy_identity')->table('users')->insert([
            'id' => $id,
            'name' => 'Person',
            'email' => $email,
            'password' => 'hashed-secret',
            'user_role' => $role,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    public function test_it_refuses_to_run_without_a_configured_source(): void
    {
        config(['database.connections.legacy_identity.database' => null]);

        $this->artisan('identity:import-legacy')->assertFailed();
    }

    public function test_it_refuses_a_source_that_is_its_own_database(): void
    {
        $default = config('database.default');
        config([
            'database.connections.legacy_identity.database' => config("database.connections.{$default}.database"),
        ]);

        $this->artisan('identity:import-legacy')->assertFailed();
    }

    public function test_a_dry_run_writes_nothing(): void
    {
        $this->configureLegacySource();
        $this->seedLegacyUser(42);

        $this->artisan('identity:import-legacy')->assertSuccessful();

        $this->assertDatabaseCount('users', 0);
    }

    public function test_it_preserves_the_identifier_because_it_is_the_oauth_subject(): void
    {
        $this->configureLegacySource();
        $this->seedLegacyUser(42);

        $this->artisan('identity:import-legacy --apply')->assertSuccessful();

        $this->assertDatabaseHas('users', ['id' => 42, 'email' => 'person@example.com']);
    }

    public function test_running_it_twice_changes_nothing_the_second_time(): void
    {
        $this->configureLegacySource();
        $this->seedLegacyUser(42);

        $this->artisan('identity:import-legacy --apply')->assertSuccessful();
        $this->artisan('identity:import-legacy --apply')
            ->expectsOutputToContain('users     created 0, updated 0, unchanged 1, skipped 0')
            ->assertSuccessful();

        $this->assertDatabaseCount('users', 1);
    }

    public function test_an_active_user_imported_after_the_grant_migration_receives_current_client_grants(): void
    {
        $this->configureLegacySource();
        $this->seedLegacyUser(42);
        $currentClientId = $this->client();
        $revokedClientId = $this->client(revoked: true);

        $this->artisan('identity:import-legacy --apply')->assertSuccessful();

        $this->assertDatabaseHas('oauth_client_grants', [
            'subject' => 42,
            'oauth_client_id' => $currentClientId,
        ]);
        $this->assertDatabaseMissing('oauth_client_grants', [
            'subject' => 42,
            'oauth_client_id' => $revokedClientId,
        ]);
    }

    public function test_reimporting_an_existing_user_does_not_restore_a_removed_grant(): void
    {
        $this->configureLegacySource();
        $this->seedLegacyUser(42);
        $clientId = $this->client();
        $this->artisan('identity:import-legacy --apply')->assertSuccessful();
        DB::table('oauth_client_grants')
            ->where('subject', 42)
            ->where('oauth_client_id', $clientId)
            ->delete();

        $this->artisan('identity:import-legacy --apply')->assertSuccessful();

        $this->assertDatabaseMissing('oauth_client_grants', [
            'subject' => 42,
            'oauth_client_id' => $clientId,
        ]);
    }

    public function test_importing_an_inactive_user_does_not_create_client_grants(): void
    {
        $this->configureLegacySource();
        $this->seedLegacyUser(42, role: 'pending');
        $clientId = $this->client();

        $this->artisan('identity:import-legacy --apply')->assertSuccessful();

        $this->assertDatabaseMissing('oauth_client_grants', [
            'subject' => 42,
            'oauth_client_id' => $clientId,
        ]);
    }

    public function test_it_skips_a_row_whose_address_belongs_to_a_different_identifier(): void
    {
        $this->configureLegacySource();
        $this->seedLegacyUser(42, 'taken@example.com');

        DB::table('users')->insert([
            'id' => 99,
            'name' => 'Someone else',
            'email' => 'taken@example.com',
            'password' => 'hashed-secret',
            'user_role' => 'user',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->artisan('identity:import-legacy --apply')->assertSuccessful();

        $this->assertDatabaseMissing('users', ['id' => 42]);
        $this->assertDatabaseHas('users', ['id' => 99, 'email' => 'taken@example.com']);
    }

    public function test_it_never_lowers_a_passkey_signature_counter(): void
    {
        $this->configureLegacySource();
        $this->seedLegacyUser(42);

        DB::connection('legacy_identity')->table('webauthn_credentials')->insert([
            'user_id' => 42,
            'credential_id' => 'credential-abc',
            'public_key' => 'key-material',
            'counter' => 5,
            'name' => 'Passkey',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->artisan('identity:import-legacy --apply')->assertSuccessful();

        // Simulate the credential being used here after the import.
        DB::table('webauthn_credentials')->where('credential_id', 'credential-abc')->update(['counter' => 11]);

        $this->artisan('identity:import-legacy --apply')->assertSuccessful();

        $this->assertDatabaseHas('webauthn_credentials', ['credential_id' => 'credential-abc', 'counter' => 11]);
    }

    public function test_it_never_resurrects_a_tombstoned_subject_or_its_passkeys(): void
    {
        $this->configureLegacySource();
        $this->seedLegacyUser(42);
        DB::connection('legacy_identity')->table('webauthn_credentials')->insert([
            'user_id' => 42,
            'credential_id' => 'deleted-subject-credential',
            'public_key' => 'key-material',
            'counter' => 1,
            'name' => 'Passkey',
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('identity_tombstones')->insert([
            'public_id' => (string) Str::uuid(),
            'subject' => 42,
            'tombstoned_at' => now(),
            'purge_after' => now()->addDays(30),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->artisan('identity:import-legacy --apply')
            ->expectsOutputToContain('users#42 skipped: this OAuth subject has a provider deletion tombstone.')
            ->expectsOutputToContain('passkey#1 skipped: its owner users#42 is not present.')
            ->assertSuccessful();

        $this->assertDatabaseMissing('users', ['id' => 42]);
        $this->assertDatabaseMissing('webauthn_credentials', [
            'credential_id' => 'deleted-subject-credential',
        ]);
    }

    private function client(bool $revoked = false): string
    {
        $id = (string) Str::uuid();
        DB::table('oauth_clients')->insert([
            'id' => $id,
            'name' => $revoked ? 'Retired Application' : 'Current Application',
            'secret' => 'secret',
            'redirect_uris' => json_encode(['https://app.example.test/oauth/callback']),
            'grant_types' => json_encode(['authorization_code']),
            'revoked' => $revoked,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return $id;
    }
}
