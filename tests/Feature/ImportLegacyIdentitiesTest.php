<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
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

    private function seedLegacyUser(int $id, string $email = 'person@example.com'): void
    {
        DB::connection('legacy_identity')->table('users')->insert([
            'id' => $id,
            'name' => 'Person',
            'email' => $email,
            'password' => 'hashed-secret',
            'user_role' => 'user',
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
}
