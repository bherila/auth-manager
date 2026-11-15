<?php

namespace Tests\Feature;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

final class TwoFactorLinkSecretMigrationTest extends TestCase
{
    use RefreshDatabase;

    public function test_the_additive_migration_uses_the_configured_table_and_preserves_existing_attempts(): void
    {
        Schema::create('configured_two_factor_attempts', static function (Blueprint $table): void {
            $table->id();
            $table->string('token');
        });
        DB::table('configured_two_factor_attempts')->insert(['id' => 1, 'token' => 'synthetic-existing-challenge']);
        config(['bherila-auth.two_factor.table' => 'configured_two_factor_attempts']);
        $migration = require database_path('migrations/2026_11_15_000000_add_link_secret_hash_to_two_factor_attempts.php');

        $migration->up();
        $migration->up();

        $this->assertTrue(Schema::hasColumn('configured_two_factor_attempts', 'link_secret_hash'));
        $this->assertDatabaseHas('configured_two_factor_attempts', [
            'id' => 1, 'token' => 'synthetic-existing-challenge', 'link_secret_hash' => null,
        ]);
        $this->assertTrue(Schema::hasColumn('auth_two_factor_attempts', 'link_secret_hash'));

        $migration->down();
        $migration->down();

        $this->assertFalse(Schema::hasColumn('configured_two_factor_attempts', 'link_secret_hash'));
        $this->assertTrue(Schema::hasColumn('auth_two_factor_attempts', 'link_secret_hash'));
        $this->assertDatabaseHas('configured_two_factor_attempts', ['id' => 1, 'token' => 'synthetic-existing-challenge']);
    }
}
