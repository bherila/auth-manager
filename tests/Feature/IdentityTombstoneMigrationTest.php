<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

class IdentityTombstoneMigrationTest extends TestCase
{
    use RefreshDatabase;

    public function test_the_migration_resumes_after_mysql_commits_its_first_ddl_stage(): void
    {
        Schema::drop('identity_tombstone_clients');
        Schema::drop('identity_tombstones');
        $this->assertTrue(Schema::hasColumn('users', 'deleted_at'));

        $migration = require database_path('migrations/2026_08_26_120000_create_identity_tombstones.php');
        $migration->up();
        $migration->up();

        $this->assertTrue(Schema::hasColumn('users', 'deleted_at'));
        $this->assertTrue(Schema::hasTable('identity_tombstones'));
        $this->assertTrue(Schema::hasTable('identity_tombstone_clients'));
    }

    public function test_mysql_sensitive_lifecycle_columns_are_declared_as_datetime(): void
    {
        $migration = file_get_contents(
            database_path('migrations/2026_08_26_120000_create_identity_tombstones.php'),
        );
        $this->assertIsString($migration);

        $this->assertStringContainsString("dateTime('tombstoned_at')", $migration);
        $this->assertStringContainsString("dateTime('purge_after')", $migration);
        $this->assertStringContainsString("dateTime('provider_purged_at')", $migration);
        $this->assertStringNotContainsString("timestamp('purge_after')", $migration);
    }
}
