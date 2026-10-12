<?php

namespace Tests\Feature;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use RuntimeException;
use Tests\TestCase;

class InvitationAcceptanceCodesMigrationTest extends TestCase
{
    use RefreshDatabase;

    private const string MIGRATION = 'migrations/2026_10_12_000200_create_invitation_acceptance_codes_table.php';

    /**
     * MariaDB refuses identifiers longer than 64 characters, and SQLite (which the suite runs on) does
     * not, so a generated index name that is too long only fails in production. Every index and unique
     * constraint the migrations create is enumerated here.
     */
    public function test_every_index_name_fits_the_mariadb_identifier_limit(): void
    {
        $names = DB::table('sqlite_master')
            ->where('type', 'index')
            ->where('name', 'not like', 'sqlite_autoindex_%')
            ->pluck('name');

        $this->assertNotEmpty($names);
        $tooLong = $names->filter(fn (string $name): bool => strlen($name) > 64)->values()->all();

        $this->assertSame([], $tooLong);
    }

    public function test_the_migration_rebuilds_the_empty_table_a_failed_mariadb_run_left_behind(): void
    {
        $migration = require database_path(self::MIGRATION);
        $migration->down();

        // What the failed run committed: the table with its key, but not the later index or columns.
        Schema::create('invitation_acceptance_codes', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('access_invitation_id')->constrained('access_invitations')->cascadeOnDelete();
            $table->char('address_hash', 64);
            $table->char('code_hash', 64);
            $table->timestamp('expires_at');
            $table->timestamp('consumed_at')->nullable();
            $table->timestamp('created_at')->nullable();
        });

        $migration->up();

        $this->assertTrue(Schema::hasColumn('access_invitations', 'verification_attempts'));
        $this->assertTrue(Schema::hasColumn('access_invitations', 'verification_send_count'));
        $this->assertTrue(Schema::hasIndex('invitation_acceptance_codes', 'invitation_codes_invitation_consumed_idx'));
    }

    public function test_the_migration_refuses_to_rebuild_a_table_that_is_in_use(): void
    {
        $migration = require database_path(self::MIGRATION);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('refusing to rebuild it');
        $migration->up();
    }
}
