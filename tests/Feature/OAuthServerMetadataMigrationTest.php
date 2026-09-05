<?php

namespace Tests\Feature;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

class OAuthServerMetadataMigrationTest extends TestCase
{
    private const DEFAULT_CONNECTION = 'oauth_metadata_default';

    private const PASSPORT_CONNECTION = 'oauth_metadata_passport';

    /** @var array<string, mixed> */
    private array $originalConnections;

    private mixed $originalDefaultConnection;

    private mixed $originalPassportConnection;

    protected function setUp(): void
    {
        parent::setUp();

        $this->originalConnections = config('database.connections');
        $this->originalDefaultConnection = config('database.default');
        $this->originalPassportConnection = config('passport.connection');

        $connection = [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
            'foreign_key_constraints' => true,
        ];

        config()->set('database.connections.'.self::DEFAULT_CONNECTION, $connection);
        config()->set('database.connections.'.self::PASSPORT_CONNECTION, $connection);
        config()->set('database.default', self::DEFAULT_CONNECTION);
        config()->set('passport.connection', self::PASSPORT_CONNECTION);
        DB::purge(self::DEFAULT_CONNECTION);
        DB::purge(self::PASSPORT_CONNECTION);
    }

    protected function tearDown(): void
    {
        DB::purge(self::DEFAULT_CONNECTION);
        DB::purge(self::PASSPORT_CONNECTION);
        config()->set('database.connections', $this->originalConnections);
        config()->set('database.default', $this->originalDefaultConnection);
        config()->set('passport.connection', $this->originalPassportConnection);

        parent::tearDown();
    }

    public function test_metadata_migration_only_updates_passports_configured_connection(): void
    {
        $columns = [
            'oauth_clients' => ['dynamically_registered_at', 'last_used_at', 'scopes'],
            'oauth_auth_codes' => ['resource_uri'],
            'oauth_access_tokens' => ['resource_uri'],
            'oauth_refresh_tokens' => ['resource_uri'],
        ];

        foreach (array_keys($columns) as $table) {
            Schema::connection(self::PASSPORT_CONNECTION)->create($table, function (Blueprint $table): void {
                $table->string('id')->primary();
            });
        }

        $migration = require database_path('migrations/2026_09_04_000000_add_oauth_server_metadata.php');
        $this->assertSame(self::PASSPORT_CONNECTION, $migration->getConnection());

        $migration->up();

        foreach ($columns as $table => $tableColumns) {
            $this->assertFalse(Schema::connection(self::DEFAULT_CONNECTION)->hasTable($table));

            foreach ($tableColumns as $column) {
                $this->assertTrue(Schema::connection(self::PASSPORT_CONNECTION)->hasColumn($table, $column));
            }
        }

        $migration->down();

        foreach ($columns as $table => $tableColumns) {
            $this->assertFalse(Schema::connection(self::DEFAULT_CONNECTION)->hasTable($table));

            foreach ($tableColumns as $column) {
                $this->assertTrue(Schema::connection(self::PASSPORT_CONNECTION)->hasColumn($table, $column));
            }
        }
    }
}
