<?php

namespace Tests\Feature;

use BWH\Auth\OAuth\Session\RememberedProviderLogins;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

class ProviderRecoveryEpochMigrationTest extends TestCase
{
    use RefreshDatabase;

    public function test_remembered_logins_persist_the_recovery_epoch_on_the_application_connection(): void
    {
        $logins = app(RememberedProviderLogins::class);
        $hash = RememberedProviderLogins::tokenHash('synthetic-remember-token');

        $logins->put('synthetic-guard', 'synthetic-account', 'synthetic-provider', '01SYNTHETICSUBJECT', 7, $hash, 3);

        $row = $logins->find('synthetic-guard', 'synthetic-account');
        $this->assertNotNull($row);
        $this->assertSame(3, (int) $row->epoch);
        $this->assertSame(7, (int) $row->generation);
        $this->assertSame($hash, $row->token_hash);
        $this->assertSame('01SYNTHETICSUBJECT', $row->subject);
    }

    public function test_upgrade_keeps_legacy_baselines_and_can_be_repeated_without_erasing_epochs(): void
    {
        $tables = ['oauth_auth_codes', 'oauth_access_tokens', 'oauth_refresh_tokens'];
        foreach ($tables as $table) {
            $this->assertTrue(Schema::hasColumn($table, 'provider_epoch'));
            Schema::dropColumns($table, ['provider_epoch']);
        }
        $this->assertTrue(Schema::hasColumn('provider_remembered_logins', 'epoch'));
        Schema::dropColumns('provider_remembered_logins', ['epoch']);
        $hash = RememberedProviderLogins::tokenHash('synthetic-legacy-token');
        DB::table('provider_remembered_logins')->insert([
            'guard' => 'legacy-guard',
            'user_id' => 'legacy-account',
            'provider' => 'synthetic-provider',
            'subject' => '123',
            'generation' => 7,
            'token_hash' => $hash,
            'recorded_at' => now(),
        ]);

        $migration = require database_path('migrations/2026_11_24_000000_add_provider_epoch_columns.php');
        $migration->up();
        $this->assertDatabaseHas('provider_remembered_logins', [
            'user_id' => 'legacy-account', 'generation' => 7, 'token_hash' => $hash, 'epoch' => null,
        ]);
        DB::table('provider_remembered_logins')->where('user_id', 'legacy-account')->update(['epoch' => 4]);

        $migration->up();
        $migration->down();

        $this->assertDatabaseHas('provider_remembered_logins', [
            'user_id' => 'legacy-account', 'generation' => 7, 'token_hash' => $hash, 'epoch' => 4,
        ]);
        foreach ($tables as $table) {
            $this->assertTrue(Schema::hasColumn($table, 'provider_epoch'));
        }
    }
}
