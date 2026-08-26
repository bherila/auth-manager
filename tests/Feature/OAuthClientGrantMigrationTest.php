<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Tests\TestCase;

class OAuthClientGrantMigrationTest extends TestCase
{
    use RefreshDatabase;

    public function test_cutover_backfills_every_active_subject_and_non_revoked_client_pair(): void
    {
        Schema::drop('oauth_client_grants');
        $user = User::factory()->create(['user_role' => 'user']);
        $admin = User::factory()->create(['user_role' => 'admin,user']);
        $disabled = User::factory()->create(['user_role' => '']);
        $clientId = $this->client(revoked: false);
        $revokedClientId = $this->client(revoked: true);

        $migration = require database_path('migrations/2026_08_26_090000_create_oauth_client_grants_table.php');
        $migration->up();

        $this->assertDatabaseHas('oauth_client_grants', [
            'subject' => (string) $user->getKey(),
            'oauth_client_id' => $clientId,
        ]);
        $this->assertDatabaseHas('oauth_client_grants', [
            'subject' => (string) $admin->getKey(),
            'oauth_client_id' => $clientId,
        ]);
        $this->assertDatabaseMissing('oauth_client_grants', [
            'subject' => (string) $disabled->getKey(),
        ]);
        $this->assertDatabaseMissing('oauth_client_grants', [
            'oauth_client_id' => $revokedClientId,
        ]);
        $this->assertSame(2, DB::table('oauth_client_grants')->count());
    }

    private function client(bool $revoked): string
    {
        $id = (string) Str::uuid();
        DB::table('oauth_clients')->insert([
            'id' => $id,
            'name' => $revoked ? 'Revoked Application' : 'Current Application',
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
