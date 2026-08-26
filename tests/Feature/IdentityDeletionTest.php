<?php

namespace Tests\Feature;

use App\Http\Middleware\EnsureCredentialVersion;
use App\Models\IdentityTombstone;
use App\Models\PassportClient;
use App\Models\User;
use App\Services\DirectoryAdminService;
use App\Services\IdentityTombstonePurger;
use App\Services\UserAccountStatusService;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Laravel\Passport\Bridge\AccessTokenRepository;
use Laravel\Passport\ClientRepository;
use Tests\TestCase;

class IdentityDeletionTest extends TestCase
{
    use RefreshDatabase;

    public function test_deleting_a_person_immediately_tombstones_the_account_and_revokes_every_credential_path(): void
    {
        Carbon::setTestNow('2026-08-26 12:00:00');
        $admin = User::factory()->create(['user_role' => 'admin']);
        $target = User::factory()->create([
            'user_role' => 'user',
            'remember_token' => 'remember-me',
        ]);
        [$client] = $this->authorizationCodeClient('Connected Application');
        [$secondClient] = $this->authorizationCodeClient('Second Application');
        $this->publicAuthorizationCodeClient();
        $this->clientCredentialsClient();
        [$revokedClient] = $this->authorizationCodeClient('Revoked Application');
        $revokedClient->forceFill(['revoked' => true])->save();

        DB::table('oauth_client_grants')->insert([
            'subject' => $target->id,
            'oauth_client_id' => $client->getKey(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        $accessTokenId = $this->accessToken($target, $client);
        $refreshTokenId = $this->refreshToken($accessTokenId);
        $authorizationCodeId = $this->authorizationCode($target, $client);
        $deviceCodeId = $this->deviceCode($target, $client);
        DB::table('sessions')->insert([
            'id' => 'target-session',
            'user_id' => $target->id,
            'ip_address' => '127.0.0.1',
            'user_agent' => 'test',
            'payload' => 'serialized-session',
            'last_activity' => now()->timestamp,
        ]);
        DB::table('password_reset_tokens')->insert([
            'email' => $target->email,
            'token' => 'reset-token',
            'created_at' => now(),
        ]);

        $response = $this->actingAs($admin)
            ->deleteJson("/api/admin/users/{$target->id}")
            ->assertAccepted()
            ->assertJsonPath('tombstone.subject', (string) $target->id)
            ->assertJsonPath('tombstone.expected_application_count', 2)
            ->assertJsonPath('tombstone.tombstoned_at', '2026-08-26T12:00:00.000000Z')
            ->assertJsonPath('tombstone.purge_after', '2026-09-25T12:00:00.000000Z');

        $tombstoneId = $response->json('tombstone.id');
        $deleted = User::withTrashed()->findOrFail($target->id);
        $this->assertTrue($deleted->trashed());
        $this->assertFalse($deleted->canLogin());
        $this->assertSame(1, $deleted->credential_version);
        $this->assertNull($deleted->remember_token);
        $this->assertNull(app(UserAccountStatusService::class)
            ->credentialVersionIfActive((string) $target->id));
        $this->assertTrue(app(AccessTokenRepository::class)->isAccessTokenRevoked($accessTokenId));

        $this->assertDatabaseHas('oauth_access_tokens', ['id' => $accessTokenId, 'revoked' => true]);
        $this->assertDatabaseHas('oauth_refresh_tokens', ['id' => $refreshTokenId, 'revoked' => true]);
        $this->assertDatabaseHas('oauth_auth_codes', ['id' => $authorizationCodeId, 'revoked' => true]);
        $this->assertDatabaseHas('oauth_device_codes', ['id' => $deviceCodeId, 'revoked' => true]);
        $this->assertDatabaseMissing('sessions', ['user_id' => $target->id]);
        $this->assertDatabaseMissing('password_reset_tokens', ['email' => $target->email]);
        $this->assertDatabaseHas('identity_tombstones', [
            'public_id' => $tombstoneId,
            'subject' => $target->id,
            'provider_purged_at' => null,
        ]);
        $this->assertDatabaseHas('identity_tombstone_clients', [
            'identity_tombstone_id' => IdentityTombstone::query()->where('public_id', $tombstoneId)->value('id'),
            'oauth_client_id' => $client->getKey(),
            'oauth_client_name' => 'Connected Application',
        ]);
        $this->assertDatabaseHas('identity_tombstone_clients', [
            'oauth_client_id' => $secondClient->getKey(),
            'oauth_client_name' => 'Second Application',
        ]);
        $this->assertDatabaseCount('identity_tombstone_clients', 2);
        $this->assertDatabaseHas('auth_audit_log', [
            'user_id' => $target->id,
            'acting_user_id' => $admin->id,
            'event' => DirectoryAdminService::EVENT_USER_TOMBSTONED,
        ]);
        $this->actingAs($admin)
            ->getJson('/api/admin/users')
            ->assertOk()
            ->assertJsonMissing(['id' => $target->id]);

        $this->actingAs($deleted)
            ->withSession([EnsureCredentialVersion::SESSION_KEY => 0])
            ->get('/')
            ->assertRedirect('/login');
        $this->assertGuest();
    }

    public function test_the_last_active_provider_admin_cannot_be_tombstoned(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);

        $this->actingAs($admin)
            ->deleteJson("/api/admin/users/{$admin->id}")
            ->assertUnprocessable()
            ->assertJsonValidationErrors('user');

        $this->assertFalse($admin->refresh()->trashed());
        $this->assertDatabaseCount('identity_tombstones', 0);
        $this->assertDatabaseMissing('auth_audit_log', [
            'user_id' => $admin->id,
            'event' => DirectoryAdminService::EVENT_USER_TOMBSTONED,
        ]);
    }

    public function test_reconciliation_requires_the_snapshotted_confidential_client_and_exposes_only_minimal_pending_data(): void
    {
        Carbon::setTestNow('2026-08-26 12:00:00');
        $admin = User::factory()->create(['user_role' => 'admin']);
        $target = User::factory()->create(['user_role' => 'user']);
        [$client, $secret] = $this->authorizationCodeClient('Connected Application');

        $tombstoneId = $this->actingAs($admin)
            ->deleteJson("/api/admin/users/{$target->id}")
            ->assertAccepted()
            ->json('tombstone.id');

        $this->flushHeaders();
        $this->getJson('/api/reconciliation/identity-tombstones')
            ->assertUnauthorized()
            ->assertHeader('WWW-Authenticate', 'Basic realm="identity-reconciliation", charset="UTF-8"')
            ->assertHeader('Cache-Control', 'no-store, private');
        $this->actingAs($admin)
            ->getJson('/api/reconciliation/identity-tombstones')
            ->assertUnauthorized();
        $this->withBasicAuth((string) $client->getKey(), 'wrong-secret')
            ->getJson('/api/reconciliation/identity-tombstones')
            ->assertUnauthorized();

        $response = $this->withBasicAuth((string) $client->getKey(), $secret)
            ->getJson('/api/reconciliation/identity-tombstones')
            ->assertOk()
            ->assertHeader('Cache-Control', 'no-store, private')
            ->assertExactJson([
                'contract_version' => 1,
                'data' => [[
                    'id' => $tombstoneId,
                    'subject' => (string) $target->id,
                    'tombstoned_at' => '2026-08-26T12:00:00.000000Z',
                    'purge_after' => '2026-09-25T12:00:00.000000Z',
                    'provider_purged_at' => null,
                ]],
                'has_more' => false,
            ]);
        $this->assertStringNotContainsString($target->name, $response->getContent());
        $this->assertStringNotContainsString($target->email, $response->getContent());

        $client->forceFill(['revoked' => true])->save();
        $this->withBasicAuth((string) $client->getKey(), $secret)
            ->getJson('/api/reconciliation/identity-tombstones')
            ->assertUnauthorized();
    }

    public function test_acknowledgement_is_client_bound_and_idempotent(): void
    {
        Carbon::setTestNow('2026-08-26 12:00:00');
        $admin = User::factory()->create(['user_role' => 'admin']);
        $target = User::factory()->create(['user_role' => 'user']);
        [$client, $secret] = $this->authorizationCodeClient('Expected Application');

        $tombstoneId = $this->actingAs($admin)
            ->deleteJson("/api/admin/users/{$target->id}")
            ->json('tombstone.id');
        $unassignedClient = $this->authorizationCodeClient('Registered Later');

        $this->withBasicAuth(
            (string) $unassignedClient[0]->getKey(),
            $unassignedClient[1],
        )->putJson("/api/reconciliation/identity-tombstones/{$tombstoneId}/acknowledgement")
            ->assertNotFound();

        $first = $this->withBasicAuth((string) $client->getKey(), $secret)
            ->putJson("/api/reconciliation/identity-tombstones/{$tombstoneId}/acknowledgement")
            ->assertOk()
            ->json('acknowledgement.acknowledged_at');

        Carbon::setTestNow('2026-08-26 12:05:00');
        $second = $this->withBasicAuth((string) $client->getKey(), $secret)
            ->putJson("/api/reconciliation/identity-tombstones/{$tombstoneId}/acknowledgement")
            ->assertOk()
            ->json('acknowledgement.acknowledged_at');

        $this->assertSame($first, $second);
        $this->assertSame('2026-08-26T12:00:00.000000Z', $second);
        $this->withBasicAuth((string) $client->getKey(), $secret)
            ->getJson('/api/reconciliation/identity-tombstones')
            ->assertOk()
            ->assertJsonPath('data', []);
        $this->assertDatabaseCount('identity_tombstone_clients', 1);
    }

    public function test_the_pending_feed_is_bounded_and_drains_by_acknowledgement(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        [$client, $secret] = $this->authorizationCodeClient();
        $first = User::factory()->create(['user_role' => 'user']);
        $second = User::factory()->create(['user_role' => 'user']);
        $firstId = $this->actingAs($admin)->deleteJson("/api/admin/users/{$first->id}")->json('tombstone.id');
        $this->actingAs($admin)->deleteJson("/api/admin/users/{$second->id}")->assertAccepted();

        $this->withBasicAuth((string) $client->getKey(), $secret)
            ->getJson('/api/reconciliation/identity-tombstones?limit=1')
            ->assertOk()
            ->assertJsonCount(1, 'data')
            ->assertJsonPath('data.0.id', $firstId)
            ->assertJsonPath('has_more', true);

        $this->withBasicAuth((string) $client->getKey(), $secret)
            ->putJson("/api/reconciliation/identity-tombstones/{$firstId}/acknowledgement")
            ->assertOk();
        $this->withBasicAuth((string) $client->getKey(), $secret)
            ->getJson('/api/reconciliation/identity-tombstones?limit=1')
            ->assertOk()
            ->assertJsonCount(1, 'data')
            ->assertJsonPath('has_more', false);

        $this->withBasicAuth((string) $client->getKey(), $secret)
            ->getJson('/api/reconciliation/identity-tombstones?limit=101')
            ->assertUnprocessable();
    }

    public function test_scheduled_purge_hard_deletes_after_every_acknowledgement(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $target = User::factory()->create(['user_role' => 'user']);
        [$client, $secret] = $this->authorizationCodeClient();
        $accessTokenId = $this->accessToken($target, $client);
        $refreshTokenId = $this->refreshToken($accessTokenId);

        $tombstoneId = $this->actingAs($admin)
            ->deleteJson("/api/admin/users/{$target->id}")
            ->json('tombstone.id');
        $this->withBasicAuth((string) $client->getKey(), $secret)
            ->putJson("/api/reconciliation/identity-tombstones/{$tombstoneId}/acknowledgement")
            ->assertOk();

        $this->artisan('identities:purge-tombstones')
            ->expectsOutputToContain('Purged 1 identities')
            ->assertSuccessful();

        $this->assertNull(User::withTrashed()->find($target->id));
        $this->assertDatabaseMissing('oauth_client_grants', ['subject' => $target->id]);
        $this->assertDatabaseMissing('oauth_access_tokens', ['id' => $accessTokenId]);
        $this->assertDatabaseMissing('oauth_refresh_tokens', ['id' => $refreshTokenId]);
        $tombstone = IdentityTombstone::query()->where('public_id', $tombstoneId)->firstOrFail();
        $this->assertSame(IdentityTombstonePurger::REASON_ALL_ACKNOWLEDGED, $tombstone->purge_reason);
        $this->assertNotNull($tombstone->provider_purged_at);
        $this->assertSame([], $tombstone->unacknowledged_clients);
        $this->assertDatabaseHas('auth_audit_log', [
            'user_id' => null,
            'email' => null,
            'event' => DirectoryAdminService::EVENT_USER_TOMBSTONED,
        ]);
    }

    public function test_retention_expiry_names_missing_apps_and_keeps_their_feed_available(): void
    {
        Carbon::setTestNow('2026-08-26 12:00:00');
        Log::spy();
        $admin = User::factory()->create(['user_role' => 'admin']);
        $target = User::factory()->create(['user_role' => 'user']);
        [$client, $secret] = $this->authorizationCodeClient('Unavailable Application');

        $tombstoneId = $this->actingAs($admin)
            ->deleteJson("/api/admin/users/{$target->id}")
            ->json('tombstone.id');

        $this->artisan('identities:purge-tombstones')
            ->expectsOutputToContain('1 remain within retention')
            ->assertSuccessful();
        $this->assertNotNull(User::withTrashed()->find($target->id));

        Carbon::setTestNow('2026-09-25 12:00:00');
        $this->artisan('identities:purge-tombstones')
            ->expectsOutputToContain('1 expired with unacknowledged applications')
            ->assertSuccessful();

        $this->assertNull(User::withTrashed()->find($target->id));
        $tombstone = IdentityTombstone::query()->where('public_id', $tombstoneId)->firstOrFail();
        $this->assertSame(IdentityTombstonePurger::REASON_RETENTION_EXPIRED, $tombstone->purge_reason);
        $this->assertSame([[
            'id' => (string) $client->getKey(),
            'name' => 'Unavailable Application',
        ]], $tombstone->unacknowledged_clients);
        Log::shouldHaveReceived('warning')->once()->with(
            'Provider identity purged after its retention window with unacknowledged relying applications.',
            [
                'identity_tombstone_id' => $tombstoneId,
                'unacknowledged_applications' => [[
                    'id' => (string) $client->getKey(),
                    'name' => 'Unavailable Application',
                ]],
            ],
        );

        $this->withBasicAuth((string) $client->getKey(), $secret)
            ->getJson('/api/reconciliation/identity-tombstones')
            ->assertOk()
            ->assertJsonPath('data.0.id', $tombstoneId)
            ->assertJsonPath('data.0.provider_purged_at', '2026-09-25T12:00:00.000000Z');
        $this->withBasicAuth((string) $client->getKey(), $secret)
            ->putJson("/api/reconciliation/identity-tombstones/{$tombstoneId}/acknowledgement")
            ->assertOk();
    }

    public function test_retention_purge_is_registered_as_an_hourly_non_overlapping_schedule(): void
    {
        $event = collect(app(Schedule::class)->events())
            ->first(static fn ($event): bool => str_contains(
                (string) $event->command,
                'identities:purge-tombstones',
            ));

        $this->assertNotNull($event);
        $this->assertSame('0 * * * *', $event->expression);
        $this->assertTrue($event->withoutOverlapping);
    }

    /**
     * @return array{PassportClient, string}
     */
    private function authorizationCodeClient(string $name = 'Connected Application'): array
    {
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient(
            $name,
            ['https://app.example.test/oauth/callback'],
        );
        $this->assertInstanceOf(PassportClient::class, $client);
        $this->assertIsString($client->plainSecret);

        return [$client, $client->plainSecret];
    }

    private function publicAuthorizationCodeClient(): PassportClient
    {
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient(
            'Public Application',
            ['https://public.example.test/oauth/callback'],
            false,
        );
        $this->assertInstanceOf(PassportClient::class, $client);

        return $client;
    }

    private function clientCredentialsClient(): PassportClient
    {
        $client = app(ClientRepository::class)->createClientCredentialsGrantClient('Machine Client');
        $this->assertInstanceOf(PassportClient::class, $client);

        return $client;
    }

    private function accessToken(User $user, PassportClient $client): string
    {
        $id = Str::random(80);
        DB::table('oauth_access_tokens')->insert([
            'id' => $id,
            'user_id' => $user->id,
            'client_id' => $client->getKey(),
            'name' => null,
            'scopes' => '[]',
            'revoked' => false,
            'credential_version' => (int) $user->credential_version,
            'created_at' => now(),
            'updated_at' => now(),
            'expires_at' => now()->addMinutes(5),
        ]);

        return $id;
    }

    private function refreshToken(string $accessTokenId): string
    {
        $id = Str::random(80);
        DB::table('oauth_refresh_tokens')->insert([
            'id' => $id,
            'access_token_id' => $accessTokenId,
            'revoked' => false,
            'expires_at' => now()->addDay(),
        ]);

        return $id;
    }

    private function authorizationCode(User $user, PassportClient $client): string
    {
        $id = Str::random(80);
        DB::table('oauth_auth_codes')->insert([
            'id' => $id,
            'user_id' => $user->id,
            'client_id' => $client->getKey(),
            'scopes' => '[]',
            'revoked' => false,
            'credential_version' => (int) $user->credential_version,
            'expires_at' => now()->addMinutes(5),
        ]);

        return $id;
    }

    private function deviceCode(User $user, PassportClient $client): string
    {
        $id = Str::random(80);
        DB::table('oauth_device_codes')->insert([
            'id' => $id,
            'user_id' => $user->id,
            'client_id' => $client->getKey(),
            'user_code' => Str::upper(Str::random(8)),
            'scopes' => '[]',
            'revoked' => false,
            'user_approved_at' => now(),
            'last_polled_at' => null,
            'expires_at' => now()->addMinutes(5),
        ]);

        return $id;
    }
}
