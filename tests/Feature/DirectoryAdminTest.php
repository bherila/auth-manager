<?php

namespace Tests\Feature;

use App\Models\User;
use App\Services\DirectoryAdminService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Tests\TestCase;

class DirectoryAdminTest extends TestCase
{
    use RefreshDatabase;

    public function test_directory_administration_requires_an_active_provider_admin(): void
    {
        $this->get('/admin/users')->assertRedirect('/login');
        $this->getJson('/api/admin/users')->assertUnauthorized();

        $nonAdmin = User::factory()->create(['user_role' => 'user']);
        $this->actingAs($nonAdmin)->get('/admin/users')->assertForbidden();
        $this->actingAs($nonAdmin)->getJson('/api/admin/users')->assertForbidden();

        $disabledAdmin = User::factory()->create([
            'user_role' => 'admin',
            'disabled_at' => now(),
        ]);
        $this->actingAs($disabledAdmin)->getJson('/api/admin/users')->assertForbidden();
    }

    public function test_admin_page_and_list_explain_the_provider_and_application_boundary(): void
    {
        $this->withoutVite();
        $admin = User::factory()->create(['user_role' => 'admin']);
        $disabled = User::factory()->create(['user_role' => 'user', 'disabled_at' => now()]);
        $clientId = $this->client('Example Application');

        $this->actingAs($admin)
            ->get('/admin/users')
            ->assertOk()
            ->assertSee('A selected grant permits OAuth, but never creates a record inside a connected application.');
        $this->actingAs($admin)
            ->get('/')
            ->assertOk()
            ->assertSee('Directory administration');

        $response = $this->actingAs($admin)->getJson('/api/admin/users')->assertOk();
        $users = collect($response->json('users'))->keyBy('id');

        $this->assertSame('active', $users->get($admin->id)['status']);
        $this->assertSame('disabled', $users->get($disabled->id)['status']);
        $this->assertSame($clientId, $response->json('clients.0.id'));
        $this->assertSame('Example Application', $response->json('clients.0.name'));
    }

    public function test_admin_can_create_a_person_with_explicit_initial_grants(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $clientId = $this->client();

        $response = $this->actingAs($admin)->postJson('/api/admin/users', [
            'name' => 'New Person',
            'email' => 'new-person@example.test',
            'password' => 'long-temporary-password',
            'password_confirmation' => 'long-temporary-password',
            'enabled' => true,
            'client_ids' => [$clientId],
        ])->assertCreated();

        $subject = $response->json('user.id');
        $this->assertDatabaseHas('users', [
            'id' => $subject,
            'email' => 'new-person@example.test',
            'user_role' => 'user',
            'disabled_at' => null,
        ]);
        $this->assertDatabaseHas('oauth_client_grants', [
            'subject' => $subject,
            'oauth_client_id' => $clientId,
        ]);
        $this->assertDatabaseHas('auth_audit_log', [
            'user_id' => $subject,
            'acting_user_id' => $admin->id,
            'event' => DirectoryAdminService::EVENT_USER_CREATED,
            'succeeded' => true,
        ]);
    }

    public function test_disabling_a_person_preserves_grants_and_revokes_sessions_and_tokens(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $target = User::factory()->create(['user_role' => 'user', 'remember_token' => 'remember-me']);
        $clientId = $this->client();
        DB::table('oauth_client_grants')->insert([
            'subject' => $target->id,
            'oauth_client_id' => $clientId,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        $accessTokenId = $this->accessToken($target, $clientId);
        $refreshTokenId = $this->refreshToken($accessTokenId);
        $authorizationCodeId = $this->authorizationCode($target, $clientId);
        DB::table('sessions')->insert([
            'id' => 'target-session',
            'user_id' => $target->id,
            'ip_address' => null,
            'user_agent' => null,
            'payload' => '',
            'last_activity' => now()->timestamp,
        ]);

        $this->actingAs($admin)
            ->postJson("/api/admin/users/{$target->id}/disable")
            ->assertOk()
            ->assertJsonPath('user.status', 'disabled');

        $target->refresh();
        $this->assertFalse($target->canLogin());
        $this->assertNull($target->remember_token);
        $this->assertDatabaseHas('oauth_client_grants', [
            'subject' => $target->id,
            'oauth_client_id' => $clientId,
        ]);
        $this->assertDatabaseHas('oauth_access_tokens', ['id' => $accessTokenId, 'revoked' => true]);
        $this->assertDatabaseHas('oauth_refresh_tokens', ['id' => $refreshTokenId, 'revoked' => true]);
        $this->assertDatabaseHas('oauth_auth_codes', ['id' => $authorizationCodeId, 'revoked' => true]);
        $this->assertDatabaseMissing('sessions', ['id' => 'target-session']);
        $this->assertDatabaseHas('auth_audit_log', [
            'user_id' => $target->id,
            'acting_user_id' => $admin->id,
            'event' => DirectoryAdminService::EVENT_USER_DISABLED,
        ]);
    }

    public function test_the_last_active_provider_admin_cannot_be_disabled(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);

        $this->actingAs($admin)
            ->postJson("/api/admin/users/{$admin->id}/disable")
            ->assertUnprocessable()
            ->assertJsonValidationErrors('user');

        $this->assertTrue($admin->refresh()->canLogin());
        $this->assertDatabaseMissing('auth_audit_log', [
            'user_id' => $admin->id,
            'event' => DirectoryAdminService::EVENT_USER_DISABLED,
        ]);
    }

    public function test_admin_can_reenable_a_legacy_disabled_person(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $target = User::factory()->create(['user_role' => 'pending']);

        $this->actingAs($admin)
            ->postJson("/api/admin/users/{$target->id}/enable")
            ->assertOk()
            ->assertJsonPath('user.status', 'active');

        $target->refresh();
        $this->assertSame('user', $target->user_role);
        $this->assertTrue($target->canLogin());
        $this->assertDatabaseHas('auth_audit_log', [
            'user_id' => $target->id,
            'acting_user_id' => $admin->id,
            'event' => DirectoryAdminService::EVENT_USER_ENABLED,
        ]);
    }

    public function test_email_and_password_changes_take_effect_and_are_audited(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $target = User::factory()->create([
            'user_role' => 'user',
            'email_verified_at' => now(),
            'password' => Hash::make('old-password-value'),
        ]);
        $clientId = $this->client();
        $accessTokenId = $this->accessToken($target, $clientId);

        $this->actingAs($admin)
            ->patchJson("/api/admin/users/{$target->id}/email", [
                'email' => 'changed@example.test',
            ])
            ->assertOk()
            ->assertJsonPath('user.email', 'changed@example.test');

        $this->actingAs($admin)
            ->putJson("/api/admin/users/{$target->id}/password", [
                'password' => 'replacement-password',
                'password_confirmation' => 'replacement-password',
            ])
            ->assertOk();

        $target->refresh();
        $this->assertSame('changed@example.test', $target->email);
        $this->assertNull($target->email_verified_at);
        $this->assertTrue(Hash::check('replacement-password', $target->password));
        $this->assertFalse(Hash::check('old-password-value', $target->password));
        $this->assertDatabaseHas('oauth_access_tokens', ['id' => $accessTokenId, 'revoked' => true]);
        $this->assertDatabaseHas('auth_audit_log', [
            'user_id' => $target->id,
            'acting_user_id' => $admin->id,
            'event' => DirectoryAdminService::EVENT_EMAIL_CHANGED,
        ]);
        $this->assertDatabaseHas('auth_audit_log', [
            'user_id' => $target->id,
            'acting_user_id' => $admin->id,
            'event' => DirectoryAdminService::EVENT_PASSWORD_RESET,
        ]);
    }

    public function test_grant_management_is_audited_and_revocation_invalidates_tokens(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $target = User::factory()->create(['user_role' => 'user']);
        $clientId = $this->client();

        $this->actingAs($admin)
            ->putJson("/api/admin/users/{$target->id}/clients/{$clientId}")
            ->assertOk()
            ->assertJsonPath('user.client_ids.0', $clientId);

        $accessTokenId = $this->accessToken($target, $clientId);
        $refreshTokenId = $this->refreshToken($accessTokenId);
        $authorizationCodeId = $this->authorizationCode($target, $clientId);

        $this->actingAs($admin)
            ->deleteJson("/api/admin/users/{$target->id}/clients/{$clientId}")
            ->assertOk()
            ->assertJsonPath('user.client_ids', []);

        $this->assertDatabaseMissing('oauth_client_grants', [
            'subject' => $target->id,
            'oauth_client_id' => $clientId,
        ]);
        $this->assertDatabaseHas('oauth_access_tokens', ['id' => $accessTokenId, 'revoked' => true]);
        $this->assertDatabaseHas('oauth_refresh_tokens', ['id' => $refreshTokenId, 'revoked' => true]);
        $this->assertDatabaseHas('oauth_auth_codes', ['id' => $authorizationCodeId, 'revoked' => true]);
        $this->assertDatabaseHas('auth_audit_log', [
            'user_id' => $target->id,
            'acting_user_id' => $admin->id,
            'event' => DirectoryAdminService::EVENT_CLIENT_GRANTED,
        ]);
        $this->assertDatabaseHas('auth_audit_log', [
            'user_id' => $target->id,
            'acting_user_id' => $admin->id,
            'event' => DirectoryAdminService::EVENT_CLIENT_REVOKED,
        ]);
    }

    private function client(string $name = 'Example Application'): string
    {
        $id = (string) Str::uuid();
        DB::table('oauth_clients')->insert([
            'id' => $id,
            'name' => $name,
            'secret' => 'secret',
            'redirect_uris' => json_encode(['https://app.example.test/oauth/callback']),
            'grant_types' => json_encode(['authorization_code', 'refresh_token']),
            'revoked' => false,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return $id;
    }

    private function accessToken(User $user, string $clientId): string
    {
        $id = Str::random(80);
        DB::table('oauth_access_tokens')->insert([
            'id' => $id,
            'user_id' => $user->id,
            'client_id' => $clientId,
            'name' => null,
            'scopes' => '[]',
            'revoked' => false,
            'created_at' => now(),
            'updated_at' => now(),
            'expires_at' => now()->addMinutes(5),
        ]);

        return $id;
    }

    private function authorizationCode(User $user, string $clientId): string
    {
        $id = Str::random(80);
        DB::table('oauth_auth_codes')->insert([
            'id' => $id,
            'user_id' => $user->id,
            'client_id' => $clientId,
            'scopes' => '[]',
            'revoked' => false,
            'expires_at' => now()->addMinutes(10),
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
}
