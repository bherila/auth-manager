<?php

namespace Tests\Feature;

use App\Http\Middleware\EnsureCredentialVersion;
use App\Models\User;
use BWH\Auth\Models\AuthAuditLog;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Tests\TestCase;

class AccountSettingsTest extends TestCase
{
    use RefreshDatabase;

    private function person(): User
    {
        return User::factory()->create(['name' => 'Example Person', 'email' => 'person@example.test', 'user_role' => 'user', 'password' => 'current-example-password']);
    }

    private function passwordData(): array
    {
        return ['current_password' => 'current-example-password', 'password' => 'new-example-password', 'password_confirmation' => 'new-example-password'];
    }

    public function test_account_hub_requires_active_session_and_exposes_only_readonly_profile(): void
    {
        $this->withoutVite()->get('/settings')->assertRedirect('/login');
        $user = $this->person();
        $this->actingAs($user)->get('/settings?return_url=https://untrusted.example.test')
            ->assertOk()->assertSee('Example Person')->assertSee('person@example.test')
            ->assertSee('Manage passkeys')->assertSee('Contact an administrator')
            ->assertDontSee('untrusted.example.test')->assertHeader('Cache-Control', 'no-store, private');
        $this->actingAs($user)->patchJson('/settings', ['email' => 'other@example.test'])->assertMethodNotAllowed();
        $user->update(['disabled_at' => now()]);
        $this->actingAs($user)->get('/settings')->assertForbidden();
        $this->putJson('/settings/password', $this->passwordData())->assertForbidden();
    }

    public function test_password_change_revokes_credentials_and_sessions_without_touching_another_person(): void
    {
        $user = $this->person();
        $other = User::factory()->create(['password' => 'other-example-password']);
        $clientId = (string) Str::uuid();
        DB::table('oauth_clients')->insert(['id' => $clientId, 'name' => 'Example App', 'secret' => 'synthetic-secret', 'redirect_uris' => '[]', 'grant_types' => '[]', 'revoked' => false]);
        foreach ([$user, $other] as $person) {
            DB::table('oauth_access_tokens')->insert(['id' => 'access-'.$person->id, 'user_id' => $person->id, 'client_id' => $clientId, 'scopes' => '[]', 'revoked' => false]);
            DB::table('oauth_refresh_tokens')->insert(['id' => 'refresh-'.$person->id, 'access_token_id' => 'access-'.$person->id, 'revoked' => false]);
            DB::table('oauth_auth_codes')->insert(['id' => 'code-'.$person->id, 'user_id' => $person->id, 'client_id' => $clientId, 'scopes' => '[]', 'revoked' => false, 'expires_at' => now()->addMinute()]);
        }
        DB::table('sessions')->insert(['id' => 'other-device-session', 'user_id' => $user->id, 'payload' => '', 'last_activity' => time()]);
        $this->actingAs($user)->withSession(['sentinel' => 'private-session-state'])->putJson('/settings/password', $this->passwordData() + ['user_id' => $other->id])
            ->assertOk()->assertJsonPath('success', true)->assertSessionMissing('sentinel');
        $this->assertGuest();
        $this->assertTrue(Hash::check('new-example-password', $user->fresh()->password));
        $this->assertFalse(Hash::check('current-example-password', $user->fresh()->password));
        $this->assertSame(1, $user->fresh()->credential_version);
        foreach (['oauth_access_tokens' => 'access-', 'oauth_refresh_tokens' => 'refresh-', 'oauth_auth_codes' => 'code-'] as $table => $prefix) {
            $this->assertDatabaseHas($table, ['id' => $prefix.$user->id, 'revoked' => true]);
            $this->assertDatabaseHas($table, ['id' => $prefix.$other->id, 'revoked' => false]);
        }
        $this->assertTrue(Hash::check('other-example-password', $other->fresh()->password));
        $this->assertDatabaseMissing('sessions', ['id' => 'other-device-session']);
        $audit = AuthAuditLog::where('event', 'self_password_changed')->sole();
        $this->assertSame((string) $user->id, (string) $audit->user_id);
        $this->assertSame('password', $audit->auth_method);
        $this->assertStringNotContainsString('example-password', $audit->toJson());
        $this->actingAs($user->fresh())->withSession([EnsureCredentialVersion::SESSION_KEY => 0])->getJson('/settings')->assertUnauthorized();
    }

    public function test_current_password_and_confirmation_are_required_and_secrets_are_not_flashed(): void
    {
        $user = $this->person();
        $this->actingAs($user)->putJson('/settings/password', array_replace($this->passwordData(), ['current_password' => 'wrong']))->assertUnprocessable()->assertJsonValidationErrors('current_password');
        $this->putJson('/settings/password', array_replace($this->passwordData(), ['password_confirmation' => 'different']))->assertUnprocessable()->assertJsonValidationErrors('password');
        $this->putJson('/settings/password', array_replace($this->passwordData(), ['password' => 'short', 'password_confirmation' => 'short']))->assertUnprocessable()->assertJsonValidationErrors('password');
        $this->assertSame(0, $user->fresh()->credential_version);
        $this->assertTrue(Hash::check('current-example-password', $user->fresh()->password));
        $this->assertSame(0, AuthAuditLog::where('event', 'self_password_changed')->count());
    }

    public function test_password_mutation_requires_csrf_and_does_not_flash_credentials(): void
    {
        $user = $this->person();
        $this->app['env'] = 'production';
        $this->actingAs($user)->putJson('/settings/password', $this->passwordData())->assertStatus(419);
        $this->assertSame(0, $user->fresh()->credential_version);
        $this->app['env'] = 'testing';
        $this->from('/settings')->put('/settings/password', array_replace($this->passwordData(), ['current_password' => 'wrong']))
            ->assertRedirect('/settings')->assertSessionMissing('_old_input.current_password')->assertSessionMissing('_old_input.password')->assertSessionMissing('_old_input.password_confirmation');
    }

    public function test_password_change_rechecks_current_database_credentials_and_account_status(): void
    {
        $user = $this->person();
        $this->actingAs($user);
        User::whereKey($user->id)->update(['password' => Hash::make('administrator-replacement')]);
        $this->putJson('/settings/password', $this->passwordData())->assertUnprocessable()->assertJsonValidationErrors('current_password');
        User::whereKey($user->id)->update(['disabled_at' => now()]);
        $this->putJson('/settings/password', $this->passwordData())->assertForbidden();
        $this->assertSame(0, $user->fresh()->credential_version);
    }

    public function test_password_confirmation_attempts_are_throttled(): void
    {
        $this->actingAs($this->person());
        for ($i = 0; $i < 5; $i++) {
            $this->putJson('/settings/password', array_replace($this->passwordData(), ['current_password' => 'wrong']))->assertUnprocessable();
        }
        $this->putJson('/settings/password', $this->passwordData())->assertTooManyRequests();
    }

    public function test_old_password_stops_authenticating_and_new_password_starts_a_current_session(): void
    {
        $user = $this->person();
        $this->actingAs($user)->putJson('/settings/password', $this->passwordData())->assertOk();
        $this->post('/login', ['email' => $user->email, 'password' => 'current-example-password'])->assertSessionHasErrors('email');
        $this->assertGuest();
        $this->post('/login', ['email' => $user->email, 'password' => 'new-example-password'])->assertRedirect('/');
        $this->assertAuthenticatedAs($user);
        $this->assertSame(1, session(EnsureCredentialVersion::SESSION_KEY));
    }

    public function test_multibyte_passwords_exceeding_bcrypt_limit_are_validation_errors(): void
    {
        $this->actingAs($this->person())->putJson('/settings/password', [
            'current_password' => 'current-example-password',
            'password' => str_repeat('é', 40),
            'password_confirmation' => str_repeat('é', 40),
        ])->assertUnprocessable()->assertJsonValidationErrors('password');
    }
}
