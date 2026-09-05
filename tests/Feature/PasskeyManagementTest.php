<?php

namespace Tests\Feature;

use App\Http\Middleware\RequireRecentPasskeyAuthentication;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class PasskeyManagementTest extends TestCase
{
    use RefreshDatabase;

    public function test_passkey_management_page_requires_an_active_authenticated_user(): void
    {
        $this->withoutVite();

        $this->get('/settings/passkeys')->assertRedirect('/login');

        $activeUser = User::factory()->create(['user_role' => 'user']);
        $this->actingAs($activeUser)
            ->get('/settings/passkeys')
            ->assertOk()
            ->assertSee('Manage passkeys')
            ->assertSee('passkey-management-mount', false);

        $disabledUser = User::factory()->create([
            'user_role' => 'user',
            'disabled_at' => now(),
        ]);
        $this->actingAs($disabledUser)
            ->get('/settings/passkeys')
            ->assertForbidden();
    }

    public function test_passkey_registration_requires_a_recent_credential_verification(): void
    {
        $user = User::factory()->create(['user_role' => 'user']);

        $this->postJson('/api/passkeys/register/options')->assertUnauthorized();

        $response = $this->actingAs($user)
            ->postJson('/api/passkeys/register/options')
            ->assertForbidden()
            ->assertJsonPath('message', 'Please sign in again before managing passkeys.');

        $this->assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));

        $this->actingAs($user)
            ->deleteJson('/api/passkeys/1')
            ->assertForbidden()
            ->assertJsonPath('message', 'Please sign in again before managing passkeys.');

        $this->withSession([
            RequireRecentPasskeyAuthentication::SESSION_KEY => now()->subMinutes(11)->getTimestamp(),
        ])->actingAs($user)
            ->postJson('/api/passkeys/register/options')
            ->assertForbidden();

        $this->withSession([
            RequireRecentPasskeyAuthentication::SESSION_KEY => now()->addSecond()->getTimestamp(),
        ])->actingAs($user)
            ->postJson('/api/passkeys/register/options')
            ->assertForbidden();
    }

    public function test_a_fresh_password_login_can_start_passkey_registration(): void
    {
        $user = User::factory()->create([
            'user_role' => 'user',
            'password' => bcrypt('synthetic-password'),
        ]);

        $this->post('/login', [
            'email' => $user->email,
            'password' => 'synthetic-password',
        ])->assertRedirect('/');

        $authenticatedAt = session(RequireRecentPasskeyAuthentication::SESSION_KEY);
        $this->assertIsInt($authenticatedAt);
        $this->assertGreaterThanOrEqual(now()->subSecond()->getTimestamp(), $authenticatedAt);
        $this->assertLessThanOrEqual(now()->getTimestamp(), $authenticatedAt);

        $this->postJson('/api/passkeys/register/options')
            ->assertOk()
            ->assertJsonStructure(['challenge', 'rp', 'user']);
    }
}
