<?php

namespace Tests\Feature;

use BWH\Auth\Models\AuthAuditLog;
use BWH\AuthManager\Http\Middleware\EnsureCredentialVersion;
use BWH\AuthManager\Http\Middleware\RequireRecentPasskeyAuthentication;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\DirectoryAdminService;
use BWH\AuthManager\Services\ProviderAdministrators;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\ClientRepository;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Tests\TestCase;

class ProviderAdministratorsTest extends TestCase
{
    use RefreshDatabase;

    public function test_provider_authority_can_be_granted_and_revoked_without_changing_application_permissions(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $target = User::factory()->create(['user_role' => 'user,access-view:example-app']);
        $password = $target->password;
        $this->recent($admin)->putJson($this->url($target), $this->change($target, true))->assertOk()->assertJsonPath('user.roles', ['user', 'access-view:example-app', 'admin']);
        $this->assertSame(1, $target->fresh()->credential_version);
        $this->assertSame(0, DB::table('oauth_client_grants')->count());
        $this->recent($admin)->putJson($this->url($target), $this->change($target->fresh(), false))->assertOk()->assertJsonPath('user.roles', ['user', 'access-view:example-app']);
        $this->assertSame(2, $target->fresh()->credential_version);
        $this->assertSame($password, $target->fresh()->password);
        $records = AuthAuditLog::query()->where('event', DirectoryAdminService::EVENT_ADMINISTRATOR_CHANGED)->orderBy('id')->get();
        $this->assertCount(2, $records);
        $this->assertSame([$admin->id, $admin->id], $records->pluck('acting_user_id')->all());
        $this->assertSame([$target->id, $target->id], $records->pluck('user_id')->all());
        $this->assertTrue($records[0]->metadata['administrator']);
        $this->assertFalse($records[1]->metadata['administrator']);
    }

    public function test_ordinary_and_application_only_administrators_cannot_elevate_themselves_or_others(): void
    {
        $target = User::factory()->create();
        $this->putJson($this->url($target), $this->change($target, true))->assertUnauthorized();
        foreach (['user', 'user,access-manage:example-app', 'user,access-manage:*'] as $role) {
            $actor = User::factory()->create(['user_role' => $role]);
            $this->recent($actor)->putJson($this->url($target), $this->change($target, true))->assertForbidden();
            $this->recent($actor)->putJson($this->url($actor), $this->change($actor, true))->assertForbidden();
            $this->recent($actor)->postJson('/api/admin/confirm', ['password' => 'password'])->assertForbidden();
        }
        $actor = User::factory()->create(['user_role' => 'admin', 'disabled_at' => now()]);
        $this->recent($actor)->putJson($this->url($target), $this->change($target, true))->assertForbidden();
        $this->assertFalse($target->fresh()->hasRole('admin'));
    }

    public function test_recent_confirmation_is_actor_bound_and_never_accepts_old_or_future_timestamps(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin', 'password' => 'synthetic-administrator-password']);
        $target = User::factory()->create();
        $this->actingAs($admin)->putJson($this->url($target), $this->change($target, true))->assertForbidden();
        foreach ([['user_id' => (string) $admin->id, 'authenticated_at' => now()->subSeconds(301)->timestamp],
            ['user_id' => (string) $admin->id, 'authenticated_at' => now()->addSecond()->timestamp],
            ['user_id' => (string) $target->id, 'authenticated_at' => now()->timestamp]] as $proof) {
            $this->withSession([RequireRecentPasskeyAuthentication::SESSION_KEY => $proof])->putJson($this->url($target), $this->change($target, true))->assertForbidden();
        }
        $this->postJson('/api/admin/confirm', ['password' => 'wrong'])->assertUnprocessable();
        $this->postJson('/api/admin/confirm', ['password' => 'synthetic-administrator-password'])->assertOk();
        $this->putJson($this->url($target), $this->change($target, true))->assertOk();
    }

    public function test_self_demotion_keeps_ordinary_sign_in_and_ends_the_old_administrator_session(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        User::factory()->create(['user_role' => 'admin']);
        $this->recent($admin)->putJson($this->url($admin), $this->change($admin, false))->assertOk()->assertJsonPath('redirect', route('auth-manager.login'));
        $this->assertGuest();
        $this->assertSame(['user'], $admin->fresh()->roleNames());
        $this->assertTrue($admin->fresh()->canLogin());
        $this->actingAs($admin->fresh())->withSession([EnsureCredentialVersion::SESSION_KEY => 0])->getJson('/api/admin/users')->assertUnauthorized();
    }

    public function test_disabled_or_deleted_administrators_do_not_satisfy_recovery_safeguard(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        User::factory()->create(['user_role' => 'admin', 'disabled_at' => now()]);
        User::factory()->create(['user_role' => 'admin', 'deleted_at' => now()]);
        $this->recent($admin)->putJson($this->url($admin), $this->change($admin, false))->assertUnprocessable()->assertJsonValidationErrors('user');
        $this->postJson("/api/admin/users/{$admin->id}/disable")->assertUnprocessable();
        $this->deleteJson("/api/admin/users/{$admin->id}")->assertUnprocessable();
        $this->artisan('auth-manager:user-roles', ['user' => (string) $admin->id, '--remove' => ['admin']])->assertFailed();
        $this->assertTrue($admin->fresh()->hasRole('admin'));
    }

    public function test_disabled_targets_cannot_be_promoted_but_can_have_old_authority_removed(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $disabled = User::factory()->create(['user_role' => 'user', 'disabled_at' => now()]);
        $this->recent($admin)->putJson($this->url($disabled), $this->change($disabled, true))->assertUnprocessable();
        $this->artisan('auth-manager:user-roles', ['user' => (string) $disabled->id, '--add' => ['admin']])->assertFailed();
        $disabled->forceFill(['user_role' => 'admin'])->save();
        $this->putJson($this->url($disabled), $this->change($disabled, false))->assertOk();
        $this->assertNotNull($disabled->fresh()->disabled_at);
        $deleted = User::factory()->create(['deleted_at' => now()]);
        $this->putJson($this->url($deleted), $this->change($deleted, true))->assertNotFound();
    }

    public function test_stale_role_disable_and_delete_requests_fail_explicitly_without_new_audits(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $target = User::factory()->create();
        $old = app(ProviderAdministrators::class)->revision($target);
        $this->artisan('auth-manager:user-roles', ['user' => (string) $target->id, '--add' => ['admin']])->assertSuccessful();
        $this->recent($admin)->putJson($this->url($target), ['administrator' => false, 'expected_revision' => $old])->assertConflict();
        $this->postJson("/api/admin/users/{$target->id}/disable", ['expected_revision' => $old])->assertConflict();
        $this->deleteJson("/api/admin/users/{$target->id}", ['expected_revision' => $old])->assertConflict();
        $this->assertTrue($target->fresh()->hasRole('admin'));
        $this->assertNull($target->fresh()->disabled_at);
        $this->assertSame(0, AuthAuditLog::where('auth_method', 'admin')->count());
    }

    public function test_role_changes_revoke_every_old_session_and_pending_credential_path(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin']);
        $target = User::factory()->create(['remember_token' => 'synthetic-remember-token']);
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Example', ['https://app.example.test/oauth/callback']);
        DB::table('oauth_access_tokens')->insert(['id' => 'synthetic-token', 'user_id' => $target->id, 'client_id' => $client->id, 'scopes' => '[]', 'revoked' => false, 'credential_version' => 0]);
        DB::table('sessions')->insert(['id' => 'synthetic-session', 'user_id' => $target->id, 'payload' => 'unused', 'last_activity' => time()]);
        DB::table('trusted_devices')->insert(['user_id' => $target->id, 'token_hash' => hash('sha256', 'synthetic-device'), 'credential_version' => 0, 'expires_at' => now()->addDay()]);
        DB::table('auth_two_factor_attempts')->insert(['user_id' => $target->id, 'token' => 'synthetic-code-attempt', 'code' => '123456', 'expires_at' => now()->addMinute()]);
        DB::table('password_reset_tokens')->insert(['email' => $target->email, 'token' => 'synthetic-reset']);
        $this->recent($admin)->putJson($this->url($target), $this->change($target, true))->assertOk();
        $this->assertTrue((bool) DB::table('oauth_access_tokens')->value('revoked'));
        $this->assertNull($target->fresh()->remember_token);
        foreach (['sessions', 'trusted_devices', 'auth_two_factor_attempts', 'password_reset_tokens'] as $table) {
            $this->assertSame(0, DB::table($table)->count());
        }
    }

    public function test_actor_authority_is_rechecked_after_locking_even_if_middleware_saw_the_old_role(): void
    {
        $actor = User::factory()->create(['user_role' => 'admin']);
        $target = User::factory()->create();
        $request = Request::create('/api/admin/users');
        DB::table('users')->where('id', $actor->id)->update(['user_role' => 'user', 'credential_version' => 1]);
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Example', ['https://app.example.test/oauth/callback']);
        foreach (['disable', 'tombstone', 'changeAdministrator', 'changeName', 'changeEmail', 'enable', 'resetPassword', 'grantClient', 'revokeClient', 'create'] as $method) {
            try {
                if ($method === 'changeAdministrator') {
                    app(DirectoryAdminService::class)->changeAdministrator($request, $actor, $target, true, app(ProviderAdministrators::class)->revision($target));
                } elseif ($method === 'create') {
                    app(DirectoryAdminService::class)->create($request, $actor, ['name' => 'Synthetic', 'email' => 'new@example.test', 'password' => 'synthetic-password', 'enabled' => true, 'client_ids' => []]);
                } elseif (in_array($method, ['changeName', 'changeEmail', 'resetPassword'], true)) {
                    app(DirectoryAdminService::class)->{$method}($request, $actor, $target, $method === 'changeEmail' ? 'changed@example.test' : 'Changed synthetic value');
                } elseif (in_array($method, ['grantClient', 'revokeClient'], true)) {
                    app(DirectoryAdminService::class)->{$method}($request, $actor, $target, $client);
                } else {
                    app(DirectoryAdminService::class)->{$method}($request, $actor, $target);
                }
                $this->fail('A stale administrator mutation was accepted.');
            } catch (HttpException $failure) {
                $this->assertSame(403, $failure->getStatusCode());
            }
        }
        $this->assertFalse($target->fresh()->hasRole('admin'));
        $this->assertNull($target->fresh()->disabled_at);
    }

    public function test_administrator_confirmation_does_not_refresh_stale_passkey_enrollment_proof(): void
    {
        $admin = User::factory()->create(['user_role' => 'admin', 'password' => 'synthetic-current-password']);
        $target = User::factory()->create();
        $old = ['user_id' => (string) $admin->id, 'authenticated_at' => now()->subMinutes(20)->timestamp];
        $this->actingAs($admin)->withSession([RequireRecentPasskeyAuthentication::SESSION_KEY => $old])
            ->postJson('/api/admin/confirm', ['password' => 'synthetic-current-password'])->assertOk();
        $this->assertSame($old, session(RequireRecentPasskeyAuthentication::SESSION_KEY));
        $this->assertSame((int) $admin->credential_version, session(ProviderAdministrators::CONFIRMATION_KEY)['credential_version']);
        $this->postJson('/api/passkeys/register/options')->assertForbidden();
        $this->putJson($this->url($target), $this->change($target, true))->assertOk();
    }

    public function test_a_password_challenge_started_before_an_admin_reset_cannot_create_a_new_session_afterward(): void
    {
        config(['auth-manager.sign_in.code_after_password' => true, 'auth-manager.sign_in.code_only' => false]);
        $admin = User::factory()->create(['user_role' => 'admin']);
        $target = User::factory()->create(['user_role' => 'admin', 'password' => 'old-synthetic-password']);
        $this->post('/login', ['email' => $target->email, 'password' => 'old-synthetic-password'])->assertRedirect();
        $attempt = DB::table('auth_two_factor_attempts')->where('user_id', $target->id)->sole();
        $this->actingAs($admin)->withSession([EnsureCredentialVersion::SESSION_KEY => 0])
            ->putJson("/api/admin/users/{$target->id}/password", ['password' => 'new-synthetic-password', 'password_confirmation' => 'new-synthetic-password'])->assertOk();
        $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $attempt->token, 'code' => $attempt->code])->assertUnprocessable();
        $this->assertAuthenticatedAs($admin);
        $this->assertSame(0, DB::table('auth_two_factor_attempts')->where('user_id', $target->id)->count());
    }

    public function test_self_password_rotation_clears_old_pending_codes_and_reset_links(): void
    {
        $user = User::factory()->create(['password' => 'old-synthetic-password', 'user_role' => 'user']);
        DB::table('auth_two_factor_attempts')->insert(['user_id' => $user->id, 'token' => 'old-self-attempt', 'code' => '123456', 'expires_at' => now()->addMinute()]);
        DB::table('password_reset_tokens')->insert(['email' => $user->email, 'token' => 'old-self-reset']);
        $this->actingAs($user)->putJson('/settings/password', ['current_password' => 'old-synthetic-password', 'password' => 'new-synthetic-password', 'password_confirmation' => 'new-synthetic-password'])->assertOk();
        $this->assertGuest();
        $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => 'old-self-attempt', 'code' => '123456'])->assertUnprocessable();
        $this->assertSame(0, DB::table('password_reset_tokens')->count());
    }

    private function recent(User $actor): static
    {
        return $this->actingAs($actor)->withSession([
            EnsureCredentialVersion::SESSION_KEY => (int) $actor->credential_version,
            RequireRecentPasskeyAuthentication::SESSION_KEY => ['user_id' => (string) $actor->id, 'authenticated_at' => now()->timestamp],
        ]);
    }

    private function url(User $user): string
    {
        return "/api/admin/users/{$user->id}/provider-administrator";
    }

    /** @return array{administrator: bool, expected_revision: string} */
    private function change(User $user, bool $administrator): array
    {
        return ['administrator' => $administrator, 'expected_revision' => app(ProviderAdministrators::class)->revision($user->fresh())];
    }
}
