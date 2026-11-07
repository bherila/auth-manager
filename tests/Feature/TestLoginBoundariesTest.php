<?php

namespace Tests\Feature;

use BWH\AuthManager\Http\Middleware\EnsureCredentialVersion;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\DirectoryCopy\DirectoryArchive;
use BWH\AuthManager\Services\DirectoryCopy\DirectoryTransfer;
use BWH\AuthManager\Services\IdentityRetirement;
use BWH\AuthManager\Services\ProviderAdministrators;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;
use InvalidArgumentException;
use Tests\TestCase;

final class TestLoginBoundariesTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        $this->withoutVite();
        config(['app.key' => 'base64:'.base64_encode(str_repeat('k', 32))]);
    }

    public function test_flags_are_not_mass_assignable_http_writable_or_exposed_in_default_json(): void
    {
        $ordinary = new User;
        $ordinary->fill(['is_test_login' => true, 'test_login_expires_at' => now()->addHour()]);
        $this->assertFalse($ordinary->isTestLogin());
        $this->assertNull($ordinary->test_login_expires_at);
        $flagged = $this->syntheticUser();
        $this->assertArrayNotHasKey('is_test_login', $flagged->toArray());
        $this->assertArrayNotHasKey('test_login_expires_at', $flagged->toArray());

        $this->asAdministrator()->postJson('/api/admin/users', [
            'name' => 'Ordinary synthetic person', 'email' => 'ordinary@example.test',
            'password' => 'synthetic-long-password', 'password_confirmation' => 'synthetic-long-password',
            'enabled' => true, 'client_ids' => [], 'is_test_login' => true,
            'test_login_expires_at' => now()->addHour()->toIso8601String(), 'user_role' => 'admin',
        ])->assertCreated();
        $created = User::where('email', 'ordinary@example.test')->firstOrFail();
        $this->assertFalse($created->isTestLogin());
        $this->assertNull($created->test_login_expires_at);
        $this->assertSame(['user'], $created->roleNames());
    }

    public function test_existing_identities_cannot_be_converted_or_promoted_into_a_permanent_administrator(): void
    {
        $flagged = $this->syntheticUser();
        $ordinary = User::factory()->create();
        $this->refuses(fn () => $ordinary->forceFill(['is_test_login' => true, 'test_login_expires_at' => now()->addHour()])->save());
        $this->assertFalse($ordinary->fresh()->isTestLogin());
        $this->refuses(fn () => $flagged->forceFill(['is_test_login' => false])->save());
        $flagged->refresh();
        $this->refuses(fn () => $flagged->forceFill(['user_role' => 'admin,user'])->save());
        $flagged->refresh();
        $this->artisan('auth-manager:user-roles', ['user' => (string) $flagged->id, '--add' => ['admin']])
            ->expectsOutputToContain('Test logins cannot hold provider-administrator authority.')->assertFailed();
        $this->asAdministrator()->putJson('/api/admin/users/'.$flagged->id.'/provider-administrator', [
            'administrator' => true, 'expected_revision' => app(ProviderAdministrators::class)->revision($flagged),
        ])->assertUnprocessable();
        $this->assertSame(['user'], $flagged->fresh()->roleNames());
        $this->assertTrue($flagged->fresh()->isTestLogin());
    }

    public function test_invalid_test_login_states_fail_closed_and_can_still_be_retired(): void
    {
        $user = $this->syntheticUser();
        foreach ([['test_login_expires_at' => null], ['test_login_expires_at' => now()->subSecond()],
            ['disabled_at' => now()], ['user_role' => 'admin'], ['email' => 'not-an-email-address']] as $state) {
            DB::table('users')->where('id', $user->id)->update([
                'test_login_expires_at' => now()->addHour(), 'disabled_at' => null,
                'user_role' => 'user', 'email' => 'synthetic@example.test', ...$state,
            ]);
            $this->assertFalse($user->fresh()->canLogin());
        }
        // A revoked domain/invalid address must not prevent permanent cleanup.
        $user->refresh();
        DB::transaction(function () use ($user): void {
            app(ProviderAdministrators::class)->lockDirectory();
            app(IdentityRetirement::class)->retire($user);
        });
        $this->assertTrue($user->fresh()->trashed());
        $this->assertDatabaseHas('identity_tombstones', ['subject' => $user->id]);
    }

    public function test_an_administrator_cannot_move_a_test_login_to_a_non_synthetic_address(): void
    {
        $user = $this->syntheticUser();
        $this->refuses(fn () => $user->forceFill(['email' => 'invalid-address'])->save());
        $this->assertSame('synthetic@example.test', $user->fresh()->email);
    }

    public function test_live_test_logins_cannot_escape_expiry_through_selected_or_portable_exports(): void
    {
        $user = $this->syntheticUser();
        $this->assertSame(1, Artisan::call('identity:export', ['--subject' => [(string) $user->id]]));
        $this->assertStringContainsString('test logins cannot be copied', Artisan::output());
        $this->assertStringNotContainsString('"password"', Artisan::output());
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Retire all test logins');
        app(DirectoryTransfer::class)->snapshot();
    }

    public function test_portable_retired_subjects_keep_their_tombstone_and_cannot_become_permanent_logins(): void
    {
        $user = $this->syntheticUser();
        DB::transaction(function () use ($user): void {
            app(ProviderAdministrators::class)->lockDirectory();
            app(IdentityRetirement::class)->retire($user);
        });
        $snapshot = app(DirectoryTransfer::class)->snapshot();
        $row = DirectoryArchive::unpackRow($snapshot['tables']['users'][0]);
        $this->assertNotNull($row['deleted_at']);
        $this->assertNotEmpty($snapshot['tables']['identity_tombstones']);

        config(['database.connections.test-login-copy-target' => ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '', 'foreign_key_constraints' => true]]);
        DB::setDefaultConnection('test-login-copy-target');
        config(['passport.connection' => 'test-login-copy-target']);
        try {
            $this->artisan('migrate', ['--database' => 'test-login-copy-target', '--force' => true])->assertSuccessful();
            app(DirectoryTransfer::class)->import(hash('sha256', 'synthetic-retired-archive'), $snapshot, true);
            $copy = User::withTrashed()->findOrFail($user->id);
            $this->assertTrue($copy->trashed());
            $this->assertFalse($copy->canLogin());
            $this->assertDatabaseHas('identity_tombstones', ['subject' => $user->id]);
            $this->artisan('auth-manager:user-roles', ['user' => (string) $copy->id, '--add' => ['admin']])->assertFailed();
        } finally {
            DB::setDefaultConnection('sqlite');
            config(['passport.connection' => null]);
            DB::purge('test-login-copy-target');
        }
    }

    private function syntheticUser(): User
    {
        $user = User::factory()->make(['email' => 'synthetic@example.test', 'user_role' => 'user']);
        $user->forceFill(['is_test_login' => true, 'test_login_expires_at' => now()->addHour()])->save();

        return $user;
    }

    private function asAdministrator(): static
    {
        $admin = User::factory()->create(['user_role' => 'admin']);

        return $this->actingAs($admin)->withSession([
            EnsureCredentialVersion::SESSION_KEY => (int) $admin->credential_version,
            ProviderAdministrators::CONFIRMATION_KEY => ['user_id' => (string) $admin->id,
                'credential_version' => (int) $admin->credential_version, 'authenticated_at' => now()->timestamp],
        ]);
    }

    private function refuses(callable $action): void
    {
        try {
            $action();
            $this->fail('The test-login boundary accepted an unsafe transition.');
        } catch (ValidationException $exception) {
            $this->assertNotEmpty($exception->errors());
        }
    }
}
