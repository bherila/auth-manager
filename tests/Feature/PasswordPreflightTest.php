<?php

namespace Tests\Feature;

use BWH\Auth\Contracts\AuthAuditLogger;
use BWH\Auth\Contracts\LoginThrottle;
use BWH\Auth\Models\TwoFactorAttempt;
use BWH\Auth\Services\PasswordCredentials;
use BWH\Auth\Support\LoginThrottleState;
use BWH\Auth\Support\PasswordCredentialResult;
use BWH\AuthManager\Http\Middleware\EnsureCredentialVersion;
use BWH\AuthManager\Http\Middleware\RequireRecentPasskeyAuthentication;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\AuthenticationContext;
use Illuminate\Auth\Events\Login;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Mockery;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

class PasswordPreflightTest extends TestCase
{
    use RefreshDatabase;

    public function test_password_endpoint_delegates_to_shared_preflight_with_one_throttle_and_failure_audit(): void
    {
        $this->mock(LoginThrottle::class)->shouldReceive('inspect')->once()->andReturn(LoginThrottleState::allowed(false, 0, 5, null, 'person@example.test', '127.0.0.1', 'password'));
        $this->mock(PasswordCredentials::class)->shouldReceive('verify')->once()
            ->with(Mockery::type(Request::class), ['email' => 'person@example.test', 'password' => 'synthetic-password'])
            ->andReturn(PasswordCredentialResult::invalid());
        $this->mock(AuthAuditLogger::class)->shouldReceive('loginFailed')->once()
            ->with(Mockery::type(Request::class), null, 'person@example.test', 'Invalid credentials', 'password');

        $this->post('/login', ['email' => 'person@example.test', 'password' => 'synthetic-password', 'remember' => true])->assertSessionHasErrors('email');

        $this->assertGuest();
        $this->assertDatabaseCount('auth_two_factor_attempts', 0);
    }

    public function test_denied_credentials_never_open_a_session_or_rehash_before_the_policy_gate(): void
    {
        Event::fake([Login::class]);
        $user = User::factory()->create(['user_role' => 'user', 'disabled_at' => now(), 'remember_token' => null]);
        $old = Hash::make('synthetic-password', ['rounds' => 5]);
        DB::table('users')->where('id', $user->id)->update(['password' => $old]);

        $this->post('/login', ['email' => $user->email, 'password' => 'synthetic-password', 'remember' => true])->assertSessionHasErrors('email');

        $this->assertGuest();
        $this->assertSame($old, $user->fresh()->password);
        $this->assertNull($user->fresh()->remember_token);
        $this->assertFalse(session()->has(RequireRecentPasskeyAuthentication::SESSION_KEY));
        $this->assertDatabaseCount('auth_two_factor_attempts', 0);
        Event::assertNotDispatched(Login::class);
    }

    /** @return array<string, array{bool}> */
    public static function secondFactorModes(): array
    {
        return ['password only' => [false], 'password and code' => [true]];
    }

    #[DataProvider('secondFactorModes')]
    public function test_disabling_rehash_is_respected_in_both_password_modes(bool $secondFactor): void
    {
        Mail::fake();
        config(['hashing.rehash_on_login' => false, 'auth-manager.sign_in.code_after_password' => $secondFactor]);
        $user = User::factory()->create(['user_role' => 'user']);
        $old = Hash::make('synthetic-password', ['rounds' => 5]);
        DB::table('users')->where('id', $user->id)->update(['password' => $old]);

        $this->post('/login', ['email' => $user->email, 'password' => 'synthetic-password'])->assertRedirect($secondFactor ? '/login' : '/');

        $this->assertSame($old, $user->fresh()->password);
        if ($secondFactor) {
            $this->assertGuest();
            $this->assertSame(1, TwoFactorAttempt::count());
        } else {
            $this->assertAuthenticatedAs($user);
        }
    }

    public function test_single_factor_caller_completes_remember_and_authentication_context_after_preflight(): void
    {
        $user = User::factory()->create(['user_role' => 'user', 'password' => 'synthetic-password', 'remember_token' => null, 'credential_version' => 4]);

        $this->post('/login', ['email' => $user->email, 'password' => 'synthetic-password', 'remember' => true])->assertRedirect('/');

        $this->assertAuthenticatedAs($user);
        $this->assertNotNull($user->fresh()->remember_token);
        $this->assertSame(4, session()->get(EnsureCredentialVersion::SESSION_KEY));
        $this->assertTrue(session()->has(RequireRecentPasskeyAuthentication::SESSION_KEY));
        $this->assertSame(['pwd'], session()->get(AuthenticationContext::SESSION_KEY.'.amr'));
        $this->assertDatabaseCount('auth_two_factor_attempts', 0);
    }
}
