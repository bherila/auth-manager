<?php

namespace Tests\Feature;

use BWH\Auth\Mail\TwoFactorLoginMail;
use BWH\Auth\Models\TwoFactorAttempt;
use BWH\AuthManager\Http\Middleware\RequireRecentPasskeyAuthentication;
use BWH\AuthManager\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Testing\TestResponse;
use InvalidArgumentException;
use Tests\TestCase;

/** The per-instance settings that require a code after the password and turn off code-only sign-in. */
final class PasswordSecondFactorTest extends TestCase
{
    use RefreshDatabase;

    private const PASSWORD = 'synthetic-password';

    protected function setUp(): void
    {
        parent::setUp();
        $this->withoutVite();
        Cache::flush();
        Mail::fake();
    }

    public function test_the_defaults_leave_password_sign_in_and_code_only_sign_in_unchanged(): void
    {
        $this->assertFalse(config('auth-manager.sign_in.code_after_password'));
        $this->assertTrue(config('auth-manager.sign_in.code_only'));
        $user = $this->person();

        $this->post('/login', $this->credentials($user))->assertRedirect('/');

        $this->assertAuthenticatedAs($user);
        $this->assertSame(0, TwoFactorAttempt::count());
        Mail::assertNothingSent();

        Auth::logout();
        $this->postJson('/login/email-code', ['email' => $user->email])->assertOk();
        $this->assertSame(1, TwoFactorAttempt::count());
    }

    public function test_a_correct_password_alone_creates_no_session_and_emails_a_code(): void
    {
        $this->requireCode();
        $user = $this->person();

        $this->post('/login', $this->credentials($user))->assertRedirect('/login');

        $this->assertGuest();
        $this->assertFalse(session()->has(RequireRecentPasskeyAuthentication::SESSION_KEY));
        $this->assertNull($user->fresh()->remember_token);
        $this->assertSame(1, TwoFactorAttempt::count());
        Mail::assertSent(TwoFactorLoginMail::class, 1);

        $this->get('/oauth/authorize?client_id=synthetic&response_type=code')->assertForbidden();
        $this->assertGuest();
    }

    public function test_the_login_page_shows_only_the_code_step_until_the_challenge_ends(): void
    {
        $this->requireCode();
        $user = $this->person();
        $this->post('/login', $this->credentials($user));
        $attempt = TwoFactorAttempt::firstOrFail();

        $this->get('/login')->assertOk()
            ->assertSee('data-attempt-token="'.$attempt->token.'"', false)
            ->assertSee('data-email="'.$user->email.'"', false)
            ->assertDontSee('id="password"', false)
            ->assertDontSee('id="passkey-login-mount"', false);

        $attempt->update(['is_used' => true]);

        $this->get('/login')->assertOk()
            ->assertSee('id="password"', false)
            ->assertDontSee('data-attempt-token', false);
    }

    public function test_verifying_the_code_finishes_sign_in_at_the_intended_destination(): void
    {
        $this->requireCode();
        $user = $this->person();
        $this->withSession(['url.intended' => url('/settings')]);
        $this->post('/login', $this->credentials($user));
        $attempt = TwoFactorAttempt::firstOrFail();

        $this->verify($attempt->token, $attempt->code)
            ->assertOk()
            ->assertJsonPath('redirect', url('/settings'));

        $this->assertAuthenticatedAs($user);
        $this->assertTrue(session()->has(RequireRecentPasskeyAuthentication::SESSION_KEY));
        $this->assertFalse(session()->has((string) config('bherila-auth.two_factor.session_user_key')));
        $this->assertTrue($attempt->fresh()->is_used);
        $this->get('/login')->assertOk()->assertSee('id="password"', false);
    }

    public function test_keep_me_signed_in_survives_the_challenge(): void
    {
        $this->requireCode();
        $user = $this->person();
        $this->post('/login', [...$this->credentials($user), 'remember' => '1']);
        $this->assertNull($user->fresh()->remember_token);
        $attempt = TwoFactorAttempt::firstOrFail();

        $this->verify($attempt->token, $attempt->code)->assertOk();

        $this->assertNotNull($user->fresh()->remember_token);
    }

    public function test_a_wrong_code_does_not_sign_in(): void
    {
        $this->requireCode();
        $user = $this->person();
        $this->post('/login', $this->credentials($user));
        $attempt = TwoFactorAttempt::firstOrFail();

        $this->verify($attempt->token, $attempt->code === '000000' ? '000001' : '000000')->assertStatus(422);

        $this->assertGuest();
    }

    public function test_a_wrong_password_and_a_disabled_account_never_open_a_challenge(): void
    {
        $this->requireCode();
        $user = $this->person();

        $this->from('/login')->post('/login', ['email' => $user->email, 'password' => 'not-the-password'])
            ->assertRedirect('/login')
            ->assertSessionHasErrors('email');

        $disabled = $this->person(['disabled_at' => now()]);
        $this->from('/login')->post('/login', $this->credentials($disabled))
            ->assertRedirect('/login')
            ->assertSessionHasErrors('email');

        $this->assertGuest();
        $this->assertSame(0, TwoFactorAttempt::count());
        Mail::assertNothingSent();
    }

    public function test_an_account_disabled_during_the_challenge_cannot_finish_it(): void
    {
        $this->requireCode();
        $user = $this->person();
        $this->post('/login', $this->credentials($user));
        $attempt = TwoFactorAttempt::firstOrFail();

        $user->forceFill(['disabled_at' => now()])->save();

        $this->verify($attempt->token, $attempt->code)->assertStatus(422);
        $this->assertGuest();
    }

    public function test_resending_replaces_the_code_and_a_reload_keeps_the_new_one(): void
    {
        $this->requireCode();
        $user = $this->person();
        $this->post('/login', $this->credentials($user));
        $first = TwoFactorAttempt::firstOrFail();

        $token = $this->postJson('/login/challenge/resend')->assertOk()->json('attempt_token');

        $this->assertNotSame($first->token, $token);
        $this->assertTrue($first->fresh()->is_used);
        $this->get('/login')->assertSee('data-attempt-token="'.$token.'"', false);
        $this->verify($first->token, $first->code)->assertStatus(422);
        $this->assertGuest();

        $next = TwoFactorAttempt::where('token', $token)->firstOrFail();
        $this->verify($token, $next->code)->assertOk();
        $this->assertAuthenticatedAs($user);
    }

    public function test_resending_needs_a_live_challenge_in_this_session(): void
    {
        $this->requireCode();

        $this->postJson('/login/challenge/resend')->assertStatus(422);

        Mail::assertNothingSent();
    }

    public function test_codes_sent_through_the_password_flow_are_limited_per_account(): void
    {
        $this->requireCode();
        $user = $this->person();
        $this->post('/login', $this->credentials($user));
        foreach (range(1, 4) as $ignored) {
            $this->postJson('/login/challenge/resend')->assertOk();
        }

        $this->postJson('/login/challenge/resend')->assertStatus(429);
        $this->from('/login')->post('/login', $this->credentials($user))->assertSessionHasErrors('email');

        Mail::assertSent(TwoFactorLoginMail::class, 5);
    }

    public function test_starting_over_ends_the_challenge(): void
    {
        $this->requireCode();
        $user = $this->person();
        $this->post('/login', $this->credentials($user));
        $attempt = TwoFactorAttempt::firstOrFail();

        $this->postJson('/login/challenge/cancel')->assertOk();

        $this->assertTrue($attempt->fresh()->is_used);
        $this->verify($attempt->token, $attempt->code)->assertStatus(422);
        $this->assertGuest();
        $this->get('/login')->assertSee('id="password"', false);
    }

    public function test_without_javascript_the_code_form_finishes_sign_in(): void
    {
        $this->requireCode();
        $user = $this->person();
        $this->post('/login', $this->credentials($user));
        $attempt = TwoFactorAttempt::firstOrFail();

        $this->get('/login')->assertOk()
            ->assertSee('<noscript>', false)
            ->assertSee('action="/api/auth/two-factor/verify"', false);

        $wrong = $attempt->code === '000000' ? '000001' : '000000';
        $this->post('/api/auth/two-factor/verify', ['attempt_token' => $attempt->token, 'code' => $wrong])
            ->assertRedirect('/login')
            ->assertSessionHasErrors('code');
        $this->assertGuest();

        $this->post('/api/auth/two-factor/verify', ['attempt_token' => $attempt->token, 'code' => $attempt->code])
            ->assertRedirect();
        $this->assertAuthenticatedAs($user);
    }

    public function test_code_only_sign_in_can_be_turned_off_for_every_address(): void
    {
        config(['auth-manager.sign_in.code_only' => false]);
        $user = $this->person();

        $known = $this->postJson('/login/email-code', ['email' => $user->email])->assertNotFound();
        $unknown = $this->postJson('/login/email-code', ['email' => 'unknown@example.test'])->assertNotFound();

        $this->assertSame($unknown->json('message'), $known->json('message'));
        $this->assertSame(0, TwoFactorAttempt::count());
        Mail::assertNothingSent();
    }

    public function test_the_login_page_stops_offering_code_only_sign_in_when_it_is_off(): void
    {
        config(['auth-manager.sign_in.code_only' => false]);
        $user = $this->person();

        $this->get('/login')->assertOk()
            ->assertDontSee('id="email-code-login-mount"', false)
            ->assertSee('id="passkey-login-mount"', false)
            ->assertSee('id="password"', false);

        $this->followingRedirects()
            ->from('/login')
            ->post('/login', ['email' => $user->email, 'password' => 'not-the-password'])
            ->assertSee('Try again.', false)
            ->assertDontSee('sign-in code');
    }

    public function test_both_settings_together_still_finish_through_the_code_step(): void
    {
        $this->requireCode();
        config(['auth-manager.sign_in.code_only' => false]);
        $user = $this->person();

        $this->post('/login', $this->credentials($user));
        $attempt = TwoFactorAttempt::firstOrFail();
        $this->get('/login')->assertSee('id="email-code-login-mount"', false);

        $this->verify($attempt->token, $attempt->code)->assertOk();
        $this->assertAuthenticatedAs($user);
    }

    public function test_a_password_is_rehashed_only_after_it_is_verified(): void
    {
        $this->requireCode();
        $user = $this->person();
        $old = Hash::make(self::PASSWORD, ['rounds' => 5]);
        DB::table('users')->where('id', $user->getKey())->update(['password' => $old]);

        $this->from('/login')->post('/login', ['email' => $user->email, 'password' => 'not-the-password']);
        $this->assertSame($old, $user->fresh()->password);

        $this->post('/login', $this->credentials($user));
        $this->assertNotSame($old, $user->fresh()->password);
        $this->assertTrue(Hash::check(self::PASSWORD, $user->fresh()->password));
    }

    public function test_settings_that_are_not_true_or_false_stop_the_configuration_loading(): void
    {
        foreach (['AUTH_MANAGER_REQUIRE_CODE_AFTER_PASSWORD', 'AUTH_MANAGER_ALLOW_CODE_ONLY_SIGN_IN'] as $name) {
            $previousEnv = $_ENV[$name] ?? null;
            $previousServer = $_SERVER[$name] ?? null;
            try {
                $_ENV[$name] = $_SERVER[$name] = 'maybe';
                try {
                    require config_path('auth-manager.php');
                    $this->fail("{$name} accepted an invalid value.");
                } catch (InvalidArgumentException $exception) {
                    $this->assertStringContainsString($name, $exception->getMessage());
                }
            } finally {
                if ($previousEnv === null) {
                    unset($_ENV[$name]);
                } else {
                    $_ENV[$name] = $previousEnv;
                }
                if ($previousServer === null) {
                    unset($_SERVER[$name]);
                } else {
                    $_SERVER[$name] = $previousServer;
                }
            }
        }
    }

    private function requireCode(): void
    {
        config(['auth-manager.sign_in.code_after_password' => true]);
    }

    /** @param array<string, mixed> $attributes */
    private function person(array $attributes = []): User
    {
        return User::factory()->create([
            'user_role' => 'user',
            'password' => Hash::make(self::PASSWORD),
            'remember_token' => null,
            ...$attributes,
        ]);
    }

    /** @return array{email: string, password: string} */
    private function credentials(User $user): array
    {
        return ['email' => $user->email, 'password' => self::PASSWORD];
    }

    private function verify(string $token, string $code): TestResponse
    {
        return $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $token, 'code' => $code]);
    }
}
