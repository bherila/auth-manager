<?php

namespace Tests\Feature;

use BWH\Auth\Contracts\LocalCredentialPolicy;
use BWH\Auth\Mail\PasswordResetConfirmationMail;
use BWH\Auth\Mail\PasswordResetNoticeMail;
use BWH\Auth\Models\TwoFactorAttempt;
use BWH\AuthManager\Models\User;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Sleep;
use Tests\TestCase;

/** auth-manager#112: forgot-password and reset pages, off unless the instance enables them. */
final class SelfServicePasswordResetTest extends TestCase
{
    use RefreshDatabase;

    private const NEW_PASSWORD = 'a-new-synthetic-password';

    protected function setUp(): void
    {
        parent::setUp();
        $this->withoutVite();
        Cache::flush();
        Mail::fake();
        Sleep::fake();
        config(['auth-manager.sign_in.password_reset' => true]);
    }

    public function test_it_is_off_by_default_and_every_page_answers_404(): void
    {
        config(['auth-manager.sign_in.password_reset' => false]);
        $user = $this->person();

        $this->get('/forgot-password')->assertNotFound();
        $this->post('/forgot-password', ['email' => $user->email])->assertNotFound();
        $this->get('/reset-password/token')->assertNotFound();
        $this->post('/reset-password', $this->resetFields($user, 'token'))->assertNotFound();

        Mail::assertNothingSent();
        $this->get('/login')->assertOk()->assertDontSee('/forgot-password');
    }

    public function test_the_default_comes_from_the_shipped_configuration(): void
    {
        $this->assertFalse((require base_path('config/auth-manager.php'))['sign_in']['password_reset']);
    }

    public function test_the_package_reset_routes_stay_off(): void
    {
        $user = $this->person();

        $this->postJson('/api/auth/forgot-password', ['email' => $user->email])->assertNotFound();
        $this->postJson('/api/auth/reset-password', $this->resetFields($user, 'token'))->assertNotFound();
    }

    public function test_the_login_page_links_to_the_reset_page_without_javascript(): void
    {
        $this->get('/login')->assertOk()->assertSee('/forgot-password"', false)->assertDontSee('id="forgot-password"', false);
    }

    public function test_known_and_unknown_addresses_get_the_same_answer(): void
    {
        $user = $this->person();

        $known = $this->from('/forgot-password')->post('/forgot-password', ['email' => $user->email]);
        $unknown = $this->from('/forgot-password')->post('/forgot-password', ['email' => 'nobody@example.test']);

        $known->assertRedirect('/forgot-password')->assertSessionHas('status');
        $unknown->assertRedirect('/forgot-password')->assertSessionHas('status', $known->getSession()->get('status'));
        Mail::assertSent(PasswordResetConfirmationMail::class, 1);
    }

    public function test_a_failed_send_gets_the_same_answer(): void
    {
        $user = $this->person();
        Mail::shouldReceive('to')->andThrow(new \RuntimeException('Synthetic mail failure'));

        $this->from('/forgot-password')->post('/forgot-password', ['email' => $user->email])
            ->assertRedirect('/forgot-password')
            ->assertSessionHas('status');
    }

    public function test_the_emailed_link_uses_the_configured_address_not_the_request_host(): void
    {
        config(['bherila-auth.password_resets.reset_url' => 'https://id.example.test/reset-password/{token}?email={email}']);
        $user = $this->person();

        $this->withHeader('Host', 'attacker.example.test')->post('/forgot-password', ['email' => $user->email]);

        Mail::assertSent(PasswordResetConfirmationMail::class, fn (PasswordResetConfirmationMail $mail): bool => str_starts_with($mail->resetUrl, 'https://id.example.test/reset-password/'));
    }

    public function test_requests_are_limited_per_address_whether_or_not_it_has_an_account(): void
    {
        foreach (['person@example.test', 'nobody@example.test'] as $email) {
            for ($i = 0; $i < 3; $i++) {
                $this->from('/forgot-password')->post('/forgot-password', ['email' => $email])->assertSessionHas('status');
            }
            $this->from('/forgot-password')->post('/forgot-password', ['email' => $email])
                ->assertRedirect('/forgot-password')
                ->assertSessionHasErrors('email');
        }
    }

    public function test_requests_and_completions_are_limited_per_ip(): void
    {
        for ($i = 0; $i < 10; $i++) {
            $this->from('/forgot-password')->post('/forgot-password', ['email' => "person{$i}@example.test"])->assertSessionHas('status');
        }
        $this->from('/forgot-password')->post('/forgot-password', ['email' => 'another@example.test'])->assertSessionHasErrors('email');

        for ($i = 0; $i < 10; $i++) {
            $this->from('/reset-password/token')->post('/reset-password', ['token' => 'token', 'email' => "person{$i}@example.test"]);
        }
        $this->from('/reset-password/token')
            ->post('/reset-password', ['token' => 'token', 'email' => 'another@example.test', 'password' => self::NEW_PASSWORD, 'password_confirmation' => self::NEW_PASSWORD])
            ->assertSessionHasErrors(['email' => 'Too many password reset attempts. Please try again later.']);
    }

    public function test_completions_are_limited_per_address(): void
    {
        $user = $this->person();
        for ($i = 0; $i < 10; $i++) {
            $this->from('/reset-password/token')->post('/reset-password', ['token' => 'token', 'email' => $user->email]);
        }

        $this->from('/reset-password/token')->withServerVariables(['REMOTE_ADDR' => '198.51.100.7'])
            ->post('/reset-password', $this->resetFields($user, 'token'))
            ->assertSessionHasErrors(['email' => 'Too many password reset attempts. Please try again later.']);
    }

    public function test_a_completed_reset_creates_no_session_and_returns_to_login(): void
    {
        $user = $this->person();

        $this->post('/reset-password', $this->resetFields($user, $this->tokenFor($user)))
            ->assertRedirect('/login')
            ->assertSessionHas('status');

        $this->assertGuest();
        $this->assertTrue(Hash::check(self::NEW_PASSWORD, $user->fresh()->password));
        Mail::assertSent(PasswordResetNoticeMail::class, fn (PasswordResetNoticeMail $mail): bool => $mail->hasTo($user->email));
        $this->assertDatabaseHas('auth_audit_log', ['user_id' => $user->id, 'event' => 'password_reset_completed']);
    }

    public function test_a_reset_still_returns_through_the_second_factor(): void
    {
        config(['auth-manager.sign_in.code_after_password' => true]);
        $user = $this->person();
        $this->post('/reset-password', $this->resetFields($user, $this->tokenFor($user)))->assertRedirect('/login');

        $this->post('/login', ['email' => $user->email, 'password' => self::NEW_PASSWORD])->assertRedirect('/login');

        $this->assertGuest();
        $this->assertSame(1, TwoFactorAttempt::count());
    }

    public function test_a_signed_in_browser_is_signed_out_by_the_reset(): void
    {
        $user = $this->person();

        $this->actingAs($user)->post('/reset-password', $this->resetFields($user, $this->tokenFor($user)))->assertRedirect('/login');

        $this->assertGuest();
    }

    public function test_a_reset_ends_earlier_sessions_remember_me_and_oauth_credentials(): void
    {
        $user = $this->person();
        $user->forceFill(['remember_token' => 'synthetic-remember-token'])->save();
        DB::table('sessions')->insert(['id' => 'synthetic-session', 'user_id' => $user->id, 'payload' => '', 'last_activity' => now()->timestamp]);
        $version = (int) $user->credential_version;
        DB::table('oauth_access_tokens')->insert(['id' => 'synthetic-token', 'user_id' => $user->id, 'client_id' => '00000000-0000-0000-0000-000000000000', 'revoked' => false]);

        $this->post('/reset-password', $this->resetFields($user, $this->tokenFor($user)))->assertRedirect('/login');

        $fresh = $user->fresh();
        $this->assertSame($version + 1, (int) $fresh->credential_version);
        $this->assertNotSame('synthetic-remember-token', $fresh->remember_token);
        $this->assertDatabaseMissing('sessions', ['id' => 'synthetic-session']);
        $this->assertSame(1, (int) DB::table('oauth_access_tokens')->where('id', 'synthetic-token')->value('revoked'));
    }

    public function test_a_code_requested_with_the_old_password_cannot_finish_after_a_reset(): void
    {
        config(['auth-manager.sign_in.code_after_password' => true]);
        $user = $this->person();
        $this->post('/login', ['email' => $user->email, 'password' => 'synthetic-password']);
        $this->assertSame(1, TwoFactorAttempt::count());

        $this->post('/reset-password', $this->resetFields($user, $this->tokenFor($user)))->assertRedirect('/login');

        $this->assertSame(0, TwoFactorAttempt::count());
    }

    public function test_a_token_cannot_be_used_twice(): void
    {
        $user = $this->person();
        $token = $this->tokenFor($user);
        $this->post('/reset-password', $this->resetFields($user, $token))->assertRedirect('/login');

        $this->from("/reset-password/{$token}")
            ->post('/reset-password', [...$this->resetFields($user, $token), 'password' => 'another-synthetic-password', 'password_confirmation' => 'another-synthetic-password'])
            ->assertSessionHasErrors('email');

        $this->assertTrue(Hash::check(self::NEW_PASSWORD, $user->fresh()->password));
    }

    public function test_a_bad_token_and_an_unknown_address_get_the_same_error(): void
    {
        $user = $this->person();

        $invalid = ['email' => 'This password reset link is invalid or has expired. Request a new one.'];

        $this->from('/reset-password/token')->post('/reset-password', $this->resetFields($user, 'wrong-token'))->assertSessionHasErrors($invalid);
        $this->from('/reset-password/token')->post('/reset-password', [...$this->resetFields($user, 'wrong-token'), 'email' => 'nobody@example.test'])->assertSessionHasErrors($invalid);
        $this->assertTrue(Hash::check('synthetic-password', $user->fresh()->password));
    }

    public function test_a_token_from_before_an_account_became_ineligible_cannot_set_a_password(): void
    {
        $user = $this->person();
        $token = $this->tokenFor($user);
        $this->refuseLocalCredentials();

        $this->from("/reset-password/{$token}")->post('/reset-password', $this->resetFields($user, $token))->assertSessionHasErrors('email');

        $this->assertTrue(Hash::check('synthetic-password', $user->fresh()->password));
        $this->assertSame(0, (int) $user->fresh()->credential_version);
        Mail::assertNotSent(PasswordResetNoticeMail::class);
    }

    public function test_an_ineligible_account_gets_no_link_and_the_same_answer(): void
    {
        $user = $this->person();
        $this->refuseLocalCredentials();

        $this->from('/forgot-password')->post('/forgot-password', ['email' => $user->email])->assertSessionHas('status');

        Mail::assertNothingSent();
    }

    public function test_a_disabled_account_can_reset_but_still_cannot_sign_in(): void
    {
        $user = $this->person();
        $user->forceFill(['disabled_at' => now()])->save();

        $this->post('/forgot-password', ['email' => $user->email]);
        Mail::assertSent(PasswordResetConfirmationMail::class, 1);

        $this->post('/reset-password', $this->resetFields($user, $this->tokenFor($user)))->assertRedirect('/login');
        $this->assertTrue(Hash::check(self::NEW_PASSWORD, $user->fresh()->password));

        $this->post('/login', ['email' => $user->email, 'password' => self::NEW_PASSWORD]);
        $this->assertGuest();
    }

    public function test_the_minimum_password_length_is_enforced_on_the_page_and_the_server(): void
    {
        config(['auth-manager.password_min_length' => 20]);
        $user = $this->person();
        $token = $this->tokenFor($user);

        $this->get("/reset-password/{$token}?email=".urlencode($user->email))->assertOk()->assertSee('minlength="20"', false);

        $this->from("/reset-password/{$token}")
            ->post('/reset-password', [...$this->resetFields($user, $token), 'password' => 'short-password', 'password_confirmation' => 'short-password'])
            ->assertSessionHasErrors('password');
        $this->assertTrue(Hash::check('synthetic-password', $user->fresh()->password));
    }

    public function test_a_password_over_72_bytes_is_refused_even_within_72_characters(): void
    {
        $user = $this->person();
        $token = $this->tokenFor($user);
        $password = str_repeat('é', 40);

        $this->get("/reset-password/{$token}")->assertOk()->assertSee('maxlength="72"', false);
        $this->from("/reset-password/{$token}")
            ->post('/reset-password', [...$this->resetFields($user, $token), 'password' => $password, 'password_confirmation' => $password])
            ->assertSessionHasErrors(['password' => 'The password must use at most 72 UTF-8 bytes.']);

        $this->assertTrue(Hash::check('synthetic-password', $user->fresh()->password));
    }

    public function test_a_link_sent_to_an_earlier_address_cannot_reach_whoever_has_it_now(): void
    {
        $original = $this->person();
        $token = $this->tokenFor($original);
        $original->update(['email' => 'moved@example.test']);
        $replacement = User::factory()->create(['email' => 'person@example.test', 'password' => 'replacement-password', 'user_role' => 'user']);

        $this->from("/reset-password/{$token}")->post('/reset-password', $this->resetFields($replacement, $token))->assertSessionHasErrors('email');

        $this->assertTrue(Hash::check('replacement-password', $replacement->fresh()->password));
    }

    public function test_a_link_is_cancelled_when_the_address_changes(): void
    {
        $user = $this->person();
        $this->tokenFor($user);

        $user->update(['email' => 'moved@example.test']);

        $this->assertDatabaseCount('password_reset_tokens', 0);
    }

    public function test_a_signed_in_person_is_not_blocked_by_the_passkey_recency_check(): void
    {
        $user = $this->person();

        $this->actingAs($user)->from('/forgot-password')->post('/forgot-password', ['email' => $user->email])->assertSessionHas('status');
        Mail::assertSent(PasswordResetConfirmationMail::class, 1);
    }

    private function person(): User
    {
        return User::factory()->create(['email' => 'person@example.test', 'password' => 'synthetic-password', 'user_role' => 'user']);
    }

    private function tokenFor(User $user): string
    {
        return Password::broker()->createToken($user);
    }

    /** @return array<string, string> */
    private function resetFields(User $user, string $token): array
    {
        return ['token' => $token, 'email' => $user->email, 'password' => self::NEW_PASSWORD, 'password_confirmation' => self::NEW_PASSWORD];
    }

    private function refuseLocalCredentials(): void
    {
        $this->app->instance(LocalCredentialPolicy::class, new class implements LocalCredentialPolicy
        {
            public function mayUseLocalCredentials(Authenticatable $user, Request $request): bool
            {
                return false;
            }
        });
    }
}
