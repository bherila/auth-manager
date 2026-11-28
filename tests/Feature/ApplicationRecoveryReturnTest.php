<?php

namespace Tests\Feature;

use BWH\Auth\Mail\PasswordResetConfirmationMail;
use BWH\Auth\Mail\TwoFactorLoginMail;
use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Models\RegisteredApplication;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\OAuthClientGrantService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Sleep;
use Illuminate\Support\Str;
use Tests\TestCase;

final class ApplicationRecoveryReturnTest extends TestCase
{
    use RefreshDatabase;

    private const PASSWORD = 'new-synthetic-password';

    protected function setUp(): void
    {
        parent::setUp();
        $this->withoutVite();
        Mail::fake();
        Sleep::fake();
        config(['auth-manager.sign_in.password_reset' => true,
            'auth-manager.sign_in.code_after_password' => true,
            'bherila-auth.password_resets.reset_url' => 'http://localhost/reset-password/{token}?email={email}']);
    }

    public function test_application_recovery_email_survives_a_fresh_browser_and_still_requires_second_factor(): void
    {
        [$client, $application] = $this->application();
        $user = User::factory()->create(['email' => 'person@example.test', 'password' => 'old-synthetic-password', 'user_role' => 'user']);
        app(OAuthClientGrantService::class)->grant((string) $user->id, (string) $client->id);
        $this->get('/forgot-password?client_id='.$client->id)->assertOk()->assertSee('name="client_id"', false);
        $this->post('/forgot-password', ['email' => $user->email, 'client_id' => $client->id])->assertRedirect();
        $mail = Mail::sent(PasswordResetConfirmationMail::class)->sole();
        parse_str((string) parse_url($mail->resetUrl, PHP_URL_QUERY), $query);
        $this->assertSame((string) $client->id, $query['client_id'] ?? null);

        // Opening the email in a different browser must not depend on the old OAuth session.
        Auth::forgetGuards();
        session()->flush();
        $this->get($mail->resetUrl)->assertOk()->assertSee('value="'.$client->id.'"', false);
        $token = basename(parse_url($mail->resetUrl, PHP_URL_PATH));
        $this->post('/reset-password', ['email' => $user->email, 'token' => $token,
            'password' => self::PASSWORD, 'password_confirmation' => self::PASSWORD, 'client_id' => $query['client_id']])
            ->assertRedirect('/login');
        $this->assertGuest();
        $this->post('/login', ['email' => $user->email, 'password' => self::PASSWORD])->assertRedirect('/login');
        $this->assertGuest();
        $challenge = Mail::sent(TwoFactorLoginMail::class)->sole()->attempt;
        $verify = $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $challenge->token, 'code' => $challenge->code])->assertOk();
        $this->assertAuthenticatedAs($user);
        $destination = $verify->json('redirect');
        $this->assertStringStartsWith(route('auth-manager.sign-in-return').'?', $destination);
        $this->get($destination)->assertRedirect($application->launch_url);
    }

    public function test_recovery_from_an_existing_oauth_request_carries_only_a_registered_client(): void
    {
        [$client] = $this->application();
        $intended = url('/oauth/authorize').'?'.http_build_query(['client_id' => $client->id,
            'redirect_uri' => 'https://app.example.test/oauth/callback', 'state' => 'old-state']);
        $this->withSession(['url.intended' => $intended])->get('/forgot-password')
            ->assertSee('value="'.$client->id.'"', false);
        $this->assertSame($intended, session('url.intended'));
    }

    public function test_direct_provider_recovery_and_login_keep_the_provider_destination(): void
    {
        config(['auth-manager.sign_in.code_after_password' => false]);
        $user = User::factory()->create(['email' => 'person@example.test', 'password' => self::PASSWORD, 'user_role' => 'user']);
        $this->get('/forgot-password')->assertOk()->assertDontSee('name="client_id"', false);
        $this->post('/forgot-password', ['email' => $user->email]);
        $this->assertStringNotContainsString('client_id', Mail::sent(PasswordResetConfirmationMail::class)->sole()->resetUrl);
        $this->post('/login', ['email' => $user->email, 'password' => self::PASSWORD])->assertRedirect(route('auth-manager.home'));
    }

    public function test_return_rechecks_current_grant_client_and_application_without_accepting_a_browser_url(): void
    {
        [$client, $application] = $this->application();
        $user = User::factory()->create(['user_role' => 'user']);
        $url = '/sign-in-return?'.http_build_query(['client_id' => $client->id, 'return_url' => 'https://attacker.example.test']);
        $this->actingAs($user)->get($url)->assertRedirect(route('auth-manager.home'));
        app(OAuthClientGrantService::class)->grant((string) $user->id, (string) $client->id);
        $this->get($url)->assertRedirect($application->launch_url);
        $client->update(['revoked' => true]);
        $this->get($url)->assertRedirect(route('auth-manager.home'));
        $client->update(['revoked' => false]);
        $application->update(['enabled' => false]);
        $this->get($url)->assertRedirect(route('auth-manager.home'));
    }

    public function test_invalid_client_input_and_foreign_oauth_intent_are_ignored(): void
    {
        [$client] = $this->application();
        foreach (['client_id[]=invalid', 'client_id=https://attacker.example.test', 'client_id=missing'] as $query) {
            $this->get('/forgot-password?'.$query)->assertOk()->assertDontSee('name="client_id"', false);
        }
        $this->withSession(['url.intended' => 'https://attacker.example.test/oauth/authorize?'.http_build_query([
            'client_id' => $client->id, 'redirect_uri' => 'https://app.example.test/oauth/callback'])])
            ->get('/forgot-password')->assertOk()->assertDontSee('name="client_id"', false);
    }

    public function test_back_to_sign_in_restarts_the_application_instead_of_losing_recovery_context(): void
    {
        [$client] = $this->application();
        $return = route('auth-manager.sign-in-return', ['client_id' => $client->id]);
        $this->get('/forgot-password?client_id='.$client->id)->assertSee($return);
        $this->get('/reset-password/synthetic-token?client_id='.$client->id)->assertSee($return);
        $this->get($return)->assertRedirect(route('auth-manager.login'));
        $this->assertSame($return, session('url.intended'));
    }

    public function test_an_unregistered_oauth_callback_cannot_supply_recovery_context(): void
    {
        [$client] = $this->application();
        $this->withSession(['url.intended' => url('/oauth/authorize').'?'.http_build_query([
            'client_id' => $client->id, 'redirect_uri' => 'https://attacker.example.test/callback'])])
            ->get('/forgot-password')->assertOk()->assertDontSee('name="client_id"', false);
    }

    /** @return array{PassportClient, RegisteredApplication} */
    private function application(): array
    {
        $client = PassportClient::create(['id' => (string) Str::uuid(), 'name' => 'Example Application', 'secret' => 'synthetic-secret',
            'redirect_uris' => ['https://app.example.test/oauth/callback'], 'grant_types' => ['authorization_code'], 'revoked' => false]);
        $app = RegisteredApplication::create(['key' => 'example-app', 'name' => 'Example Application',
            'launch_url' => 'https://app.example.test/auth/redirect', 'enabled' => true]);
        $app->clients()->attach($client);

        return [$client, $app];
    }
}
