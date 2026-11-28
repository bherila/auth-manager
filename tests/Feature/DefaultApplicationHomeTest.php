<?php

namespace Tests\Feature;

use BWH\Auth\Mail\TwoFactorLoginMail;
use BWH\AuthManager\Models\PassportClient;
use BWH\AuthManager\Models\RegisteredApplication;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\OAuthClientGrantService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Sleep;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

final class DefaultApplicationHomeTest extends TestCase
{
    use RefreshDatabase;

    private User $user;

    private PassportClient $client;

    private RegisteredApplication $application;

    protected function setUp(): void
    {
        parent::setUp();
        $this->withoutVite();
        Mail::fake();
        Sleep::fake();
        config(['application-registry.launch_enabled' => true,
            'application-registry.default_application' => 'example-app']);
        $this->user = User::factory()->create(['user_role' => 'user', 'password' => 'synthetic-password']);
        $this->client = PassportClient::create(['id' => (string) Str::uuid(), 'name' => 'Example Application',
            'secret' => 'synthetic-secret', 'redirect_uris' => ['https://app.example.test/oauth/callback'],
            'grant_types' => ['authorization_code'], 'revoked' => false]);
        $this->application = RegisteredApplication::create(['key' => 'example-app', 'name' => 'Example Application',
            'launch_url' => 'https://app.example.test/auth/redirect', 'enabled' => true]);
        $this->application->clients()->attach($this->client);
        app(OAuthClientGrantService::class)->grant((string) $this->user->id, (string) $this->client->id);
    }

    public function test_non_admin_home_starts_the_granted_application_sso_flow(): void
    {
        // Grants use the row id even when the external subject is opaque.
        $this->user->getConnection()->table('users')->where('id', $this->user->id)->update(['subject' => (string) Str::ulid()]);
        $this->actingAs($this->user->fresh())->get('/?return_url=https://attacker.example.test&default_application=other')
            ->assertRedirect($this->application->launch_url);
    }

    public function test_guests_still_see_the_sign_in_page(): void
    {
        $this->get('/')->assertOk()->assertViewIs('welcome')->assertSee('Sign in');
    }

    #[DataProvider('administratorRoles')]
    public function test_provider_administrators_keep_the_provider_home(string $roles): void
    {
        $this->user->update(['user_role' => $roles]);
        $this->actingAs($this->user)->get('/')->assertOk()->assertViewIs('welcome')->assertSee('Directory administration');
    }

    public static function administratorRoles(): array
    {
        return [['admin'], ['user,admin']];
    }

    #[DataProvider('unavailableDestinations')]
    public function test_default_launch_never_creates_or_bypasses_access(string $state): void
    {
        match ($state) {
            'unset' => config(['application-registry.default_application' => null]),
            'unknown' => config(['application-registry.default_application' => 'missing']),
            'launches-off' => config(['application-registry.launch_enabled' => false]),
            'ungranted' => DB::table('oauth_client_grants')->where('subject', (string) $this->user->id)->delete(),
            'disabled-app' => $this->application->update(['enabled' => false]),
            'unmapped' => $this->application->clients()->detach(),
            'revoked-client' => $this->client->update(['revoked' => true]),
            'dynamic-client' => $this->client->forceFill(['dynamically_registered_at' => now()])->save(),
            'wrong-grant-type' => $this->client->update(['grant_types' => ['client_credentials']]),
            'disabled-user' => $this->user->update(['disabled_at' => now()]),
        };
        $before = DB::table('oauth_client_grants')->count();
        $this->actingAs($this->user)->get('/')->assertOk()->assertViewIs('welcome');
        $this->assertSame($before, DB::table('oauth_client_grants')->count());
    }

    public static function unavailableDestinations(): array
    {
        return array_map(static fn (string $state): array => [$state], [
            'unset', 'unknown', 'launches-off', 'ungranted', 'disabled-app', 'unmapped',
            'revoked-client', 'dynamic-client', 'wrong-grant-type', 'disabled-user',
        ]);
    }

    public function test_password_login_uses_the_home_policy_after_authentication(): void
    {
        config(['auth-manager.sign_in.code_after_password' => false]);
        $response = $this->post('/login', ['email' => $this->user->email, 'password' => 'synthetic-password'])
            ->assertRedirect(route('auth-manager.home'));
        $this->assertAuthenticatedAs($this->user);
        $this->get($response->headers->get('Location'))->assertRedirect($this->application->launch_url);
    }

    public function test_password_challenge_must_finish_before_default_launch(): void
    {
        config(['auth-manager.sign_in.code_after_password' => true]);
        $this->post('/login', ['email' => $this->user->email, 'password' => 'synthetic-password'])->assertRedirect('/login');
        $this->assertGuest();
        $this->get('/')->assertOk()->assertViewIs('welcome');
        $attempt = Mail::sent(TwoFactorLoginMail::class)->sole()->attempt;
        $response = $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $attempt->token, 'code' => $attempt->code])
            ->assertOk();
        $this->assertAuthenticatedAs($this->user);
        $this->get($response->json('redirect'))->assertRedirect($this->application->launch_url);
    }

    public function test_explicit_settings_and_oauth_destinations_take_precedence(): void
    {
        config(['auth-manager.sign_in.code_after_password' => false]);
        $oauth = url('/oauth/authorize').'?'.http_build_query(['client_id' => $this->client->id,
            'redirect_uri' => 'https://app.example.test/oauth/callback', 'state' => 'synthetic-state']);
        $this->withSession(['url.intended' => $oauth])
            ->post('/login', ['email' => $this->user->email, 'password' => 'synthetic-password'])->assertRedirect($oauth);
        $this->actingAs($this->user)->get('/settings')->assertOk()->assertViewIs('settings.account');
        $this->withSession(['url.intended' => url('/settings')]);
        $this->assertSame(url('/settings'), $this->user->getLoginRedirectUrl());
        $this->assertSame(route('auth-manager.home', absolute: false), $this->user->getLoginRedirectUrl());
    }
}
