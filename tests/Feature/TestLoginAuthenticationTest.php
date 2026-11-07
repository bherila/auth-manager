<?php

namespace Tests\Feature;

use BWH\Auth\Mail\TwoFactorLoginMail;
use BWH\Auth\Models\TwoFactorAttempt;
use BWH\Auth\OAuth\AuthenticationRequirement;
use BWH\AuthManager\Http\Middleware\EnsureCredentialVersion;
use BWH\AuthManager\Http\Middleware\RequireRecentPasskeyAuthentication;
use BWH\AuthManager\Models\TrustedDevice;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\AuthenticationContext;
use BWH\AuthManager\Services\OAuthClientGrantService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

final class TestLoginAuthenticationTest extends TestCase
{
    use RefreshDatabase;

    private const PASSWORD = 'synthetic-test-login-password';

    private const CALLBACK = 'https://app.example.test/oauth/callback';

    private ?string $keys = null;

    protected function setUp(): void
    {
        parent::setUp();
        $this->withoutVite();
        $this->freezeTime();
        Cache::flush();
        Mail::fake();
        config(['app.key' => 'base64:'.base64_encode(str_repeat('k', 32)),
            'auth-manager.sign_in.code_after_password' => true,
            'auth-manager.sign_in.trusted_devices' => true]);
    }

    protected function tearDown(): void
    {
        if ($this->keys !== null) {
            File::deleteDirectory($this->keys);
        }
        Passport::$keyPath = null;
        parent::tearDown();
    }

    public function test_only_the_explicit_valid_flag_skips_mail_without_creating_second_factor_proof(): void
    {
        $ordinary = User::factory()->create(['email' => 'ordinary@example.test', 'password' => self::PASSWORD]);
        $this->post('/login', $this->credentials($ordinary))->assertRedirect();
        $this->assertGuest();
        Mail::assertSent(TwoFactorLoginMail::class, 1);
        $this->assertSame(1, TwoFactorAttempt::count());

        $user = $this->syntheticUser();
        $this->freshBrowser();
        Mail::fake();
        $response = $this->post('/login', $this->credentials($user) + ['remember' => true]);
        $response->assertRedirect(route('auth-manager.home'));
        $this->assertAuthenticatedAs($user);
        Mail::assertNothingSent();
        $this->assertSame(1, TwoFactorAttempt::count());
        $this->assertSame(0, TrustedDevice::count());
        $this->assertSame(['pwd'], session(AuthenticationContext::SESSION_KEY.'.amr'));
        $this->assertSame(AuthenticationRequirement::ACR_SINGLE, session(AuthenticationContext::SESSION_KEY.'.acr'));
        $this->assertFalse(session()->has(RequireRecentPasskeyAuthentication::SESSION_KEY));
        $this->assertNotNull($response->getCookie(auth('web')->getRecallerName()));
        $this->postJson('/api/passkeys/register/options')->assertForbidden();
    }

    public function test_password_exemption_does_not_refresh_old_passkey_proof_or_leave_a_pending_challenge(): void
    {
        $user = $this->syntheticUser();
        $proof = ['user_id' => (string) $user->id, 'authenticated_at' => now()->subMinutes(20)->timestamp];
        $attempt = TwoFactorAttempt::createForUser($user);
        $this->withSession([
            RequireRecentPasskeyAuthentication::SESSION_KEY => $proof,
            'auth_manager_password_challenge' => ['token' => $attempt->token, 'email' => $user->email],
            config('bherila-auth.two_factor.session_user_key') => $user->id,
        ])->post('/login', $this->credentials($user))->assertRedirect();

        $this->assertSame($proof, session(RequireRecentPasskeyAuthentication::SESSION_KEY));
        $this->assertFalse(session()->has(config('bherila-auth.two_factor.session_user_key')));
        $this->assertTrue($attempt->fresh()->is_used);
        $this->postJson('/api/passkeys/register/options')->assertForbidden();
        Mail::assertNothingSent();
    }

    /** @return array<string, array{string}> */
    public static function strongerAssurance(): array
    {
        return ['MFA' => [AuthenticationRequirement::ACR_MFA],
            'phishing resistant' => [AuthenticationRequirement::ACR_PHISHING_RESISTANT],
            'emailed factor' => [AuthenticationRequirement::AMR_PREFIX.'otp']];
    }

    #[DataProvider('strongerAssurance')]
    public function test_password_exemption_does_not_satisfy_requested_stronger_assurance(string $acr): void
    {
        $user = $this->syntheticUser();
        [$client] = $this->client($user);
        $authorize = $this->authorizeUrl($client, ['acr_values' => $acr]);
        $this->get($authorize)->assertRedirect(route('auth-manager.login'));
        $this->post('/login', $this->credentials($user))->assertRedirect();
        $response = $this->get($authorize)->assertRedirect();
        parse_str((string) parse_url($response->headers->get('Location'), PHP_URL_QUERY), $query);
        $this->assertSame('unmet_authentication_requirements', $query['error'] ?? null);
        $this->assertArrayNotHasKey('code', $query);
        $this->assertSame(['pwd'], session(AuthenticationContext::SESSION_KEY.'.amr'));
        Mail::assertNothingSent();
    }

    public function test_expiry_refuses_browser_remember_bearer_refresh_and_status_before_the_scheduler(): void
    {
        $this->signingKeys();
        $user = $this->syntheticUser(['test_login_expires_at' => now()->addMinute()]);
        [$client, $secret] = $this->client($user);
        $response = $this->post('/login', $this->credentials($user) + ['remember' => true])->assertRedirect();
        $cookie = $response->getCookie(auth('web')->getRecallerName());
        $this->assertNotNull($cookie);
        $codeResponse = $this->get($this->authorizeUrl($client))->assertRedirect();
        parse_str((string) parse_url($codeResponse->headers->get('Location'), PHP_URL_QUERY), $query);
        $this->assertIsString($query['code'] ?? null);
        $tokens = $this->post('/oauth/token', [
            'grant_type' => 'authorization_code', 'client_id' => (string) $client->id, 'client_secret' => $secret,
            'redirect_uri' => self::CALLBACK, 'code' => $query['code'], 'code_verifier' => str_repeat('v', 64),
        ])->assertOk()->json();
        $this->freshBrowser()->withToken($tokens['access_token'])->getJson('/api/oauth/user')->assertOk()
            ->assertJsonPath('amr', ['pwd'])->assertJsonPath('acr', AuthenticationRequirement::ACR_SINGLE);
        $this->freshBrowser()->withBasicAuth((string) $client->id, $secret)
            ->postJson('/api/reconciliation/identity-status', ['subject' => (string) $user->id])->assertJsonPath('active', true);

        $this->travelTo($user->test_login_expires_at);
        $this->assertNull($user->fresh()->disabled_at, 'The scheduler has not disabled this account.');
        $this->freshBrowser()->withToken($tokens['access_token'])->getJson('/api/oauth/user')->assertUnauthorized();
        $this->freshBrowser()->post('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => (string) $client->id,
            'client_secret' => $secret, 'refresh_token' => $tokens['refresh_token']])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
        $this->freshBrowser()->withBasicAuth((string) $client->id, $secret)
            ->postJson('/api/reconciliation/identity-status', ['subject' => (string) $user->id])->assertJsonPath('active', false);
        $this->freshBrowser()->actingAs($user->fresh(), 'web')
            ->withSession([EnsureCredentialVersion::SESSION_KEY => 0])->getJson('/settings')->assertUnauthorized();
        $this->assertGuest('web');
        $this->freshBrowser()->withCookie($cookie->getName(), (string) $cookie->getValue())->getJson('/settings')->assertUnauthorized();
        $this->assertGuest('web');
        $this->freshBrowser()->post('/login', $this->credentials($user))->assertSessionHasErrors('email');
        $this->assertGuest();
    }

    public function test_test_logins_require_explicit_static_grants_even_in_the_resource_profile(): void
    {
        config(['auth-manager.profile' => 'resource', 'auth-manager.dynamic_client_registration' => true]);
        $test = $this->syntheticUser();
        $ordinary = User::factory()->create();
        [$allowed] = $this->client($test);
        $other = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Other application', [self::CALLBACK]);
        $dynamic = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Dynamic application', [self::CALLBACK]);
        $dynamic->forceFill(['dynamically_registered_at' => now()])->save();
        $grants = app(OAuthClientGrantService::class);
        $this->assertTrue($grants->allows((string) $ordinary->id, (string) $dynamic->id));
        $this->assertTrue($grants->allows((string) $test->id, (string) $allowed->id));
        $this->assertFalse($grants->allows((string) $test->id, (string) $other->id));
        $this->assertFalse($grants->allows((string) $test->id, (string) $dynamic->id));
        DB::table('oauth_client_grants')->insert(['subject' => $test->id, 'oauth_client_id' => $dynamic->id]);
        $this->assertFalse($grants->allows((string) $test->id, (string) $dynamic->id), 'Even a stale dynamic grant must not broaden test-login scope.');
    }

    public function test_expiry_uses_utc_even_when_the_embedding_host_has_another_timezone(): void
    {
        $deadline = now('UTC')->addMinute();
        $user = $this->syntheticUser(['test_login_expires_at' => $deadline]);
        $previous = date_default_timezone_get();
        try {
            date_default_timezone_set('Pacific/Honolulu');
            $this->assertSame($deadline->timestamp, $user->fresh()->test_login_expires_at->timestamp);
            $this->assertTrue($user->fresh()->canLogin());
            $this->travelTo($deadline);
            $this->assertFalse($user->fresh()->canLogin());
        } finally {
            date_default_timezone_set($previous);
        }
    }

    /** @param array<string, mixed> $attributes */
    private function syntheticUser(array $attributes = []): User
    {
        $user = User::factory()->make(['email' => 'synthetic-'.Str::lower(Str::random(8)).'@example.test', 'password' => self::PASSWORD]);
        $user->forceFill(['is_test_login' => true, 'test_login_expires_at' => now()->addHour(), ...$attributes])->save();

        return $user;
    }

    /** @return array{Client, string} */
    private function client(User $user): array
    {
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Example application', [self::CALLBACK]);
        app(OAuthClientGrantService::class)->grant((string) $user->id, (string) $client->id);

        return [$client, (string) $client->plain_secret];
    }

    /** @param array<string, string> $extra */
    private function authorizeUrl(Client $client, array $extra = []): string
    {
        return '/oauth/authorize?'.http_build_query(['client_id' => (string) $client->id, 'redirect_uri' => self::CALLBACK,
            'response_type' => 'code', 'scope' => 'identity:read', 'state' => 'synthetic-state',
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', str_repeat('v', 64), true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256', ...$extra]);
    }

    /** @return array{email:string,password:string} */
    private function credentials(User $user): array
    {
        return ['email' => $user->email, 'password' => self::PASSWORD];
    }

    private function freshBrowser(): static
    {
        Auth::forgetGuards();
        Auth::shouldUse('web');
        $this->flushSession();
        $this->withoutHeader('Authorization');
        $this->defaultCookies = $this->unencryptedCookies = [];

        return $this;
    }

    private function signingKeys(): void
    {
        $this->keys = storage_path('framework/testing/test-login-oauth-'.Str::uuid());
        File::ensureDirectoryExists($this->keys, 0700);
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $this->assertNotFalse($key);
        $this->assertTrue(openssl_pkey_export($key, $private));
        File::put($this->keys.'/oauth-private.key', $private);
        File::put($this->keys.'/oauth-public.key', openssl_pkey_get_details($key)['key']);
        chmod($this->keys.'/oauth-private.key', 0600);
        chmod($this->keys.'/oauth-public.key', 0600);
        Passport::loadKeysFrom($this->keys);
    }
}
