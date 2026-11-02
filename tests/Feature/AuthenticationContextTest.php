<?php

namespace Tests\Feature;

use BWH\Auth\Events\PasskeyLoginSucceeded;
use BWH\Auth\Models\PasskeyCredential;
use BWH\Auth\Models\TwoFactorAttempt;
use BWH\Auth\OAuth\AuthenticationRequirement;
use BWH\AuthManager\Http\Middleware\EnforceAuthenticationRequest;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\AuthenticationContext;
use BWH\AuthManager\Services\OAuthClientGrantService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Tests\TestCase;

/** auth-manager#113, slice P2: recording how a person authenticated, and enforcing requests for more. */
final class AuthenticationContextTest extends TestCase
{
    use RefreshDatabase;

    private const CALLBACK = 'https://app.example.test/oauth/callback';

    private const PASSWORD = 'synthetic-password';

    private const PHISHING_RESISTANT = AuthenticationRequirement::ACR_PHISHING_RESISTANT;

    private string $keyDirectory;

    protected function setUp(): void
    {
        parent::setUp();
        $this->withoutVite();
        Cache::flush();
        Mail::fake();
        config()->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
        $this->keyDirectory = storage_path('framework/testing/oauth-'.Str::uuid());
        File::ensureDirectoryExists($this->keyDirectory, 0700);
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $privateKey);
        File::put($this->keyDirectory.'/oauth-private.key', $privateKey);
        File::put($this->keyDirectory.'/oauth-public.key', openssl_pkey_get_details($key)['key']);
        chmod($this->keyDirectory.'/oauth-private.key', 0600);
        chmod($this->keyDirectory.'/oauth-public.key', 0600);
        Passport::loadKeysFrom($this->keyDirectory);
    }

    protected function tearDown(): void
    {
        File::deleteDirectory($this->keyDirectory);
        Carbon::setTestNow();
        parent::tearDown();
    }

    public function test_a_verified_password_records_pwd(): void
    {
        $user = $this->person();

        $this->signInWithPassword($user);

        $this->assertContext(['pwd'], AuthenticationRequirement::ACR_SINGLE);
    }

    public function test_a_wrong_password_records_nothing(): void
    {
        $user = $this->person();

        $this->post('/login', ['email' => $user->email, 'password' => 'wrong-password']);

        $this->assertFalse(session()->has(AuthenticationContext::SESSION_KEY));
    }

    public function test_an_emailed_code_records_otp(): void
    {
        $user = $this->person();
        $token = $this->postJson('/login/email-code', ['email' => $user->email])->json('attempt_token');

        $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $token, 'code' => TwoFactorAttempt::where('token', $token)->value('code')])->assertOk();

        $this->assertContext(['otp'], AuthenticationRequirement::ACR_SINGLE);
    }

    public function test_a_password_then_code_records_mfa(): void
    {
        config(['auth-manager.sign_in.code_after_password' => true]);
        $user = $this->person();
        $this->signInWithPassword($user);
        $this->assertFalse(session()->has(AuthenticationContext::SESSION_KEY), 'The password alone must record nothing.');

        $attempt = TwoFactorAttempt::query()->latest('id')->firstOrFail();
        $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $attempt->token, 'code' => $attempt->code])->assertOk();

        $this->assertContext(['pwd', 'otp', 'mfa'], AuthenticationRequirement::ACR_MFA);
    }

    public function test_a_passkey_records_its_class_and_only_user_verification_reaches_the_rung(): void
    {
        $user = $this->person();
        $this->actingAs($user)->get('/');

        event(new PasskeyLoginSucceeded($user, new PasskeyCredential(['backup_eligible' => true]), true));
        $this->assertContext(['swk'], self::PHISHING_RESISTANT);

        event(new PasskeyLoginSucceeded($user, new PasskeyCredential(['backup_eligible' => false]), true));
        $this->assertContext(['hwk'], self::PHISHING_RESISTANT);

        event(new PasskeyLoginSucceeded($user, new PasskeyCredential(['backup_eligible' => true]), false));
        $this->assertContext(['swk'], AuthenticationRequirement::ACR_SINGLE);
    }

    public function test_a_context_recorded_for_someone_else_is_ignored(): void
    {
        $user = $this->person();
        $other = $this->person('other@example.test');
        $request = request();
        $request->setLaravelSession($this->app['session.store']);
        AuthenticationContext::record($request, $other, ['pwd'], AuthenticationRequirement::ACR_SINGLE);

        $this->assertNull(AuthenticationContext::for($request, $user));
    }

    public function test_no_request_issues_a_code_as_before_even_with_no_recorded_context(): void
    {
        [$user, $client] = $this->granted();

        $this->assertArrayHasKey('code', $this->callbackQuery($this->authorize($user, $client)));
    }

    public function test_a_restored_session_with_no_context_cannot_satisfy_max_age(): void
    {
        [$user, $client] = $this->granted();

        $this->authorize($user, $client, ['max_age' => '3600'])->assertRedirect('/login');
    }

    public function test_max_age_passes_while_fresh_and_asks_again_once_stale(): void
    {
        [$user, $client] = $this->granted();
        $this->signInWithPassword($user);

        $this->assertArrayHasKey('code', $this->callbackQuery($this->authorize($user, $client, ['max_age' => '600'])));

        Carbon::setTestNow(now()->addHour());
        $this->authorize($user, $client, ['max_age' => '600'])->assertRedirect('/login');
    }

    public function test_prompt_login_asks_even_right_after_a_sign_in_and_then_continues(): void
    {
        [$user, $client] = $this->granted();
        $this->signInWithPassword($user);

        $this->authorize($user, $client, ['prompt' => 'login'])->assertRedirect('/login');
        $this->assertAuthenticatedAs($user);

        $return = $this->signInWithPassword($user);
        $this->assertStringContainsString('/oauth/authorize', (string) $return->headers->get('Location'));

        $this->assertArrayHasKey('code', $this->callbackQuery($this->authorize($user, $client, ['prompt' => 'login'])));
        $this->assertFalse(session()->has(EnforceAuthenticationRequest::SESSION_KEY));
    }

    public function test_repeating_a_forced_request_in_the_same_second_does_not_skip_the_sign_in(): void
    {
        [$user, $client] = $this->granted();
        Carbon::setTestNow(now());
        $this->signInWithPassword($user);

        $this->authorize($user, $client, ['prompt' => 'login'])->assertRedirect('/login');
        $this->authorize($user, $client, ['prompt' => 'login'])->assertRedirect('/login');
        $this->authorize($user, $client, ['max_age' => '0'])->assertRedirect('/login');
        $this->authorize($user, $client, ['max_age' => '0'])->assertRedirect('/login');
    }

    public function test_a_sign_in_in_the_same_second_as_the_request_still_counts(): void
    {
        [$user, $client] = $this->granted();
        Carbon::setTestNow(now());
        $this->signInWithPassword($user);
        $this->authorize($user, $client, ['prompt' => 'login'])->assertRedirect('/login');

        $this->signInWithPassword($user);

        $this->assertArrayHasKey('code', $this->callbackQuery($this->authorize($user, $client, ['prompt' => 'login'])));
    }

    public function test_max_age_zero_behaves_like_prompt_login(): void
    {
        [$user, $client] = $this->granted();
        $this->signInWithPassword($user);

        $this->authorize($user, $client, ['max_age' => '0'])->assertRedirect('/login');
    }

    public function test_a_different_person_signing_in_cancels_the_flow(): void
    {
        [$user, $client] = $this->granted();
        $other = $this->person('other@example.test');
        app(OAuthClientGrantService::class)->grant((string) $other->getKey(), (string) $client->getKey());
        $this->signInWithPassword($user);
        $this->authorize($user, $client, ['prompt' => 'login'])->assertRedirect('/login');

        $this->signInWithPassword($other);
        $response = $this->get($this->authorizeUrl($client, ['prompt' => 'login']));

        $this->assertSame('access_denied', $this->callbackQuery($response)['error']);
        $this->assertGuest();
    }

    public function test_a_guest_is_sent_to_sign_in_with_only_the_requested_methods(): void
    {
        [, $client] = $this->granted();

        $this->get($this->authorizeUrl($client, ['acr_values' => self::PHISHING_RESISTANT]))->assertRedirect('/login');

        $this->get('/login')->assertOk()
            ->assertSee('Sign in again to continue.')
            ->assertSee('id="passkey-login-mount"', false)
            ->assertDontSee('id="password"', false)
            ->assertDontSee('id="email-code-login-mount"', false);
    }

    public function test_a_method_set_without_passwords_shows_no_password_form(): void
    {
        [, $client] = $this->granted();

        $this->get($this->authorizeUrl($client, ['acr_values' => 'urn:auth-manager:amr:otp urn:auth-manager:amr:hwk urn:auth-manager:amr:swk']));

        $this->get('/login')->assertOk()
            ->assertSee('id="passkey-login-mount"', false)
            ->assertSee('id="email-code-login-mount"', false)
            ->assertSee('id="email"', false)
            ->assertDontSee('id="password"', false);
    }

    public function test_an_abandoned_request_stops_narrowing_the_login_page(): void
    {
        [, $client] = $this->granted();
        $this->get($this->authorizeUrl($client, ['acr_values' => self::PHISHING_RESISTANT]));

        Carbon::setTestNow(now()->addHour());

        $this->get('/login')->assertOk()->assertSee('id="password"', false)->assertDontSee('Sign in again to continue.');
    }

    public function test_a_person_with_no_such_method_is_refused_back_to_the_client(): void
    {
        [$user, $client] = $this->granted();

        $query = $this->callbackQuery($this->authorize($user, $client, ['acr_values' => self::PHISHING_RESISTANT]));

        $this->assertSame('unmet_authentication_requirements', $query['error']);
        $this->assertSame('state-value', $query['state']);
    }

    public function test_only_passkeys_of_the_requested_class_count(): void
    {
        [$user, $client] = $this->granted();
        PasskeyCredential::query()->create(['user_id' => $user->getKey(), 'credential_id' => 'synthetic', 'public_key' => 'synthetic', 'counter' => 0, 'backup_eligible' => true]);

        $this->assertSame('unmet_authentication_requirements', $this->callbackQuery($this->authorize($user, $client, ['acr_values' => 'urn:auth-manager:amr:hwk']))['error']);
        $this->authorize($user, $client, ['acr_values' => 'urn:auth-manager:amr:swk'])->assertRedirect('/login');
    }

    public function test_a_sign_in_that_still_misses_the_request_is_refused_rather_than_looping(): void
    {
        [$user, $client] = $this->granted();
        PasskeyCredential::query()->create(['user_id' => $user->getKey(), 'credential_id' => 'synthetic', 'public_key' => 'synthetic', 'counter' => 0]);
        $this->authorize($user, $client, ['acr_values' => self::PHISHING_RESISTANT])->assertRedirect('/login');

        $this->signInWithPassword($user);

        $this->assertSame('unmet_authentication_requirements', $this->callbackQuery($this->get($this->authorizeUrl($client, ['acr_values' => self::PHISHING_RESISTANT])))['error']);
    }

    public function test_a_verified_passkey_satisfies_a_request_for_multi_factor(): void
    {
        [$user, $client] = $this->granted();
        $this->actingAs($user)->withSession([AuthenticationContext::SESSION_KEY => [
            'user_id' => (string) $user->getKey(), 'auth_time' => now()->getTimestamp(), 'amr' => ['swk'], 'acr' => self::PHISHING_RESISTANT,
        ]]);

        $this->assertArrayHasKey('code', $this->callbackQuery($this->get($this->authorizeUrl($client, ['acr_values' => AuthenticationRequirement::ACR_MFA]))));
    }

    public function test_password_then_code_does_not_satisfy_a_request_for_phishing_resistant(): void
    {
        [$user, $client] = $this->granted();
        PasskeyCredential::query()->create(['user_id' => $user->getKey(), 'credential_id' => 'synthetic', 'public_key' => 'synthetic', 'counter' => 0]);
        $this->actingAs($user)->withSession([AuthenticationContext::SESSION_KEY => [
            'user_id' => (string) $user->getKey(), 'auth_time' => now()->getTimestamp(), 'amr' => ['pwd', 'otp', 'mfa'], 'acr' => AuthenticationRequirement::ACR_MFA,
        ]]);

        $this->get($this->authorizeUrl($client, ['acr_values' => self::PHISHING_RESISTANT]))->assertRedirect('/login');
    }

    public function test_a_request_for_multi_factor_offers_what_can_satisfy_it(): void
    {
        [, $client] = $this->granted();

        $this->get($this->authorizeUrl($client, ['acr_values' => AuthenticationRequirement::ACR_MFA]));
        $this->get('/login')->assertOk()->assertSee('id="passkey-login-mount"', false)->assertDontSee('id="password"', false);

        config(['auth-manager.sign_in.code_after_password' => true]);
        $this->get('/login')->assertOk();
        $this->assertSame(['password', 'passkey'], EnforceAuthenticationRequest::offeredMethods([AuthenticationRequirement::ACR_MFA]));
    }

    public function test_a_person_with_no_passkey_cannot_meet_multi_factor_without_the_code_setting(): void
    {
        [$user, $client] = $this->granted();

        $this->assertSame('unmet_authentication_requirements', $this->callbackQuery($this->authorize($user, $client, ['acr_values' => AuthenticationRequirement::ACR_MFA]))['error']);
    }

    public function test_an_unsupported_value_fails_clearly(): void
    {
        [$user, $client] = $this->granted();

        $this->assertSame('invalid_request', $this->callbackQuery($this->authorize($user, $client, ['acr_values' => 'urn:example:unknown']))['error']);
        $this->assertSame('invalid_request', $this->callbackQuery($this->authorize($user, $client, ['max_age' => 'soon']))['error']);
    }

    public function test_an_error_is_never_sent_to_an_unregistered_address(): void
    {
        [$user, $client] = $this->granted();

        $this->actingAs($user)->get($this->authorizeUrl($client, ['acr_values' => 'urn:example:unknown', 'redirect_uri' => 'https://attacker.example.test/']))->assertStatus(400);
    }

    public function test_silent_authorization_stays_refused(): void
    {
        [$user, $client] = $this->granted();

        $this->authorize($user, $client, ['prompt' => 'none', 'max_age' => '0'])->assertStatus(400);
    }

    public function test_the_context_follows_the_code_token_and_refresh_and_reaches_the_identity_response(): void
    {
        [$user, $client, $secret] = $this->granted();
        $this->signInWithPassword($user);
        $authTime = now()->getTimestamp();
        $code = $this->callbackQuery($this->authorize($user, $client))['code'];

        Carbon::setTestNow(now()->addMinutes(10));
        $tokens = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code', 'client_id' => (string) $client->getKey(), 'client_secret' => $secret,
            'redirect_uri' => self::CALLBACK, 'code' => $code, 'code_verifier' => $this->verifier(),
        ])->assertOk();

        $expected = ['auth_time' => $authTime, 'amr' => ['pwd'], 'acr' => AuthenticationRequirement::ACR_SINGLE];
        $this->freshIdentity($tokens->json('access_token'))->assertOk()->assertJson($expected);

        // A refresh authenticates nobody, so it must not move auth_time.
        Carbon::setTestNow(now()->addHour());
        $refreshed = $this->postJson('/oauth/token', [
            'grant_type' => 'refresh_token', 'client_id' => (string) $client->getKey(), 'client_secret' => $secret, 'refresh_token' => $tokens->json('refresh_token'),
        ])->assertOk();
        $this->freshIdentity($refreshed->json('access_token'))->assertOk()->assertJson($expected);
    }

    public function test_an_unknown_context_is_left_out_of_the_identity_response(): void
    {
        [$user, $client, $secret] = $this->granted();
        $code = $this->callbackQuery($this->authorize($user, $client))['code'];
        $tokens = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code', 'client_id' => (string) $client->getKey(), 'client_secret' => $secret,
            'redirect_uri' => self::CALLBACK, 'code' => $code, 'code_verifier' => $this->verifier(),
        ])->assertOk();

        $this->freshIdentity($tokens->json('access_token'))->assertOk()->assertJsonMissingPath('auth_time')->assertJsonMissingPath('amr');
        $this->assertNull(DB::table('oauth_access_tokens')->value('auth_time'));
    }

    public function test_the_supported_values_follow_the_instance_settings(): void
    {
        $this->assertContains(AuthenticationRequirement::ACR_MFA, EnforceAuthenticationRequest::supportedValues());
        $this->assertContains('urn:auth-manager:amr:otp', EnforceAuthenticationRequest::supportedValues());

        config(['auth-manager.sign_in.code_only' => false]);
        $this->assertNotContains('urn:auth-manager:amr:otp', EnforceAuthenticationRequest::supportedValues());

        config(['auth-manager.sign_in.code_after_password' => true]);
        $this->assertNotContains('urn:auth-manager:amr:pwd', EnforceAuthenticationRequest::supportedValues());
    }

    private function person(string $email = 'person@example.test'): User
    {
        return User::factory()->create(['email' => $email, 'password' => self::PASSWORD, 'user_role' => 'user']);
    }

    /** @return array{User, Client, string} */
    private function granted(): array
    {
        $user = $this->person();
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Example Application', [self::CALLBACK]);
        app(OAuthClientGrantService::class)->grant((string) $user->getKey(), (string) $client->getKey());

        return [$user, $client, (string) $client->plain_secret];
    }

    private function signInWithPassword(User $user): TestResponse
    {
        Auth::forgetGuards();

        return $this->post('/login', ['email' => $user->email, 'password' => self::PASSWORD]);
    }

    /** @param  array<string, string>  $extra */
    private function authorize(User $user, Client $client, array $extra = []): TestResponse
    {
        return $this->actingAs($user)->get($this->authorizeUrl($client, $extra));
    }

    /** @param  array<string, string>  $extra */
    private function authorizeUrl(Client $client, array $extra = []): string
    {
        return '/oauth/authorize?'.http_build_query([
            'client_id' => (string) $client->getKey(),
            'redirect_uri' => self::CALLBACK,
            'response_type' => 'code',
            'state' => 'state-value',
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $this->verifier(), true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
            ...$extra,
        ]);
    }

    private function verifier(): string
    {
        return str_repeat('v', 64);
    }

    /** @return array<string, string> */
    private function callbackQuery(TestResponse $response): array
    {
        $location = (string) $response->headers->get('Location');
        $this->assertStringStartsWith(self::CALLBACK, $location, "Status {$response->getStatusCode()}: {$location}");
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);

        return $query;
    }

    private function freshIdentity(string $token): TestResponse
    {
        Auth::forgetGuards();

        return $this->withToken($token)->getJson('/api/oauth/user');
    }

    /** @param  list<string>  $amr */
    private function assertContext(array $amr, string $acr): void
    {
        $context = session(AuthenticationContext::SESSION_KEY);
        $this->assertSame($amr, $context['amr'] ?? null);
        $this->assertSame($acr, $context['acr'] ?? null);
        $this->assertSame(now()->getTimestamp(), $context['auth_time'] ?? null);
    }
}
