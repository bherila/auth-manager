<?php

namespace Tests\Feature;

use BWH\Auth\Contracts\LocalCredentialPolicy;
use BWH\Auth\Mail\TwoFactorLoginMail;
use BWH\Auth\Models\AuthAuditLog;
use BWH\Auth\Models\TwoFactorAttempt;
use BWH\Auth\OAuth\AuthenticationRequirement;
use BWH\AuthManager\Http\Middleware\EnsureCredentialVersion;
use BWH\AuthManager\Http\Middleware\RequireRecentPasskeyAuthentication;
use BWH\AuthManager\Models\TrustedDevice;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\AuthenticationContext;
use BWH\AuthManager\Services\DirectoryAdminService;
use BWH\AuthManager\Services\OAuthClientGrantService;
use BWH\AuthManager\Services\TrustedDevices;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use InvalidArgumentException;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Cookie;
use Tests\TestCase;

/** auth-manager#114: skipping the emailed code on a browser already confirmed with one. */
final class TrustedDevicesTest extends TestCase
{
    use RefreshDatabase;

    private const CALLBACK = 'https://app.example.test/oauth/callback';

    private const PASSWORD = 'synthetic-password';

    private const NEW_PASSWORD = 'another-synthetic-password';

    private string $keyDirectory;

    protected function setUp(): void
    {
        parent::setUp();
        $this->withoutVite();
        Cache::flush();
        Mail::fake();
        config(['auth-manager.sign_in.code_after_password' => true, 'auth-manager.sign_in.trusted_devices' => true]);
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

    public function test_it_is_off_by_default_with_thirty_days(): void
    {
        $config = require base_path('config/auth-manager.php');

        $this->assertFalse($config['sign_in']['trusted_devices']);
        $this->assertSame(30, $config['sign_in']['trusted_device_days']);
    }

    public function test_a_mistyped_duration_stops_the_configuration_from_loading(): void
    {
        $_ENV['AUTH_MANAGER_TRUSTED_DEVICE_DAYS'] = '0';
        putenv('AUTH_MANAGER_TRUSTED_DEVICE_DAYS=0');

        try {
            $this->expectException(InvalidArgumentException::class);
            require base_path('config/auth-manager.php');
        } finally {
            unset($_ENV['AUTH_MANAGER_TRUSTED_DEVICE_DAYS']);
            putenv('AUTH_MANAGER_TRUSTED_DEVICE_DAYS');
        }
    }

    // Acceptance: with the setting off, no device cookie is issued or honored.

    public function test_with_the_setting_off_no_cookie_is_issued_even_if_asked_for(): void
    {
        config(['auth-manager.sign_in.trusted_devices' => false]);
        $user = $this->person();

        $this->post('/login', $this->credentials($user));
        $this->get('/login')->assertDontSee('data-trust-days', false)->assertDontSee('trust_device', false);
        $attempt = TwoFactorAttempt::firstOrFail();
        $response = $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $attempt->token, 'code' => $attempt->code, 'trust_device' => true])->assertOk();

        $this->assertNull($response->getCookie(TrustedDevices::COOKIE, false));
        $this->assertSame(0, TrustedDevice::count());
    }

    public function test_with_the_setting_off_an_existing_cookie_is_not_honored(): void
    {
        $user = $this->person();
        $token = $this->confirmBrowser($user);
        config(['auth-manager.sign_in.trusted_devices' => false]);

        $this->withCookie(TrustedDevices::COOKIE, $token);
        $this->assertAskedForCode($user);
    }

    public function test_the_setting_means_nothing_unless_a_code_follows_the_password(): void
    {
        config(['auth-manager.sign_in.code_after_password' => false]);
        $user = $this->person();

        $this->assertFalse(TrustedDevices::enabled());
        $this->post('/login', [...$this->credentials($user), 'trust_device' => '1'])->assertRedirect('/');

        $this->assertAuthenticatedAs($user);
        $this->assertSame(0, TrustedDevice::count());
    }

    public function test_with_the_setting_off_the_settings_page_shows_nothing_about_it(): void
    {
        config(['auth-manager.sign_in.trusted_devices' => false]);

        $this->actingAs($this->person())->get('/settings')->assertOk()->assertDontSee('Trusted browsers');
    }

    // Issuing.

    public function test_the_code_step_offers_the_choice_with_and_without_javascript(): void
    {
        $user = $this->person();
        $this->post('/login', $this->credentials($user));

        $this->get('/login')->assertOk()
            ->assertSee('data-trust-days="30"', false)
            ->assertSee('name="trust_device"', false);
    }

    public function test_leaving_the_choice_unchecked_issues_nothing(): void
    {
        $user = $this->person();
        $this->post('/login', $this->credentials($user));
        $attempt = TwoFactorAttempt::firstOrFail();

        $response = $this->verify($attempt, []);

        $this->assertNull($response->getCookie(TrustedDevices::COOKIE, false));
        $this->assertSame(0, TrustedDevice::count());
    }

    public function test_the_cookie_is_host_only_secure_http_only_and_expires_with_the_row(): void
    {
        $user = $this->person();
        $this->post('/login', $this->credentials($user));
        $attempt = TwoFactorAttempt::firstOrFail();

        $cookie = $this->verify($attempt, ['trust_device' => true])->getCookie(TrustedDevices::COOKIE, false);

        $this->assertInstanceOf(Cookie::class, $cookie);
        $this->assertStringStartsWith('__Host-', $cookie->getName());
        $this->assertTrue($cookie->isSecure());
        $this->assertTrue($cookie->isHttpOnly());
        $this->assertSame(Cookie::SAMESITE_STRICT, $cookie->getSameSite());
        $this->assertNull($cookie->getDomain());
        $this->assertSame('/', $cookie->getPath());

        $device = TrustedDevice::firstOrFail();
        $this->assertSame($device->expires_at->getTimestamp(), $cookie->getExpiresTime());
        $this->assertSame(now()->addDays(30)->toDateString(), $device->expires_at->toDateString());
        $this->assertSame((int) $user->credential_version, $device->credential_version);
        $this->assertSame(1, AuthAuditLog::query()->where('event', 'trusted_device_added')->where('user_id', $user->getKey())->count());
    }

    public function test_an_emailed_code_alone_never_confirms_a_browser(): void
    {
        $user = $this->person();
        $this->postJson('/login/email-code', ['email' => $user->email])->assertOk();
        $attempt = TwoFactorAttempt::firstOrFail();

        $response = $this->verify($attempt, ['trust_device' => true]);

        $this->assertAuthenticatedAs($user);
        $this->assertNull($response->getCookie(TrustedDevices::COOKIE, false));
        $this->assertSame(0, TrustedDevice::count());
    }

    public function test_confirming_a_browser_again_replaces_its_row(): void
    {
        $user = $this->person();
        $token = $this->confirmBrowser($user);
        [$client] = $this->client($user);

        // A request for more forces the code here, and the person can confirm the browser again.
        $this->withCookie(TrustedDevices::COOKIE, $token);
        $this->get($this->authorizeUrl($client, ['acr_values' => AuthenticationRequirement::ACR_MFA]));
        $this->post('/login', $this->credentials($user));
        $attempt = TwoFactorAttempt::query()->latest('id')->firstOrFail();
        // The test client leaves cookies off a JSON request unless told otherwise; a browser sends them.
        $this->withCredentials()->verify($attempt, ['trust_device' => true]);

        $this->assertSame(1, TrustedDevice::count());
    }

    // Skipping the code.

    public function test_a_confirmed_browser_skips_the_code_and_reports_only_the_password(): void
    {
        $user = $this->person();
        $token = $this->confirmBrowser($user);
        Mail::fake();
        $attempts = TwoFactorAttempt::count();

        $this->withCookie(TrustedDevices::COOKIE, $token);
        $this->withSession(['url.intended' => url('/settings')]);
        $this->post('/login', $this->credentials($user))->assertRedirect(url('/settings'));

        $this->assertAuthenticatedAs($user);
        $this->assertSame($attempts, TwoFactorAttempt::count());
        Mail::assertNothingSent();

        $context = session(AuthenticationContext::SESSION_KEY);
        $this->assertSame(['pwd'], $context['amr']);
        $this->assertSame(AuthenticationRequirement::ACR_SINGLE, $context['acr']);
        $this->assertNotNull(TrustedDevice::firstOrFail()->last_used_at);
        $this->assertSame(1, AuthAuditLog::query()->where('auth_method', 'trusted_device')->where('user_id', $user->getKey())->count());
    }

    public function test_the_cookie_is_no_substitute_for_the_password(): void
    {
        $user = $this->person();
        $token = $this->confirmBrowser($user);

        $this->withCookie(TrustedDevices::COOKIE, $token);
        $this->post('/login', ['email' => $user->email, 'password' => 'wrong-password'])->assertSessionHasErrors();

        $this->assertGuest();
    }

    public function test_keep_me_signed_in_survives_skipping_the_code(): void
    {
        $user = $this->person();
        $token = $this->confirmBrowser($user);

        $this->withCookie(TrustedDevices::COOKIE, $token);
        $this->post('/login', [...$this->credentials($user), 'remember' => '1']);

        $this->assertNotNull($user->fresh()->remember_token);
    }

    public function test_skipping_ends_a_challenge_left_open_in_another_tab(): void
    {
        $user = $this->person();
        $token = $this->confirmBrowser($user);
        $this->post('/login', $this->credentials($user));
        $open = TwoFactorAttempt::query()->latest('id')->firstOrFail();

        $this->withCookie(TrustedDevices::COOKIE, $token);
        $this->post('/login', $this->credentials($user));

        $this->assertAuthenticatedAs($user);
        $this->assertTrue($open->fresh()->is_used);
        $this->assertFalse(session()->has((string) config('bherila-auth.two_factor.session_user_key')));
    }

    public function test_an_account_that_may_not_use_local_credentials_still_meets_the_challenge(): void
    {
        $user = $this->person();
        $token = $this->confirmBrowser($user);
        $this->app->instance(LocalCredentialPolicy::class, new class implements LocalCredentialPolicy
        {
            public function mayUseLocalCredentials(Authenticatable $user, Request $request): bool
            {
                return false;
            }
        });

        $this->withCookie(TrustedDevices::COOKIE, $token);
        $this->post('/login', $this->credentials($user));

        $this->assertGuest();
    }

    // Acceptance: a stolen database copy of the table can't be replayed as a cookie.

    public function test_the_table_holds_no_token_and_its_hash_is_not_accepted_as_a_cookie(): void
    {
        $user = $this->person();
        $token = $this->confirmBrowser($user);
        $stored = TrustedDevice::firstOrFail();

        $this->assertSame(hash('sha256', $token), $stored->token_hash);
        $this->assertNotContains($token, array_values($stored->getAttributes()));
        $this->assertArrayNotHasKey('token_hash', $stored->toArray());

        $this->withCookie(TrustedDevices::COOKIE, (string) $stored->token_hash);
        $this->assertAskedForCode($user);
    }

    public function test_one_persons_cookie_does_nothing_for_another(): void
    {
        $owner = $this->person();
        $token = $this->confirmBrowser($owner);
        $other = $this->person(['email' => 'other@example.test']);

        $this->withCookie(TrustedDevices::COOKIE, $token);
        $this->assertAskedForCode($other);
    }

    public function test_an_expired_device_asks_for_the_code_and_use_does_not_extend_it(): void
    {
        $user = $this->person();
        $token = $this->confirmBrowser($user);
        $expires = TrustedDevice::firstOrFail()->expires_at->getTimestamp();

        $this->withCookie(TrustedDevices::COOKIE, $token);
        $this->post('/login', $this->credentials($user));
        $this->assertSame($expires, TrustedDevice::firstOrFail()->expires_at->getTimestamp());
        $this->newBrowser();

        Carbon::setTestNow(now()->addDays(31));
        $this->withCookie(TrustedDevices::COOKIE, $token);
        $this->assertAskedForCode($user);
    }

    // Acceptance: a trusted device stops working once the credential version advances.

    public function test_a_password_reset_ends_trust(): void
    {
        config(['auth-manager.sign_in.password_reset' => true]);
        $user = $this->person();
        $token = $this->confirmBrowser($user);

        $this->post('/reset-password', [
            'token' => Password::broker()->createToken($user),
            'email' => $user->email,
            'password' => self::NEW_PASSWORD,
            'password_confirmation' => self::NEW_PASSWORD,
        ])->assertRedirect();
        $this->assertSame(1, (int) $user->fresh()->credential_version);
        $this->newBrowser();

        $this->withCookie(TrustedDevices::COOKIE, $token);
        $this->assertAskedForCode($user, self::NEW_PASSWORD);
    }

    public function test_changing_the_password_ends_trust(): void
    {
        $user = $this->person();
        $token = $this->confirmBrowser($user);

        $this->actingAs($user)->putJson('/settings/password', [
            'current_password' => self::PASSWORD,
            'password' => self::NEW_PASSWORD,
            'password_confirmation' => self::NEW_PASSWORD,
        ])->assertOk();
        $this->newBrowser();

        $this->withCookie(TrustedDevices::COOKIE, $token);
        $this->assertAskedForCode($user, self::NEW_PASSWORD);
    }

    public function test_an_administrator_reset_ends_trust(): void
    {
        $user = $this->person();
        $token = $this->confirmBrowser($user);

        $administrator = $this->administrator();
        app(DirectoryAdminService::class)->resetPassword($this->sessionRequest($administrator), $administrator, $user, self::NEW_PASSWORD);
        $this->newBrowser();

        $this->withCookie(TrustedDevices::COOKIE, $token);
        $this->assertAskedForCode($user, self::NEW_PASSWORD);
    }

    public function test_disabling_the_account_ends_trust_even_once_it_is_enabled_again(): void
    {
        $user = $this->person();
        $token = $this->confirmBrowser($user);
        $administrator = $this->administrator();
        $directory = app(DirectoryAdminService::class);

        $directory->disable($this->sessionRequest($administrator), $administrator, $user);
        $this->newBrowser();
        $this->withCookie(TrustedDevices::COOKIE, $token);
        $this->post('/login', $this->credentials($user))->assertSessionHasErrors('email');
        $this->assertGuest();

        $directory->enable($this->sessionRequest($administrator), $administrator, $user->fresh());
        $this->newBrowser();
        $this->withCookie(TrustedDevices::COOKIE, $token);
        $this->assertAskedForCode($user);
    }

    // A sign-in that skips the code never counts as more than a password.

    /** @return iterable<string, array{string}> */
    public static function valuesAPasswordCannotMeet(): iterable
    {
        yield 'multi-factor' => [AuthenticationRequirement::ACR_MFA];
        yield 'emailed code' => [AuthenticationRequirement::AMR_PREFIX.'otp'];
    }

    #[DataProvider('valuesAPasswordCannotMeet')]
    public function test_a_request_for_more_than_a_password_forces_the_code_and_then_succeeds(string $value): void
    {
        $user = $this->person();
        $token = $this->confirmBrowser($user);
        [$client] = $this->client($user);
        $attempts = TwoFactorAttempt::count();
        $url = $this->authorizeUrl($client, ['acr_values' => $value]);

        $this->withCookie(TrustedDevices::COOKIE, $token);
        $this->get($url)->assertRedirect('/login');
        $this->post('/login', $this->credentials($user))->assertRedirect('/login');

        $this->assertGuest();
        $this->assertSame($attempts + 1, TwoFactorAttempt::count());

        $this->verify(TwoFactorAttempt::query()->latest('id')->firstOrFail(), [])->assertOk();

        $this->assertSame(AuthenticationRequirement::ACR_MFA, session(AuthenticationContext::SESSION_KEY)['acr']);
        $this->assertArrayHasKey('code', $this->callbackQuery($this->get($url)));
    }

    public function test_a_session_that_skipped_the_code_is_asked_again_when_an_application_wants_more(): void
    {
        $user = $this->person();
        $token = $this->confirmBrowser($user);
        [$client] = $this->client($user);

        $this->withCookie(TrustedDevices::COOKIE, $token);
        $this->post('/login', $this->credentials($user));
        $this->assertSame(['pwd'], session(AuthenticationContext::SESSION_KEY)['amr']);

        $url = $this->authorizeUrl($client, ['acr_values' => AuthenticationRequirement::ACR_MFA]);
        $this->get($url)->assertRedirect('/login');
        $this->assertAuthenticatedAs($user);

        $attempts = TwoFactorAttempt::count();
        $this->post('/login', $this->credentials($user))->assertRedirect('/login');
        $this->assertSame($attempts + 1, TwoFactorAttempt::count());
    }

    public function test_a_forced_fresh_sign_in_with_no_method_named_accepts_the_password(): void
    {
        $user = $this->person();
        $token = $this->confirmBrowser($user);
        [$client] = $this->client($user);
        $attempts = TwoFactorAttempt::count();
        $url = $this->authorizeUrl($client, ['prompt' => 'login']);

        $this->withCookie(TrustedDevices::COOKIE, $token);
        $this->get($url)->assertRedirect('/login');
        $this->post('/login', $this->credentials($user));

        $this->assertAuthenticatedAs($user);
        $this->assertSame($attempts, TwoFactorAttempt::count());
        $this->assertArrayHasKey('code', $this->callbackQuery($this->get($url)));
    }

    public function test_a_request_that_accepts_any_rung_accepts_the_password(): void
    {
        $user = $this->person();
        $token = $this->confirmBrowser($user);
        [$client] = $this->client($user);
        $url = $this->authorizeUrl($client, ['acr_values' => AuthenticationRequirement::ACR_SINGLE]);

        $this->withCookie(TrustedDevices::COOKIE, $token);
        $this->get($url)->assertRedirect('/login');
        $this->post('/login', $this->credentials($user));

        $this->assertAuthenticatedAs($user);
        $this->assertArrayHasKey('code', $this->callbackQuery($this->get($url)));
    }

    // A passkey reaches the mfa rung, so enrolling one must not be a way round the code.

    public function test_a_session_that_skipped_the_code_cannot_manage_passkeys(): void
    {
        $user = $this->person();
        $token = $this->confirmBrowser($user);

        $this->withCookie(TrustedDevices::COOKIE, $token);
        $this->post('/login', $this->credentials($user));

        $this->postJson('/api/passkeys/register/options')->assertForbidden();
        $this->deleteJson('/api/passkeys/1')->assertForbidden();
    }

    public function test_confirming_the_password_again_does_not_open_passkeys_after_skipping_the_code(): void
    {
        $user = $this->person();
        $token = $this->confirmBrowser($user);

        $this->withCookie(TrustedDevices::COOKIE, $token);
        $this->post('/login', $this->credentials($user));
        // ConfirmApplicationAccessController records this from a password alone.
        RequireRecentPasskeyAuthentication::recordCredentialVerification($this->sessionRequest($user));

        $this->assertTrue(session()->has(RequireRecentPasskeyAuthentication::SESSION_KEY));
        $this->postJson('/api/passkeys/register/options')->assertForbidden();
    }

    public function test_a_session_restored_with_no_context_cannot_open_passkeys_with_a_password(): void
    {
        $user = $this->person();

        $this->actingAs($user)->withSession([RequireRecentPasskeyAuthentication::SESSION_KEY => [
            'user_id' => (string) $user->getKey(),
            'authenticated_at' => now()->getTimestamp(),
        ]]);

        $this->postJson('/api/passkeys/register/options')->assertForbidden();
    }

    public function test_a_sign_in_with_the_code_can_manage_passkeys(): void
    {
        $user = $this->person();
        $this->confirmBrowserAndStaySignedIn($user);

        $this->assertNotSame(403, $this->postJson('/api/passkeys/register/options')->getStatusCode());
    }

    public function test_with_the_setting_off_the_passkey_guard_is_unchanged(): void
    {
        config(['auth-manager.sign_in.trusted_devices' => false]);
        $user = $this->person();

        $this->actingAs($user)->withSession([RequireRecentPasskeyAuthentication::SESSION_KEY => [
            'user_id' => (string) $user->getKey(),
            'authenticated_at' => now()->getTimestamp(),
        ]]);

        $this->assertNotSame(403, $this->postJson('/api/passkeys/register/options')->getStatusCode());
    }

    // Seeing and revoking.

    public function test_a_person_sees_their_browsers_and_which_one_this_is_but_not_anyone_elses(): void
    {
        $user = $this->person();
        $token = $this->confirmBrowser($user, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/131.0 Safari/537.36');
        $other = $this->person(['email' => 'other@example.test']);
        TrustedDevice::query()->create([
            'user_id' => $other->getKey(),
            'token_hash' => hash('sha256', 'other-token'),
            'credential_version' => 0,
            'user_agent' => 'Mozilla/5.0 (Windows NT 10.0) Gecko/20100101 Firefox/133.0',
            'expires_at' => now()->addDay(),
        ]);

        $this->withCookie(TrustedDevices::COOKIE, $token);
        $this->actingAs($user)->get('/settings')->assertOk()
            ->assertSee('Trusted browsers')
            ->assertSee('Chrome on macOS')
            ->assertSee('(this browser)')
            ->assertDontSee('Firefox on Windows')
            ->assertDontSee((string) TrustedDevice::query()->where('user_id', $user->getKey())->value('token_hash'));
    }

    public function test_a_device_from_an_earlier_credential_version_is_not_listed(): void
    {
        $user = $this->person();
        $this->confirmBrowser($user);
        $user->forceFill(['credential_version' => 1])->save();

        $this->actingAs($user->fresh())->withSession($this->credentialVersionSession(1))->get('/settings')->assertOk()->assertSee('No trusted browsers.');
    }

    public function test_removing_this_browser_clears_its_cookie_and_asks_for_the_code_next_time(): void
    {
        $user = $this->person();
        $token = $this->confirmBrowser($user);
        $device = TrustedDevice::firstOrFail();

        $this->withCookie(TrustedDevices::COOKIE, $token);
        $response = $this->actingAs($user)->delete('/settings/trusted-devices/'.$device->getKey())->assertRedirect('/settings');

        $this->assertLessThan(time(), $response->getCookie(TrustedDevices::COOKIE, false)->getExpiresTime());
        $this->assertSame(0, TrustedDevice::count());
        $this->assertSame(1, AuthAuditLog::query()->where('event', 'trusted_device_revoked')->count());
        $this->newBrowser();

        $this->withCookie(TrustedDevices::COOKIE, $token);
        $this->assertAskedForCode($user);
    }

    public function test_removing_another_browser_keeps_this_ones_cookie(): void
    {
        $user = $this->person();
        $token = $this->confirmBrowser($user);
        $elsewhere = TrustedDevice::query()->create([
            'user_id' => $user->getKey(),
            'token_hash' => hash('sha256', 'elsewhere'),
            'credential_version' => 0,
            'expires_at' => now()->addDay(),
        ]);

        $this->withCookie(TrustedDevices::COOKIE, $token);
        $response = $this->actingAs($user)->delete('/settings/trusted-devices/'.$elsewhere->getKey())->assertRedirect('/settings');

        $this->assertNull($response->getCookie(TrustedDevices::COOKIE, false));
        $this->assertSame(1, TrustedDevice::count());
    }

    public function test_nobody_can_remove_someone_elses_browser(): void
    {
        $owner = $this->person();
        $this->confirmBrowser($owner);
        $device = TrustedDevice::firstOrFail();
        $other = $this->person(['email' => 'other@example.test']);

        $this->actingAs($other)->delete('/settings/trusted-devices/'.$device->getKey())->assertNotFound();

        $this->assertSame(1, TrustedDevice::count());
    }

    public function test_removing_all_touches_only_this_person_and_needs_a_session(): void
    {
        $user = $this->person();
        $this->confirmBrowser($user);
        $other = $this->person(['email' => 'other@example.test']);
        TrustedDevice::query()->create([
            'user_id' => $other->getKey(),
            'token_hash' => hash('sha256', 'other-token'),
            'credential_version' => 0,
            'expires_at' => now()->addDay(),
        ]);

        $this->delete('/settings/trusted-devices')->assertRedirect();
        $this->assertSame(2, TrustedDevice::count());

        $this->actingAs($user)->delete('/settings/trusted-devices')->assertRedirect('/settings');

        $this->assertSame(1, TrustedDevice::count());
        $this->assertSame((string) $other->getKey(), (string) TrustedDevice::firstOrFail()->user_id);
    }

    public function test_an_unrecognized_browser_string_is_escaped_and_still_named(): void
    {
        $user = $this->person();
        TrustedDevice::query()->create([
            'user_id' => $user->getKey(),
            'token_hash' => hash('sha256', 'odd'),
            'credential_version' => 0,
            'user_agent' => '<script>alert(1)</script>',
            'expires_at' => now()->addDay(),
        ]);

        $this->actingAs($user)->get('/settings')->assertOk()->assertSee('Unknown browser')->assertDontSee('<script>alert(1)</script>', false);
    }

    // Pruning.

    public function test_pruning_removes_expired_and_outdated_rows_and_keeps_the_rest(): void
    {
        $user = $this->person(['credential_version' => 2]);
        $row = fn (string $name, int $version, Carbon $expires) => TrustedDevice::query()->create([
            'user_id' => $user->getKey(),
            'token_hash' => hash('sha256', $name),
            'credential_version' => $version,
            'expires_at' => $expires,
        ]);
        $kept = $row('kept', 2, now()->addDay());
        $row('expired', 2, now()->subSecond());
        $row('outdated', 1, now()->addDay());

        $this->assertSame(2, TrustedDevice::pruneUnusable());
        $this->assertSame([$kept->getKey()], TrustedDevice::query()->pluck('id')->all());
    }

    public function test_pruning_with_the_setting_off_removes_every_row(): void
    {
        $user = $this->person();
        $this->confirmBrowser($user);
        config(['auth-manager.sign_in.trusted_devices' => false]);

        $this->assertSame(1, TrustedDevice::pruneUnusable());
    }

    public function test_deleting_the_account_removes_its_devices(): void
    {
        $user = $this->person();
        $this->confirmBrowser($user);

        $user->forceDelete();

        $this->assertSame(0, TrustedDevice::count());
    }

    private function assertAskedForCode(User $user, string $password = self::PASSWORD): void
    {
        $attempts = TwoFactorAttempt::count();
        Mail::fake();

        $this->post('/login', ['email' => $user->email, 'password' => $password])->assertRedirect('/login');

        $this->assertGuest();
        $this->assertSame($attempts + 1, TwoFactorAttempt::count());
        Mail::assertSent(TwoFactorLoginMail::class, 1);
    }

    /** Password, code and the choice to trust, ending as a new browser holding only the token. */
    private function confirmBrowser(User $user, ?string $userAgent = null): string
    {
        $token = $this->confirmBrowserAndStaySignedIn($user, $userAgent);
        $this->newBrowser();

        return $token;
    }

    private function confirmBrowserAndStaySignedIn(User $user, ?string $userAgent = null): string
    {
        if ($userAgent !== null) {
            $this->withHeader('User-Agent', $userAgent);
        }
        $this->post('/login', $this->credentials($user))->assertRedirect('/login');
        $attempt = TwoFactorAttempt::query()->latest('id')->firstOrFail();
        $token = $this->verify($attempt, ['trust_device' => true])->assertOk()->getCookie(TrustedDevices::COOKIE)?->getValue();
        $this->assertIsString($token);
        $this->assertNotSame('', $token);

        return $token;
    }

    private function newBrowser(): void
    {
        session()->flush();
        Auth::forgetGuards();
        $this->defaultCookies = [];
        // One application instance serves every request here, so its queue outlives each response.
        app('cookie')->flushQueuedCookies();
    }

    /** @param  array<string, mixed>  $extra */
    private function verify(TwoFactorAttempt $attempt, array $extra): TestResponse
    {
        return $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $attempt->token, 'code' => $attempt->code, ...$extra]);
    }

    /** @param  array<string, mixed>  $attributes */
    private function person(array $attributes = []): User
    {
        return User::factory()->create([
            'user_role' => 'user',
            'password' => self::PASSWORD,
            'remember_token' => null,
            ...$attributes,
        ]);
    }

    private function administrator(): User
    {
        return User::factory()->create(['email' => 'administrator@example.test', 'user_role' => 'admin', 'password' => self::PASSWORD]);
    }

    /** @return array{email: string, password: string} */
    private function credentials(User $user): array
    {
        return ['email' => $user->email, 'password' => self::PASSWORD];
    }

    private function sessionRequest(?User $user = null): Request
    {
        $request = Request::create('/');
        $request->setLaravelSession(session()->driver());
        if ($user !== null) {
            $request->setUserResolver(static fn (): User => $user);
            $request->session()->put(EnsureCredentialVersion::SESSION_KEY, (int) $user->credential_version);
        }

        return $request;
    }

    /** @return array<string, int> */
    private function credentialVersionSession(int $version): array
    {
        return ['auth_credential_version' => $version];
    }

    /** @return array{Client} */
    private function client(User $user): array
    {
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Example Application', [self::CALLBACK]);
        app(OAuthClientGrantService::class)->grant((string) $user->getKey(), (string) $client->getKey());

        return [$client];
    }

    /** @param  array<string, string>  $extra */
    private function authorizeUrl(Client $client, array $extra = []): string
    {
        return '/oauth/authorize?'.http_build_query([
            'client_id' => (string) $client->getKey(),
            'redirect_uri' => self::CALLBACK,
            'response_type' => 'code',
            'state' => 'state-value',
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', str_repeat('v', 64), true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
            ...$extra,
        ]);
    }

    /** @return array<string, string> */
    private function callbackQuery(TestResponse $response): array
    {
        $location = (string) $response->headers->get('Location');
        $this->assertStringStartsWith(self::CALLBACK, $location, "Status {$response->getStatusCode()}: {$location}");
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);

        return $query;
    }
}
