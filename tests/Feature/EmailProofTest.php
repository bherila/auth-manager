<?php

namespace Tests\Feature;

use BWH\Auth\Models\TwoFactorAttempt;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Services\EmailProof;
use BWH\AuthManager\Services\OAuthClientGrantService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Sleep;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Tests\TestCase;

/** AR-1: the identity response's `email_verified` claim is true only for a proven, current address. */
final class EmailProofTest extends TestCase
{
    use RefreshDatabase;

    private const CALLBACK = 'https://app.example.test/oauth/callback';

    private const PASSWORD = 'synthetic-password';

    private const NEW_PASSWORD = 'a-new-synthetic-password';

    private string $keyDirectory;

    protected function setUp(): void
    {
        parent::setUp();
        $this->withoutVite();
        Cache::flush();
        Mail::fake();
        Sleep::fake();
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
        parent::tearDown();
    }

    public function test_a_proven_address_is_reported_as_verified(): void
    {
        $user = $this->person(verified: true);

        $this->identityFor($user)->assertOk()->assertJsonPath('email_verified', true);
    }

    public function test_an_unproven_address_omits_the_claim_rather_than_sending_false(): void
    {
        $user = $this->person(verified: false);

        $this->identityFor($user)->assertOk()->assertJsonMissingPath('email_verified');
    }

    public function test_a_verified_emailed_code_does_not_yet_prove_the_address(): void
    {
        // The attempt records no destination, so a challenge raced with an address change could
        // have mailed the former address; a code sign-in proves nothing until it does.
        $user = $this->person(verified: false);
        $token = $this->postJson('/login/email-code', ['email' => $user->email])->json('attempt_token');

        $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $token, 'code' => TwoFactorAttempt::where('token', $token)->value('code')])->assertOk();

        $this->assertAuthenticatedAs($user);
        $this->assertNull($user->fresh()->email_verified_at);
        $this->identityFor($user->fresh())->assertJsonMissingPath('email_verified');
    }

    public function test_a_password_alone_proves_nothing(): void
    {
        config(['auth-manager.sign_in.code_after_password' => false]);
        $user = $this->person(verified: false);

        $this->post('/login', ['email' => $user->email, 'password' => self::PASSWORD]);

        $this->assertAuthenticatedAs($user);
        $this->assertNull($user->fresh()->email_verified_at);
    }

    public function test_an_address_change_withdraws_codes_mailed_to_the_former_address(): void
    {
        $user = $this->person(verified: false);
        $token = $this->postJson('/login/email-code', ['email' => $user->email])->json('attempt_token');
        $code = (string) TwoFactorAttempt::where('token', $token)->value('code');

        Auth::forgetGuards();
        $this->actingAs($this->administrator())
            ->patchJson("/api/admin/users/{$user->id}/email", ['email' => 'changed@example.test'])
            ->assertOk();
        Auth::forgetGuards();
        $this->app['auth']->guard('web')->logout();

        $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $token, 'code' => $code]);

        $this->assertSame(0, TwoFactorAttempt::query()->where('user_id', $user->id)->count(), 'The change withdraws codes still outstanding.');
        $this->assertSame('changed@example.test', $user->fresh()->email);
        $this->assertNull($user->fresh()->email_verified_at);
    }

    public function test_an_address_change_clears_proof_and_the_claim(): void
    {
        $user = $this->person(verified: true);

        $this->actingAs($this->administrator())
            ->patchJson("/api/admin/users/{$user->id}/email", ['email' => 'changed@example.test'])
            ->assertOk();

        $this->assertNull($user->fresh()->email_verified_at);
        $this->identityFor($user->fresh())->assertJsonMissingPath('email_verified');
    }

    public function test_proof_for_an_address_the_account_no_longer_has_is_not_recorded(): void
    {
        $user = $this->person(verified: false);
        $stale = User::query()->findOrFail($user->id);
        DB::table('users')->where('id', $user->id)->update(['email' => 'changed@example.test']);

        app(EmailProof::class)->proveCurrentAddress($stale);

        $this->assertNull($user->fresh()->email_verified_at);
    }

    public function test_proof_already_recorded_keeps_its_original_time(): void
    {
        $user = $this->person(verified: false);
        $user->forceFill(['email_verified_at' => now()->subYear()])->save();
        $original = $user->fresh()->email_verified_at;

        app(EmailProof::class)->proveCurrentAddress($user->fresh());

        $this->assertEquals($original, $user->fresh()->email_verified_at);
    }

    public function test_completing_an_emailed_password_reset_proves_the_address(): void
    {
        config(['auth-manager.sign_in.password_reset' => true]);
        $user = $this->person(verified: false);
        $token = Password::broker()->createToken($user);

        $this->post('/reset-password', $this->resetFields($user, $token))->assertRedirect();

        $this->assertNotNull($user->fresh()->email_verified_at);
    }

    public function test_a_reset_link_mailed_before_an_address_change_stops_working(): void
    {
        config(['auth-manager.sign_in.password_reset' => true]);
        $user = $this->person(verified: false);
        $token = Password::broker()->createToken($user);
        $formerEmail = $user->email;

        $this->actingAs($this->administrator())
            ->patchJson("/api/admin/users/{$user->id}/email", ['email' => 'changed@example.test'])
            ->assertOk();
        $this->app['auth']->guard('web')->logout();

        $this->assertSame(0, DB::table('password_reset_tokens')->where('email', $formerEmail)->count());
        $this->post('/reset-password', ['token' => $token, 'email' => 'changed@example.test', 'password' => self::NEW_PASSWORD, 'password_confirmation' => self::NEW_PASSWORD]);

        $this->assertNull($user->fresh()->email_verified_at);
    }

    private function person(bool $verified, string $email = 'person@example.test'): User
    {
        return User::factory()->create([
            'email' => $email,
            'password' => self::PASSWORD,
            'user_role' => 'user',
            'email_verified_at' => $verified ? now() : null,
        ]);
    }

    private function administrator(): User
    {
        return User::factory()->create(['email' => 'admin@example.test', 'user_role' => 'admin']);
    }

    /** The identity response for a fresh authorization-code login by `$user`. */
    private function identityFor(User $user): TestResponse
    {
        // A fresh browser: nothing carried over from an earlier request in the test (an admin's
        // session, its recorded sign-in context) may decide this person's authorization.
        Auth::forgetGuards();
        $this->flushSession();

        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Example Application '.Str::random(6), [self::CALLBACK]);
        app(OAuthClientGrantService::class)->grant((string) $user->getKey(), (string) $client->getKey());

        $location = (string) $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'client_id' => (string) $client->getKey(),
            'redirect_uri' => self::CALLBACK,
            'response_type' => 'code',
            'state' => 'state-value',
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $this->verifier(), true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
        ]))->headers->get('Location');
        $this->assertStringStartsWith(self::CALLBACK, $location);
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);

        $tokens = $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code', 'client_id' => (string) $client->getKey(), 'client_secret' => (string) $client->plain_secret,
            'redirect_uri' => self::CALLBACK, 'code' => $query['code'], 'code_verifier' => $this->verifier(),
        ])->assertOk();

        Auth::forgetGuards();

        return $this->withToken((string) $tokens->json('access_token'))->getJson('/api/oauth/user');
    }

    private function verifier(): string
    {
        return str_repeat('v', 64);
    }

    /** @return array<string, string> */
    private function resetFields(User $user, string $token): array
    {
        return ['token' => $token, 'email' => $user->email, 'password' => self::NEW_PASSWORD, 'password_confirmation' => self::NEW_PASSWORD];
    }
}
