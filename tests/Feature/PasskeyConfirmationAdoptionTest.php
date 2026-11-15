<?php

namespace Tests\Feature;

use BWH\Auth\Http\Middleware\RequirePasswordConfirmation;
use BWH\Auth\Models\PasskeyCredential;
use BWH\Auth\Models\TwoFactorAttempt;
use BWH\Auth\OAuth\Session\AuthenticationContext as SharedAuthenticationContext;
use BWH\AuthManager\Http\Middleware\EnsureCredentialVersion;
use BWH\AuthManager\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use OpenSSLAsymmetricKey;
use Tests\TestCase;

final class PasskeyConfirmationAdoptionTest extends TestCase
{
    use RefreshDatabase;

    public function test_explicit_password_confirmation_unblocks_enrollment_but_does_not_refresh_removal_proof(): void
    {
        $user = User::factory()->create(['password' => 'synthetic-password', 'user_role' => 'user']);
        $this->actingAs($user)->postJson('/api/passkeys/register/options')->assertStatus(423)
            ->assertJsonPath('error', 'password_confirmation_required');
        $this->postJson('/api/auth/confirm-password', ['password' => 'wrong'])->assertUnprocessable();
        $this->postJson('/api/passkeys/register/options')->assertStatus(423);
        $this->postJson('/api/auth/confirm-password', ['password' => 'synthetic-password'])->assertOk();
        $this->postJson('/api/passkeys/register/options')->assertOk()->assertJsonStructure(['challenge']);
        $this->deleteJson('/api/passkeys/1')->assertForbidden();
        $this->travel(601)->seconds();
        $this->postJson('/api/passkeys/register/options')->assertStatus(423);
    }

    public function test_an_existing_user_verified_passkey_confirms_the_same_account_without_signing_in_again(): void
    {
        $user = User::factory()->create(['password' => Hash::make(bin2hex(random_bytes(32))), 'user_role' => 'user']);
        [$id, $key] = $this->credential($user);
        $this->actingAs($user)->postJson('/api/passkeys/register/options')->assertStatus(423);
        $this->assertion($id, $key, userVerified: false)->assertUnprocessable();
        $this->assertFalse(session()->has(RequirePasswordConfirmation::PASSKEY_SESSION_KEY));
        $this->postJson('/api/passkeys/register/options')->assertStatus(423);

        $this->assertion($id, $key)->assertOk()->assertJsonPath('success', true);
        $this->assertAuthenticatedAs($user);
        $this->assertSame((string) $user->id, session(RequirePasswordConfirmation::PASSKEY_SESSION_KEY.'.account'));
        $this->assertSame(0, $user->fresh()->credential_version);
        $this->postJson('/api/passkeys/register/options')->assertOk();
        $this->deleteJson('/api/passkeys/1')->assertForbidden();
    }

    public function test_password_confirmation_cannot_replace_a_skipped_second_factor_but_a_user_verified_passkey_can(): void
    {
        config(['auth-manager.sign_in.trusted_devices' => true, 'auth-manager.sign_in.code_after_password' => true]);
        $user = User::factory()->create(['password' => 'synthetic-password', 'user_role' => 'user']);
        [$id, $key] = $this->credential($user);
        $this->actingAs($user)->postJson('/api/auth/confirm-password', ['password' => 'synthetic-password'])->assertOk();
        $this->postJson('/api/passkeys/register/options')->assertForbidden();
        $this->assertion($id, $key)->assertOk();
        $this->postJson('/api/passkeys/register/options')->assertOk();
    }

    public function test_another_accounts_valid_signed_passkey_cannot_confirm_the_current_account(): void
    {
        $user = User::factory()->create(['user_role' => 'user']);
        $other = User::factory()->create(['user_role' => 'user']);
        [$id, $key] = $this->credential($other);
        $this->actingAs($user);
        $this->assertion($id, $key)->assertUnprocessable();
        $this->assertAuthenticatedAs($user);
        $this->assertFalse(session()->has(RequirePasswordConfirmation::PASSKEY_SESSION_KEY));
        $this->postJson('/api/passkeys/register/options')->assertStatus(423);
    }

    public function test_cross_account_and_future_passkey_proofs_do_not_unblock_enrollment(): void
    {
        $user = User::factory()->create(['user_role' => 'user']);
        foreach ([['account' => 'another-account', 'at' => now()->timestamp], ['account' => (string) $user->id, 'at' => now()->addSecond()->timestamp]] as $proof) {
            $this->actingAs($user)->withSession([RequirePasswordConfirmation::PASSKEY_SESSION_KEY => $proof])
                ->postJson('/api/passkeys/register/options')->assertStatus(423);
        }
    }

    public function test_provider_context_keeps_the_original_credential_time_and_does_not_refresh_a_stale_session(): void
    {
        $user = User::factory()->create(['password' => 'synthetic-password', 'user_role' => 'user']);
        $this->post('/login', ['email' => $user->email, 'password' => 'synthetic-password'])->assertRedirect();
        $context = session(SharedAuthenticationContext::SESSION_KEY);
        $this->assertSame((string) $user->id, $context['account']);
        $this->assertSame(['pwd'], $context['amr']);
        $this->postJson('/api/passkeys/register/options')->assertOk();
        $this->travel(601)->seconds();
        $this->postJson('/api/passkeys/register/options')->assertStatus(423);
        $this->assertSame($context, session(SharedAuthenticationContext::SESSION_KEY));
    }

    public function test_password_hash_session_guard_rejects_a_stale_hash_even_at_the_current_credential_generation(): void
    {
        $user = User::factory()->create(['user_role' => 'user', 'credential_version' => 3]);
        $this->actingAs($user)->withToken('synthetic-invalid-bearer')->withSession([
            EnsureCredentialVersion::SESSION_KEY => 3,
            'password_hash_web' => str_repeat('0', 64),
        ])->getJson('/settings')->assertUnauthorized();
        $this->assertGuest();
    }

    public function test_a_downstream_bearer_guard_switch_cannot_rewrite_the_browser_password_hash(): void
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $key);
        $details = openssl_pkey_get_details($key);
        $this->assertIsArray($details);
        config(['passport.public_key' => $details['key']]);
        $browser = User::factory()->create(['user_role' => 'user', 'password' => 'synthetic-browser-password']);
        $bearer = User::factory()->create(['user_role' => 'user', 'password' => 'synthetic-bearer-password']);
        $expected = auth('web')->hashPasswordForCookie($browser->getAuthPassword());
        Route::middleware('web')->get('/synthetic-guard-switch', static function () use ($bearer) {
            Auth::guard('api')->setUser($bearer);
            Auth::shouldUse('api');

            return response()->json(['subject' => (string) auth()->id()]);
        });

        $this->actingAs($browser)->getJson('/synthetic-guard-switch')->assertOk()
            ->assertJsonPath('subject', (string) $bearer->id);
        $this->assertSame($expected, session('password_hash_web'));
        $this->assertFalse(session()->has('password_hash_api'));
        $this->assertSame('api', Auth::getDefaultDriver());
    }

    public function test_a_downstream_request_principal_switch_cannot_poison_the_browser_password_hash(): void
    {
        $browser = User::factory()->create(['user_role' => 'user', 'password' => 'synthetic-browser-password']);
        $api = User::factory()->create(['user_role' => 'user', 'password' => 'synthetic-api-password']);
        $expected = auth('web')->hashPasswordForCookie($browser->getAuthPassword());
        Route::middleware('web')->get('/synthetic-principal-switch', static function (Request $request) use ($api) {
            $request->setUserResolver(static fn () => $api);

            return response()->json(['subject' => (string) $request->user()->id]);
        });

        $this->actingAs($browser)->getJson('/synthetic-principal-switch')->assertOk()
            ->assertJsonPath('subject', (string) $api->id);
        $this->assertSame($expected, session('password_hash_web'));
        $this->assertAuthenticatedAs($browser);
    }

    public function test_the_shared_controller_spends_a_challenge_after_five_wrong_codes_across_source_addresses(): void
    {
        $user = User::factory()->create(['user_role' => 'user']);
        $attempt = TwoFactorAttempt::createForUser($user);
        $wrong = $attempt->code === '000000' ? '111111' : '000000';
        foreach (range(1, 5) as $number) {
            $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.'.$number])
                ->postJson('/api/auth/two-factor/verify', ['attempt_token' => $attempt->token, 'code' => $wrong])
                ->assertUnprocessable();
        }
        $this->assertTrue($attempt->fresh()->is_used);
        $this->postJson('/api/auth/two-factor/verify', ['attempt_token' => $attempt->token, 'code' => $attempt->code])
            ->assertUnprocessable();
        $this->assertGuest();
    }

    /** @return array{string, OpenSSLAsymmetricKey} */
    private function credential(User $user): array
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $key);
        $details = openssl_pkey_get_details($key);
        $this->assertIsArray($details);
        $public = "\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20".str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT)."\x22\x58\x20".str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT);
        $id = $this->base64Url(random_bytes(32));
        PasskeyCredential::create([
            'user_id' => $user->id, 'credential_id' => $id, 'public_key' => base64_encode($public),
            'counter' => 0, 'rp_id' => 'id.example.test', 'name' => 'Synthetic existing passkey',
        ]);

        return [$id, $key];
    }

    private function assertion(string $id, OpenSSLAsymmetricKey $key, bool $userVerified = true): TestResponse
    {
        $options = $this->postJson('https://id.example.test/api/passkeys/confirm/options')->assertOk()->assertJsonPath('userVerification', 'required');
        $client = json_encode(['type' => 'webauthn.get', 'challenge' => $options->json('challenge'), 'origin' => 'https://id.example.test'], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $authenticator = hash('sha256', 'id.example.test', true).($userVerified ? "\x05" : "\x01").pack('N', (int) PasskeyCredential::where('credential_id', $id)->value('counter') + 1);
        $this->assertTrue(openssl_sign($authenticator.hash('sha256', $client, true), $signature, $key, OPENSSL_ALGO_SHA256));

        $response = $this->postJson('https://id.example.test/api/passkeys/confirm', ['credential' => [
            'id' => $id, 'rawId' => $id, 'type' => 'public-key',
            'response' => ['clientDataJSON' => $this->base64Url($client), 'authenticatorData' => $this->base64Url($authenticator), 'signature' => $this->base64Url($signature), 'userHandle' => $this->base64Url((string) auth()->id())],
        ]]);

        return $response;
    }

    private function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
