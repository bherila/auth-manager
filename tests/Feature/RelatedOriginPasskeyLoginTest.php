<?php

namespace Tests\Feature;

use BWH\Auth\Models\PasskeyCredential;
use BWH\Auth\OAuth\Session\AuthenticationContext;
use BWH\AuthManager\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use OpenSSLAsymmetricKey;
use Tests\TestCase;

class RelatedOriginPasskeyLoginTest extends TestCase
{
    use RefreshDatabase;

    public function test_the_login_page_offers_only_operator_enabled_rps_for_its_exact_https_origin(): void
    {
        $this->withoutVite();
        config(['bherila-auth.passkeys.related_origins' => [
            'app.example.test' => ['https://id.example.test'],
            'another.example.test' => ['https://other.example.test'],
            'https://invalid.example.test' => ['https://id.example.test'],
        ]]);

        $this->get('https://id.example.test/login')->assertOk()
            ->assertViewHas('relatedPasskeyRps', ['app.example.test'])
            ->assertSee('data-related-rps="[&quot;app.example.test&quot;]"', false);
        $this->get('http://id.example.test/login')->assertOk()->assertViewHas('relatedPasskeyRps', []);
        $this->get('https://sub.id.example.test/login')->assertOk()->assertViewHas('relatedPasskeyRps', []);
        $this->get('https://id.example.test:8443/login')->assertOk()->assertViewHas('relatedPasskeyRps', []);
    }

    public function test_no_compatibility_choices_are_offered_by_default(): void
    {
        $this->withoutVite();
        $this->get('https://id.example.test/login')->assertOk()->assertViewHas('relatedPasskeyRps', []);
    }

    public function test_an_original_rp_passkey_establishes_provider_authentication_and_keeps_new_enrollment_separate(): void
    {
        config(['bherila-auth.passkeys.rp_id' => 'example.test',
            'bherila-auth.passkeys.related_origins' => ['app.example.test' => ['https://id.example.test']]]);
        $user = User::factory()->create(['user_role' => 'user']);
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $key);
        $details = openssl_pkey_get_details($key);
        $this->assertIsArray($details);
        $public = "\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20".str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT)
            ."\x22\x58\x20".str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT);
        $id = $this->base64Url(random_bytes(32));
        $passkey = PasskeyCredential::create(['user_id' => $user->id, 'credential_id' => $id,
            'public_key' => base64_encode($public), 'counter' => 0, 'rp_id' => 'app.example.test', 'name' => 'Synthetic migrated key']);
        $options = $this->postJson('https://id.example.test/api/passkeys/auth/options?rp_id=app.example.test')
            ->assertOk()->assertJsonPath('rpId', 'app.example.test');
        $client = json_encode(['type' => 'webauthn.get', 'challenge' => $options->json('challenge'),
            'origin' => 'https://id.example.test'], JSON_THROW_ON_ERROR);
        $authenticator = hash('sha256', 'app.example.test', true)."\x05".pack('N', 1);
        $this->assertTrue(openssl_sign($authenticator.hash('sha256', $client, true), $signature, $key, OPENSSL_ALGO_SHA256));
        $this->postJson('https://id.example.test/api/passkeys/auth', ['credential' => [
            'id' => $id, 'rawId' => $id, 'type' => 'public-key', 'response' => [
                'clientDataJSON' => $this->base64Url($client), 'authenticatorData' => $this->base64Url($authenticator),
                'signature' => $this->base64Url($signature), 'userHandle' => $this->base64Url((string) $user->id),
            ],
        ]])->assertOk();

        $this->assertAuthenticatedAs($user);
        $this->assertSame((string) $user->id, session(AuthenticationContext::SESSION_KEY.'.account'));
        $this->assertSame(['hwk'], session(AuthenticationContext::SESSION_KEY.'.amr'));
        $this->assertSame('app.example.test', $passkey->fresh()->rp_id);
        $this->assertSame(1, $passkey->fresh()->counter);
        $this->postJson('https://id.example.test/api/passkeys/register/options')
            ->assertOk()->assertJsonPath('rp.id', 'example.test');
    }

    private function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
