<?php

namespace Tests\Embedded;

use BWH\Auth\Models\PasskeyCredential;
use BWH\AuthManager\Embedded\EmbeddedContext;
use BWH\AuthManager\Services\AuthenticationContext;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\DataProvider;

class EmbeddedPasskeyRememberTest extends EmbeddedTestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        // These ceremonies need only isolated in-memory databases; cookies and
        // the provider session remain on the fixture's private temporary paths.
        $app['config']->set('database.connections.host.database', ':memory:');
        $app['config']->set('database.connections.auth-manager.database', ':memory:');
    }

    /** @return array<string, array{bool}> */
    public static function choices(): array
    {
        return ['checked' => [true], 'unchecked' => [false]];
    }

    #[DataProvider('choices')]
    public function test_passkey_remember_cookies_belong_only_to_the_mounted_provider(bool $remember): void
    {
        [$user] = $this->grantedClient('synthetic-password');
        $privateKey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $this->assertInstanceOf(OpenSSLAsymmetricKey::class, $privateKey);
        $details = openssl_pkey_get_details($privateKey);
        $this->assertIsArray($details);
        $publicKey = "\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20".$details['ec']['x']."\x22\x58\x20".$details['ec']['y'];
        $id = $this->base64Url(random_bytes(32));
        app(EmbeddedContext::class)->run(fn () => PasskeyCredential::create([
            'user_id' => $user->id, 'credential_id' => $id, 'public_key' => base64_encode($publicKey),
            'counter' => 0, 'rp_id' => 'app.example.test', 'name' => 'Synthetic device',
        ]));
        $options = $this->withCredentials()->freshRequest()->postJson('/auth/api/passkeys/auth/options')->assertOk();
        $session = $this->providerSession($options);
        $clientData = json_encode([
            'type' => 'webauthn.get', 'challenge' => $options->json('challenge'), 'origin' => self::HOST,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $authData = hash('sha256', 'app.example.test', true)."\x05".pack('N', 1);
        $this->assertTrue(openssl_sign($authData.hash('sha256', $clientData, true), $signature, $privateKey, OPENSSL_ALGO_SHA256));
        $response = $this->freshRequest()->withCookie('auth_manager_session', $session)
            ->postJson('/auth/api/passkeys/auth', ['remember' => $remember, 'credential' => [
                'id' => $id, 'rawId' => $id, 'type' => 'public-key',
                'response' => [
                    'clientDataJSON' => $this->base64Url($clientData), 'authenticatorData' => $this->base64Url($authData),
                    'signature' => $this->base64Url($signature), 'userHandle' => $this->base64Url((string) $user->id),
                ],
            ]])->assertOk()->assertJsonPath('success', true);

        $this->assertAuthenticatedAs($user, 'auth-manager');
        $this->assertGuest('web');
        $this->assertNull($response->getCookie('host_session'));
        $this->assertSame(1, app(EmbeddedContext::class)->run(fn () => PasskeyCredential::sole()->counter));
        $name = auth('auth-manager')->getRecallerName();
        $cookie = $response->getCookie($name);
        if (! $remember) {
            $this->assertNull($cookie);

            return;
        }

        $this->assertNotNull($cookie);
        $this->assertSame('/auth', $cookie->getPath());
        $this->assertNull($cookie->getDomain());
        $this->assertTrue($cookie->isHttpOnly());
        $this->assertGreaterThan(time(), $cookie->getExpiresTime());
        // Drop the provider session cookie: only the provider's recaller is
        // presented to the next request, and it cannot establish a host login.
        $this->freshRequest()->withCookie($name, (string) $cookie->getValue())->get('/auth/settings')->assertOk();
        $this->assertTrue(auth('auth-manager')->viaRemember());
        $this->assertGuest('web');
        $this->assertFalse(app(EmbeddedContext::class)->run(fn () => session()->has(AuthenticationContext::SESSION_KEY)));
    }

    private function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
