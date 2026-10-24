<?php

namespace Tests\Feature;

use Laravel\Passport\Passport;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\ResourceServer;
use Tests\TestCase;

/**
 * /up must fail when Passport cannot load the signing keys: a 0644 public key makes
 * every token request fail while /up and every unauthenticated probe stay healthy.
 */
final class OAuthSigningKeysHealthTest extends TestCase
{
    private ?string $originalKeyPath;

    private string $directory;

    protected function setUp(): void
    {
        parent::setUp();
        $this->originalKeyPath = Passport::$keyPath;
        $this->directory = sys_get_temp_dir().'/health-keys-'.bin2hex(random_bytes(6));
        // Debug mode rethrows from the health route instead of answering 500.
        config(['app.debug' => false]);
    }

    protected function tearDown(): void
    {
        Passport::$keyPath = $this->originalKeyPath;
        array_map(unlink(...), glob($this->directory.'/*') ?: []);
        is_dir($this->directory) && rmdir($this->directory);
        parent::tearDown();
    }

    public function test_up_is_healthy_when_passport_loads_its_keys(): void
    {
        $this->keyFilesWithPublicMode(0600);

        $this->getJson('/up')->assertOk()->assertExactJson(['status' => 'up']);
    }

    public function test_up_fails_when_passport_refuses_a_key_file(): void
    {
        $this->keyFilesWithPublicMode(0644);

        $this->getJson('/up')->assertStatus(500)->assertExactJson(['status' => 'down']);
    }

    public function test_up_checks_the_keys_even_while_the_agent_oauth_server_is_off(): void
    {
        config(['bherila-auth.oauth_server.enabled' => false]);
        $this->keyFilesWithPublicMode(0644);

        $this->getJson('/up')->assertStatus(500);
    }

    private function keyFilesWithPublicMode(int $mode): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $this->assertNotFalse($key);
        $this->assertTrue(openssl_pkey_export($key, $private));
        $this->assertTrue(mkdir($this->directory, 0700));
        file_put_contents($this->directory.'/oauth-private.key', $private);
        $details = openssl_pkey_get_details($key);
        if ($details === false) {
            $this->fail('Could not read the generated public key.');
        }
        file_put_contents($this->directory.'/oauth-public.key', $details['key']);
        chmod($this->directory.'/oauth-private.key', 0600);
        chmod($this->directory.'/oauth-public.key', $mode);

        Passport::loadKeysFrom($this->directory);
        config(['passport.private_key' => null, 'passport.public_key' => null]);
        $this->app->forgetInstance(AuthorizationServer::class);
        $this->app->forgetInstance(ResourceServer::class);
    }
}
