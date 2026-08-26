<?php

namespace Tests\Feature;

use App\Models\User;
use App\Services\OAuthClientGrantService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Tests\TestCase;

class OAuthClientGrantEndpointTest extends TestCase
{
    use RefreshDatabase;

    private string $keyDirectory;

    protected function setUp(): void
    {
        parent::setUp();

        config()->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
        $this->keyDirectory = storage_path('framework/testing/oauth-'.Str::uuid());
        File::ensureDirectoryExists($this->keyDirectory, 0700);

        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $this->assertNotFalse($key);
        $this->assertTrue(openssl_pkey_export($key, $privateKey));
        $details = openssl_pkey_get_details($key);
        $this->assertIsArray($details);

        File::put($this->keyDirectory.'/oauth-private.key', $privateKey);
        File::put($this->keyDirectory.'/oauth-public.key', $details['key']);
        chmod($this->keyDirectory.'/oauth-private.key', 0600);
        chmod($this->keyDirectory.'/oauth-public.key', 0600);
        Passport::loadKeysFrom($this->keyDirectory);
    }

    protected function tearDown(): void
    {
        Passport::$keyPath = null;
        File::deleteDirectory($this->keyDirectory);

        parent::tearDown();
    }

    public function test_code_exchange_rechecks_a_grant_removed_after_authorization(): void
    {
        [$user, $client, $secret] = $this->grantedClient();
        $authorizationCode = $this->authorizationCode($user, $client);
        app(OAuthClientGrantService::class)->revoke((string) $user->getKey(), (string) $client->getKey());

        $this->post('/oauth/token', $this->authorizationCodePayload($client, $secret, $authorizationCode))
            ->assertStatus(400)
            ->assertJsonPath('error', 'invalid_grant');
    }

    public function test_removing_a_grant_invalidates_access_and_refresh_immediately(): void
    {
        [$user, $client, $secret] = $this->grantedClient();
        $authorizationCode = $this->authorizationCode($user, $client);
        $tokenResponse = $this->post(
            '/oauth/token',
            $this->authorizationCodePayload($client, $secret, $authorizationCode),
        )->assertOk();
        $accessToken = (string) $tokenResponse->json('access_token');
        $refreshToken = (string) $tokenResponse->json('refresh_token');

        $this->withToken($accessToken)->getJson('/api/oauth/user')->assertOk();

        app(OAuthClientGrantService::class)->revoke((string) $user->getKey(), (string) $client->getKey());
        Auth::forgetGuards();

        $this->withToken($accessToken)->getJson('/api/oauth/user')->assertUnauthorized();
        $this->withoutHeader('Authorization');
        Auth::forgetGuards();
        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => (string) $client->getKey(),
            'client_secret' => $secret,
            'refresh_token' => $refreshToken,
        ])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
    }

    public function test_deleting_a_client_invalidates_an_existing_bearer_token(): void
    {
        [$user, $client, $secret] = $this->grantedClient();
        $authorizationCode = $this->authorizationCode($user, $client);
        $accessToken = (string) $this->post(
            '/oauth/token',
            $this->authorizationCodePayload($client, $secret, $authorizationCode),
        )->assertOk()->json('access_token');

        DB::table('oauth_clients')->where('id', $client->getKey())->delete();
        Auth::forgetGuards();

        $this->withToken($accessToken)->getJson('/api/oauth/user')->assertUnauthorized();
    }

    /** @return array{User, Client, string} */
    private function grantedClient(): array
    {
        $user = User::factory()->create(['user_role' => 'user']);
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient(
            'Example Application',
            ['https://app.example.test/oauth/callback'],
        );
        $secret = (string) $client->plain_secret;
        app(OAuthClientGrantService::class)->grant((string) $user->getKey(), (string) $client->getKey());

        return [$user, $client, $secret];
    }

    private function authorizationCode(User $user, Client $client): string
    {
        $verifier = str_repeat('v', 64);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $response = $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'client_id' => (string) $client->getKey(),
            'redirect_uri' => 'https://app.example.test/oauth/callback',
            'response_type' => 'code',
            'scope' => 'identity:read',
            'state' => 'state-value',
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]))->assertRedirect();
        parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $query);
        $this->assertSame('state-value', $query['state'] ?? null);
        $this->assertIsString($query['code'] ?? null);

        session(['oauth-test-verifier' => $verifier]);

        return $query['code'];
    }

    /** @return array<string, string> */
    private function authorizationCodePayload(Client $client, string $secret, string $code): array
    {
        return [
            'grant_type' => 'authorization_code',
            'client_id' => (string) $client->getKey(),
            'client_secret' => $secret,
            'redirect_uri' => 'https://app.example.test/oauth/callback',
            'code' => $code,
            'code_verifier' => (string) session('oauth-test-verifier'),
        ];
    }
}
