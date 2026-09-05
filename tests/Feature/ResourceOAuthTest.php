<?php

namespace Tests\Feature;

use App\Models\User;
use App\Services\OAuthClientGrantService;
use BWH\Auth\Http\Middleware\EnforceOAuthPkce;
use BWH\Auth\Http\Middleware\EnforceOAuthResourceIndicator;
use BWH\Auth\OAuth\Server\OAuthResourceIndicator;
use BWH\Auth\OAuth\Server\ResourceAccessTokenRepository;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\Bridge\AccessTokenRepository;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunClassInSeparateProcess;
use Tests\TestCase;

#[RunClassInSeparateProcess]
#[PreserveGlobalState(false)]
class ResourceOAuthTest extends TestCase
{
    use RefreshDatabase;

    private const ISSUER = 'https://identity.example.test';

    private const RESOURCE = 'https://resource.example.test/mcp';

    private string $keyDirectory;

    /** @var array<string, array{process: string|false, env_set: bool, env: mixed, server_set: bool, server: mixed}> */
    private array $previousEnvironment = [];

    protected function setUp(): void
    {
        $this->setResourceEnvironment();

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

        $this->restoreEnvironment();
    }

    public function test_resource_profile_only_enables_resource_server_routes_and_middleware(): void
    {
        $this->assertSame('resource', config('auth-manager.profile'));
        $this->assertTrue(config('auth-manager.oauth_server'));
        $this->assertTrue(config('bherila-auth.routes.enabled'));
        $this->assertTrue(config('bherila-auth.oauth_server.enabled'));
        $this->assertSame(['mcp:use', 'offers:read'], array_keys(config('auth-manager.scopes')));
        $this->assertSame(self::RESOURCE, config('auth-manager.resource'));
        $this->assertNotNull(Route::getRoutes()->getByName('oauth.metadata.authorization-server'));
        $this->assertNull(Route::getRoutes()->getByName('oauth.metadata.protected-resource'));
        $this->assertNotNull(Route::getRoutes()->getByName('oauth.register'));
        $this->assertNotNull(Route::getRoutes()->getByName('oauth.introspect'));
        $this->assertContains('throttle:10,1', Route::getRoutes()->getByName('oauth.register')?->gatherMiddleware() ?? []);
        $this->assertContains('throttle:300,1', Route::getRoutes()->getByName('oauth.introspect')?->gatherMiddleware() ?? []);
        $this->assertInstanceOf(ResourceAccessTokenRepository::class, app(AccessTokenRepository::class));

        foreach (['passport.authorizations.authorize', 'passport.authorizations.approve', 'passport.authorizations.deny', 'passport.token'] as $name) {
            $route = Route::getRoutes()->getByName($name);
            $this->assertNotNull($route);
            $this->assertContains(EnforceOAuthPkce::class, $route->gatherMiddleware());
            $this->assertContains(EnforceOAuthResourceIndicator::class, $route->gatherMiddleware());
        }

        $this->getJson('/.well-known/oauth-authorization-server')
            ->assertOk()
            ->assertJsonPath('issuer', self::ISSUER);
    }

    public function test_resource_binding_survives_code_and_refresh_grants_and_rejects_wrong_targets(): void
    {
        [$user, $client, $secret] = $this->grantedClient();
        [$code, $verifier] = $this->authorizationCode($user, $client);

        $this->post('/oauth/token', $this->tokenPayload($client, $secret, $code, $verifier))
            ->assertStatus(400)
            ->assertJsonPath('error', 'invalid_grant');
        $this->post('/oauth/token', $this->tokenPayload($client, $secret, $code, $verifier, 'https://example.test/other'))
            ->assertStatus(400)
            ->assertJsonPath('error', 'invalid_target');

        [$code, $verifier] = $this->authorizationCode($user, $client);
        $issued = $this->post('/oauth/token', $this->tokenPayload($client, $secret, $code, $verifier, self::RESOURCE))
            ->assertOk();
        $claims = OAuthResourceIndicator::tokenClaims((string) $issued->json('access_token'));
        $this->assertSame(self::RESOURCE, $claims['resource'] ?? null);
        $this->assertContains(self::RESOURCE, $claims['aud'] ?? []);
        $this->assertSame(self::RESOURCE, Passport::token()->newQuery()->whereKey($claims['jti'])->value('resource_uri'));

        $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => (string) $client->getKey(),
            'client_secret' => $secret,
            'refresh_token' => (string) $issued->json('refresh_token'),
        ])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
        $refreshed = $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => (string) $client->getKey(),
            'client_secret' => $secret,
            'refresh_token' => (string) $issued->json('refresh_token'),
            'resource' => self::RESOURCE,
        ])->assertOk();
        $this->assertSame(self::RESOURCE, OAuthResourceIndicator::tokenClaims((string) $refreshed->json('access_token'))['resource'] ?? null);
    }

    public function test_uc_dynamic_registration_creates_an_untrusted_public_client(): void
    {
        $response = $this->postJson('/oauth/register', [
            'client_name' => 'Example MCP Client',
            'redirect_uris' => ['http://127.0.0.1:39053/callback'],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
            'scope' => 'mcp:use offers:read',
        ])->assertCreated()
            ->assertJsonPath('token_endpoint_auth_method', 'none')
            ->assertJsonMissingPath('client_secret');

        $client = Passport::client()->newQuery()->findOrFail($response->json('client_id'));
        $this->assertNull($client->secret);
        $this->assertNotNull($client->dynamically_registered_at);
        $this->assertFalse($client->firstParty());
        $this->assertFalse($client->skipsAuthorization(
            User::factory()->create(['user_role' => 'user']),
            Passport::scopesFor(['mcp:use', 'offers:read']),
        ));
    }

    public function test_introspection_rejects_bad_credentials_and_reports_grant_or_account_revocation(): void
    {
        [$user, $client, $secret] = $this->grantedClient();
        [$code, $verifier] = $this->authorizationCode($user, $client);
        $accessToken = (string) $this->post('/oauth/token', $this->tokenPayload($client, $secret, $code, $verifier, self::RESOURCE))
            ->assertOk()
            ->json('access_token');

        $this->post('/oauth/introspect', ['token' => $accessToken], [
            'Authorization' => 'Basic '.base64_encode('wrong:credentials'),
        ])->assertUnauthorized()->assertJsonPath('error', 'invalid_client');

        $this->introspect($accessToken)->assertOk()->assertJsonPath('active', true);
        app(OAuthClientGrantService::class)->revoke((string) $user->getKey(), (string) $client->getKey());
        $this->introspect($accessToken)->assertOk()->assertJsonPath('active', false);

        app(OAuthClientGrantService::class)->grant((string) $user->getKey(), (string) $client->getKey());
        [$code, $verifier] = $this->authorizationCode($user, $client);
        $activeToken = (string) $this->post('/oauth/token', $this->tokenPayload($client, $secret, $code, $verifier, self::RESOURCE))
            ->assertOk()
            ->json('access_token');
        $user->update(['disabled_at' => now()]);
        Auth::forgetGuards();
        $this->introspect($activeToken)->assertOk()->assertJsonPath('active', false);
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

    /** @return array{string, string} */
    private function authorizationCode(User $user, Client $client): array
    {
        $verifier = str_repeat('v', 64);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $response = $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'client_id' => (string) $client->getKey(),
            'redirect_uri' => 'https://app.example.test/oauth/callback',
            'response_type' => 'code',
            'scope' => 'mcp:use offers:read',
            'resource' => self::RESOURCE,
            'state' => 'state-value',
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]))->assertRedirect();
        parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $query);
        $this->assertIsString($query['code'] ?? null);

        return [$query['code'], $verifier];
    }

    /** @return array<string, string> */
    private function tokenPayload(Client $client, string $secret, string $code, string $verifier, ?string $resource = null): array
    {
        return array_filter([
            'grant_type' => 'authorization_code',
            'client_id' => (string) $client->getKey(),
            'client_secret' => $secret,
            'redirect_uri' => 'https://app.example.test/oauth/callback',
            'code' => $code,
            'code_verifier' => $verifier,
            'resource' => $resource,
        ], static fn (?string $value): bool => $value !== null);
    }

    private function introspect(string $token): TestResponse
    {
        return $this->post('/oauth/introspect', ['token' => $token], [
            'Authorization' => 'Basic '.base64_encode('resource-server:test-introspection-secret'),
        ]);
    }

    private function setResourceEnvironment(): void
    {
        $environment = [
            'AUTH_MANAGER_PROFILE' => 'resource',
            'AUTH_MANAGER_OAUTH_ISSUER' => self::ISSUER,
            'AUTH_MANAGER_OAUTH_RESOURCE' => self::RESOURCE,
            'AUTH_MANAGER_THEME_COOKIE_DOMAIN' => '.example.test',
            'AUTH_MANAGER_THEME_ALLOWED_HOSTS' => 'example.test',
            'AUTH_MANAGER_INTROSPECTION_CLIENT_ID' => 'resource-server',
            'AUTH_MANAGER_INTROSPECTION_SECRET_HASH' => password_hash('test-introspection-secret', PASSWORD_DEFAULT),
        ];

        foreach ($environment as $key => $value) {
            $this->previousEnvironment[$key] = [
                'process' => getenv($key),
                'env_set' => array_key_exists($key, $_ENV),
                'env' => $_ENV[$key] ?? null,
                'server_set' => array_key_exists($key, $_SERVER),
                'server' => $_SERVER[$key] ?? null,
            ];
            putenv($key.'='.$value);
            $_ENV[$key] = $value;
            $_SERVER[$key] = $value;
        }
    }

    private function restoreEnvironment(): void
    {
        foreach ($this->previousEnvironment as $key => $previous) {
            putenv($previous['process'] === false ? $key : $key.'='.$previous['process']);

            if ($previous['env_set']) {
                $_ENV[$key] = $previous['env'];
            } else {
                unset($_ENV[$key]);
            }

            if ($previous['server_set']) {
                $_SERVER[$key] = $previous['server'];
            } else {
                unset($_SERVER[$key]);
            }
        }
    }
}
