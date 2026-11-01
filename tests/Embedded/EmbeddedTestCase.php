<?php

namespace Tests\Embedded;

use BWH\AuthManager\Embedded\EmbeddedContext;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Providers\EmbeddedServiceProvider;
use BWH\AuthManager\Services\OAuthClientGrantService;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Foundation\Testing\WithConsoleEvents;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Orchestra\Testbench\TestCase;

/**
 * A minimal host application with Auth Manager mounted at /auth (docs/embedded-mode.md).
 *
 * The host has its own users table, `/` and `/login` routes, `web` group and session
 * cookie. It shares one SQLite database with the provider, so the table prefix is what
 * keeps the two apart.
 */
abstract class EmbeddedTestCase extends TestCase
{
    use WithConsoleEvents;

    protected const HOST = 'https://app.example.test';

    protected const CALLBACK = 'https://app.example.test/oauth/callback';

    /** Environment variables set before the application is created. @var array<string, string> */
    protected array $environment = [];

    /** @return array<string, string> */
    private function environment(): array
    {
        return ['APP_URL' => self::HOST, ...$this->environment];
    }

    protected string $workDirectory;

    protected function setUp(): void
    {
        $this->workDirectory = sys_get_temp_dir().'/auth-manager-embedded-'.Str::uuid();
        (new Filesystem)->ensureDirectoryExists($this->workDirectory.'/sessions', 0700);
        touch($this->workDirectory.'/database.sqlite');
        foreach ($this->environment() as $name => $value) {
            $_ENV[$name] = $_SERVER[$name] = $value;
        }

        parent::setUp();
        // No build in the test environment; EmbeddedViteTest covers the asset URLs.
        $this->withoutVite();

        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('email');
        });
        DB::table('users')->insert(['email' => 'host-user@example.test']);

        $this->artisan('auth-manager:migrate')->assertSuccessful();
        $this->createSigningKeys();
    }

    protected function tearDown(): void
    {
        foreach (array_keys($this->environment()) as $name) {
            unset($_ENV[$name], $_SERVER[$name]);
        }
        Passport::$keyPath = null;

        parent::tearDown();

        (new Filesystem)->deleteDirectory($this->workDirectory);
    }

    protected function defineEnvironment($app): void
    {
        $config = $app['config'];
        $config->set('app.key', 'base64:'.base64_encode(str_repeat('h', 32)));
        $config->set('app.url', self::HOST);
        $config->set('app.name', 'Example Host');
        $config->set('database.default', 'host');
        $config->set('database.connections.host', [
            'driver' => 'sqlite',
            'database' => $this->workDirectory.'/database.sqlite',
            'prefix' => '',
            'foreign_key_constraints' => true,
        ]);
        // A host that signs people in only through the provider serves no auth-laravel
        // routes of its own.
        $config->set('bherila-auth.routes.enabled', false);
        $config->set('session.driver', 'array');
        // The provider's sessions on disk, so each request can start from a fresh store.
        $config->set('session.files', $this->workDirectory.'/sessions');
        $config->set('auth-manager-embedded.session.driver', 'file');
        $config->set('session.cookie', 'host_session');
        $config->set('auth-manager-embedded.keys_path', $this->workDirectory.'/keys');
        $config->set('auth-manager-embedded.name', 'Example Accounts');

        // As a host does: configuration first, then the discovered provider.
        $app->register(EmbeddedServiceProvider::class);
    }

    protected function defineRoutes($router): void
    {
        Route::middleware('web')->group(function (): void {
            Route::get('/', fn () => 'host home')->name('home');
            Route::get('/login', fn () => 'host login')->name('login');
            Route::get('/.well-known/oauth-authorization-server', fn () => response()->json(['issuer' => 'host']));
        });
    }

    protected function createSigningKeys(): void
    {
        $directory = $this->workDirectory.'/keys';
        (new Filesystem)->ensureDirectoryExists($directory, 0700);
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $this->assertNotFalse($key);
        $this->assertTrue(openssl_pkey_export($key, $privateKey));
        $details = openssl_pkey_get_details($key);
        $this->assertIsArray($details);
        (new Filesystem)->put($directory.'/oauth-private.key', $privateKey);
        (new Filesystem)->put($directory.'/oauth-public.key', $details['key']);
        chmod($directory.'/oauth-private.key', 0600);
        chmod($directory.'/oauth-public.key', 0600);
    }

    /** @return array{User, Client, string} */
    protected function grantedClient(string $password): array
    {
        return app(EmbeddedContext::class)->run(function () use ($password): array {
            $user = User::factory()->create(['email' => 'person@example.test', 'password' => $password, 'user_role' => 'user']);
            $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Example Host', [self::CALLBACK]);
            app(OAuthClientGrantService::class)->grant((string) $user->getKey(), (string) $client->getKey());

            return [$user, $client, (string) $client->plain_secret];
        });
    }

    /**
     * The relying party's side of authorization code + PKCE, as auth-laravel's
     * RelyingPartyLoginController performs it, through a browser session.
     *
     * @param  array<string, string>  $extra
     * @return array{code: string, verifier: string, session: string}
     */
    protected function authorizeThroughBrowser(Client $client, string $password, array $extra = []): array
    {
        $verifier = Str::random(64);
        $query = [
            'client_id' => (string) $client->getKey(),
            'redirect_uri' => self::CALLBACK,
            'response_type' => 'code',
            'scope' => 'identity:read',
            'state' => 'state-value',
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
            ...$extra,
        ];
        ksort($query); // As the intended URL normalizes it.
        $authorize = '/auth/oauth/authorize?'.http_build_query($query);

        // A guest goes to the provider's own sign-in page, never to the host's /login.
        $guest = $this->freshRequest()->get($authorize)->assertRedirect(self::HOST.'/auth/login');
        $session = $this->providerSession($guest);

        // Signing in regenerates the session id; the new one carries the authorization on.
        $signedIn = $this->freshRequest()->withCookie('auth_manager_session', $session)
            ->post('/auth/login', ['email' => 'person@example.test', 'password' => $password])
            ->assertRedirect(self::HOST.$authorize);
        $session = $this->providerSession($signedIn);

        $approved = $this->freshRequest()->withCookie('auth_manager_session', $session)->get($authorize)->assertRedirect();
        $location = (string) $approved->headers->get('Location');
        $this->assertStringStartsWith(self::CALLBACK.'?', $location);
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);
        $this->assertSame('state-value', $query['state'] ?? null);
        $this->assertIsString($query['code'] ?? null);

        return ['code' => $query['code'], 'verifier' => $verifier, 'session' => $session];
    }

    /** The provider session id a response set, or the one the request already carried. */
    protected function providerSession(TestResponse $response): string
    {
        $cookie = $response->getCookie('auth_manager_session');
        $this->assertNotNull($cookie, 'The response did not set the provider session cookie.');

        return (string) $cookie->getValue();
    }

    /** @return array<string, mixed> */
    protected function exchange(Client $client, string $secret, string $code, string $verifier): array
    {
        return $this->freshRequest()->post('/auth/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => (string) $client->getKey(),
            'client_secret' => $secret,
            'redirect_uri' => self::CALLBACK,
            'code' => $code,
            'code_verifier' => $verifier,
        ])->assertOk()->json();
    }

    /**
     * The next request as a new process sees it: only the cookies it is given, and no
     * signed-in user remembered by a guard from an earlier request.
     */
    protected function freshRequest(): static
    {
        $this->app['auth']->forgetGuards();
        $this->app['session']->forgetDrivers();

        return $this->withoutCookies();
    }

    protected function withoutCookies(): static
    {
        $this->defaultCookies = [];
        $this->unencryptedCookies = [];

        return $this;
    }
}
