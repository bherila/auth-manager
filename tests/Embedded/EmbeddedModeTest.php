<?php

namespace Tests\Embedded;

use BWH\AuthManager\Embedded\EmbeddedContext;
use BWH\AuthManager\Embedded\EmbeddedVite;
use BWH\AuthManager\Support\Mount;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;

class EmbeddedModeTest extends EmbeddedTestCase
{
    public function test_a_relying_party_completes_authorization_code_with_pkce_under_the_prefix(): void
    {
        [$user, $client, $secret] = $this->grantedClient('correct horse battery staple');

        $authorization = $this->authorizeThroughBrowser($client, 'correct horse battery staple');
        $tokens = $this->exchange($client, $secret, $authorization['code'], $authorization['verifier']);
        $this->assertIsString($tokens['access_token'] ?? null);

        $this->freshRequest()->withToken($tokens['access_token'])->getJson('/auth/api/oauth/user')
            ->assertOk()
            ->assertJsonPath('sub', (string) $user->getKey())
            ->assertJsonPath('email', 'person@example.test');

        // The code is bound to its verifier.
        $other = $this->authorizeThroughBrowser($client, 'correct horse battery staple');
        $this->freshRequest()->post('/auth/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => (string) $client->getKey(),
            'client_secret' => $secret,
            'redirect_uri' => self::CALLBACK,
            'code' => $other['code'],
            'code_verifier' => Str::random(64),
        ])->assertStatus(400);
    }

    public function test_the_issuer_and_generated_urls_are_below_the_prefix(): void
    {
        $this->assertSame(self::HOST.'/auth', config('auth-manager.issuer'));
        $this->assertSame(self::HOST.'/auth/oauth/authorize', config('auth-manager-embedded.overlay.bherila-auth.oauth_server.authorization_endpoint'));
        $this->assertSame(self::HOST.'/auth/oauth/token', config('auth-manager-embedded.overlay.bherila-auth.oauth_server.token_endpoint'));
        $this->assertNull(config('auth-manager.theme.cookie_domain'));

        $this->get('/auth/login')
            ->assertOk()
            ->assertSee('<meta name="auth-manager-base" content="/auth">', false)
            ->assertSee('action="'.self::HOST.'/auth/login"', false)
            ->assertSee('<title>Sign in</title>', false);

        // The provider's name is its own, not the host's.
        $this->assertSame('Example Accounts', app(EmbeddedContext::class)->run(fn () => config('app.name')));
        $this->assertSame('Example Host', config('app.name'));
        $this->assertSame('Example Accounts', config('auth-manager-embedded.overlay.bherila-auth.passkeys.rp_name'));

        // The default profile publishes no metadata, embedded or not.
        $this->get('/.well-known/oauth-authorization-server/auth')->assertNotFound();
    }

    public function test_the_session_cookie_is_the_providers_own_and_scoped_to_the_prefix(): void
    {
        $response = $this->get('/auth/login')->assertOk();

        $session = $this->cookieHeader($response->headers->all('set-cookie'), 'auth_manager_session');
        $this->assertNotNull($session, 'The provider set no session cookie.');
        $this->assertMatchesRegularExpression('~;\s*path=/auth(;|$)~i', $session);
        $this->assertDoesNotMatchRegularExpression('~;\s*domain=~i', $session);
        $this->assertMatchesRegularExpression('~;\s*httponly~i', $session);
        // Neither the host's session nor the host-owned XSRF-TOKEN name is touched.
        $this->assertNull($this->cookieHeader($response->headers->all('set-cookie'), 'host_session'));
        $this->assertNull($this->cookieHeader($response->headers->all('set-cookie'), 'XSRF-TOKEN'));

        // The host's pages keep the host's own session cookie at the root path.
        $host = $this->get('/login')->assertOk()->assertSee('host login');
        $hostCookie = $this->cookieHeader($host->headers->all('set-cookie'), 'host_session');
        $this->assertNotNull($hostCookie);
        $this->assertMatchesRegularExpression('~;\s*path=/(;|$)~i', $hostCookie);
        $this->assertNull($this->cookieHeader($host->headers->all('set-cookie'), 'auth_manager_session'));
    }

    public function test_the_remember_me_cookie_is_scoped_to_the_prefix(): void
    {
        $this->grantedClient('correct horse battery staple');
        $session = $this->providerSession($this->get('/auth/login'));

        $response = $this->freshRequest()->withCookie('auth_manager_session', $session)
            ->post('/auth/login', ['email' => 'person@example.test', 'password' => 'correct horse battery staple', 'remember' => '1'])
            ->assertRedirect(self::HOST.'/auth');

        $remember = collect($response->headers->all('set-cookie'))->first(fn (string $cookie): bool => str_starts_with($cookie, 'remember_auth-manager_'));
        $this->assertNotNull($remember, 'Signing in with "remember" set no remember cookie for the provider guard.');
        $this->assertMatchesRegularExpression('~;\s*path=/auth(;|$)~i', $remember);
    }

    public function test_csrf_is_checked_against_the_providers_own_session(): void
    {
        $this->grantedClient('correct horse battery staple');
        $page = $this->get('/auth/login')->assertOk();
        $session = $this->providerSession($page);
        preg_match('~<meta name="csrf-token" content="([^"]+)">~', (string) $page->getContent(), $token);
        $this->assertNotEmpty($token[1] ?? null);

        // Laravel skips CSRF while unit tests run; check it as a deployment would.
        $this->app['env'] = 'production';
        try {
            $this->freshRequest()->withCookie('auth_manager_session', $session)
                ->post('/auth/login', ['email' => 'person@example.test', 'password' => 'correct horse battery staple'])
                ->assertStatus(419);
            $this->freshRequest()->withCookie('auth_manager_session', $session)
                ->post('/auth/login', ['email' => 'person@example.test', 'password' => 'correct horse battery staple', '_token' => $token[1]])
                ->assertRedirect(self::HOST.'/auth');
        } finally {
            $this->app['env'] = 'testing';
        }
    }

    public function test_every_provider_route_is_below_the_prefix_and_host_routes_are_untouched(): void
    {
        $outside = [];
        foreach (Route::getRoutes() as $route) {
            $uri = $route->uri();
            if (in_array($uri, ['/', 'login', '.well-known/oauth-authorization-server'], true)) {
                continue; // The host's own.
            }
            if ($uri !== 'auth' && ! str_starts_with($uri, 'auth/') && ! str_starts_with($uri, 'storage/')) {
                $outside[] = $uri;
            }
        }
        $this->assertSame([], $outside, 'Routes outside the prefix: '.implode(', ', $outside));

        // Passport's own unguarded routes were never registered at the root.
        $this->get('/oauth/authorize')->assertNotFound();
        $this->post('/oauth/token')->assertNotFound();

        // The host's names, pages and metadata still resolve to the host.
        $this->assertSame('/login', route('login', absolute: false));
        $this->assertSame('/', route('home', absolute: false));
        $this->assertSame('/auth/login', route('auth-manager.login', absolute: false));
        $this->get('/')->assertOk()->assertSee('host home');
        $this->get('/login')->assertOk()->assertSee('host login');
        $this->getJson('/.well-known/oauth-authorization-server')->assertOk()->assertExactJson(['issuer' => 'host']);
    }

    public function test_the_provider_keeps_its_own_prefixed_tables_and_users(): void
    {
        [$user, $client] = $this->grantedClient('correct horse battery staple');

        // One database: the host's tables and the provider's prefixed ones side by side.
        $this->assertTrue(Schema::hasTable('auth_manager_users'));
        $this->assertTrue(Schema::hasTable('auth_manager_oauth_clients'));
        $this->assertTrue(Schema::hasTable('auth_manager_migrations'));
        $this->assertFalse(Schema::hasTable('oauth_clients'));
        $this->assertSame(['host-user@example.test'], DB::table('users')->pluck('email')->all());
        $this->assertSame(['person@example.test'], DB::table('auth_manager_users')->pluck('email')->all());

        // Outside the context, the default connection and guard are the host's again.
        $this->assertSame('host', DB::getDefaultConnection());
        $this->assertSame('web', auth()->getDefaultDriver());
        $this->assertSame(Mount::EMBEDDED_CONNECTION, $user->getConnectionName());

        // Signing in to the provider never signs anyone in to the host.
        $this->authorizeThroughBrowser($client, 'correct horse battery staple');
        $this->assertFalse(auth('web')->check());
    }

    public function test_provider_api_errors_render_as_json(): void
    {
        $this->freshRequest()->post('/auth/api/reconciliation/identity-status', [])
            ->assertUnauthorized()
            ->assertHeader('Content-Type', 'application/json');
    }

    public function test_assets_are_served_only_from_the_package_build(): void
    {
        $directory = Mount::packagePath('public/build/assets');
        $created = ! is_dir($directory);
        $name = 'embedded-test-'.Str::lower(Str::random(8)).'.js';
        @mkdir($directory, 0755, true);
        file_put_contents($directory.'/'.$name, 'export {};');

        try {
            $this->get('/auth/build/assets/'.$name)
                ->assertOk()
                ->assertHeader('Content-Type', 'text/javascript; charset=utf-8')
                ->assertHeader('Cache-Control', 'immutable, max-age=31536000, public');
            $this->get('/auth/build/assets/missing.js')->assertNotFound();
            $this->get('/auth/build/assets/..%2F..%2F..%2Fcomposer.json')->assertNotFound();
            $this->get('/auth/build/assets/'.basename($name, '.js').'.php')->assertNotFound();
        } finally {
            @unlink($directory.'/'.$name);
            if ($created) {
                @rmdir($directory);
                @rmdir(dirname($directory));
            }
        }
    }

    public function test_provider_commands_run_against_the_providers_tables(): void
    {
        [$user] = $this->grantedClient('correct horse battery staple');

        $this->artisan('auth-manager:user-roles', ['user' => 'person@example.test', '--add' => ['admin']])->assertSuccessful();

        $this->assertSame('user,admin', DB::table('auth_manager_users')->where('id', $user->getKey())->value('user_role'));
        $this->assertSame(['host-user@example.test'], DB::table('users')->pluck('email')->all());
        $this->assertSame('host', DB::getDefaultConnection());
    }

    public function test_pages_load_the_packages_assets_below_the_prefix(): void
    {
        $manifest = Mount::packagePath('public/build/manifest.json');
        $written = ! is_file($manifest);
        if ($written) {
            @mkdir(dirname($manifest), 0755, true);
            file_put_contents($manifest, json_encode(['resources/js/app.js' => ['file' => 'assets/app-test.js', 'isEntry' => true, 'src' => 'resources/js/app.js']]));
        }

        try {
            $url = EmbeddedVite::create()->asset('resources/js/app.js');
            $this->assertMatchesRegularExpression('~\A'.preg_quote(self::HOST, '~').'/auth/build/assets/[^/]+\.js\z~', $url);
        } finally {
            if ($written) {
                @unlink($manifest);
                @rmdir(dirname($manifest));
            }
        }
    }

    /** @param list<string> $headers */
    private function cookieHeader(array $headers, string $name): ?string
    {
        foreach ($headers as $header) {
            if (str_starts_with($header, $name.'=')) {
                return $header;
            }
        }

        return null;
    }
}
