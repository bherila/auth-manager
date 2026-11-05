<?php

namespace Tests\Embedded;

use BWH\Auth\OAuth\Login\RelyingPartyAccounts;
use BWH\Auth\OAuth\Login\SubjectBoundAccounts;
use BWH\Auth\OAuth\OAuthIdentity;
use BWH\AuthManager\Embedded\EmbeddedContext;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Providers\EmbeddedServiceProvider;
use BWH\AuthManager\Services\DirectoryCopy\DirectoryArchive;
use BWH\AuthManager\Services\DirectoryCopy\DirectoryTransfer;
use BWH\AuthManager\Services\OAuthClientGrantService;
use Illuminate\Container\Container;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;

class EmbeddedDirectoryCopyTest extends EmbeddedTestCase
{
    protected function defineEnvironment($app): void
    {
        // The provider and host each use a separate SQLite in-memory connection.
        $config = $app['config'];
        $config->set('app.key', 'base64:'.base64_encode(str_repeat('h', 32)));
        $config->set('app.url', self::HOST);
        $config->set('database.default', 'host');
        $config->set('database.connections.host', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '', 'foreign_key_constraints' => true]);
        $config->set('bherila-auth.routes.enabled', false);
        $config->set('session.driver', 'array');
        $config->set('session.cookie', 'host_session');
        $config->set('auth-manager-embedded.keys_path', $this->workDirectory.'/keys');
        $app->register(EmbeddedServiceProvider::class);
    }

    public function test_embedded_export_to_standalone_keeps_the_relying_application_binding(): void
    {
        [$client, $secret] = app(EmbeddedContext::class)->run(function (): array {
            $user = User::factory()->create(['id' => 37, 'email' => 'person@example.test', 'password' => 'correct horse battery staple', 'user_role' => 'user']);
            $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Example Host', [self::CALLBACK]);
            app(OAuthClientGrantService::class)->grant((string) $user->id, (string) $client->id);

            return [$client, $client->plainSecret];
        });
        $snapshot = app(EmbeddedContext::class)->run(fn (): array => app(DirectoryTransfer::class)->snapshot());
        $archive = DirectoryArchive::decode(DirectoryArchive::encode($snapshot));
        $source = $this->app;
        $oldAppUrl = $_ENV['APP_URL'];
        $_ENV['APP_URL'] = $_SERVER['APP_URL'] = 'https://id.example.test';
        try {
            // Boot the real standalone app, with a new key, new SQLite database and new OAuth keys.
            $target = require dirname(__DIR__, 2).'/bootstrap/app.php';
            $target->make(Kernel::class)->bootstrap();
            $this->app = $target;
            Facade::setFacadeApplication($target);
            Facade::clearResolvedInstances();
            config(['app.key' => 'base64:'.base64_encode(str_repeat('t', 32)), 'database.default' => 'sqlite', 'database.connections.sqlite.database' => ':memory:', 'passport.connection' => 'sqlite', 'session.driver' => 'array', 'bherila-auth.passkeys.rp_id' => 'app.example.test']);
            DB::purge('sqlite');
            $this->artisan('migrate', ['--force' => true])->assertSuccessful();
            app(DirectoryTransfer::class)->import($archive['checksum'], $archive['payload'], true);
            $targetKeys = $this->workDirectory.'/target-keys';
            mkdir($targetKeys, 0700);
            $key = openssl_pkey_new(['private_key_bits' => 2048]);
            openssl_pkey_export($key, $private);
            file_put_contents($targetKeys.'/oauth-private.key', $private);
            file_put_contents($targetKeys.'/oauth-public.key', openssl_pkey_get_details($key)['key']);
            chmod($targetKeys.'/oauth-private.key', 0600);
            chmod($targetKeys.'/oauth-public.key', 0600);
            Passport::loadKeysFrom($targetKeys);

            $this->post('/login', ['email' => 'person@example.test', 'password' => 'correct horse battery staple'])->assertRedirect();
            $verifier = Str::random(64);
            $authorization = $this->get('/oauth/authorize?'.http_build_query([
                'client_id' => $client->id, 'redirect_uri' => self::CALLBACK, 'response_type' => 'code', 'scope' => 'identity:read', 'state' => 'test-state',
                'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='), 'code_challenge_method' => 'S256',
            ]))->assertRedirect();
            parse_str(parse_url($authorization->headers->get('Location'), PHP_URL_QUERY), $query);
            $token = $this->post('/oauth/token', ['grant_type' => 'authorization_code', 'client_id' => $client->id, 'client_secret' => $secret, 'redirect_uri' => self::CALLBACK, 'code' => $query['code'], 'code_verifier' => $verifier])->assertOk()->json('access_token');
            $this->app['auth']->forgetGuards();
            $identity = $this->withToken($token)->getJson('/api/oauth/user')->assertOk()->json();
            $this->assertSame('37', $identity['sub']);
            $this->assertSame(1, DB::table('users')->count());

            // The consumer's existing (provider, opaque subject) binding resolves unchanged.
            Schema::create('consumer_accounts', function (Blueprint $table): void {
                $table->id();
                $table->string('name');
                $table->string('email')->unique();
                $table->string('password');
                $table->timestamp('email_verified_at')->nullable();
                $table->string('oauth_provider');
                $table->string('oauth_subject');
                $table->timestamps();
            });
            DB::table('consumer_accounts')->insert(['id' => 91, 'name' => 'Existing person', 'email' => 'person@example.test', 'password' => 'unused', 'oauth_provider' => 'same-provider-name', 'oauth_subject' => '37']);
            $accounts = new class extends RelyingPartyAccounts
            {
                public function model(): string
                {
                    return PortableConsumerAccount::class;
                }
            };
            $resolved = app(SubjectBoundAccounts::class)->resolve(new OAuthIdentity('same-provider-name', $identity['sub'], $identity['name'], $identity['email']), $accounts);
            $this->assertSame(91, $resolved->id);
            $this->assertSame(1, DB::table('consumer_accounts')->count());
        } finally {
            $this->app = $source;
            Container::setInstance($source);
            Facade::setFacadeApplication($source);
            Facade::clearResolvedInstances();
            $_ENV['APP_URL'] = $_SERVER['APP_URL'] = $oldAppUrl;
        }
    }
}

class PortableConsumerAccount extends Model
{
    protected $table = 'consumer_accounts';

    protected $guarded = [];
}
