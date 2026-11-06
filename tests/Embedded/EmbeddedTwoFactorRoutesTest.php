<?php

namespace Tests\Embedded;

use BWH\Auth\Mail\TwoFactorLoginMail;
use BWH\Auth\Services\TwoFactorService;
use BWH\AuthManager\Embedded\EmbeddedContext;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Foundation\Auth\User as HostUser;
use Illuminate\Foundation\Support\Providers\RouteServiceProvider;
use Illuminate\Http\Request;
use Illuminate\Routing\CompiledRouteCollection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\DataProvider;

/** Host and provider confirmation/report names must coexist, including after cache reload. */
final class EmbeddedTwoFactorRoutesTest extends EmbeddedTestCase
{
    protected function defineEnvironment($app): void
    {
        (new Filesystem)->ensureDirectoryExists($this->workDirectory.'/bootstrap/cache', 0700);
        $app->useBootstrapPath($this->workDirectory.'/bootstrap');
        parent::defineEnvironment($app);
        $app['config']->set('auth.providers.users.model', HostUser::class);
        $app['config']->set('bherila-auth.users.model', HostUser::class);
        $app['config']->set('bherila-auth.audit.driver', 'null');
        $app['config']->set('bherila-auth.two_factor.table', 'host_two_factor_attempts');
        $app['config']->set('bherila-auth.routes', [
            'enabled' => true, 'prefix' => 'api', 'middleware' => ['web'],
            'passkeys' => false, 'password_resets' => false, 'change_password' => false, 'two_factor' => true,
        ]);
        // A real host boots its cached route file through Laravel's route provider.
        $app->register(RouteServiceProvider::class);
    }

    protected function setUp(): void
    {
        parent::setUp();
        Schema::table('users', function (Blueprint $table): void {
            $table->string('name')->nullable();
            $table->string('password')->nullable();
            $table->rememberToken();
        });
        Schema::create('host_two_factor_attempts', function (Blueprint $table): void {
            $table->id();
            $table->unsignedBigInteger('user_id');
            $table->string('token')->unique();
            $table->string('code');
            $table->boolean('is_used')->default(false);
            $table->boolean('is_suspicious')->default(false);
            $table->string('ip_address')->nullable();
            $table->text('user_agent')->nullable();
            $table->timestamp('expires_at');
            $table->timestamps();
        });
    }

    /** @return array<string, array{bool}> */
    public static function routeModes(): array
    {
        return ['uncached' => [false], 'fresh boot from route cache' => [true]];
    }

    #[DataProvider('routeModes')]
    public function test_email_links_and_form_actions_keep_their_realm_and_only_confirm_the_matching_guard(bool $cached): void
    {
        if ($cached) {
            $this->cacheRoutesAndBootFreshApplication();
        }
        Mail::fake();
        foreach (['confirm', 'confirm.submit', 'report', 'report.submit'] as $action) {
            $this->assertSame('api/auth/two-factor/'.strtok($action, '.').'/{token}', Route::getRoutes()->getByName('bherila-auth.two-factor.'.$action)?->uri());
            $this->assertSame('auth/api/auth/two-factor/'.strtok($action, '.').'/{token}', Route::getRoutes()->getByName('auth-manager.two-factor.'.$action)?->uri());
        }

        [$provider] = $this->grantedClient('synthetic-provider-password');
        $host = HostUser::query()->findOrFail(1);
        DB::table('users')->where('id', $host->getKey())->update(['email' => $provider->email]);
        $host->refresh();
        $request = Request::create(self::HOST.'/login', 'POST');
        $request->setLaravelSession(app('session')->driver('array'));
        $hostAttempt = app(TwoFactorService::class)->startChallenge($host, $request);
        $providerAttempt = app(EmbeddedContext::class)->run(fn () => app(TwoFactorService::class)->startChallenge($provider, $request));

        $links = [];
        Mail::assertSent(TwoFactorLoginMail::class, function (TwoFactorLoginMail $mail) use (&$links): bool {
            $links[(string) $mail->attempt->token] = [$mail->confirmUrl, $mail->reportUrl];

            return true;
        });
        foreach ([[$hostAttempt, '/api/auth/two-factor'], [$providerAttempt, '/auth/api/auth/two-factor']] as [$attempt, $base]) {
            $this->assertSame(self::HOST.$base.'/confirm/'.$attempt->token, $links[$attempt->token][0]);
            $this->assertSame(self::HOST.$base.'/report/'.$attempt->token, $links[$attempt->token][1]);
            $this->freshRequest()->get($base.'/confirm/'.$attempt->token)->assertOk()->assertSee('action="'.self::HOST.$base.'/confirm/'.$attempt->token.'"', false);
            $this->freshRequest()->get($base.'/report/'.$attempt->token)->assertOk()->assertSee('action="'.self::HOST.$base.'/report/'.$attempt->token.'"', false);
            $this->assertGuest('web');
            $this->assertGuest('auth-manager');
        }
        $this->freshRequest()->getJson('/api/auth/two-factor/confirm/'.$providerAttempt->token)->assertStatus(422);
        $this->freshRequest()->getJson('/auth/api/auth/two-factor/confirm/'.$hostAttempt->token)->assertStatus(422);
        $this->assertFalse($hostAttempt->fresh()->is_used);
        $this->assertFalse(app(EmbeddedContext::class)->run(fn () => $providerAttempt->fresh()->is_used));

        // Provider tokens also reach the browser's code form, so a token alone
        // must continue to be insufficient even though its email URL is correct.
        $this->freshRequest()->postJson('/auth/api/auth/two-factor/confirm/'.$providerAttempt->token)->assertStatus(422);
        $this->assertGuest('auth-manager');
        $this->freshRequest()->postJson('/auth/api/auth/two-factor/verify', ['attempt_token' => $providerAttempt->token, 'code' => $providerAttempt->code])->assertOk();
        $this->assertAuthenticatedAs($provider, 'auth-manager');
        $this->assertGuest('web');
        $this->freshRequest()->postJson('/api/auth/two-factor/confirm/'.$hostAttempt->token)->assertOk();
        $this->assertAuthenticatedAs($host, 'web');
        $this->assertSame('bherila-auth.two-factor.', config('bherila-auth.two_factor.route_name_prefix'));
    }

    private function cacheRoutesAndBootFreshApplication(): void
    {
        $routes = Route::getRoutes();
        foreach ($routes as $route) {
            $route->prepareForSerialization();
        }
        // The same payload Laravel's route:cache writes, then a new application boot.
        // Compilation also rejects duplicate names before a broken cache can be used.
        $compiled = var_export($routes->compile(), true);
        (new Filesystem)->put($this->app->getCachedRoutesPath(), "<?php\napp('router')->setCompiledRoutes({$compiled});\n");
        $this->refreshApplication();
        $this->withoutVite();
        $this->assertTrue($this->app->routesAreCached());
        $this->assertInstanceOf(CompiledRouteCollection::class, Route::getRoutes());
    }
}
