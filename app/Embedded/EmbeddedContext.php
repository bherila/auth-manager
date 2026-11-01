<?php

namespace BWH\AuthManager\Embedded;

use BWH\AuthManager\Support\Mount;
use Closure;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Foundation\Vite;
use Illuminate\Mail\Markdown;
use Illuminate\Session\SessionManager;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\View\FileViewFinder;

/**
 * The embedded provider's side of a shared Laravel process.
 *
 * Entering switches, for one provider request or command, everything the host and the
 * provider would otherwise share: the overlaid configuration files, the default
 * database connection (the prefixed `auth-manager` one), the default guard, the session
 * store and its cookie, the cookie jar's path, view lookup, the mail theme and the Vite
 * manifest. Leaving restores the host's values. Entries nest; only the outermost one
 * switches.
 */
final class EmbeddedContext
{
    /** The session driver name the provider's store is cached under, apart from the host's. */
    public const SESSION_DRIVER = 'auth-manager';

    private int $depth = 0;

    /** @var list<Closure(): void> */
    private array $restore = [];

    public function __construct(private readonly Application $app) {}

    public function active(): bool
    {
        return $this->depth > 0;
    }

    /**
     * @template T
     *
     * @param  callable(): T  $callback
     * @return T
     */
    public function run(callable $callback): mixed
    {
        $this->enter();

        try {
            return $callback();
        } finally {
            $this->leave();
        }
    }

    public function enter(): void
    {
        if ($this->depth++ > 0) {
            return;
        }

        $config = $this->app['config'];
        $saved = [];
        $set = static function (string $key, mixed $value) use ($config, &$saved): void {
            if (! array_key_exists($key, $saved)) {
                $saved[$key] = $config->get($key);
            }
            $config->set($key, $value);
        };

        foreach ((array) $config->get('auth-manager-embedded.overlay', []) as $key => $value) {
            $set($key, $value);
        }
        $set('app.name', (string) ($config->get('auth-manager-embedded.name') ?: $config->get('app.name')));
        $set('passport.guard', Mount::EMBEDDED_GUARD);
        $set('mail.markdown.paths', [Mount::packagePath('resources/views/vendor/mail'), ...(array) $config->get('mail.markdown.paths', [])]);
        $hostSession = (array) $config->get('session', []);
        $session = $this->sessionConfig($hostSession);
        $set('session', $session);

        $this->restore[] = static function () use ($config, &$saved): void {
            foreach ($saved as $key => $value) {
                $config->set($key, $value);
            }
        };

        $this->switchDatabase();
        $this->switchGuard();
        $this->switchSession($session, $hostSession);
        $this->switchViews();
        $this->switchVite();
    }

    public function leave(): void
    {
        if ($this->depth === 0 || --$this->depth > 0) {
            return;
        }

        while (($restore = array_pop($this->restore)) !== null) {
            $restore();
        }
    }

    /**
     * @param  array<string, mixed>  $host
     * @return array<string, mixed>
     */
    private function sessionConfig(array $host): array
    {
        $config = $this->app['config'];
        $driver = (string) ($config->get('auth-manager-embedded.session.driver') ?: ($host['driver'] ?? 'file'));
        $lifetime = $config->get('auth-manager-embedded.session.lifetime');

        return [
            ...$host,
            'driver' => self::SESSION_DRIVER,
            'embedded_driver' => $driver,
            'cookie' => (string) $config->get('auth-manager-embedded.session.cookie', 'auth_manager_session'),
            'path' => Mount::path('/'),
            // Host-only: a session for one application's provider is never sent to siblings.
            'domain' => null,
            'lifetime' => is_numeric($lifetime) ? (int) $lifetime : ($host['lifetime'] ?? 120),
            'connection' => $driver === 'database' ? Mount::EMBEDDED_CONNECTION : ($host['connection'] ?? null),
            'table' => $driver === 'database' ? 'sessions' : ($host['table'] ?? 'sessions'),
        ];
    }

    private function switchDatabase(): void
    {
        $previous = DB::getDefaultConnection();
        DB::setDefaultConnection(Mount::EMBEDDED_CONNECTION);
        $this->restore[] = static fn () => DB::setDefaultConnection($previous);
    }

    private function switchGuard(): void
    {
        $previous = Auth::getDefaultDriver();
        Auth::shouldUse(Mount::EMBEDDED_GUARD);
        $this->restore[] = static fn () => Auth::shouldUse($previous);
    }

    /**
     * @param  array<string, mixed>  $session
     * @param  array<string, mixed>  $host
     */
    private function switchSession(array $session, array $host): void
    {
        // The provider's store is cached by the session manager under its own driver name,
        // so the host's store (cached under the host's driver) is never reused or replaced.
        $hadStore = $this->app->resolved('session.store');
        $previousStore = $hadStore ? $this->app['session.store'] : null;
        $this->app->instance('session.store', $this->app->make(SessionManager::class)->driver(self::SESSION_DRIVER));

        // Queued cookies (remember-me among them) take the jar's defaults.
        $jar = $this->app['cookie'];
        $jar->setDefaultPathAndDomain($session['path'], null, $session['secure'] ?? null, $session['same_site'] ?? null);

        $this->restore[] = function () use ($hadStore, $previousStore, $jar, $host): void {
            if ($hadStore) {
                $this->app->instance('session.store', $previousStore);
            } else {
                $this->app->forgetInstance('session.store');
            }
            $jar->setDefaultPathAndDomain($host['path'] ?? '/', $host['domain'] ?? null, $host['secure'] ?? null, $host['same_site'] ?? null);
        };
    }

    private function switchViews(): void
    {
        $finder = $this->app['view']->getFinder();
        if (! $finder instanceof FileViewFinder) {
            return;
        }

        $paths = $finder->getPaths();
        $finder->setPaths([Mount::packagePath('resources/views'), ...array_values(array_diff($paths, [Mount::packagePath('resources/views')]))]);
        $finder->flush();
        $this->app->forgetInstance(Markdown::class);

        $this->restore[] = function () use ($finder, $paths): void {
            $finder->setPaths($paths);
            $finder->flush();
            $this->app->forgetInstance(Markdown::class);
        };
    }

    private function switchVite(): void
    {
        // A test's withoutVite() replacement, or a host's own subclass, is left alone.
        $current = $this->app->make(Vite::class);
        if ($current::class !== Vite::class) {
            return;
        }

        $this->app->instance(Vite::class, EmbeddedVite::create());
        $this->restore[] = fn () => $this->app->instance(Vite::class, $current);
    }
}
