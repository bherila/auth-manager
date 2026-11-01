<?php

namespace BWH\AuthManager\Embedded;

use BWH\Auth\AuthServiceProvider as AuthLaravelServiceProvider;
use BWH\AuthManager\Models\User;
use BWH\AuthManager\Support\Mount;
use Illuminate\Contracts\Config\Repository;
use InvalidArgumentException;
use ReflectionClass;

/**
 * Builds the embedded provider's configuration inside a host application.
 *
 * The provider's own configuration files are evaluated here, after the mount is known, so
 * their defaults follow the prefix rather than a standalone deployment. `auth-manager`
 * and the host-level wiring (connection, guards, user provider) are set persistently,
 * under names the host does not use. Files whose names a host may well use itself
 * (`branding`, `bherila-auth`, …) become an overlay that EmbeddedContext applies only
 * while a provider request or command runs.
 */
final class EmbeddedConfig
{
    /** Configuration files applied only inside the context, by key. */
    public const OVERLAID = [
        'branding',
        'delegated-access',
        'application-registry',
        'application-invitations',
        'identity-deletion',
    ];

    public static function apply(Repository $config): void
    {
        $prefix = trim((string) $config->get('auth-manager-embedded.prefix', 'auth'), '/');
        if ($prefix === '' || preg_match('~\A[a-z0-9][a-z0-9_-]*(?:/[a-z0-9][a-z0-9_-]*)*\z~', $prefix) !== 1
            || str_starts_with($prefix, '.well-known')) {
            throw new InvalidArgumentException('AUTH_MANAGER_EMBEDDED_PREFIX must be a lowercase path such as "auth".');
        }
        $config->set('auth-manager-embedded.prefix', $prefix);
        $config->set('auth-manager-embedded.enabled', true);

        $overrides = (array) $config->get('auth-manager-embedded.config', []);

        // auth-manager first: Auth Manager's bherila-auth.php reads its issuer and scopes.
        $config->set('auth-manager', self::merge(self::load('config/auth-manager.php'), (array) ($overrides['auth-manager'] ?? [])));

        $overlay = [];
        foreach (self::OVERLAID as $name) {
            $overlay[$name] = self::merge(self::load("config/{$name}.php"), (array) ($overrides[$name] ?? []));
        }
        // As auth-laravel merges a published file: package defaults, then this provider's file.
        $overlay['bherila-auth'] = self::merge(
            self::merge(self::load(self::authLaravelPath('config/bherila-auth.php'), absolute: true), self::load('config/bherila-auth.php')),
            (array) ($overrides['bherila-auth'] ?? []),
        );
        $config->set('auth-manager-embedded.overlay', $overlay);

        self::defineConnection($config);
        $config->set('auth.providers.'.Mount::EMBEDDED_USER_PROVIDER, ['driver' => 'eloquent', 'model' => User::class]);
        $config->set('auth.guards.'.Mount::EMBEDDED_GUARD, ['driver' => 'session', 'provider' => Mount::EMBEDDED_USER_PROVIDER]);
        $config->set('auth.guards.'.Mount::EMBEDDED_API_GUARD, ['driver' => 'passport', 'provider' => Mount::EMBEDDED_USER_PROVIDER]);
        // Passport belongs to the embedded provider (a host that is a relying party has no use
        // for it), so its models, migrations and commands use the provider's connection.
        $config->set('passport.connection', Mount::EMBEDDED_CONNECTION);
        $config->set('auth-manager-embedded.keys_path', $config->get('auth-manager-embedded.keys_path') ?: storage_path('app/private/auth-manager/oauth'));
    }

    public static function authLaravelPath(string $path): string
    {
        return dirname((string) (new ReflectionClass(AuthLaravelServiceProvider::class))->getFileName(), 2).'/'.$path;
    }

    private static function defineConnection(Repository $config): void
    {
        $name = 'database.connections.'.Mount::EMBEDDED_CONNECTION;
        if ($config->has($name)) {
            return;
        }

        $base = $config->get('auth-manager-embedded.database.connection') ?: $config->get('database.default');
        $connection = $config->get('database.connections.'.$base);
        if (! is_array($connection)) {
            throw new InvalidArgumentException("The embedded provider's database connection [{$base}] is not configured.");
        }
        $connection['prefix'] = ($connection['prefix'] ?? '').(string) $config->get('auth-manager-embedded.database.table_prefix', 'auth_manager_');

        $config->set($name, $connection);
    }

    /** @return array<mixed> */
    private static function load(string $path, bool $absolute = false): array
    {
        $value = require $absolute ? $path : Mount::packagePath($path);

        return is_array($value) ? $value : [];
    }

    /**
     * Recurse into associative arrays; a configured list replaces the default outright,
     * as auth-laravel's own merge does.
     *
     * @param  array<mixed>  $defaults
     * @param  array<mixed>  $configured
     * @return array<mixed>
     */
    private static function merge(array $defaults, array $configured): array
    {
        foreach ($configured as $key => $value) {
            $default = $defaults[$key] ?? null;
            $defaults[$key] = is_array($value) && is_array($default) && ! array_is_list($value)
                ? self::merge($default, $value)
                : $value;
        }

        return $defaults;
    }
}
