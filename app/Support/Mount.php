<?php

namespace BWH\AuthManager\Support;

use Illuminate\Http\Request;

/**
 * Where this provider is mounted: at the root of its own deployment, or under a path
 * prefix inside a host application (docs/embedded-mode.md).
 *
 * Read from configuration on every call, so each application instance (and each test)
 * answers for itself.
 */
final class Mount
{
    public const ROUTE_NAME_PREFIX = 'auth-manager.';

    public const EMBEDDED_WEB = 'auth-manager.web';

    public const EMBEDDED_API = 'auth-manager.api';

    public const EMBEDDED_GUARD = 'auth-manager';

    public const EMBEDDED_API_GUARD = 'auth-manager-api';

    public const EMBEDDED_USER_PROVIDER = 'auth-manager-users';

    public const EMBEDDED_CONNECTION = 'auth-manager';

    public static function embedded(): bool
    {
        return config('auth-manager-embedded.enabled') === true;
    }

    /** The prefix without slashes: '' standalone, 'auth' by default when embedded. */
    public static function prefix(): string
    {
        return self::embedded() ? trim((string) config('auth-manager-embedded.prefix', 'auth'), '/') : '';
    }

    /** A root-relative URL path for a provider path: '/login' or '/auth/login'. */
    public static function path(string $path = '/'): string
    {
        $path = '/'.ltrim($path, '/');
        $prefix = self::prefix();

        if ($prefix === '') {
            return $path;
        }

        return $path === '/' ? '/'.$prefix : '/'.$prefix.$path;
    }

    /** A request-path pattern for Request::is(), relative to the mount. */
    public static function pattern(string $pattern): string
    {
        $prefix = self::prefix();
        $pattern = ltrim($pattern, '/');

        return $prefix === '' ? $pattern : ($pattern === '' ? $prefix : $prefix.'/'.$pattern);
    }

    public static function is(Request $request, string ...$patterns): bool
    {
        return $request->is(...array_map(self::pattern(...), $patterns));
    }

    /** The request's path below the mount, without a leading slash ('' for the mount itself). */
    public static function relativePath(Request $request): string
    {
        $path = trim($request->path(), '/');
        $prefix = self::prefix();

        if ($prefix === '') {
            return $path === '/' ? '' : $path;
        }

        if ($path === $prefix) {
            return '';
        }

        return str_starts_with($path, $prefix.'/') ? substr($path, strlen($prefix) + 1) : $path;
    }

    public static function webMiddleware(): string
    {
        return self::embedded() ? self::EMBEDDED_WEB : 'web';
    }

    public static function apiMiddleware(): string
    {
        return self::embedded() ? self::EMBEDDED_API : 'api';
    }

    /** The bearer-token guard relying applications call the identity endpoint with. */
    public static function apiGuard(): string
    {
        return self::embedded() ? self::EMBEDDED_API_GUARD : 'api';
    }

    /** This package's root directory: the application itself when standalone. */
    public static function packagePath(string $path = ''): string
    {
        $root = dirname(__DIR__, 2);

        return $path === '' ? $root : $root.'/'.ltrim($path, '/');
    }
}
