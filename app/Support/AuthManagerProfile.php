<?php

namespace App\Support;

use InvalidArgumentException;

/** The two intentionally supported identity-provider deployments. */
enum AuthManagerProfile: string
{
    case Bherila = 'bherila';
    case ResourceServer = 'resource';

    public static function fromEnvironment(): self
    {
        $profile = env('AUTH_MANAGER_PROFILE', self::Bherila->value);

        if (! is_string($profile) || ($resolved = self::tryFrom($profile)) === null) {
            throw new InvalidArgumentException(sprintf(
                'AUTH_MANAGER_PROFILE must be one of: %s.',
                implode(', ', array_map(static fn (self $profile): string => $profile->value, self::cases())),
            ));
        }

        return $resolved;
    }

    /** @return array<string, string> */
    public function scopes(): array
    {
        return match ($this) {
            self::Bherila => ['identity:read' => 'Read your account identity'],
            self::ResourceServer => [
                'mcp:use' => 'Use the protected MCP service',
                'offers:read' => 'Read protected offer data',
            ],
        };
    }

    /** @return list<string> */
    public function resourceRequiredScopes(): array
    {
        return $this === self::ResourceServer ? ['mcp:use', 'offers:read'] : [];
    }

    public function defaultIssuer(): ?string
    {
        return match ($this) {
            self::Bherila => rtrim((string) env('APP_URL', 'https://id.bherila.net'), '/'),
            self::ResourceServer => null,
        };
    }

    public function defaultResource(): ?string
    {
        return match ($this) {
            self::Bherila => rtrim((string) $this->defaultIssuer(), '/').'/api/v1',
            self::ResourceServer => null,
        };
    }

    public function defaultThemeCookieDomain(): ?string
    {
        return $this === self::Bherila ? '.bherila.net' : null;
    }

    /** @return list<string> */
    public function defaultThemeAllowedHosts(): array
    {
        return $this === self::Bherila ? ['bherila.net'] : [];
    }

    public static function validatedAbsoluteUrl(mixed $value, string $name): string
    {
        if (! is_string($value) || $value === '' || strlen($value) > 2048) {
            throw new InvalidArgumentException("{$name} must be an absolute HTTPS URL.");
        }

        try {
            $parts = parse_url($value);
        } catch (\ValueError) {
            $parts = false;
        }
        $host = is_array($parts) ? strtolower((string) ($parts['host'] ?? '')) : '';
        $scheme = is_array($parts) ? strtolower((string) ($parts['scheme'] ?? '')) : '';
        if (! is_array($parts)
            || $host === ''
            || isset($parts['user'], $parts['pass'], $parts['query'], $parts['fragment'])
            || ($scheme !== 'https' && ! self::allowsLoopbackHttp($scheme, $host))) {
            throw new InvalidArgumentException("{$name} must be an absolute HTTPS URL.");
        }

        return $value;
    }

    public static function validatedThemeCookieDomain(mixed $value): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }
        if (! is_string($value) || ! self::isValidHostname(ltrim($value, '.'))) {
            throw new InvalidArgumentException('AUTH_MANAGER_THEME_COOKIE_DOMAIN must be a DNS domain.');
        }

        return '.'.ltrim(strtolower($value), '.');
    }

    /** @param list<string> $hosts @return list<string> */
    public static function validatedThemeAllowedHosts(array $hosts, ?string $cookieDomain): array
    {
        $domain = $cookieDomain === null ? null : ltrim($cookieDomain, '.');
        $validated = [];
        foreach ($hosts as $host) {
            $host = strtolower(trim($host));
            if (! self::isValidHostname($host)
                || ($domain !== null && $host !== $domain && ! str_ends_with($host, '.'.$domain))) {
                throw new InvalidArgumentException('AUTH_MANAGER_THEME_ALLOWED_HOSTS must contain hosts within the theme cookie domain.');
            }
            $validated[] = $host;
        }

        return array_values(array_unique($validated));
    }

    private static function allowsLoopbackHttp(string $scheme, string $host): bool
    {
        return $scheme === 'http'
            && in_array((string) env('APP_ENV', 'production'), ['local', 'testing'], true)
            && in_array($host, ['localhost', '127.0.0.1', '[::1]', '::1'], true);
    }

    private static function isValidHostname(string $host): bool
    {
        return $host !== ''
            && strlen($host) <= 253
            && preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i', $host) === 1;
    }
}
