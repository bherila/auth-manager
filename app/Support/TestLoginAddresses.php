<?php

namespace BWH\AuthManager\Support;

use InvalidArgumentException;

/** The synthetic-address boundary shared by provisioning and authentication. */
final class TestLoginAddresses
{
    public static function allows(string $email): bool
    {
        if (strlen($email) > 254 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            return false;
        }
        $domain = strtolower(substr($email, strrpos($email, '@') + 1));
        foreach (['example.com', 'example.net', 'example.org'] as $reserved) {
            if ($domain === $reserved || str_ends_with($domain, '.'.$reserved)) {
                return true;
            }
        }
        foreach (['test', 'example', 'invalid', 'localhost'] as $reserved) {
            if (str_ends_with($domain, '.'.$reserved)) {
                return true;
            }
        }

        foreach ((array) config('auth-manager.test_logins.allowed_domains', []) as $allowed) {
            if (is_string($allowed) && strtolower($allowed) === $domain) {
                return true;
            }
        }

        return false;
    }

    /** @return list<string> */
    public static function configuredDomains(string $value): array
    {
        $domains = array_values(array_unique(array_filter(array_map(static fn (string $domain): string => strtolower(trim($domain)), explode(',', $value)))));
        foreach ($domains as $domain) {
            if (! str_contains($domain, '.') || ! preg_match('/\A[a-z0-9.-]+\z/D', $domain)
                || filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
                throw new InvalidArgumentException('AUTH_MANAGER_TEST_LOGIN_DOMAINS must contain exact ASCII domains without wildcards or URLs.');
            }
        }

        return $domains;
    }
}
