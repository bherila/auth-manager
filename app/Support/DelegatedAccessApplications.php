<?php

namespace App\Support;

use App\Models\RegisteredApplication;
use BWH\Auth\OAuth\DelegatedAccess\TrustedUrl;
use InvalidArgumentException;
use Throwable;

/**
 * Parses the deployment-owned delegated application map from the environment.
 *
 * A malformed value prevents configuration from loading, like an unrecognized
 * AUTH_MANAGER_PROFILE. Dropping one bad entry would leave a deployment believing an
 * application is connected, or connected at the wrong contract version, so nothing is
 * skipped. Messages name the entry position and the rule, never the configured value.
 */
final class DelegatedAccessApplications
{
    public const ENVIRONMENT = 'AUTH_MANAGER_DELEGATED_ACCESS_APPLICATIONS';

    /** @return array<string, array{endpoint: string, contract_version: int}> */
    public static function fromEnvironment(): array
    {
        return self::parse(env(self::ENVIRONMENT));
    }

    /** @return array<string, array{endpoint: string, contract_version: int}> */
    public static function parse(mixed $value): array
    {
        if ($value === null || (is_string($value) && trim($value) === '')) {
            return [];
        }
        if (! is_string($value)) {
            throw self::malformed('must be a comma-separated list of key|https://endpoint|contract_version entries');
        }

        $applications = [];
        foreach (explode(',', $value) as $index => $entry) {
            $position = $index + 1;
            $fields = explode('|', trim($entry));
            if (count($fields) !== 3) {
                throw self::malformed("entry {$position} must have the form key|https://endpoint|contract_version");
            }
            [$key, $endpoint, $version] = array_map('trim', $fields);

            if (strlen($key) > RegisteredApplication::KEY_MAX_LENGTH || preg_match(RegisteredApplication::KEY_PATTERN, $key) !== 1) {
                throw self::malformed("entry {$position} has an invalid application key");
            }
            if (array_key_exists($key, $applications)) {
                throw self::malformed("entry {$position} repeats an application key");
            }
            if (! self::isTrustedEndpoint($endpoint)) {
                throw self::malformed("entry {$position} endpoint must be an absolute HTTPS URL without credentials, query, or fragment");
            }
            if (! in_array($version, ['1', '2'], true)) {
                throw self::malformed("entry {$position} contract version must be 1 or 2");
            }

            $applications[$key] = ['endpoint' => $endpoint, 'contract_version' => (int) $version];
        }

        return $applications;
    }

    /**
     * The transport's own endpoint rules plus the package's, so a value accepted here is
     * never refused later at call time. Loopback HTTP, allowed for local OAuth URLs, is not.
     */
    private static function isTrustedEndpoint(string $endpoint): bool
    {
        try {
            AuthManagerProfile::validatedAbsoluteUrl($endpoint, 'Delegated endpoint');
            TrustedUrl::validate($endpoint);
        } catch (Throwable) {
            return false;
        }

        return parse_url($endpoint, PHP_URL_SCHEME) === 'https';
    }

    private static function malformed(string $rule): InvalidArgumentException
    {
        return new InvalidArgumentException(self::ENVIRONMENT.' '.$rule.'.');
    }
}
