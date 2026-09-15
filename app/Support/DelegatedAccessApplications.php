<?php

namespace App\Support;

use App\Models\RegisteredApplication;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedContract;
use BWH\Auth\OAuth\DelegatedAccess\TrustedUrl;
use InvalidArgumentException;
use Throwable;

/**
 * The deployment-owned delegated application map, resolved and validated at use time.
 *
 * Every reader of the map goes through this service. Configuration holds only the raw
 * AUTH_MANAGER_DELEGATED_ACCESS_APPLICATIONS string and an optional literal override, so a
 * typo in this optional feature never stops the instance, or its sign-in, from loading.
 *
 * A malformed value disables delegated access as a whole: no entry is partly honoured, every
 * delegated call is refused with `invalid_configuration`, and the problem is reported once per
 * request (the service is scoped). Messages name the entry position and the rule, never the value.
 */
final class DelegatedAccessApplications
{
    public const ENVIRONMENT = 'AUTH_MANAGER_DELEGATED_ACCESS_APPLICATIONS';

    /** @var array<string, array{endpoint: string, contract_version: int}>|null */
    private ?array $applications = null;

    private ?InvalidArgumentException $failure = null;

    /** The configuration values the current result was resolved from. */
    private ?array $source = null;

    /**
     * The validated map, or an `invalid_configuration` refusal when it is malformed.
     *
     * @return array<string, array{endpoint: string, contract_version: int}>
     *
     * @throws DelegatedAccessException
     */
    public function all(): array
    {
        $this->resolve();
        if ($this->failure !== null) {
            throw new DelegatedAccessException('invalid_configuration');
        }

        return $this->applications;
    }

    /** Whether the map is malformed. Resolving it reports the problem once for this request. */
    public function malformed(): bool
    {
        $this->resolve();

        return $this->failure !== null;
    }

    /**
     * One application's entry, or null when it is not configured.
     *
     * @return array{endpoint: string, contract_version: int}|null
     *
     * @throws DelegatedAccessException when the map is malformed
     */
    public function find(string $application): ?array
    {
        return $this->all()[$application] ?? null;
    }

    /**
     * The contract version agreed with this application; version 1 when it is not configured.
     *
     * @throws DelegatedAccessException when the map is malformed
     */
    public function contractVersion(string $application): int
    {
        return $this->find($application)['contract_version'] ?? DelegatedContract::VERSION_1;
    }

    /**
     * A literal `applications` map in configuration takes precedence over the environment
     * string. Both are validated with the same rules.
     *
     * @return array<string, array{endpoint: string, contract_version: int}>
     *
     * @throws InvalidArgumentException
     */
    public static function fromConfiguration(mixed $literal, mixed $environment): array
    {
        if ($literal !== null && $literal !== []) {
            return self::validateMap($literal);
        }

        return self::parse($environment);
    }

    /**
     * @return array<string, array{endpoint: string, contract_version: int}>
     *
     * @throws InvalidArgumentException
     */
    public static function parse(mixed $value): array
    {
        if ($value === null || (is_string($value) && trim($value) === '')) {
            return [];
        }
        if (! is_string($value)) {
            throw self::invalid('must be a comma-separated list of key|https://endpoint|contract_version entries');
        }

        $applications = [];
        foreach (explode(',', $value) as $index => $entry) {
            $position = $index + 1;
            $fields = explode('|', trim($entry));
            if (count($fields) !== 3) {
                throw self::invalid("entry {$position} must have the form key|https://endpoint|contract_version");
            }
            [$key, $endpoint, $version] = array_map('trim', $fields);
            if (! in_array($version, ['1', '2'], true)) {
                throw self::invalid("entry {$position} contract version must be 1 or 2");
            }

            $applications = self::withEntry($applications, $key, $endpoint, (int) $version, "entry {$position}");
        }

        return $applications;
    }

    /**
     * @return array<string, array{endpoint: string, contract_version: int}>
     *
     * @throws InvalidArgumentException
     */
    private static function validateMap(mixed $map): array
    {
        if (! is_array($map)) {
            throw self::invalid('configuration override must be a map of application key to entry', 'delegated-access.applications');
        }

        $applications = [];
        $position = 0;
        foreach ($map as $key => $entry) {
            $position++;
            $label = "entry {$position}";
            $version = is_array($entry) ? ($entry['contract_version'] ?? DelegatedContract::VERSION_1) : null;
            if (! is_array($entry) || ! is_string($key) || ! is_string($entry['endpoint'] ?? null)) {
                throw self::invalid("{$label} must have a string key and endpoint", 'delegated-access.applications');
            }
            if (! in_array($version, [DelegatedContract::VERSION_1, DelegatedContract::VERSION_2], true)) {
                throw self::invalid("{$label} contract version must be 1 or 2", 'delegated-access.applications');
            }

            $applications = self::withEntry($applications, $key, $entry['endpoint'], $version, $label, 'delegated-access.applications');
        }

        return $applications;
    }

    /**
     * @param  array<string, array{endpoint: string, contract_version: int}>  $applications
     * @return array<string, array{endpoint: string, contract_version: int}>
     */
    private static function withEntry(array $applications, string $key, string $endpoint, int $version, string $label, string $source = self::ENVIRONMENT): array
    {
        if (strlen($key) > RegisteredApplication::KEY_MAX_LENGTH || preg_match(RegisteredApplication::KEY_PATTERN, $key) !== 1) {
            throw self::invalid("{$label} has an invalid application key", $source);
        }
        if (array_key_exists($key, $applications)) {
            throw self::invalid("{$label} repeats an application key", $source);
        }
        if (! self::isTrustedEndpoint($endpoint)) {
            throw self::invalid("{$label} endpoint must be an absolute HTTPS URL without credentials, query, or fragment", $source);
        }

        $applications[$key] = ['endpoint' => $endpoint, 'contract_version' => $version];

        return $applications;
    }

    private function resolve(): void
    {
        $literal = config('delegated-access.applications');
        $environment = config('delegated-access.applications_environment');
        $source = [$literal, $environment];
        if ($source === $this->source) {
            return;
        }

        // Re-resolved only when configuration itself changes within this instance's lifetime.
        $this->source = $source;
        $this->applications = null;
        $this->failure = null;
        try {
            $this->applications = self::fromConfiguration($literal, $environment);
        } catch (InvalidArgumentException $failure) {
            $this->failure = $failure;
            report($failure);
        }
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

    private static function invalid(string $rule, string $source = self::ENVIRONMENT): InvalidArgumentException
    {
        return new InvalidArgumentException($source.' '.$rule.'.');
    }
}
