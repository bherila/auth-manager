<?php

namespace App\Console\Commands;

use App\Support\DelegatedAccessApplications;
use App\Support\DelegatedAccessKeys;
use Dotenv\Dotenv;
use Illuminate\Console\Command;
use InvalidArgumentException;
use Throwable;

class CheckDelegatedAccessApplications extends Command
{
    protected $signature = 'auth-manager:delegated-access:check
        {--show : Print each resolved application key, endpoint, contract version and signing key id}';

    protected $description = 'Validate the delegated access application list before rebuilding the configuration cache';

    public function handle(): int
    {
        try {
            $configuration = $this->nextConfiguration();
            // The same resolution the service applies at runtime, so the two cannot disagree.
            $applications = DelegatedAccessApplications::fromConfiguration(
                $configuration['applications'] ?? null,
                $configuration['applications_environment'] ?? null,
            );
            $keys = DelegatedAccessKeys::assertDistinct(
                DelegatedAccessKeys::parse($configuration['keys_environment'] ?? null),
                $configuration['key_id'] ?? null,
                $configuration['private_key_path'] ?? null,
            );
            foreach (array_keys($keys) as $application) {
                if (! array_key_exists($application, $applications)) {
                    throw new InvalidArgumentException(DelegatedAccessKeys::ENVIRONMENT." names an application that is not configured: {$application}.");
                }
            }
        } catch (InvalidArgumentException $failure) {
            $this->components->error($failure->getMessage());

            return self::FAILURE;
        }

        $literal = $configuration['applications'] ?? null;
        if ($literal !== null && $literal !== []) {
            $this->components->warn('A literal delegated-access.applications map is configured and takes precedence over '.DelegatedAccessApplications::ENVIRONMENT.'.');
        }
        $this->components->info(sprintf('Delegated access applications are valid: %d configured, %d with their own signing key.', count($applications), count($keys)));

        if ($this->option('show')) {
            // Keys, endpoints and versions are deployment routing, not secrets.
            // Key ids name public keys; the private key paths are not printed.
            $this->table(['Application', 'Endpoint', 'Contract version', 'Signing key'], array_map(
                static fn (string $key, array $entry): array => [$key, $entry['endpoint'], (string) $entry['contract_version'], $keys[$key]['key_id'] ?? 'shared (reads only)'],
                array_keys($applications),
                $applications,
            ));
        }

        return self::SUCCESS;
    }

    /**
     * The delegated access configuration as the next `config:cache` will build it.
     *
     * The configuration file is loaded afresh rather than read from the configuration
     * repository, which holds the cached values while a cache exists. Values from the
     * environment file are applied only while it loads, and only where the process
     * environment does not already define them, matching Laravel's immutable loading.
     *
     * @return array<string, mixed>
     */
    private function nextConfiguration(): array
    {
        $previous = [];
        foreach ($this->environmentFileValues() as $name => $value) {
            if ($value === null || array_key_exists($name, $_SERVER) || array_key_exists($name, $_ENV) || getenv($name) !== false) {
                continue;
            }
            $previous[] = $name;
            $_SERVER[$name] = $value;
            $_ENV[$name] = $value;
        }

        try {
            $configuration = require $this->laravel->configPath('delegated-access.php');
        } finally {
            foreach ($previous as $name) {
                unset($_SERVER[$name], $_ENV[$name]);
            }
        }

        if (! is_array($configuration)) {
            throw new InvalidArgumentException('config/delegated-access.php must return an array.');
        }

        return $configuration;
    }

    /** @return array<string, string|null> */
    private function environmentFileValues(): array
    {
        $path = $this->laravel->environmentFilePath();
        if (! is_readable($path)) {
            return [];
        }

        try {
            return Dotenv::parse((string) file_get_contents($path));
        } catch (Throwable) {
            throw new InvalidArgumentException('The environment file could not be parsed.');
        }
    }
}
