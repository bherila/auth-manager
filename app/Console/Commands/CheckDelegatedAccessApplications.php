<?php

namespace App\Console\Commands;

use App\Support\DelegatedAccessApplications;
use Dotenv\Dotenv;
use Illuminate\Console\Command;
use InvalidArgumentException;
use Throwable;

class CheckDelegatedAccessApplications extends Command
{
    protected $signature = 'auth-manager:delegated-access:check';

    protected $description = 'Validate the delegated access application list before rebuilding the configuration cache';

    public function handle(): int
    {
        try {
            $applications = DelegatedAccessApplications::parse($this->environmentValue());
            $literal = config('delegated-access.applications');
            if ($literal !== null && $literal !== []) {
                $applications = DelegatedAccessApplications::fromConfiguration($literal, null);
                $this->components->warn('A literal delegated-access.applications map is configured and takes precedence over '.DelegatedAccessApplications::ENVIRONMENT.'.');
            }
        } catch (InvalidArgumentException $failure) {
            $this->components->error($failure->getMessage());

            return self::FAILURE;
        }

        $this->components->info(sprintf('Delegated access applications are valid: %d configured.', count($applications)));

        return self::SUCCESS;
    }

    /**
     * The value the next configuration load will see: the process environment first, as
     * Laravel's immutable repository reads it, then the environment file. The file is read
     * directly because a cached configuration stops Laravel loading it at all.
     */
    private function environmentValue(): ?string
    {
        $key = DelegatedAccessApplications::ENVIRONMENT;
        foreach ([$_SERVER[$key] ?? null, $_ENV[$key] ?? null, getenv($key)] as $value) {
            if (is_string($value)) {
                return $value;
            }
        }

        $path = $this->laravel->environmentFilePath();
        try {
            $values = is_readable($path) ? Dotenv::parse((string) file_get_contents($path)) : [];
        } catch (Throwable) {
            throw new InvalidArgumentException('The environment file could not be parsed.');
        }

        return $values[$key] ?? null;
    }
}
