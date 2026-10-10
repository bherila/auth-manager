<?php

namespace Tests\Feature;

use App\Support\DelegatedAccessApplications;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\Exceptions;
use InvalidArgumentException;
use Tests\TestCase;

class DelegatedAccessApplicationsTest extends TestCase
{
    private const MALFORMED = 'example-app|https://app.example.test/access|3,other-app|http://synthetic-secret-host.example.test/access|3';

    public function test_valid_entries_become_the_transport_map(): void
    {
        $this->assertSame([
            'example-app' => ['endpoint' => 'https://app.example.test/application-access', 'contract_version' => 3],
            'other-app2' => ['endpoint' => 'https://other.example.test:8443/access', 'contract_version' => 3],
        ], DelegatedAccessApplications::parse(
            'example-app|https://app.example.test/application-access|3, other-app2 | https://other.example.test:8443/access | 3',
        ));
    }

    /** Versions 1 and 2 are no longer spoken: an entry naming one is refused by position and rule, never by value. */
    public function test_an_entry_on_an_earlier_contract_version_makes_the_map_malformed(): void
    {
        foreach (['1', '2'] as $version) {
            $value = "example-app|https://app.example.test/access|3,other-app|https://other.example.test/access|{$version}";
            try {
                DelegatedAccessApplications::parse($value);
                $this->fail("Version {$version} must be refused.");
            } catch (InvalidArgumentException $failure) {
                $this->assertSame('AUTH_MANAGER_DELEGATED_ACCESS_APPLICATIONS entry 2 contract version must be 3; earlier versions are no longer supported.', $failure->getMessage());
            }
        }
        foreach ([1, 2, null] as $version) {
            try {
                DelegatedAccessApplications::fromConfiguration(['example-app' => array_filter(['endpoint' => 'https://app.example.test/access', 'contract_version' => $version])], null);
                $this->fail('A literal entry must name version 3.');
            } catch (InvalidArgumentException $failure) {
                $this->assertSame('delegated-access.applications entry 1 contract version must be 3; earlier versions are no longer supported.', $failure->getMessage());
            }
        }

        // At run time the whole map is refused as configuration, before anything is sent.
        Exceptions::fake();
        config(['delegated-access.applications' => [], 'delegated-access.applications_environment' => 'example-app|https://app.example.test/access|2']);
        try {
            app(DelegatedAccessApplications::class)->find('example-app');
            $this->fail('Expected invalid_configuration.');
        } catch (DelegatedAccessException $exception) {
            $this->assertSame('invalid_configuration', $exception->outcome);
        }
        Exceptions::assertReported(fn (InvalidArgumentException $failure): bool => str_contains($failure->getMessage(), 'entry 1 contract version must be 3'));
    }

    public function test_an_empty_or_unset_value_means_no_applications(): void
    {
        foreach ([null, '', '   '] as $value) {
            $this->assertSame([], DelegatedAccessApplications::parse($value));
        }
    }

    public function test_each_malformed_entry_class_is_refused(): void
    {
        $valid = 'https://app.example.test/access';
        $cases = [
            'non-string value' => true,
            'key only' => 'example-app',
            'missing version' => "example-app|{$valid}",
            'extra field' => "example-app|{$valid}|3|extra",
            'trailing empty entry' => "example-app|{$valid}|3,",
            'leading empty entry' => ",example-app|{$valid}|3",
            'empty key' => "|{$valid}|3",
            'uppercase key' => "Example-App|{$valid}|3",
            'key starting with a digit' => "1app|{$valid}|3",
            'key with an underscore' => "example_app|{$valid}|3",
            'key longer than 64 bytes' => 'a'.str_repeat('b', 64)."|{$valid}|3",
            'empty endpoint' => 'example-app||3',
            'relative endpoint' => 'example-app|app.example.test/access|3',
            'invalid host' => 'example-app|https://bad_host.example.test/access|3',
            'port zero' => 'example-app|https://app.example.test:0/access|3',
            'username' => 'example-app|https://user@app.example.test/access|3',
            'username and password' => 'example-app|https://user:password@app.example.test/access|3',
            'query' => 'example-app|https://app.example.test/access?tenant=one|3',
            'fragment' => 'example-app|https://app.example.test/access#top|3',
            'empty version' => "example-app|{$valid}|",
            'version zero' => "example-app|{$valid}|0",
            'unknown version' => "example-app|{$valid}|4",
            'version one' => "example-app|{$valid}|1",
            'version two' => "example-app|{$valid}|2",
            'padded version' => "example-app|{$valid}|01",
            'decimal version' => "example-app|{$valid}|3.0",
            'bad entry after a good one' => "example-app|{$valid}|3,other-app|{$valid}|9",
        ];

        foreach ($cases as $label => $value) {
            $this->assertRefused(fn () => DelegatedAccessApplications::parse($value), $label);
        }
    }

    public function test_duplicate_keys_are_malformed_even_with_identical_entries(): void
    {
        $this->assertRefused(fn () => DelegatedAccessApplications::parse('example-app|https://app.example.test/access|3,example-app|https://app.example.test/access|3'), 'identical duplicate');
        $this->assertRefused(fn () => DelegatedAccessApplications::parse('example-app|https://app.example.test/access|3,example-app|https://other.example.test/access|3'), 'conflicting duplicate');
    }

    public function test_non_https_endpoints_are_refused_including_local_loopback(): void
    {
        foreach ([
            'http://app.example.test/access',
            'http://localhost/access',
            'http://127.0.0.1/access',
            'HTTPS://app.example.test/access',
            'ftp://app.example.test/access',
        ] as $endpoint) {
            $this->assertRefused(fn () => DelegatedAccessApplications::parse("example-app|{$endpoint}|3"), $endpoint);
        }
    }

    public function test_a_literal_configuration_map_takes_precedence_and_obeys_the_same_rules(): void
    {
        $this->assertSame(
            ['example-app' => ['endpoint' => 'https://app.example.test/access', 'contract_version' => 3]],
            DelegatedAccessApplications::fromConfiguration(['example-app' => ['endpoint' => 'https://app.example.test/access', 'contract_version' => 3]], self::MALFORMED),
        );
        $this->assertSame(
            ['example-app' => ['endpoint' => 'https://app.example.test/access', 'contract_version' => 3]],
            DelegatedAccessApplications::fromConfiguration([], 'example-app|https://app.example.test/access|3'),
        );
        $this->assertSame(
            ['example-app' => ['endpoint' => 'https://app.example.test/access', 'contract_version' => 3]],
            DelegatedAccessApplications::fromConfiguration(['example-app' => ['endpoint' => 'https://app.example.test/access', 'contract_version' => 3]], null),
        );

        foreach ([
            'not a map' => 'example-app',
            'list entry' => [['endpoint' => 'https://app.example.test/access', 'contract_version' => 3]],
            'missing endpoint' => ['example-app' => ['contract_version' => 3]],
            'invalid key' => ['Example_App' => ['endpoint' => 'https://app.example.test/access', 'contract_version' => 3]],
            'string version' => ['example-app' => ['endpoint' => 'https://app.example.test/access', 'contract_version' => '3']],
            'unknown version' => ['example-app' => ['endpoint' => 'https://app.example.test/access', 'contract_version' => 4]],
            'non-https endpoint' => ['example-app' => ['endpoint' => 'http://app.example.test/access', 'contract_version' => 3]],
        ] as $label => $literal) {
            $this->assertRefused(fn () => DelegatedAccessApplications::fromConfiguration($literal, 'example-app|https://app.example.test/access|3'), $label);
        }
    }

    public function test_a_malformed_value_disables_every_entry_and_is_reported_once_without_the_value(): void
    {
        Exceptions::fake();
        config(['delegated-access.applications' => [], 'delegated-access.applications_environment' => self::MALFORMED]);
        $applications = app(DelegatedAccessApplications::class);

        $this->assertTrue($applications->malformed());
        // The valid first entry is not partly honoured.
        foreach ([fn () => $applications->all(), fn () => $applications->find('example-app')] as $call) {
            try {
                $call();
                $this->fail('Expected a malformed map to refuse every delegated lookup.');
            } catch (DelegatedAccessException $exception) {
                $this->assertSame('invalid_configuration', $exception->outcome);
                $this->assertSame(503, $exception->status);
            }
        }
        $this->assertTrue(app(DelegatedAccessApplications::class)->malformed());

        Exceptions::assertReportedCount(1);
        Exceptions::assertReported(fn (InvalidArgumentException $failure): bool => $failure->getMessage()
            === 'AUTH_MANAGER_DELEGATED_ACCESS_APPLICATIONS entry 2 endpoint must be an absolute HTTPS URL without credentials, query, or fragment.');

        // Correcting configuration takes effect without a stale refusal.
        config(['delegated-access.applications_environment' => 'example-app|https://app.example.test/access|3']);
        $this->assertFalse($applications->malformed());
        $this->assertSame(3, $applications->find('example-app')['contract_version']);
        $this->assertNull($applications->find('unconfigured-app'));
        Exceptions::assertReportedCount(1);
    }

    public function test_configuration_loading_never_throws_and_a_malformed_value_still_boots_the_application(): void
    {
        $this->withApplicationsEnvironment(self::MALFORMED, function (): void {
            $configuration = require config_path('delegated-access.php');
            $this->assertSame([], $configuration['applications']);
            $this->assertSame(self::MALFORMED, $configuration['applications_environment']);

            // Boot a fresh application with the value in place. phpdotenv may overwrite variables it
            // loaded itself, so re-apply the value once the environment file has been read.
            $app = require base_path('bootstrap/app.php');
            $app->afterLoadingEnvironment(fn () => $this->setApplicationsEnvironment(self::MALFORMED));
            $app->make(Kernel::class)->bootstrap();
            $this->app = $app;
            $this->assertSame(self::MALFORMED, config('delegated-access.applications_environment'));
            $this->get('/login')->assertOk();
            $this->assertTrue(app(DelegatedAccessApplications::class)->malformed());
        });
    }

    public function test_the_check_command_exits_non_zero_with_the_rule_and_never_the_value(): void
    {
        $this->withApplicationsEnvironment('example-app|https://app.example.test/application-access|3', function (): void {
            $this->artisan('auth-manager:delegated-access:check')
                ->expectsOutputToContain('1 configured')->assertExitCode(0);
        });
        $this->withApplicationsEnvironment('', function (): void {
            $this->artisan('auth-manager:delegated-access:check')
                ->expectsOutputToContain('0 configured')->assertExitCode(0);
        });
        $this->withApplicationsEnvironment(self::MALFORMED, function (): void {
            $this->artisan('auth-manager:delegated-access:check')
                ->expectsOutputToContain('entry 2 endpoint must be an absolute HTTPS URL')
                ->doesntExpectOutputToContain('synthetic-secret-host')
                ->assertExitCode(1);
        });
    }

    public function test_the_check_command_applies_literal_precedence_like_runtime(): void
    {
        $this->withCheckFixture(
            "['example-app' => ['endpoint' => 'https://literal.example.test/access', 'contract_version' => 3]]",
            self::MALFORMED,
            function (): void {
                $this->artisan('auth-manager:delegated-access:check', ['--show' => true])
                    ->expectsOutputToContain('takes precedence')
                    ->expectsTable(['Application', 'Endpoint', 'Contract version', 'Signing key'], [['example-app', 'https://literal.example.test/access', '3', 'shared (reads only)']])
                    ->assertExitCode(0);
                // The environment file's values are applied only while the file loads.
                $this->assertArrayNotHasKey(DelegatedAccessApplications::ENVIRONMENT, $_SERVER);
                $this->assertArrayNotHasKey(DelegatedAccessApplications::ENVIRONMENT, $_ENV);
            },
        );

        $this->withCheckFixture(
            "['example-app' => ['endpoint' => 'http://literal.example.test/access', 'contract_version' => 3]]",
            'example-app|https://app.example.test/access|3',
            function (): void {
                $this->artisan('auth-manager:delegated-access:check')
                    ->expectsOutputToContain('delegated-access.applications entry 1 endpoint')->assertExitCode(1);
            },
        );
    }

    public function test_the_check_command_ignores_a_stale_configuration_cache(): void
    {
        // The cache holds an old valid literal; the file no longer has it and the environment file is now malformed.
        $this->withCheckFixture('[]', self::MALFORMED, function (): void {
            $this->withStaleConfigurationCache(['example-app' => ['endpoint' => 'https://old.example.test/access']], function (): void {
                $this->artisan('auth-manager:delegated-access:check')
                    ->expectsOutputToContain('entry 2 endpoint must be an absolute HTTPS URL')
                    ->doesntExpectOutputToContain('synthetic-secret-host')
                    ->assertExitCode(1);
            });
        });

        // The cache holds an old malformed literal; the file no longer has it and the environment file is now valid.
        $this->withCheckFixture('[]', 'example-app|https://app.example.test/application-access|3', function (): void {
            $this->withStaleConfigurationCache(['example-app' => ['endpoint' => 'http://old.example.test/access']], function (): void {
                $this->artisan('auth-manager:delegated-access:check', ['--show' => true])
                    ->expectsTable(['Application', 'Endpoint', 'Contract version', 'Signing key'], [['example-app', 'https://app.example.test/application-access', '3', 'shared (reads only)']])
                    ->assertExitCode(0);
            });
        });
    }

    public function test_the_check_command_lets_the_process_environment_win_over_the_environment_file(): void
    {
        $this->withCheckFixture('[]', self::MALFORMED, function (): void {
            $this->setApplicationsEnvironment('example-app|https://app.example.test/application-access|3');
            $this->artisan('auth-manager:delegated-access:check', ['--show' => true])
                ->expectsTable(['Application', 'Endpoint', 'Contract version', 'Signing key'], [['example-app', 'https://app.example.test/application-access', '3', 'shared (reads only)']])
                ->assertExitCode(0);
        });
    }

    /**
     * Run the check against a temporary copy of config/delegated-access.php whose literal
     * `applications` is replaced, and a temporary environment file defining the list, with the
     * list absent from the process environment.
     */
    private function withCheckFixture(string $literalPhp, string $environmentFileValue, callable $callback): void
    {
        $key = DelegatedAccessApplications::ENVIRONMENT;
        $directory = sys_get_temp_dir().'/delegated-access-check-'.bin2hex(random_bytes(6));
        mkdir($directory);
        $configuration = str_replace("'applications' => [],", "'applications' => {$literalPhp},", (string) file_get_contents(config_path('delegated-access.php')));
        $this->assertStringContainsString("'applications' => {$literalPhp},", $configuration);
        file_put_contents($directory.'/delegated-access.php', $configuration);
        file_put_contents($directory.'/.env.check', $key.'="'.$environmentFileValue."\"\n");

        $configPath = $this->app->configPath();
        $environmentPath = $this->app->environmentPath();
        $environmentFile = $this->app->environmentFile();
        $previous = [getenv($key), $_ENV[$key] ?? null, array_key_exists($key, $_ENV), $_SERVER[$key] ?? null, array_key_exists($key, $_SERVER)];
        putenv($key);
        unset($_ENV[$key], $_SERVER[$key]);
        $this->app->useConfigPath($directory);
        $this->app->useEnvironmentPath($directory);
        $this->app->loadEnvironmentFrom('.env.check');

        try {
            $callback();
        } finally {
            $this->app->useConfigPath($configPath);
            $this->app->useEnvironmentPath($environmentPath);
            $this->app->loadEnvironmentFrom($environmentFile);
            putenv($previous[0] === false ? $key : $key.'='.$previous[0]);
            if ($previous[2]) {
                $_ENV[$key] = $previous[1];
            } else {
                unset($_ENV[$key]);
            }
            if ($previous[4]) {
                $_SERVER[$key] = $previous[3];
            } else {
                unset($_SERVER[$key]);
            }
            @unlink($directory.'/delegated-access.php');
            @unlink($directory.'/.env.check');
            @rmdir($directory);
        }
    }

    /**
     * The application as it runs with a configuration cache: the repository was loaded from the
     * cache (Laravel's own `config_loaded_from_cache` flag) and holds an old literal map.
     */
    private function withStaleConfigurationCache(array $literal, callable $callback): void
    {
        $loadedFromCache = $this->app->bound('config_loaded_from_cache') ? $this->app->make('config_loaded_from_cache') : null;
        $stale = [config('delegated-access.applications'), config('delegated-access.applications_environment')];
        $this->app->instance('config_loaded_from_cache', true);
        config(['delegated-access.applications' => $literal, 'delegated-access.applications_environment' => null]);

        try {
            $this->assertTrue($this->app->configurationIsCached());
            $callback();
        } finally {
            config(['delegated-access.applications' => $stale[0], 'delegated-access.applications_environment' => $stale[1]]);
            $this->app->instance('config_loaded_from_cache', $loadedFromCache ?? false);
        }
    }

    private function assertRefused(callable $parse, string $label): void
    {
        try {
            $parse();
            $this->fail("Expected the {$label} case to be refused.");
        } catch (InvalidArgumentException) {
            $this->addToAssertionCount(1);
        }
    }

    private function setApplicationsEnvironment(string $value): void
    {
        $key = DelegatedAccessApplications::ENVIRONMENT;
        putenv($key.'='.$value);
        $_ENV[$key] = $value;
        $_SERVER[$key] = $value;
    }

    private function withApplicationsEnvironment(string $value, callable $callback): void
    {
        $key = DelegatedAccessApplications::ENVIRONMENT;
        $previous = [getenv($key), $_ENV[$key] ?? null, array_key_exists($key, $_ENV), $_SERVER[$key] ?? null, array_key_exists($key, $_SERVER)];
        $this->setApplicationsEnvironment($value);

        try {
            $callback();
        } finally {
            putenv($previous[0] === false ? $key : $key.'='.$previous[0]);
            if ($previous[2]) {
                $_ENV[$key] = $previous[1];
            } else {
                unset($_ENV[$key]);
            }
            if ($previous[4]) {
                $_SERVER[$key] = $previous[3];
            } else {
                unset($_SERVER[$key]);
            }
        }
    }
}
