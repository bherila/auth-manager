<?php

namespace Tests\Feature;

use App\Support\DelegatedAccessKeys;
use BWH\Auth\OAuth\DelegatedAccess\DelegatedAccessException;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/**
 * Per-application signing keys: the value's rules, and the check that runs before a configuration cache.
 */
class DelegatedAccessKeysTest extends TestCase
{
    public function test_each_listed_application_has_its_own_key_and_others_fall_back_to_the_shared_one(): void
    {
        config(['delegated-access.key_id' => 'shared-v1', 'delegated-access.private_key_path' => '/keys/shared.pem',
            'delegated-access.keys_environment' => ' example-app | example-v2 | /keys/example.pem ,other-app|other-v1|/keys/other.pem']);
        $keys = app(DelegatedAccessKeys::class);

        $this->assertSame(['key_id' => 'example-v2', 'private_key_path' => '/keys/example.pem', 'own' => true], $keys->for('example-app'));
        $this->assertSame(['key_id' => 'other-v1', 'private_key_path' => '/keys/other.pem', 'own' => true], $keys->for('other-app'));
        $this->assertSame(['key_id' => 'shared-v1', 'private_key_path' => '/keys/shared.pem', 'own' => false], $keys->for('third-app'));
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function malformed(): array
    {
        return [
            'two fields' => ['example-app|example-v1', 'entry 1 must have the form'],
            'bad application key' => ['Example_App|example-v1|/keys/a.pem', 'entry 1 has an invalid application key'],
            'repeated application' => ['example-app|a|/keys/a.pem,example-app|b|/keys/b.pem', 'entry 2 repeats an application key'],
            'bad key id' => ['example-app|bad key|/keys/a.pem', 'entry 1 key id must be'],
            'relative path' => ['example-app|example-v1|keys/a.pem', 'entry 1 private key path must be absolute'],
        ];
    }

    #[DataProvider('malformed')]
    public function test_a_malformed_value_names_the_rule_and_refuses_every_application(string $value, string $rule): void
    {
        try {
            DelegatedAccessKeys::parse($value);
            $this->fail('Accepted a malformed value');
        } catch (InvalidArgumentException $failure) {
            $this->assertStringContainsString($rule, $failure->getMessage());
            $this->assertStringNotContainsString('/keys/', $failure->getMessage());
        }

        config(['delegated-access.keys_environment' => $value]);
        $this->expectExceptionObject(new DelegatedAccessException('invalid_configuration'));
        app(DelegatedAccessKeys::class)->for('another-app');
    }

    public function test_the_check_command_validates_keys_and_shows_key_ids_but_never_paths(): void
    {
        $this->withEnvironment([
            'AUTH_MANAGER_DELEGATED_ACCESS_APPLICATIONS' => 'example-app|https://app.example.test/access|2,other-app|https://other.example.test/access|2',
            DelegatedAccessKeys::ENVIRONMENT => 'example-app|example-v2|/keys/synthetic-private.pem',
        ], function (): void {
            $this->artisan('auth-manager:delegated-access:check', ['--show' => true])
                ->expectsOutputToContain('2 configured, 1 with their own signing key')
                ->expectsTable(['Application', 'Endpoint', 'Contract version', 'Signing key'], [
                    ['example-app', 'https://app.example.test/access', '2', 'example-v2'],
                    ['other-app', 'https://other.example.test/access', '2', 'shared (reads only)'],
                ])
                ->doesntExpectOutputToContain('synthetic-private')
                ->assertExitCode(0);
        });

        $this->withEnvironment([
            'AUTH_MANAGER_DELEGATED_ACCESS_APPLICATIONS' => 'example-app|https://app.example.test/access|2',
            DelegatedAccessKeys::ENVIRONMENT => 'missing-app|missing-v1|/keys/synthetic-private.pem',
        ], function (): void {
            $this->artisan('auth-manager:delegated-access:check')
                ->expectsOutputToContain('names an application that is not configured: missing-app')
                ->assertExitCode(1);
        });

        $this->withEnvironment([
            'AUTH_MANAGER_DELEGATED_ACCESS_APPLICATIONS' => 'example-app|https://app.example.test/access|2',
            DelegatedAccessKeys::ENVIRONMENT => 'example-app|example-v1|keys/synthetic-private.pem',
        ], function (): void {
            $this->artisan('auth-manager:delegated-access:check')
                ->expectsOutputToContain('private key path must be absolute')
                ->doesntExpectOutputToContain('synthetic-private')
                ->assertExitCode(1);
        });
    }

    /**
     * @param  array<string, string>  $values
     */
    private function withEnvironment(array $values, callable $callback): void
    {
        $previous = [];
        foreach ($values as $key => $value) {
            $previous[$key] = [getenv($key), $_ENV[$key] ?? null, array_key_exists($key, $_ENV), $_SERVER[$key] ?? null, array_key_exists($key, $_SERVER)];
            putenv("{$key}={$value}");
            $_ENV[$key] = $value;
            $_SERVER[$key] = $value;
        }

        try {
            $callback();
        } finally {
            foreach ($previous as $key => [$env, $envValue, $inEnv, $serverValue, $inServer]) {
                putenv($env === false ? $key : "{$key}={$env}");
                if ($inEnv) {
                    $_ENV[$key] = $envValue;
                } else {
                    unset($_ENV[$key]);
                }
                if ($inServer) {
                    $_SERVER[$key] = $serverValue;
                } else {
                    unset($_SERVER[$key]);
                }
            }
        }
    }
}
