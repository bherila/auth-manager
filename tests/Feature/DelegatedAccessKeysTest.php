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
            'another application\'s key id' => ['example-app|same-v1|/keys/a.pem,other-app|same-v1|/keys/b.pem', 'entry 2 reuses another application\'s key'],
            'another application\'s key file' => ['example-app|a-v1|/keys/a.pem,other-app|b-v1|/keys/a.pem', 'entry 2 reuses another application\'s key'],
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

    /** Listing the shared key as an application's own would let writes be signed with it. */
    public function test_an_own_key_that_is_the_shared_key_refuses_every_application(): void
    {
        config(['delegated-access.key_id' => 'shared-v1', 'delegated-access.private_key_path' => '/keys/shared.pem']);

        foreach (['example-app|shared-v1|/keys/own.pem', 'example-app|own-v1|/keys/shared.pem'] as $value) {
            config(['delegated-access.keys_environment' => $value]);
            try {
                app(DelegatedAccessKeys::class)->for('example-app');
                $this->fail('Accepted the shared key as an application\'s own');
            } catch (DelegatedAccessException $refusal) {
                $this->assertSame('invalid_configuration', $refusal->outcome);
            }
        }
    }

    public function test_the_check_command_validates_keys_and_shows_key_ids_but_never_paths(): void
    {
        $this->withEnvironment([
            'AUTH_MANAGER_DELEGATED_ACCESS_APPLICATIONS' => 'example-app|https://app.example.test/access|3,other-app|https://other.example.test/access|3',
            DelegatedAccessKeys::ENVIRONMENT => 'example-app|example-v2|/keys/synthetic-private.pem',
        ], function (): void {
            $this->artisan('auth-manager:delegated-access:check', ['--show' => true])
                ->expectsOutputToContain('2 configured, 1 with their own signing key')
                ->expectsTable(['Application', 'Endpoint', 'Contract version', 'Signing key'], [
                    ['example-app', 'https://app.example.test/access', '3', 'example-v2'],
                    ['other-app', 'https://other.example.test/access', '3', 'shared (reads only)'],
                ])
                ->doesntExpectOutputToContain('synthetic-private')
                ->assertExitCode(0);
        });

        $this->withEnvironment([
            'AUTH_MANAGER_DELEGATED_ACCESS_APPLICATIONS' => 'example-app|https://app.example.test/access|3,other-app|https://other.example.test/access|3',
            'AUTH_MANAGER_DELEGATED_ACCESS_WRITES_APPLICATIONS' => 'example-app,other-app',
            DelegatedAccessKeys::ENVIRONMENT => 'example-app|example-v2|/keys/synthetic-private.pem',
        ], function (): void {
            $this->artisan('auth-manager:delegated-access:check')
                ->expectsOutputToContain('Writes are listed for other-app, but it has no key of its own')
                ->doesntExpectOutputToContain('Writes are listed for example-app')
                ->assertExitCode(0);
        });

        $this->withEnvironment([
            'AUTH_MANAGER_DELEGATED_ACCESS_APPLICATIONS' => 'example-app|https://app.example.test/access|3',
            DelegatedAccessKeys::ENVIRONMENT => 'missing-app|missing-v1|/keys/synthetic-private.pem',
        ], function (): void {
            $this->artisan('auth-manager:delegated-access:check')
                ->expectsOutputToContain('names an application that is not configured: missing-app')
                ->assertExitCode(1);
        });

        $this->withEnvironment([
            'AUTH_MANAGER_DELEGATED_ACCESS_APPLICATIONS' => 'example-app|https://app.example.test/access|3',
            DelegatedAccessKeys::ENVIRONMENT => 'example-app|example-v1|keys/synthetic-private.pem',
        ], function (): void {
            $this->artisan('auth-manager:delegated-access:check')
                ->expectsOutputToContain('private key path must be absolute')
                ->doesntExpectOutputToContain('synthetic-private')
                ->assertExitCode(1);
        });

        $this->withEnvironment([
            'AUTH_MANAGER_DELEGATED_ACCESS_APPLICATIONS' => 'example-app|https://app.example.test/access|3',
            'AUTH_MANAGER_DELEGATED_ACCESS_KEY_ID' => 'shared-v1',
            DelegatedAccessKeys::ENVIRONMENT => 'example-app|shared-v1|/keys/synthetic-private.pem',
        ], function (): void {
            $this->artisan('auth-manager:delegated-access:check')
                ->expectsOutputToContain('entry 1 reuses the instance-wide key')
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
